from protocol.a_symmetricstate import SymmetricState
from protocol.a_keypair import generate_keypair, public_key
from crypto.a_x25519 import x25519

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
STATIC_KEY_SIZE = 32
TAG_SIZE = 16


class HandshakeState:

    def __init__(self):
        self.symmetric = SymmetricState()
        self.s = None
        self.s_pub = None
        self.e = None
        self.e_pub = None
        self.rs = None
        self.re = None
        self.initiator = True
        self.message_pattern = 0

    def initialize(self, initiator: bool, s=None, rs=None):
        self.initiator = initiator
        self.symmetric.initialize_symmetric(PROTOCOL_NAME)
        if s is None:
            self.s, self.s_pub = generate_keypair()
        else:
            self.s = s
            self.s_pub = public_key(s)
        self.rs = rs
        self.e = None
        self.e_pub = None
        self.re = None
        self.message_pattern = 0

    def dh(self, private_key, public_key):
        return x25519(private_key, public_key)

    def read_message(self, message):
        if self.message_pattern == 0:
            if not self.initiator:
                self.re = message[:32]
                self.symmetric.mix_hash(self.re)
                payload = message[32:]
                if payload:
                    payload = self.symmetric.decrypt_and_hash(payload)
                self.message_pattern = 1
                return payload
            raise RuntimeError("Unexpected handshake state")

        elif self.message_pattern == 1:
            if not self.initiator:
                raise RuntimeError("Unexpected handshake state")
            index = 0
            self.re = message[index:index + 32]
            index += 32
            self.symmetric.mix_hash(self.re)
            shared = self.dh(self.e, self.re)
            self.symmetric.mix_key(shared)

            encrypted_static = message[index:index + STATIC_KEY_SIZE + TAG_SIZE]
            index += STATIC_KEY_SIZE + TAG_SIZE
            self.rs = self.symmetric.decrypt_and_hash(encrypted_static)
            shared = self.dh(self.e, self.rs)
            self.symmetric.mix_key(shared)

            payload = b""
            if index < len(message):
                payload = self.symmetric.decrypt_and_hash(message[index:])

            self.message_pattern = 2
            return payload

        elif self.message_pattern == 2:
            if self.initiator:
                raise RuntimeError("Initiator cannot receive message 3")
            index = 0
            encrypted_static = message[index:index + STATIC_KEY_SIZE + TAG_SIZE]
            index += STATIC_KEY_SIZE + TAG_SIZE
            self.rs = self.symmetric.decrypt_and_hash(encrypted_static)
            shared = self.dh(self.e, self.rs)
            self.symmetric.mix_key(shared)

            payload = self.symmetric.decrypt_and_hash(message[index:])
            self.message_pattern = 3
            return payload

        raise RuntimeError("Unexpected handshake state")

    def write_message(self, payload=b""):
        message = b""
        if self.message_pattern == 0:
            self.e, self.e_pub = generate_keypair()
            message += self.e_pub
            self.symmetric.mix_hash(self.e_pub)
            message += self.symmetric.encrypt_and_hash(payload)
            self.message_pattern = 1
            return message

        elif self.message_pattern == 1:
            if self.initiator:
                raise RuntimeError("Unexpected handshake state")
            self.e, self.e_pub = generate_keypair()
            message += self.e_pub
            self.symmetric.mix_hash(self.e_pub)
            shared = self.dh(self.e, self.re)
            self.symmetric.mix_key(shared)
            encrypted_static = self.symmetric.encrypt_and_hash(self.s_pub)
            message += encrypted_static
            shared = self.dh(self.s, self.re)
            self.symmetric.mix_key(shared)
            message += self.symmetric.encrypt_and_hash(payload)
            self.message_pattern = 2
            return message

        elif self.message_pattern == 2:
            if not self.initiator:
                raise RuntimeError("Responder cannot send message 3")
            encrypted_static = self.symmetric.encrypt_and_hash(self.s_pub)
            message += encrypted_static
            shared = self.dh(self.s, self.re)
            self.symmetric.mix_key(shared)
            message += self.symmetric.encrypt_and_hash(payload)
            self.message_pattern = 3
            return message

        raise RuntimeError("Unexpected handshake state")

    def split(self):
        send_cipher, recv_cipher = self.symmetric.split()
        if not self.initiator:
            send_cipher, recv_cipher = recv_cipher, send_cipher
        return send_cipher, recv_cipher