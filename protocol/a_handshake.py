"""
Handshake state machine.

This module wraps a Noise_XX-style message flow that we use only to transport
the two ephemeral X25519 public keys between the parties. The Noise
SymmetricState/CipherState plumbing (mix_hash, mix_key, encrypt_and_hash) runs
during the three message rounds, but its split() output is NOT what secures the
application channel.

The actual session keys come from the project key schedule: once both ephemeral
public keys are known, each side authenticates the handshake with
HMAC(PSK, transcript) and derives the directional keys + nonce bases with HKDF
using the PSK as salt (see derive_session_keys() -> protocol.j_key_schedule).
The captured ephemeral-ephemeral shared secret (self.ee_shared) is the IKM for
that derivation.

In short: Noise here is an ephemeral-key transport; PSK + HKDF is the security.
Keeping the Noise wrapper lets the wire format stay close to a real handshake
while the key schedule follows the spec exactly.
"""

from protocol.a_symmetricstate import SymmetricState
from protocol.a_keypair import generate_keypair, public_key
from crypto.a_x25519 import x25519
from protocol.j_transcript import build_handshake_transcript, transcript_hash
from protocol.j_key_schedule import derive_keys

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
PROTOCOL_INFO = "SecureChannel-v1"
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
        self.psk = b""
        self.client_id = ""
        self.server_id = ""
        self.ee_shared = None

    def initialize(self, initiator: bool, s=None, rs=None, psk=b"", client_id="", server_id=""):
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
        self.psk = psk
        self.client_id = client_id
        self.server_id = server_id
        self.ee_shared = None

    def dh(self, private_key, public_key):
        return x25519(private_key, public_key)

    def read_message(self, message):
        if self.message_pattern == 0:
            if not self.initiator:
                self.re = message[:32]
                self.symmetric.mix_hash(self.re)
                payload = self.symmetric.decrypt_and_hash(message[32:])
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
            self.ee_shared = shared
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
            self.ee_shared = shared
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

    def transcript(self):
        # Both ephemeral public keys ordered as (client, server) so that the
        # initiator and the responder build the exact same transcript bytes.
        if self.initiator:
            client_pub, server_pub = self.e_pub, self.re
        else:
            client_pub, server_pub = self.re, self.e_pub
        return build_handshake_transcript(
            PROTOCOL_INFO, self.client_id, self.server_id, client_pub, server_pub
        )

    def derive_session_keys(self):
        # Spec key schedule: HKDF over the ephemeral-ephemeral shared secret with
        # the PSK as the salt, producing the two directional keys + nonce bases.
        th = transcript_hash(self.transcript())
        return derive_keys(self.ee_shared, self.psk, th)

    def split(self):
        return self.derive_session_keys()