from crypto.j_sha256 import sha256
from crypto.j_hkdf import hkdf
from protocol.a_cipherstate import CipherState


HASHLEN = 32


class SymmetricState:

    def __init__(self):
        self.cipher_state = CipherState()
        self.ck = b""
        self.h = b""
    def initialize_symmetric(self, protocol_name: bytes):
        if len(protocol_name) <= HASHLEN:
            self.h = protocol_name.ljust(HASHLEN, b"\x00")
        else:
            self.h = sha256(protocol_name)
        self.ck = self.h
        self.cipher_state.initialize_key(None)

    def _noise_hkdf(self, ck: bytes, ikm: bytes):
        output = hkdf(salt=ck,ikm=ikm,info=b"",length=64)

        return output[:32], output[32:]
    def mix_hash(self, data: bytes):
        self.h = sha256(self.h + data)
        
    def mix_key(self, input_key_material: bytes):
        self.ck, temp_k = self._noise_hkdf( self.ck,input_key_material)
        self.cipher_state.initialize_key(temp_k)


    def encrypt_and_hash(self, plaintext: bytes):

        if self.cipher_state.has_key():
            ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        else:
            ciphertext = plaintext
        self.mix_hash(ciphertext)
        return ciphertext


    def decrypt_and_hash(self, ciphertext: bytes):
        if self.cipher_state.has_key():
            plaintext = self.cipher_state.decrypt_with_ad(self.h,ciphertext)
        else:
            plaintext = ciphertext
        self.mix_hash(ciphertext)
        return plaintext

    def split(self):
        temp_k1, temp_k2 = self._noise_hkdf(self.ck,b"")
        c1 = CipherState()
        c2 = CipherState()
        c1.initialize_key(temp_k1)
        c2.initialize_key(temp_k2)
        return c1, c2