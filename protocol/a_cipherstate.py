from crypto.a_aead_chacha20_poly1305 import (
    chacha20_aead_encrypt,
    chacha20_aead_decrypt,
)

NONCE_MAX = (1 << 64) - 1

class CipherState:
    def __init__(self):
        self.k = None
        self.n = 0

    def initialize_key(self, key: bytes | None):
        self.k = key
        self.n = 0

    def has_key(self):
        return self.k is not None

    def _nonce_parts(self):
        constant = b"\x00\x00\x00\x00"
        iv = self.n.to_bytes(8, "little")
        return constant, iv

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes):
        if self.k is None:
            return plaintext
        if self.n > NONCE_MAX:
            raise OverflowError("CipherState nonce exhausted")
        constant, iv = self._nonce_parts()
        ciphertext, tag = chacha20_aead_encrypt(aad=ad,key=self.k,iv=iv,constant=constant,plaintext=plaintext,)
        self.n += 1
        return ciphertext + tag

    def decrypt_with_ad(self, ad: bytes, data: bytes):
        if self.k is None:
            return data
        if self.n > NONCE_MAX:
            raise OverflowError("CipherState nonce exhausted")
        ciphertext = data[:-16]
        tag = data[-16:]
        constant, iv = self._nonce_parts()
        plaintext = chacha20_aead_decrypt(aad=ad,key=self.k,iv=iv,constant=constant,ciphertext=ciphertext,received_tag=tag,)
        if plaintext is None:
            raise ValueError("Authentication failed")
        self.n += 1
        return plaintext
