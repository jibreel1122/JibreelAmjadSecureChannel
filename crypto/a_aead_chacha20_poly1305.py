import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.a_poly1305_key_gen import poly1305_key_gen
from crypto.a_chacha20 import chacha20_encrypt,chacha20_decrypt
from crypto.a_poly1305 import poly1305_mac
from crypto.a_poly1305 import num_to_n_le_bytes
def pad16(x):
    if len(x) % 16 == 0:
        return b''
    else:
        return bytes(16 - (len(x) % 16))

 
def chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
   nonce = constant + iv
   otk = poly1305_key_gen(key, nonce)
   ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
   mac_data  = aad + pad16(aad)
   mac_data += ciphertext + pad16(ciphertext)
   mac_data += num_to_n_le_bytes(len(aad),8)
   mac_data += num_to_n_le_bytes(len(ciphertext),8)
   tag = poly1305_mac(mac_data, otk)
   return (ciphertext, tag)

def chacha20_aead_decrypt(aad, key, iv, constant, ciphertext,received_tag):
    nonce = constant + iv
    otk = poly1305_key_gen(key, nonce)
    mac_data  = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += num_to_n_le_bytes(len(aad),8)
    mac_data += num_to_n_le_bytes(len(ciphertext),8)
    calculated_tag = poly1305_mac(mac_data, otk)
    if received_tag != calculated_tag:
        return None
    plaintext = chacha20_decrypt(key, 1, nonce, ciphertext)
    return plaintext