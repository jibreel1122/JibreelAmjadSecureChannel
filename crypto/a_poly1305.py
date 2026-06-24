import math,os,sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.a_chacha20 import chacha20_block
def le_bytes_to_num(b):
    return int.from_bytes(b,"little")

def num_to_16_le_bytes(num):
    return num.to_bytes(16,"little")

def poly1305_mac(msg, key):
    r = le_bytes_to_num(key[:16])
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = le_bytes_to_num(key[16:32])
    a = 0 # a is the accumulator
    p = (1<<130)-5
    for i in range(math.ceil(len(msg) / 16)):
        n = le_bytes_to_num(msg[i*16 : (i+1)*16] + b'\x01')
        a += n
        a = (r * a) % p
    a = (a + s) % (1 << 128)
    return num_to_16_le_bytes(a)

def poly1305_key_gen(key,nonce):
    counter = 0
    block = chacha20_block(key,counter,nonce)
    return block[:32]