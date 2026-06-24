import math,os,sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.a_chacha20 import chacha20_block

def poly1305_key_gen(key,nonce):
    counter = 0
    block = chacha20_block(key,counter,nonce)
    return block[:32]