import math

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