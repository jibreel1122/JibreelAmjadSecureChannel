P = 2**255 - 19
A = 486662
a24 = (A-2)//4
bits = 255
def decodeLittleEndian(b, bits):
    return sum([b[i] << 8*i for i in range((bits+7)//8)])

def decodeUCoordinate(u, bits):
    u_list = list(u)
    if bits % 8:
       u_list[-1] &= (1<<(bits%8))-1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
    u = u % P
    return u.to_bytes((bits + 7)//8, "little")
def decodeScalar25519(k):
    k_list =  list(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def mask(swap):
    return 0-swap
def cswap(swap, x_2, x_3):
         dummy = mask(swap) & (x_2 ^ x_3)
         x_2 = x_2 ^ dummy
         x_3 = x_3 ^ dummy
         return (x_2, x_3)

def montgomery_ladder(k, u):
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0
    for t in range(bits - 1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t
        Ap = (x_2 + z_2) % P
        AA = (Ap * Ap) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * Ap) % P
        CB = (C * B) % P

        x_3 = ((DA + CB) * (DA + CB)) % P
        z_3 = (x_1 * ((DA - CB) * (DA - CB) % P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + a24 * E)) % P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    # Affine x-coordinate
    x = (x_2 * pow(z_2, P - 2, P)) % P

    # RFC 7748 encoding
    result = bytearray(x.to_bytes(32, "little"))
    result[31] &= 0x7F

    return bytes(result)

def x25519(k, u):
    k = decodeScalar25519(k)
    u = decodeUCoordinate(u, 255)
    return montgomery_ladder(k, u)