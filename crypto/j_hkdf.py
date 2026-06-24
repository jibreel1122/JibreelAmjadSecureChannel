from crypto.j_hmac import hmac_sha256

HASH_LEN = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if salt == b"":
        salt = b"\x00" * HASH_LEN
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    n = (length + HASH_LEN - 1) // HASH_LEN

    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm = okm + t

    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


if __name__ == "__main__":
    ikm = input("IKM: ")
    salt = input("Salt: ")
    info = input("Info: ")
    length = int(input("Length: "))

    print(hkdf(salt.encode(), ikm.encode(), info.encode(), length).hex())
