from j_sha256 import sha256

BLOCK_SIZE = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:

    # if key is longer than block size we hash it first
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    # pad key with zeros to make it block size
    if len(key) < BLOCK_SIZE:
        key = key + b'\x00' * (BLOCK_SIZE - len(key))

    ipad = bytes([b ^ 0x36 for b in key])
    opad = bytes([b ^ 0x5C for b in key])

    inner_hash = sha256(ipad + message)
    result = sha256(opad + inner_hash)

    return result


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    return hmac_sha256(key, message).hex()


if __name__ == "__main__":
    k = input("Key: ")
    msg = input("Message: ")

    print(hmac_sha256_hex(k.encode(), msg.encode()))
