from crypto.j_hkdf import hkdf


def derive_keys(shared_secret: bytes, psk: bytes, transcript_hash: bytes) -> dict:
    print("deriving client_key")
    client_key = hkdf(psk, shared_secret, b"client key", 32)

    print("deriving server_key")
    server_key = hkdf(psk, shared_secret, b"server key", 32)

    print("deriving client_nonce_base")
    client_nonce_base = hkdf(psk, shared_secret, b"client nonce", 12)

    print("deriving server_nonce_base")
    server_nonce_base = hkdf(psk, shared_secret, b"server nonce", 12)

    keys = {
        "client_key": client_key,
        "server_key": server_key,
        "client_nonce_base": client_nonce_base,
        "server_nonce_base": server_nonce_base,
    }
    return keys


if __name__ == "__main__":
    print("crypto key schedule by jibreel bornat at birzeit 2026")

    shared_secret = b"jibreel bornat birzeit shared secret 2026"
    psk = b"jibreel bornat birzeit psk 2026"
    transcript_hash = b"crypto handshake transcript hash 2026"

    keys = derive_keys(shared_secret, psk, transcript_hash)

    print("client_key:", keys["client_key"].hex())
    print("server_key:", keys["server_key"].hex())
    print("client_nonce_base:", keys["client_nonce_base"].hex())
    print("server_nonce_base:", keys["server_nonce_base"].hex())
