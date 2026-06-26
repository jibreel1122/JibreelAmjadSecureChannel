import os
from crypto.a_x25519 import x25519

BASE_POINT = b"\x09" + b"\x00" * 31


def generate_private_key():
    return os.urandom(32)


def public_key(private_key: bytes):
    return x25519(private_key, BASE_POINT)


def generate_keypair():
    sk = generate_private_key()
    pk = public_key(sk)
    return sk, pk