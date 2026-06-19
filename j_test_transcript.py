import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "crypto")
    )
)

from j_transcript import build_handshake_transcript, transcript_hash, encode_field


def test_case(name, fn):
    print(f"Testing: {name}")
    ok = fn()
    if ok:
        print("PASS\n")
    else:
        print("FAIL\n")


def test_encode_field():
    f = encode_field(b"abc")
    return f == (3).to_bytes(4, "big") + b"abc"


def test_same_inputs_same_hash():
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))

    t1 = build_handshake_transcript("v1", "c", "s", pub1, pub2)
    t2 = build_handshake_transcript("v1", "c", "s", pub1, pub2)

    return transcript_hash(t1) == transcript_hash(t2)


def test_different_pubkeys_different_hash():
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))
    pub3 = bytes(range(1, 33))

    t1 = build_handshake_transcript("v1", "c", "s", pub1, pub2)
    t2 = build_handshake_transcript("v1", "c", "s", pub3, pub2)

    return transcript_hash(t1) != transcript_hash(t2)


def test_different_identities_different_hash():
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))

    t1 = build_handshake_transcript("v1", "client1", "server1", pub1, pub2)
    t2 = build_handshake_transcript("v1", "client2", "server1", pub1, pub2)

    return transcript_hash(t1) != transcript_hash(t2)


def test_field_order_matters():
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))

    t1 = build_handshake_transcript("v1", "alice", "bob", pub1, pub2)
    t2 = build_handshake_transcript("v1", "bob", "alice", pub1, pub2)

    return transcript_hash(t1) != transcript_hash(t2)


if __name__ == "__main__":

    test_case("encode_field length prefix", test_encode_field)
    test_case("same inputs give same transcript hash", test_same_inputs_same_hash)
    test_case("different pubkeys give different hash", test_different_pubkeys_different_hash)
    test_case("different identities give different hash", test_different_identities_different_hash)
    test_case("swapping client/server id changes the hash", test_field_order_matters)
