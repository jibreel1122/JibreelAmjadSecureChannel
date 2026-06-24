import sys
import os
import hashlib

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from protocol.j_transcript import build_handshake_transcript, transcript_hash, encode_field


def test_hash_matches_library(name, proto, client_id, server_id, client_pub, server_pub):
    t = build_handshake_transcript(proto, client_id, server_id, client_pub, server_pub)
    mine = transcript_hash(t).hex()
    library = hashlib.sha256(t).hexdigest()

    print("Testing:", name)
    if mine == library:
        print("PASS\n")
        return True
    else:
        print("FAIL")
        print("mine   :", mine)
        print("library:", library)
        print()
        return False


def test_encode_field():
    print("Testing: encode_field length prefix")
    f = encode_field(b"abc")
    if f == (3).to_bytes(4, "big") + b"abc":
        print("PASS\n")
        return True
    print("FAIL\n")
    return False


def test_different_identities_different_hash():
    print("Testing: different identities give different hash")
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))
    t1 = build_handshake_transcript("v1", "gaza", "birzeit", pub1, pub2)
    t2 = build_handshake_transcript("v1", "palestine", "birzeit", pub1, pub2)
    if transcript_hash(t1) != transcript_hash(t2):
        print("PASS\n")
        return True
    print("FAIL\n")
    return False


if __name__ == "__main__":
    pub1 = bytes(range(32))
    pub2 = bytes(range(32, 64))

    results = []
    results.append(test_encode_field())
    results.append(test_hash_matches_library("free palestine", "SecureChannel-v1", "free", "palestine", pub1, pub2))
    results.append(test_hash_matches_library("gaza", "SecureChannel-v1", "gaza", "birzeit", pub1, pub2))
    results.append(test_hash_matches_library("birzeit", "SecureChannel-v1", "birzeit", "computer engineer 2026", pub1, pub2))
    results.append(test_different_identities_different_hash())

    passed = sum(1 for r in results if r)
    print("transcript tests passed", passed, "of", len(results))
