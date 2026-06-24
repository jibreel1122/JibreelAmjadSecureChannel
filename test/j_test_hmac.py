import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from crypto.j_hmac import hmac_sha256


def test_case(name, key, message, expected):
    result = hmac_sha256(key, message).hex()

    print("Testing:", name)
    if result == expected:
        print("PASS\n")
        return True
    else:
        print("FAIL")
        print("Expected:", expected)
        print("Got     :", result)
        print()
        return False


if __name__ == "__main__":
    cases = [
        ("rfc4231 test case 1", b"\x0b" * 20, b"Hi There",
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ("rfc4231 test case 2", b"Jefe", b"what do ya want for nothing?",
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        ("rfc4231 test case 3", b"\xaa" * 20, b"\xdd" * 50,
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    ]

    passed = 0
    for name, key, message, expected in cases:
        if test_case(name, key, message, expected):
            passed = passed + 1

    print("hmac tests passed", passed, "of", len(cases))
