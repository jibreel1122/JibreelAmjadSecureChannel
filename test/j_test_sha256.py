import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from crypto.j_sha256 import sha256


def test_case(name, message, expected):
    result = sha256(message).hex()

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
        ("empty string", b"",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", b"abc",
         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("two block message",
         b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]

    passed = 0
    for name, message, expected in cases:
        if test_case(name, message, expected):
            passed = passed + 1

    print("sha256 tests passed", passed, "of", len(cases))
