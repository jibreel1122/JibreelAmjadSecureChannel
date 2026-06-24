import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from crypto.j_sha256 import sha256


def test_case(message, expected):
    result = sha256(message.encode()).hex()

    print(f"Testing: {message}")

    if result == expected:
        print("PASS\n")
    else:
        print("FAIL")
        print("Expected:", expected)
        print("Got     :", result)
        print()


if __name__ == "__main__":

    test_case(
        "jibreel",
        "f11b89f74b77333322a46a4b042b990f03c1e27eda2f4429d4229ebba5bcac7b"
)

    test_case(
        "amjad",
        "ffc8a893622c8529e4b933e5491369c3a29c3f006c8ca337e5fbd23d6f9f0cc0"
    )

    test_case(
        "110 out of 100",
        "c3f31fa7cb1006ff82aeb6ff44cad39996a2b4c3999d912aae23545239bc266d"
    )
