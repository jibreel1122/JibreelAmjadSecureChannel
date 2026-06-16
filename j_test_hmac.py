import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "crypto")
    )
)

from j_hmac import hmac_sha256


def test_case(key, message, expected):
    result = hmac_sha256(key.encode(), message.encode()).hex()

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
        "jibreel",
        "748161a09b2b2d27511a330cb9207e21641edf14d25f7108b59f5e6e8a8478fb"
)

    test_case(
        "jibreel",
        "amjad",
        "c6fe32c0f66e5adc69271d3b7e7bfd44940701b5ecc67869e8562aded627574e"
    )

    test_case(
        "jibreel",
        "110 out of 100",
        "e362796cbd093fd4776363a76a658f5149c24f2f2c60ddd2e8684f15d9a7dc24"
    )