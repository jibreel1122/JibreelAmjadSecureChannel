import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.a_poly1305_key_gen import poly1305_key_gen

number_of_tests = 3

def test__model(i, key, nonce, poly1305_key):
    result = poly1305_key_gen(key, nonce)
    assert result == poly1305_key
    print(f"Test Vector #{i+1} PASSED")

list_of_tests = [

    (
        bytes(32),
        bytes(12),
        bytes.fromhex(
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
        )
    ),

    (
        bytes.fromhex(
            "00000000000000000000000000000000"
            "00000000000000000000000000000001"
        ),
        bytes.fromhex(
            "000000000000000000000002"
        ),
        bytes.fromhex(
            "ecfa254f845f647473d3cb140da9e876"
            "06cb33066c447b87bc2666dde3fbb739"
        )
    ),

    (
        bytes.fromhex(
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0"
        ),
        bytes.fromhex(
            "000000000000000000000002"
        ),
        bytes.fromhex(
            "965e3bc6f9ec7ed9560808f4d229f94b"
            "137ff275ca9b3fcbdd59deaad23310ae"
        )
    ),

]

for i in range(number_of_tests):
    test__model(i,list_of_tests[i][0],list_of_tests[i][1],list_of_tests[i][2])