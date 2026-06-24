import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.a_chacha20 import chacha20_block
number_of_tests=5
def test__model(i,key, nonce,counter,expected):
    result = chacha20_block(key, counter, nonce)
    assert len(result) == 64
    assert result == expected
    print(f"Test Vector #{i+1} PASSED")
list_of_tests = [
    (
        bytes(32),
        bytes(12),
        0,
        bytes.fromhex(
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a37"
            "6a43b8f41518a11cc387b669b2ee6586"
        )
    ),

    (
        bytes(32),
        bytes(12),
        1,
        bytes.fromhex(
            "9f07e7be5551387a98ba977c732d080d"
            "cb0f29a048e3656912c6533e32ee7aed"
            "29b721769ce64e43d57133b074d839d5"
            "31ed1f28510afb45ace10a1f4b794d6f"
        )
    ),

    (
        bytes.fromhex(
            "00000000000000000000000000000000"
            "00000000000000000000000000000001"
        ),
        bytes(12),
        1,
        bytes.fromhex(
            "3aeb5224ecf849929b9d828db1ced4dd"
            "832025e8018b8160b82284f3c949aa5a"
            "8eca00bbb4a73bdad192b5c42f73f2fd"
            "4e273644c8b36125a64addeb006c13a0"
        )
    ),

    (
        bytes.fromhex(
            "00ff0000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        bytes(12),
        2,
        bytes.fromhex(
            "72d54dfbf12ec44b362692df94137f32"
            "8fea8da73990265ec1bbbea1ae9af0ca"
            "13b25aa26cb4a648cb9b9d1be65b2c09"
            "24a66c54d545ec1b7374f4872e99f096"
        )
    ),

    (
        bytes(32),
        bytes.fromhex("000000000000000000000002"),
        0,
        bytes.fromhex(
            "c2c64d378cd536374ae204b9ef933fcd"
            "1a8b2288b3dfa49672ab765b54ee27c7"
            "8a970e0e955c14f3a88e741b97c286f7"
            "5f8fc299e8148362fa198a39531bed6d"
        )
    ),
]
for i in range(0,number_of_tests):
      expected = test__model(i,list_of_tests[i][0],list_of_tests[i][1],list_of_tests[i][2],list_of_tests[i][3])