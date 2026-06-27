import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.a_poly1305 import poly1305_mac
number_of_tests = 11

def test__model(i, key, msg, tag):
    result = poly1305_mac(msg, key)
    assert result == tag
    print(f"Test Vector #{i+1} PASSED")
list_of_tests = [
    (
        bytes(32),
        bytes(64),
        bytes(16)
    ),
    (
        bytes.fromhex(
            "00000000000000000000000000000000"
            "36e5f6b5c5e06070f0efca96227a863e"
        ),
        (
            b"Any submission to the IETF intended "
            b"by the Contributor for publication "
            b"as all or part of an IETF Internet-Draft "
            b"or RFC and any statement made within the "
            b"context of an IETF activity is considered "
            b"an \"IETF Contribution\". Such statements "
            b"include oral statements in IETF sessions, "
            b"as well as written and electronic communications "
            b"made at any time or place, which are addressed to"
        ),
        bytes.fromhex(
            "36e5f6b5c5e06070f0efca96227a863e"
        )
    ),
    (
        bytes.fromhex(
            "36e5f6b5c5e06070f0efca96227a863e"
            "00000000000000000000000000000000"
        ),
        (
            b"Any submission to the IETF intended "
            b"by the Contributor for publication "
            b"as all or part of an IETF Internet-Draft "
            b"or RFC and any statement made within the "
            b"context of an IETF activity is considered "
            b"an \"IETF Contribution\". Such statements "
            b"include oral statements in IETF sessions, "
            b"as well as written and electronic communications "
            b"made at any time or place, which are addressed to"
        ),
        bytes.fromhex(
            "f3477e7cd95417af89a6b8794c310cf0"
        )
    ),
    (
        bytes.fromhex(
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0"
        ),
        (
            b"'Twas brillig, and the slithy toves\n"
            b"Did gyre and gimble in the wabe:\n"
            b"All mimsy were the borogoves,\n"
            b"And the mome raths outgrabe."
        ),
        bytes.fromhex(
            "4541669a7eaaee61e708dc7cbcc5eb62"
        )
    ),
    (
        bytes.fromhex(
            "02000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "ffffffffffffffffffffffffffffffff"
        ),
        bytes.fromhex(
            "03000000000000000000000000000000"
        )
    ),
    (
        bytes.fromhex(
            "02000000000000000000000000000000"
            "ffffffffffffffffffffffffffffffff"
        ),
        bytes.fromhex(
            "02000000000000000000000000000000"
        ),
        bytes.fromhex(
            "03000000000000000000000000000000"
        )
    ),
    (
        bytes.fromhex(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "ffffffffffffffffffffffffffffffff"
            "f0ffffffffffffffffffffffffffffff"
            "11000000000000000000000000000000"
        ),
        bytes.fromhex(
            "05000000000000000000000000000000"
        )
    ),
    (
        bytes.fromhex(
            "01000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "ffffffffffffffffffffffffffffffff"
            "fbfefefefefefefefefefefefefefefe"
            "01010101010101010101010101010101"
        ),
        bytes.fromhex(
            "00000000000000000000000000000000"
        )
    ),
    (
        bytes.fromhex(
            "02000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "fdffffffffffffffffffffffffffffff"
        ),
        bytes.fromhex(
            "faffffffffffffffffffffffffffffff"
        )
    ),
    (
        bytes.fromhex(
            "01000000000000000400000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "e33594d7505e43b90000000000000000"
            "3394d7505e4379cd0100000000000000"
            "00000000000000000000000000000000"
            "01000000000000000000000000000000"
        ),
        bytes.fromhex(
            "14000000000000005500000000000000"
        )
    ),
    (
        bytes.fromhex(
            "01000000000000000400000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "e33594d7505e43b90000000000000000"
            "3394d7505e4379cd0100000000000000"
            "00000000000000000000000000000000"
        ),
        bytes.fromhex(
            "13000000000000000000000000000000"
        )
    ),
]

for i in range(number_of_tests):
    test__model(i,list_of_tests[i][0],list_of_tests[i][1],list_of_tests[i][2])