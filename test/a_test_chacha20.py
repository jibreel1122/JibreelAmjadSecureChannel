import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.a_chacha20 import chacha20_encrypt
number_of_tests=3
def test__model(i,key, nonce,counter,plaintext,ciphertext):
    result = chacha20_encrypt(key, counter, nonce,plaintext)
    assert result == ciphertext
    print(f"Test Vector #{i+1} PASSED")
list_of_tests = [
    (
        bytes(32),
        bytes(12),
        0,
        bytes(64),
        bytes.fromhex(
            "76b8e0ada0f13d90405d6ae55386bd28"
            "bdd219b8a08ded1aa836efcc8b770dc7"
            "da41597c5157488d7724e03fb8d84a37"
            "6a43b8f41518a11cc387b669b2ee6586"
        )
    ),

    (
        bytes.fromhex(
            "00000000000000000000000000000000"
            "00000000000000000000000000000001"
        ),
        bytes.fromhex("000000000000000000000002"),
        1,
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
            "a3fbf07df3fa2fde4f376ca23e827370"
            "41605d9f4f4f57bd8cff2c1d4b7955ec"
            "2a97948bd3722915c8f3d337f7d37005"
            "0e9e96d647b7c39f56e031ca5eb6250d"
            "4042e02785ececfa4b4bb5e8ead0440e"
            "20b6e8db09d881a7c6132f420e527950"
            "42bdfa7773d8a9051447b3291ce1411c"
            "680465552aa6c405b7764d5e87bea85a"
            "d00f8449ed8f72d0d662ab052691ca66"
            "424bc86d2df80ea41f43abf937d3259d"
            "c4b2d0dfb48a6c9139ddd7f76966e928"
            "e635553ba76c5c879d7b35d49eb2e62b"
            "0871cdac638939e25e8a1e0ef9d5280f"
            "a8ca328b351c3c765989cbcf3daa8b6c"
            "cc3aaf9f3979c92b3720fc88dc95ed84"
            "a1be059c6499b9fda236e7e818b04b0b"
            "c39c1e876b193bfe5569753f88128cc0"
            "8aaa9b63d1a16f80ef2554d7189c411f"
            "5869ca52c5b83fa36ff216b9c1d30062"
            "bebcfd2dc5bce0911934fda79a86f6e6"
            "98ced759c3ff9b6477338f3da4f9cd85"
            "14ea9982ccafb341b2384dd902f3d1ab"
            "7ac61dd29c6f21ba5b862f3730e37cfd"
            "c4fd806c22f221"
        )
    ),
    (
        bytes.fromhex(
            "1c9240a5eb55d38af333888604f6b5f0"
            "473917c1402b80099dca5cbc207075c0"
        ),
        bytes.fromhex("000000000000000000000002"),
        42,
        (
            b"'Twas brillig, and the slithy toves\n"
            b"Did gyre and gimble in the wabe:\n"
            b"All mimsy were the borogoves,\n"
            b"And the mome raths outgrabe."
        ),
        bytes.fromhex(
            "62e6347f95ed87a45ffae7426f27a1df"
            "5fb69110044c0d73118effa95b01e5cf"
            "166d3df2d721caf9b21e5fb14c616871"
            "fd84c54f9d65b283196c7fe4f60553eb"
            "f39c6402c42234e32a356b3e764312a6"
            "1a5532055716ead6962568f87d3f3f77"
            "04c6a8d1bcd1bf4d50d6154b6da731b1"
            "87b58dfd728afa36757a797ac188d1"
        )
    ),
]
for i in range(0,number_of_tests):
      expected = test__model(i,list_of_tests[i][0],list_of_tests[i][1],list_of_tests[i][2],list_of_tests[i][3],list_of_tests[i][4])