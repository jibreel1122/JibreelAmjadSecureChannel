import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.a_aead_chacha20_poly1305 import chacha20_aead_decrypt

number_of_tests = 1

def test__model(i, aad, key, iv, constant, plaintext, ciphertext, tag):
    result_plaintext= chacha20_aead_decrypt(aad, key,iv,constant,ciphertext,tag)

    assert result_plaintext == plaintext

    print(f"Test Vector #{i+1} PASSED")


list_of_tests = [

    (
        bytes.fromhex(
            "50515253c0c1c2c3c4c5c6c7"
        ),

        bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
        ),

        bytes.fromhex(
            "4041424344454647"
        ),

        bytes.fromhex(
            "07000000"
        ),

        bytes.fromhex(
            "4c616469657320616e642047656e746c"
            "656d656e206f662074686520636c6173"
            "73206f66202739393a20496620492063"
            "6f756c64206f6666657220796f75206f"
            "6e6c79206f6e652074697020666f7220"
            "746865206675747572652c2073756e73"
            "637265656e20776f756c642062652069"
            "742e"
        ),

        bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116"
        ),

        bytes.fromhex(
            "1ae10b594f09e26a7e902ecbd0600691"
        )
    ),

]

for i in range(number_of_tests):
    test__model(
        i,
        list_of_tests[i][0],
        list_of_tests[i][1],
        list_of_tests[i][2],
        list_of_tests[i][3],
        list_of_tests[i][4],
        list_of_tests[i][5],
        list_of_tests[i][6]
    )