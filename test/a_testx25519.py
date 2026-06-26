import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.a_x25519 import x25519

number_of_tests = 2


def test__model(i, scalar, u_coordinate, expected):
    result = x25519(scalar, u_coordinate)

    assert result == expected

    print(f"Test Vector #{i+1} PASSED")


list_of_tests = [

    (
        bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd"
            "62144c0ac1fc5a18506a2244ba449ac4"
        ),

        bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c"
            "726624ec26b3353b10a903a6d0ab1c4c"
        ),

        bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f"
            "32eccf03491c71f754b4075577a28552"
        )
    ),

    (
        bytes.fromhex(
            "4b66e9d4d1b4673c5ad22691957d6af5"
            "c11b6421e0ea01d42ca4169e7918ba0d"
        ),

        bytes.fromhex(
            "e5210f12786811d3f4b7959d0538ae2c"
            "31dbe7106fc03c3efc4cd549c715a493"
        ),

        bytes.fromhex(
            "95cbde9476e8907d7aade45cb4b873f8"
            "8b595a68799fa152e6f8f7647aac7957"
        )
    ),

]


for i in range(number_of_tests):
    test__model(
        i,
        list_of_tests[i][0],
        list_of_tests[i][1],
        list_of_tests[i][2]
    )