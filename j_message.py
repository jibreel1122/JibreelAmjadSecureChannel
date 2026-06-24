import struct


def make_associated_data(sequence_number):
    return struct.pack(">Q", sequence_number)


def pack_message(sequence_number, ciphertext, authentication_tag):
    if len(authentication_tag) != 16:
        raise ValueError("authentication tag must be exactly 16 bytes")
    print("packing message seq", sequence_number)
    seq_bytes = struct.pack(">Q", sequence_number)
    length_bytes = struct.pack(">I", len(ciphertext))
    return seq_bytes + length_bytes + ciphertext + authentication_tag


def unpack_message(data):
    if len(data) < 8 + 4 + 16:
        raise ValueError("data too short to be a valid message")
    print("unpacking message of size", len(data))
    sequence_number = struct.unpack(">Q", data[0:8])[0]
    ciphertext_length = struct.unpack(">I", data[8:12])[0]
    remaining = data[12:]
    if ciphertext_length != len(remaining) - 16:
        raise ValueError("declared ciphertext length does not match data")
    ciphertext = remaining[:ciphertext_length]
    authentication_tag = remaining[ciphertext_length:]
    return sequence_number, ciphertext, authentication_tag


if __name__ == "__main__":
    print("crypto message test amjad qaher birzeit 2026")
    seq = 7
    text = b"hello from birzeit crypto"
    fake_tag = b"amjadqaher2026!!"
    print("fake tag length", len(fake_tag))
    wire = pack_message(seq, text, fake_tag)
    print("wire bytes length", len(wire))
    out_seq, out_text, out_tag = unpack_message(wire)
    assert out_seq == seq
    assert out_text == text
    assert out_tag == fake_tag
    print("ad bytes", make_associated_data(seq))
    print("round trip ok amjad qaher 2026")
