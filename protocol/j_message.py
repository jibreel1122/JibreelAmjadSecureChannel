import struct

PROTOCOL_VERSION = 1
MESSAGE_TYPE_CHAT = 1


def make_header(msg_type, sender_id, seq):
    sender_bytes = sender_id.encode()
    header = bytes([PROTOCOL_VERSION])
    header += bytes([msg_type])
    header += len(sender_bytes).to_bytes(2, "big")
    header += sender_bytes
    header += struct.pack(">Q", seq)
    return header


def read_header(header):
    version = header[0]
    msg_type = header[1]
    sender_len = struct.unpack(">H", header[2:4])[0]
    sender_id = header[4:4 + sender_len].decode()
    seq = struct.unpack(">Q", header[4 + sender_len:12 + sender_len])[0]
    return version, msg_type, sender_id, seq


def pack_message(header, cipher, tag):
    if len(tag) != 16:
        raise ValueError("tag must be exactly 16 bytes")
    header_len_bytes = struct.pack(">H", len(header))
    cipher_len_bytes = struct.pack(">I", len(cipher))
    return header_len_bytes + header + cipher_len_bytes + cipher + tag


def unpack_message(data):
    if len(data) < 2:
        raise ValueError("data too short to be a valid message")
    header_len = struct.unpack(">H", data[0:2])[0]
    header = data[2:2 + header_len]
    rest = data[2 + header_len:]
    if len(rest) < 4 + 16:
        raise ValueError("data too short to be a valid message")
    cipher_len = struct.unpack(">I", rest[0:4])[0]
    body = rest[4:]
    if cipher_len != len(body) - 16:
        raise ValueError("declared ciphertext length does not match data")
    cipher = body[:cipher_len]
    tag = body[cipher_len:]
    return header, cipher, tag


if __name__ == "__main__":
    print("crypto message test jibreel bornat birzeit 2026")
    seq = 7
    sender_id = "jibreel-client"
    text = b"hello from birzeit crypto"
    test_tag = b"jibreelbornat26!"

    header = make_header(MESSAGE_TYPE_CHAT, sender_id, seq)
    print("header bytes", header)

    wire = pack_message(header, text, test_tag)
    print("wire length", len(wire))

    out_header, out_text, out_tag = unpack_message(wire)
    out_version, out_type, out_sender_id, out_seq = read_header(out_header)

    assert out_header == header
    assert out_text == text
    assert out_tag == test_tag
    assert out_version == PROTOCOL_VERSION
    assert out_type == MESSAGE_TYPE_CHAT
    assert out_sender_id == sender_id
    assert out_seq == seq
    print("round trip ok jibreel bornat 2026")
