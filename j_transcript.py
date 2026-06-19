from j_sha256 import sha256


def encode_field(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def build_handshake_transcript(protocol_info, client_id, server_id, client_pub, server_pub):

    out = b""
    out += encode_field(protocol_info.encode())
    out += encode_field(client_id.encode())
    out += encode_field(server_id.encode())
    out += encode_field(client_pub)
    out += encode_field(server_pub)
    return out


def transcript_hash(transcript: bytes) -> bytes:
    return sha256(transcript)


if __name__ == "__main__":
    client_pub = bytes(range(32))
    server_pub = bytes(range(32, 64))

    t = build_handshake_transcript("SecureChannel-v1", "client1", "server1", client_pub, server_pub)

    print(t.hex())
    print(transcript_hash(t).hex())
