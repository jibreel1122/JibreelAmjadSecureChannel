import socket
import struct

from j_transcript import build_handshake_transcript, transcript_hash
from j_key_schedule import derive_keys
from j_message import pack_message, unpack_message, make_associated_data

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


PROTOCOL = "SecureChannel-v1"


def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)))
    sock.sendall(data)


def recv_frame(sock):
    header = b""
    while len(header) < 4:
        part = sock.recv(4 - len(header))
        if not part:
            raise ConnectionError("connection closed while reading length")
        header += part
    length = struct.unpack(">I", header)[0]
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ConnectionError("connection closed while reading data")
        data += part
    return data


def connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("connecting to", ip, port)
    sock.connect((ip, port))
    print("connection status: connected")
    return sock


def make_nonce(nonce_base, seq):
    return (int.from_bytes(nonce_base, "big") ^ seq).to_bytes(12, "big")


def encrypt_message(key, nonce_base, seq, plaintext):
    aad = make_associated_data(seq)
    nonce = make_nonce(nonce_base, seq)
    combined = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    ct = combined[:-16]
    tag = combined[-16:]
    return pack_message(seq, ct, tag)


def decrypt_message(key, nonce_base, frame):
    seq, ct, tag = unpack_message(frame)
    aad = make_associated_data(seq)
    nonce = make_nonce(nonce_base, seq)
    pt = ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad)
    return seq, pt


def do_handshake(sock, client_id, server_id):
    print("starting handshake")
    client_priv = X25519PrivateKey.generate()
    client_pub = client_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    send_frame(sock, PROTOCOL.encode())
    send_frame(sock, client_id.encode())
    send_frame(sock, client_pub)

    server_id_recv = recv_frame(sock).decode()
    server_pub = recv_frame(sock)

    print("got server id", server_id_recv)
    shared = client_priv.exchange(X25519PublicKey.from_public_bytes(server_pub))

    transcript = build_handshake_transcript(PROTOCOL, client_id, server_id_recv, client_pub, server_pub)
    th = transcript_hash(transcript)
    keys = derive_keys(shared, th)

    print("authentication / handshake successful")
    return keys


def send_secure(sock, key, nonce_base, seq, plaintext):
    frame = encrypt_message(key, nonce_base, seq, plaintext)
    send_frame(sock, frame)


def recv_secure(sock, key, nonce_base):
    frame = recv_frame(sock)
    seq, pt = decrypt_message(key, nonce_base, frame)
    return seq, pt


def run_client(ip="127.0.0.1", port=9999, client_id="jibreel-client", server_id="server"):
    sock = connect(ip, port)
    keys = do_handshake(sock, client_id, server_id)
    print("secure channel ready")

    seq = 0
    while True:
        text = input("message: ")
        if text == "quit":
            print("closing connection")
            break
        send_secure(sock, keys["client_key"], keys["client_nonce_base"], seq, text.encode())
        seq = seq + 1
        in_seq, pt = recv_secure(sock, keys["server_key"], keys["server_nonce_base"])
        print("received plaintext:", pt.decode())

    sock.close()
    print("connection status: closed")


def self_test():
    print("offline self test by jibreel bornat birzeit 2026")
    shared_secret = b"jibreel bornat birzeit shared secret 2026"
    th = b"crypto handshake transcript hash 2026"
    keys = derive_keys(shared_secret, th)

    plaintext = b"hello from jibreel bornat crypto 2026"
    for seq in [0, 1, 5]:
        frame = encrypt_message(keys["client_key"], keys["client_nonce_base"], seq, plaintext)
        out_seq, pt = decrypt_message(keys["client_key"], keys["client_nonce_base"], frame)
        assert out_seq == seq
        assert pt == plaintext
        print("seq", seq, "decrypted plaintext:", pt.decode())

    print("self test ok")


if __name__ == "__main__":
    self_test()
