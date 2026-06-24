import socket
import struct

from protocol.j_message import pack_message, unpack_message, make_associated_data

from crypto.a_aead import encrypt, decrypt
from protocol.a_handshake import do_handshake


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
    ct, tag = encrypt(key, nonce, plaintext, aad)
    return pack_message(seq, ct, tag)


def decrypt_message(key, nonce_base, frame):
    seq, ct, tag = unpack_message(frame)
    aad = make_associated_data(seq)
    nonce = make_nonce(nonce_base, seq)
    pt = decrypt(key, nonce, ct, tag, aad)
    return seq, pt


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
    print("authentication / handshake successful")
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


if __name__ == "__main__":
    print("crypto client by jibreel bornat birzeit 2026")
    run_client()
