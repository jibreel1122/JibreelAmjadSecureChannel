import socket
import struct

from protocol.a_handshake import HandshakeState
from protocol.j_message import pack_message, unpack_message, make_header, read_header, MESSAGE_TYPE_CHAT
from crypto.a_aead_chacha20_poly1305 import chacha20_aead_encrypt, chacha20_aead_decrypt


def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)))
    sock.sendall(data)


def recv_frame(sock):
    buf = b""
    while len(buf) < 4:
        part = sock.recv(4 - len(buf))
        if not part:
            raise ConnectionError("connection closed while reading length")
        buf += part
    length = struct.unpack(">I", buf)[0]
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise ConnectionError("connection closed while reading data")
        data += part
    return data


def connect(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("connecting to server...")
    sock.connect((ip, port))
    print("connected to server")
    return sock


def make_constant_and_iv(nonce_base, seq):
    constant = nonce_base[0:4]
    iv = (int.from_bytes(nonce_base[4:12], "big") ^ seq).to_bytes(8, "big")
    return constant, iv


def encrypt_message(key, nonce_base, seq, sender_id, plaintext):
    header = make_header(MESSAGE_TYPE_CHAT, sender_id, seq)
    constant, iv = make_constant_and_iv(nonce_base, seq)
    ct, tag = chacha20_aead_encrypt(header, key, iv, constant, plaintext)
    return pack_message(header, ct, tag)


def decrypt_message(key, nonce_base, frame):
    header, ct, tag = unpack_message(frame)
    _, _, sender_id, seq = read_header(header)
    constant, iv = make_constant_and_iv(nonce_base, seq)
    pt = chacha20_aead_decrypt(header, key, iv, constant, ct, tag)
    return seq, sender_id, pt


def send_secure(sock, key, nonce_base, seq, sender_id, plaintext):
    frame = encrypt_message(key, nonce_base, seq, sender_id, plaintext)
    send_frame(sock, frame)


def recv_secure(sock, key, nonce_base):
    frame = recv_frame(sock)
    seq, sender_id, pt = decrypt_message(key, nonce_base, frame)
    return seq, sender_id, pt


def do_client_handshake(sock, handshake_state):
    # Message 1 (Initiator -> Responder)
    msg1 = handshake_state.write_message()
    send_frame(sock, msg1)

    # Message 2 (Responder -> Initiator)
    msg2 = recv_frame(sock)
    handshake_state.read_message(msg2)

    # Message 3 (Initiator -> Responder)
    msg3 = handshake_state.write_message()
    send_frame(sock, msg3)

    # Split returns two CipherState objects (send, recv)
    send_cipher, recv_cipher = handshake_state.split()

    # Extract keys and provide standard 12-byte zeroed nonces for your custom loop
    return {
        "client_key": send_cipher.k,
        "server_key": recv_cipher.k,
        "client_nonce_base": b"\x00" * 12,
        "server_nonce_base": b"\x00" * 12
    }


def run_client(ip="127.0.0.1", port=8000, client_id="jibreel-client", server_id="server"):
    sock = connect(ip, port)
    handshake = HandshakeState()
    handshake.initialize(initiator=True)
    keys = do_client_handshake(sock, handshake)
    print("handshake completed")
    print("secure channel ready")
    seq = 0
    while True:
        text = input("message: ")
        if text == "quit":
            print("closing connection")
            break
        send_secure(sock, keys["client_key"], keys["client_nonce_base"], seq, client_id, text.encode())
        seq = seq + 1
        in_seq, sender_id, pt = recv_secure(sock, keys["server_key"], keys["server_nonce_base"])
        print("message from", sender_id, ":", pt.decode())
    sock.close()
    print("connection closed")


if __name__ == "__main__":
    print("crypto client by jibreel bornat birzeit 2026")
    run_client()