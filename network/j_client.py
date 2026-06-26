import os
import socket
import struct

from protocol.a_handshake import HandshakeState
from protocol.j_message import pack_message, unpack_message, make_header, read_header, MESSAGE_TYPE_CHAT
from protocol.j_transcript import transcript_hash
from crypto.a_aead_chacha20_poly1305 import chacha20_aead_encrypt, chacha20_aead_decrypt
from crypto.j_hmac import hmac_sha256


def load_psk():
    psk = os.environ.get("SECURECHANNEL_PSK")
    if psk is not None:
        return psk.encode()
    return b"birzeit-encs4320-demo-psk"


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


class AuthFailure(Exception):
    pass


class ReplayRejected(Exception):
    pass


def decrypt_message(key, nonce_base, frame):
    header, ct, tag = unpack_message(frame)
    _, _, sender_id, seq = read_header(header)
    constant, iv = make_constant_and_iv(nonce_base, seq)
    pt = chacha20_aead_decrypt(header, key, iv, constant, ct, tag)
    if pt is None:
        raise AuthFailure("authentication failed: header or ciphertext was tampered")
    return seq, sender_id, pt


def send_secure(sock, key, nonce_base, seq, sender_id, plaintext):
    frame = encrypt_message(key, nonce_base, seq, sender_id, plaintext)
    send_frame(sock, frame)


_expected_recv_seq = {}


def recv_secure(sock, key, nonce_base):
    frame = recv_frame(sock)
    seq, sender_id, pt = decrypt_message(key, nonce_base, frame)
    expected = _expected_recv_seq.get(id(sock), 0)
    if seq != expected:
        raise ReplayRejected("replay or reordering detected "
                             "(expected " + str(expected) + ", got " + str(seq) + ")")
    _expected_recv_seq[id(sock)] = expected + 1
    return seq, sender_id, pt


def do_client_handshake(sock, handshake_state):
    msg1 = handshake_state.write_message()
    send_frame(sock, msg1)

    msg2 = recv_frame(sock)
    handshake_state.read_message(msg2)

    th = transcript_hash(handshake_state.transcript())
    server_tag = recv_frame(sock)
    if server_tag != hmac_sha256(handshake_state.psk, th):
        raise ValueError("handshake authentication failed: bad PSK or man-in-the-middle")

    client_tag = hmac_sha256(handshake_state.psk, th)
    msg3 = handshake_state.write_message(client_tag)
    send_frame(sock, msg3)

    return handshake_state.split()


def do_handshake(sock, client_id="jibreel-client", server_id="server"):
    handshake = HandshakeState()
    handshake.initialize(initiator=True, psk=load_psk(),
                         client_id=client_id, server_id=server_id)
    return do_client_handshake(sock, handshake)


def run_client(ip="127.0.0.1", port=8000, client_id="jibreel-client", server_id="server"):
    sock = connect(ip, port)
    keys = do_handshake(sock, client_id, server_id)
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