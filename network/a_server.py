# network/server.py

import socket

from protocol.a_handshake import HandshakeState
from protocol.j_transcript import transcript_hash
from crypto.j_hmac import hmac_sha256
from network.j_client import load_psk,send_frame,recv_frame,encrypt_message,decrypt_message,AuthFailure;
HOST = "127.0.0.1"
PORT = 8000
SERVER_ID = "server"
CLIENT_ID = "jibreel-client"

def recv_packet(sock):
    length = int.from_bytes(sock.recv(4), "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data

def send_packet(sock, packet):
    sock.sendall(len(packet).to_bytes(4, "big"))
    sock.sendall(packet)

def perform_handshake(sock):
    responder = HandshakeState()
    responder.initialize(initiator=False, psk=load_psk(),
                         client_id=CLIENT_ID, server_id=SERVER_ID)
    msg1 = recv_frame(sock)
    responder.read_message(msg1)
    msg2 = responder.write_message()
    send_frame(sock, msg2)
    th = transcript_hash(responder.transcript())
    server_tag = hmac_sha256(responder.psk, th)
    send_frame(sock, server_tag)
    msg3 = recv_frame(sock)
    client_tag = responder.read_message(msg3)
    if client_tag != hmac_sha256(responder.psk, th):
        raise ValueError("handshake authentication failed: bad PSK or man-in-the-middle")

    return responder.split()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")
    conn, addr = server.accept()
    print(f"Client connected: {addr}")
    keys = perform_handshake(conn)
    print("Handshake complete.\n")
    recv_seq = 0
    send_seq = 0
    while True:
        try:
            frame = recv_frame(conn)
        except Exception as e:
            print(e)
            break
        try:
            seq, sender_id, plaintext = decrypt_message(keys["client_key"],keys["client_nonce_base"], frame)
        except AuthFailure:
            print("Authentication failed: message discarded.")
            continue
        if seq != recv_seq:
            print("Replay/reordered message rejected.")
            continue
        recv_seq += 1
        print("Client:", plaintext.decode())
        if plaintext == b"quit":
            break
        reply = input("Server> ").encode()
        frame = encrypt_message(keys["server_key"], keys["server_nonce_base"],send_seq, SERVER_ID, reply)
        send_frame(conn, frame)
        send_seq += 1
    conn.close()
    server.close()


if __name__ == "__main__":
    main()