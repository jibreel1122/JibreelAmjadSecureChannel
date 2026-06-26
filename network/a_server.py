# network/server.py

import socket

from protocol.a_handshake import HandshakeState
from protocol.a_replay import ReplayProtectedChannel


HOST = "127.0.0.1"
PORT = 8000


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
    responder.initialize(initiator=False)
    msg1 = recv_packet(sock)
    responder.read_message(msg1)
    msg2 = responder.write_message()
    send_packet(sock, msg2)
    msg3 = recv_packet(sock)
    responder.read_message(msg3)
    send_cipher, recv_cipher = responder.split()
    return ReplayProtectedChannel(send_cipher, recv_cipher)

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Listening on {HOST}:{PORT}")
    conn, addr = server.accept()
    print(f"Client connected: {addr}")
    secure = perform_handshake(conn)
    print("Handshake complete.\n")
    while True:
        try:
            packet = recv_packet(conn)
            plaintext = secure.decrypt(packet)
            print("Client:", plaintext.decode())
            if plaintext == b"quit":
                break
            reply = input("Server> ").encode()
            packet = secure.encrypt(reply)
            send_packet(conn, packet)
        except Exception as e:
            print(e)
            break
    conn.close()
    server.close()


def do_server_handshake(sock, handshake_state):
    msg1 = sock.recv(4096)
    handshake_state.read_message(msg1)
    msg2 = handshake_state.write_message()
    sock.sendall(msg2)
    msg3 = sock.recv(4096)
    handshake_state.read_message(msg3)
    return handshake_state.split()

if __name__ == "__main__":
    main()