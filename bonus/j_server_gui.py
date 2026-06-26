import os
import socket
import sys
import threading
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import network.a_server as a_server
from network.j_client import send_frame, recv_frame, encrypt_message, decrypt_message, AuthFailure


listener = None
conn = None
keys = None
send_seq = 0
recv_seq = 0


def add_chat(line):
    chat.config(state="normal")
    chat.insert("end", line + "\n")
    chat.see("end")
    chat.config(state="disabled")


def set_status(text):
    status.config(text=text)


def recv_loop():
    global conn, recv_seq
    while conn is not None:
        try:
            frame = recv_frame(conn)
        except Exception as e:
            set_status("disconnected: " + str(e))
            conn = None
            break
        try:
            seq, sender_id, pt = decrypt_message(keys["client_key"], keys["client_nonce_base"], frame)
        except AuthFailure:
            set_status("Authentication failed: message discarded.")
            continue
        if seq != recv_seq:
            set_status("Replay/reordered message rejected.")
            continue
        recv_seq = recv_seq + 1
        add_chat(sender_id + ": " + pt.decode())


def do_listen():
    global listener, conn, keys
    port = int(port_entry.get())
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((a_server.HOST, port))
        listener.listen(1)
        set_status("listening on " + a_server.HOST + ":" + str(port) + ", waiting for client...")
        conn, addr = listener.accept()
        set_status("client connected from " + str(addr) + ", running handshake...")
        keys = a_server.perform_handshake(conn)
    except Exception as e:
        conn = None
        keys = None
        set_status("listen failed: " + str(e))
        return
    set_status("connected")
    add_chat("auth ok: secure channel ready by jibreel bornat 2026")
    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()


def listen_clicked():
    set_status("starting server...")
    t = threading.Thread(target=do_listen, daemon=True)
    t.start()


def send_clicked(event=None):
    global send_seq
    if conn is None:
        set_status("no client connected")
        return
    text = msg_entry.get()
    if text == "":
        return
    try:
        frame = encrypt_message(keys["server_key"], keys["server_nonce_base"], send_seq, a_server.SERVER_ID, text.encode())
        send_frame(conn, frame)
    except Exception as e:
        set_status("send failed: " + str(e))
        return
    send_seq = send_seq + 1
    add_chat("me: " + text)
    msg_entry.delete(0, "end")


if __name__ == "__main__":
    print("crypto server gui by jibreel bornat 2026")

    root = tk.Tk()
    root.title("crypto chat - server")

    tk.Label(root, text="Port").grid(row=0, column=0)
    port_entry = tk.Entry(root)
    port_entry.insert(0, str(a_server.PORT))
    port_entry.grid(row=0, column=1)

    listen_btn = tk.Button(root, text="Start server", command=listen_clicked)
    listen_btn.grid(row=0, column=2)

    status = tk.Label(root, text="not listening")
    status.grid(row=1, column=0, columnspan=3)

    chat = tk.Text(root, width=60, height=20, state="disabled")
    chat.grid(row=2, column=0, columnspan=3)

    msg_entry = tk.Entry(root, width=50)
    msg_entry.grid(row=3, column=0, columnspan=2)
    msg_entry.bind("<Return>", send_clicked)

    send_btn = tk.Button(root, text="Send", command=send_clicked)
    send_btn.grid(row=3, column=2)

    root.mainloop()
