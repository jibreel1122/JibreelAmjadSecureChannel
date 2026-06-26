import os
import sys
import threading
import tkinter as tk

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import network.j_client as j_client
from protocol.j_message import unpack_message, pack_message


sock = None
keys = None
out_seq = 0


def add_chat(line):
    chat.config(state="normal")
    chat.insert("end", line + "\n")
    chat.see("end")
    chat.config(state="disabled")


def set_status(text):
    status.config(text=text)


def recv_loop():
    global sock
    while sock is not None:
        try:
            seq, sender_id, pt = j_client.recv_secure(sock, keys["server_key"], keys["server_nonce_base"])
        except Exception as e:
            set_status("disconnected: " + str(e))
            sock = None
            break
        add_chat(sender_id + ": " + pt.decode())


def do_connect():
    global sock, keys
    ip = ip_entry.get()
    port = int(port_entry.get())
    try:
        sock = j_client.connect(ip, port)
        keys = j_client.do_handshake(sock, "jibreel-client", "server")
    except Exception as e:
        sock = None
        keys = None
        set_status("connect failed: " + str(e))
        return
    set_status("connected")
    add_chat("auth ok: secure channel ready by jibreel bornat 2026")
    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()


def connect_clicked():
    set_status("connecting...")
    t = threading.Thread(target=do_connect, daemon=True)
    t.start()


def send_clicked(event=None):
    global out_seq
    if sock is None:
        set_status("not connected")
        return
    text = msg_entry.get()
    if text == "":
        return
    try:
        j_client.send_secure(sock, keys["client_key"], keys["client_nonce_base"], out_seq, "jibreel-client", text.encode())
    except Exception as e:
        set_status("send failed: " + str(e))
        return
    out_seq = out_seq + 1
    add_chat("me: " + text)
    msg_entry.delete(0, "end")


def send_tampered_clicked(event=None):
    global out_seq
    if sock is None:
        set_status("not connected")
        return
    text = msg_entry.get()
    if text == "":
        text = "tampered message"
    try:
        frame = j_client.encrypt_message(keys["client_key"], keys["client_nonce_base"], out_seq, "jibreel-client", text.encode())
        header, cipher, tag = unpack_message(frame)
        bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        bad_frame = pack_message(header, cipher, bad_tag)
        j_client.send_frame(sock, bad_frame)
    except Exception as e:
        set_status("send failed: " + str(e))
        return
    out_seq = out_seq + 1
    add_chat("me (tampered tag): " + text)
    msg_entry.delete(0, "end")
    set_status("sent a message with one flipped tag byte, watch the server reject it")


def send_tampered_header_clicked(event=None):
    global out_seq
    if sock is None:
        set_status("not connected")
        return
    text = msg_entry.get()
    if text == "":
        text = "tampered header message"
    try:
        frame = j_client.encrypt_message(keys["client_key"], keys["client_nonce_base"], out_seq, "jibreel-client", text.encode())
        header, cipher, tag = unpack_message(frame)
        bad_header = header[:1] + bytes([header[1] ^ 0x01]) + header[2:]
        bad_frame = pack_message(bad_header, cipher, tag)
        j_client.send_frame(sock, bad_frame)
    except Exception as e:
        set_status("send failed: " + str(e))
        return
    out_seq = out_seq + 1
    add_chat("me (tampered header): " + text)
    msg_entry.delete(0, "end")
    set_status("sent a message with one flipped header bit, watch the server reject it")


if __name__ == "__main__":
    print("crypto gui by jibreel bornat 2026")

    root = tk.Tk()
    root.title("crypto chat")

    tk.Label(root, text="IP").grid(row=0, column=0)
    ip_entry = tk.Entry(root)
    ip_entry.insert(0, "127.0.0.1")
    ip_entry.grid(row=0, column=1)

    tk.Label(root, text="Port").grid(row=0, column=2)
    port_entry = tk.Entry(root)
    port_entry.insert(0, "8000")
    port_entry.grid(row=0, column=3)

    connect_btn = tk.Button(root, text="Connect", command=connect_clicked)
    connect_btn.grid(row=0, column=4)

    status = tk.Label(root, text="not connected")
    status.grid(row=1, column=0, columnspan=5)

    chat = tk.Text(root, width=60, height=20, state="disabled")
    chat.grid(row=2, column=0, columnspan=5)

    msg_entry = tk.Entry(root, width=50)
    msg_entry.grid(row=3, column=0, columnspan=4)
    msg_entry.bind("<Return>", send_clicked)

    send_btn = tk.Button(root, text="Send", command=send_clicked)
    send_btn.grid(row=3, column=4)

    tamper_btn = tk.Button(root, text="Send tampered tag", command=send_tampered_clicked)
    tamper_btn.grid(row=4, column=0, columnspan=5)

    tamper_header_btn = tk.Button(root, text="Send tampered header", command=send_tampered_header_clicked)
    tamper_header_btn.grid(row=5, column=0, columnspan=5)

    root.mainloop()
