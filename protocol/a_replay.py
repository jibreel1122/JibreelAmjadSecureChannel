import struct


class ReplayProtectedChannel:

    def __init__(self, send_cipher, recv_cipher):
        self.send_cipher = send_cipher
        self.recv_cipher = recv_cipher
        self.send_seq = 0
        self.recv_seq = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        seq_bytes = struct.pack(">Q", self.send_seq)
        ciphertext = self.send_cipher.encrypt_with_ad(seq_bytes,plaintext)
        packet = seq_bytes + ciphertext
        self.send_seq += 1
        return packet

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 8:
            raise ValueError("Packet too short")
        seq_bytes = packet[:8]
        ciphertext = packet[8:]
        seq = struct.unpack(">Q", seq_bytes)[0]
        if seq != self.recv_seq:
            raise ValueError(f"Replay/Reordering detected "f"(expected {self.recv_seq}, got {seq})")
        plaintext = self.recv_cipher.decrypt_with_ad(seq_bytes,ciphertext)
        self.recv_seq += 1
        return plaintext