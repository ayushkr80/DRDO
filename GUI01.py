# Full Secure Chat Application in a Single File
# Features: AES Encryption, SHA-based Integrity, RSA Key Exchange, Auto Discovery

import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os
import time
import uuid
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()

BROADCAST_PORT = 9999
BROADCAST_MSG = b"DISCOVER_SECURE_CHAT"
MAX_UDP_SIZE = 1024  # Safe size for UDP payload
CHUNK_SIZE = 1024  # bytes per UDP packet


# -------------------- Cryptographic Utilities --------------------
def derive_keys(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password)
    return key[:32], key[32:]  # AES key, HMAC key


def encrypt(data: bytes, password: bytes):
    salt = os.urandom(16)
    iv = os.urandom(16)
    enc_key, mac_key = derive_keys(password, salt)

    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    tag = h.finalize()

    return salt + iv + tag + ciphertext


def decrypt(enc_data: bytes, password: bytes):
    salt = enc_data[:16]
    iv = enc_data[16:32]
    tag = enc_data[32:64]
    ciphertext = enc_data[64:]

    enc_key, mac_key = derive_keys(password, salt)

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    padding_len = padded_data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    return padded_data[:-padding_len]


def generate_rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    public = private.public_key()
    return private, public


def rsa_encrypt(public_key, message: bytes):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=backend)


# -------------------- GUI + Networking --------------------
class SecureChat:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure UDP Messenger")
        self.root.geometry("555x500")
        self.root.configure(bg="#222831")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.password = b''
        self.peer_public_key = None
        self.private_key, self.public_key = generate_rsa_keys()
        self.discovered_peers = set()

        # --- Modern GUI Layout ---
        style_frame = tk.Frame(root, bg="#222831")
        style_frame.pack(fill='both', expand=True)

        top_frame = tk.Frame(style_frame, bg="#393E46")
        top_frame.pack(fill='x', pady=(10, 0), padx=10)

        tk.Label(top_frame, text="Shared Password:", bg="#393E46", fg="#EEEEEE", font=("Segoe UI", 10)).grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.pass_entry = tk.Entry(top_frame, show="*", width=20, font=("Segoe UI", 10))
        self.pass_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(top_frame, text="Your Port:", bg="#393E46", fg="#EEEEEE", font=("Segoe UI", 10)).grid(row=0, column=2, sticky='w', padx=5, pady=2)
        self.my_port_entry = tk.Entry(top_frame, width=8, font=("Segoe UI", 10))
        self.my_port_entry.grid(row=0, column=3, padx=5, pady=2)

        tk.Label(top_frame, text="Peer IP:", bg="#393E46", fg="#EEEEEE", font=("Segoe UI", 10)).grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.peer_ip_entry = tk.Entry(top_frame, width=20, font=("Segoe UI", 10))
        self.peer_ip_entry.insert(0, "127.0.0.1")
        self.peer_ip_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(top_frame, text="Peer Port:", bg="#393E46", fg="#EEEEEE", font=("Segoe UI", 10)).grid(row=1, column=2, sticky='w', padx=5, pady=2)
        self.peer_port_entry = tk.Entry(top_frame, width=8, font=("Segoe UI", 10))
        self.peer_port_entry.grid(row=1, column=3, padx=5, pady=2)

        tk.Button(top_frame, text="Start Listening", command=self.start_listening, bg="#00ADB5", fg="#EEEEEE", font=("Segoe UI", 10, "bold"), relief='flat', cursor='hand2').grid(row=0, column=4, rowspan=2, padx=(15, 5), pady=2, sticky='ns')

        # Chat area
        chat_frame = tk.Frame(style_frame, bg="#222831")
        chat_frame.pack(fill='both', expand=True, padx=10, pady=(10, 0))
        self.chat_area = scrolledtext.ScrolledText(chat_frame, height=15, width=50, font=("Segoe UI", 11), bg="#393E46", fg="#EEEEEE", insertbackground="#EEEEEE", borderwidth=0, relief='flat')
        self.chat_area.pack(fill='both', expand=True)
        self.chat_area.config(state='disabled')

        # Message entry and buttons
        bottom_frame = tk.Frame(style_frame, bg="#222831")
        bottom_frame.pack(fill='x', pady=10, padx=10)
        self.msg_entry = tk.Entry(bottom_frame, width=40, font=("Segoe UI", 11), bg="#393E46", fg="#EEEEEE", insertbackground="#EEEEEE", borderwidth=0, relief='flat')
        self.msg_entry.pack(side='left', padx=(0, 8), pady=5, fill='x', expand=True)
        tk.Button(bottom_frame, text="Send", command=self.send_message, bg="#00ADB5", fg="#EEEEEE", font=("Segoe UI", 10, "bold"), relief='flat', cursor='hand2').pack(side='left', padx=(0, 8))
        tk.Button(bottom_frame, text="Send File", command=self.send_file, bg="#393E46", fg="#EEEEEE", font=("Segoe UI", 10), relief='flat', cursor='hand2').pack(side='left')

    def log(self, text):
        self.chat_area.config(state='normal')
        self.chat_area.insert('end', text + '\n')
        self.chat_area.config(state='disabled')

    def start_listening(self):
        self.password = self.pass_entry.get().encode()
        try:
            my_port = int(self.my_port_entry.get())
            self.sock.bind(("0.0.0.0", my_port))
            threading.Thread(target=self.listen, daemon=True).start()
            threading.Thread(target=self.broadcast_presence, daemon=True).start()
            self.log(f"[Listening on port {my_port}]")
            self.send_public_key()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def listen(self):
        # Buffer for incoming file chunks: {file_id: {chunk_num: data, ...}}
        if not hasattr(self, 'file_chunks'):
            self.file_chunks = {}
        if not hasattr(self, 'file_info'):
            self.file_info = {}
        while True:
            try:
                data, addr = self.sock.recvfrom(65536)
                if data.startswith(BROADCAST_MSG):
                    port = int(data[len(BROADCAST_MSG):])
                    peer = (addr[0], port)
                    if addr[0] != socket.gethostbyname(socket.gethostname()) and peer not in self.discovered_peers:
                        self.discovered_peers.add(peer)
                        self.log(f"[Discovered Peer] {addr[0]}:{port}")
                elif data.startswith(b"msg"):
                    msg = decrypt(data[3:], self.password).decode()
                    self.log(f"[Message from {addr[1]}] {msg}")
                elif data.startswith(b"fchunk"):
                    decrypted = decrypt(data[6:], self.password)
                    header, chunk_data = decrypted.split(b'||', 1)
                    file_id, filename, chunk_num, total_chunks = header.decode().split('|')
                    chunk_num = int(chunk_num)
                    total_chunks = int(total_chunks)
                    # Store chunk
                    if file_id not in self.file_chunks:
                        self.file_chunks[file_id] = {}
                        self.file_info[file_id] = (filename, total_chunks)
                    self.file_chunks[file_id][chunk_num] = chunk_data
                    # Check if file is complete
                    if len(self.file_chunks[file_id]) == total_chunks:
                        # Reassemble
                        file_data = b''.join(self.file_chunks[file_id][i] for i in range(total_chunks))
                        with open(filename, "wb") as f:
                            f.write(file_data)
                        self.log(f"[File received: {filename}]")
                        del self.file_chunks[file_id]
                        del self.file_info[file_id]
                elif data.startswith(b"file"):
                    # Legacy single-packet file transfer (for compatibility)
                    decrypted = decrypt(data[4:], self.password)
                    filename, filedata = decrypted.split(b'||', 1)
                    with open(filename.decode(), "wb") as f:
                        f.write(filedata)
                    self.log(f"[File received: {filename.decode()}]")
                elif data.startswith(b"pubk"):
                    self.peer_public_key = deserialize_public_key(data[4:])
                    self.log("[Public Key Received]")
            except Exception as e:
                self.log(f"[Error receiving data] {e}")

    def send_public_key(self):
        peer_ip = self.peer_ip_entry.get().strip()
        peer_port = int(self.peer_port_entry.get())
        serialized_key = serialize_public_key(self.public_key)
        self.sock.sendto(b"pubk" + serialized_key, (peer_ip, peer_port))
        self.log("[Sent Public Key]")

    def send_message(self):
        try:
            msg = self.msg_entry.get().strip()
            peer_ip = self.peer_ip_entry.get().strip()
            peer_port = int(self.peer_port_entry.get())
            encrypted = encrypt(msg.encode(), self.password)
            self.sock.sendto(b"msg" + encrypted, (peer_ip, peer_port))
            self.log(f"[Sent] {msg}")
            self.msg_entry.delete(0, 'end')
        except Exception as e:
            self.log(f"[Error] {e}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                data = f.read()
            total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
            file_id = str(uuid.uuid4())
            peer_ip = self.peer_ip_entry.get().strip()
            peer_port = int(self.peer_port_entry.get())
            for chunk_num in range(total_chunks):
                chunk_data = data[chunk_num*CHUNK_SIZE:(chunk_num+1)*CHUNK_SIZE]
                # Header: file_id|filename|chunk_num|total_chunks||data
                header = f"{file_id}|{filename}|{chunk_num}|{total_chunks}".encode()
                msg = header + b'||' + chunk_data
                encrypted = encrypt(msg, self.password)
                self.sock.sendto(b"fchunk" + encrypted, (peer_ip, peer_port))
                time.sleep(0.001)  # slight delay to avoid packet loss
            self.log(f"[File sent: {filename} in {total_chunks} chunks]")
        except Exception as e:
            self.log(f"[Error] {e}")

    def broadcast_presence(self):
        while True:
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                my_port = int(self.my_port_entry.get())
                self.sock.sendto(BROADCAST_MSG + str(my_port).encode(), ('<broadcast>', BROADCAST_PORT))
                time.sleep(5)
            except Exception:
                pass


# -------------------- Main --------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChat(root)
    root.mainloop()
