import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
import threading
import json
import time
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct

# Constants
DISCOVERY_PORT = 12345
CHAT_PORT = 12346
BUFFER_SIZE = 8192
LOG_FILE = 'chat_logs.json'
TIMESTAMP_LEN = 19
MAX_FILE_SIZE = 10 * 1024 * 1024

class Peer:
    def __init__(self, ip, port=CHAT_PORT, username=None):
        self.ip = ip
        self.port = port
        self.username = username
        self.public_key = None

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Decentralized P2P Multi-Chat System")
        self.root.geometry("800x600")

        # State
        self.username = None
        self.peers = {}
        self.current_peer = None
        self.sock = None
        self.discovery_sock = None
        self.listen_sock = None
        self.running = False
        self.private_key = None
        self.public_key = None
        self.session_aes_key = None
        self.logs = self.load_logs()
        self.connection_lock = threading.Lock()

        # Generate RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048, 
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        self.setup_gui()
        self.start_discovery_thread()

    def setup_gui(self):
        tk.Label(self.root, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.root, width=20)
        self.username_entry.pack()
        tk.Button(self.root, text="Start Broadcasting", command=self.set_username_and_broadcast).pack(pady=5)

        tk.Label(self.root, text="Discovered Peers:").pack(pady=5)
        self.peers_listbox = tk.Listbox(self.root, height=5)
        self.peers_listbox.pack(pady=5, fill=tk.BOTH, expand=True)
        self.peers_listbox.bind('<<ListboxSelect>>', self.on_peer_select)
        tk.Button(self.root, text="Connect to Selected Peer", command=self.connect_to_peer).pack(pady=5)
        tk.Button(self.root, text="Disconnect", command=self.disconnect).pack(pady=2)

        tk.Label(self.root, text="Chat:").pack(pady=5)
        self.chat_display = scrolledtext.ScrolledText(self.root, height=15, state=tk.DISABLED)
        self.chat_display.pack(pady=5, fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.pack(side=tk.LEFT, pady=5, padx=5, fill=tk.X, expand=True)
        self.message_entry.bind('<Return>', self.send_message)
        tk.Button(self.root, text="Send Message", command=self.send_message).pack(side=tk.LEFT, pady=5)

        tk.Button(self.root, text="Share File", command=self.share_file).pack(pady=5)

        self.status_label = tk.Label(self.root, text="Status: Ready")
        self.status_label.pack(pady=5)

    def display_message(self, msg):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, msg + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def on_peer_select(self, event):
        selection = self.peers_listbox.curselection()
        if selection:
            ip = list(self.peers.keys())[selection[0]]
            self.current_peer = self.peers[ip]
            self.display_message(f"Selected peer: {self.current_peer.username}")

    def recv_exact(self, sock, size):
        data = b''
        while len(data) < size:
            try:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    raise Exception("Connection closed")
                data += chunk
            except socket.timeout:
                continue
            except Exception as e:
                raise Exception(f"Receive error: {e}")
        return data

    def set_username_and_broadcast(self):
        self.username = self.username_entry.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Enter a username!")
            return
        
        self.running = True
        self.broadcast_thread = threading.Thread(target=self.broadcast_presence, daemon=True)
        self.broadcast_thread.start()
        
        self.tcp_listener_thread = threading.Thread(target=self.tcp_listener, daemon=True)
        self.tcp_listener_thread.start()
        
        self.status_label.config(text=f"Status: Broadcasting as {self.username}")
        self.display_message(f"Started broadcasting as {self.username}")

    def load_logs(self):
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_logs(self):
        with open(LOG_FILE, 'w') as f:
            json.dump(self.logs, f, indent=2)

    def log_message(self, sender, message, timestamp):
        if sender not in self.logs:
            self.logs[sender] = []
        self.logs[sender].append({"message": message, "timestamp": timestamp})
        self.save_logs()

    def start_discovery_thread(self):
        try:
            self.discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.discovery_sock.bind(('', DISCOVERY_PORT))
            self.discovery_thread = threading.Thread(target=self.listen_for_peers, daemon=True)
            self.discovery_thread.start()
        except Exception as e:
            print(f"Discovery setup error: {e}")

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '127.0.0.1'

    def broadcast_presence(self):
        while self.running:
            try:
                pubkey_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                message = f"{self.username}|{self.get_local_ip()}|{pubkey_pem}"
                target = ('<broadcast>', DISCOVERY_PORT)
                self.discovery_sock.sendto(message.encode(), target)
                time.sleep(5)
            except Exception as e:
                print(f"Broadcast error: {e}")
                time.sleep(1)

    def listen_for_peers(self):
        while True:
            try:
                data, addr = self.discovery_sock.recvfrom(1024)
                decoded_data = data.decode(errors='ignore')
                parts = decoded_data.split('|')
                if len(parts) >= 3:
                    username, ip, pubkey_pem = parts[0], parts[1], '|'.join(parts[2:])
                    
                    if username == self.username:
                        continue
                    if ip == self.get_local_ip():
                        continue
                        
                    try:
                        pubkey = serialization.load_pem_public_key(
                            pubkey_pem.encode(), 
                            backend=default_backend()
                        )
                        
                        if ip in self.peers and self.peers[ip].username == username:
                            continue
                            
                        peer = Peer(ip, CHAT_PORT, username)
                        peer.public_key = pubkey
                        self.peers[ip] = peer
                        self.update_peers_list()
                        self.display_message(f"Discovered peer: {username} ({ip})")
                    except Exception as key_e:
                        print(f"Key parse error: {key_e}")
            except Exception as e:
                print(f"Listen receive error: {e}")

    def update_peers_list(self):
        self.root.after(0, self._update_peers_list_ui)

    def _update_peers_list_ui(self):
        self.peers_listbox.delete(0, tk.END)
        for peer in self.peers.values():
            self.peers_listbox.insert(tk.END, f"{peer.username} ({peer.ip})")

    def connect_to_peer(self):
        if not self.current_peer:
            messagebox.showerror("Error", "Select a peer first!")
            return
            
        with self.connection_lock:
            if self.sock:
                messagebox.showerror("Error", "Already connected to a peer!")
                return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(10)
            sock.connect((self.current_peer.ip, self.current_peer.port))
            
            self.handle_key_exchange(sock, is_incoming=False)
            sock.settimeout(2.0)  # Set a reasonable timeout for ongoing communication
            
            with self.connection_lock:
                self.sock = sock
                
            self.receive_thread = threading.Thread(target=self.receive_messages, args=(sock,), daemon=True)
            self.receive_thread.start()
            
            self.status_label.config(text=f"Status: Connected to {self.current_peer.username}")
            self.display_message(f"Connected to {self.current_peer.username}")
            
        except socket.timeout:
            messagebox.showerror("Error", "Connection timed out")
            if 'sock' in locals():
                sock.close()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")
            if 'sock' in locals():
                sock.close()

    def tcp_listener(self):
        while self.running:
            try:
                if not hasattr(self, 'listen_sock') or not self.listen_sock:
                    self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.listen_sock.settimeout(1.0)  # Short timeout for clean shutdown
                    self.listen_sock.bind(('', CHAT_PORT))
                    self.listen_sock.listen(5)

                client_sock, addr = self.listen_sock.accept()
                client_sock.settimeout(10)
                
                peer_ip = addr[0]
                if peer_ip in self.peers:
                    # Check if we're already connected
                    with self.connection_lock:
                        if self.sock:
                            print("Already connected, rejecting new connection")
                            client_sock.close()
                            continue
                            
                    self.current_peer = self.peers[peer_ip]
                    try:
                        self.handle_key_exchange(client_sock, is_incoming=True)
                        client_sock.settimeout(2.0)
                        
                        with self.connection_lock:
                            self.sock = client_sock
                            
                        self.receive_thread = threading.Thread(
                            target=self.receive_messages, 
                            args=(client_sock,), 
                            daemon=True
                        )
                        self.receive_thread.start()
                        
                        self.status_label.config(text=f"Status: Connected to {self.current_peer.username} (incoming)")
                        self.display_message(f"Connected to {self.current_peer.username} (incoming)")
                        
                    except Exception as ke:
                        print(f"Key exchange failed: {ke}")
                        client_sock.close()
                        with self.connection_lock:
                            if self.sock == client_sock:
                                self.sock = None
                else:
                    print(f"Unknown peer {peer_ip}, closing")
                    client_sock.close()
                    
            except socket.timeout:
                continue
            except OSError as e:
                if self.running:  # Only log if we're supposed to be running
                    print(f"TCP listener error: {e}")
                if hasattr(self, 'listen_sock'):
                    try:
                        self.listen_sock.close()
                    except:
                        pass
                    self.listen_sock = None
                time.sleep(1)

    def handle_key_exchange(self, sock, is_incoming):
        try:
            if is_incoming:
                # Wait for encrypted AES key
                len_data = self.recv_exact(sock, 4)
                resp_len = struct.unpack('>I', len_data)[0]
                encrypted_key = self.recv_exact(sock, resp_len)
                
                self.session_aes_key = self.private_key.decrypt(
                    encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Send acknowledgement
                sock.send(struct.pack('>I', 0))
            else:
                # Send encrypted AES key
                self.session_aes_key = os.urandom(32)
                encrypted_key = self.current_peer.public_key.encrypt(
                    self.session_aes_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                sock.send(struct.pack('>I', len(encrypted_key)) + encrypted_key)
                # Wait for acknowledgement
                ack_data = self.recv_exact(sock, 4)
                ack_len = struct.unpack('>I', ack_data)[0]
                if ack_len > 0:
                    self.recv_exact(sock, ack_len)
        except Exception as e:
            print(f"Key exchange error: {e}")
            try:
                sock.close()
            except:
                pass
            raise

    def disconnect(self):
        with self.connection_lock:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None
                
        self.session_aes_key = None
        self.current_peer = None
        self.status_label.config(text="Status: Disconnected")
        self.display_message("Disconnected")

    def send_message(self, event=None):
        with self.connection_lock:
            if not self.sock or not self.session_aes_key:
                messagebox.showerror("Error", "Not connected!")
                return
            sock = self.sock

        message = self.message_entry.get().strip()
        if not message:
            return
            
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_message(self.username, message, timestamp)

        try:
            signature = self.private_key.sign(
                message.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

            payload = {
                'type': 'message',
                'username': self.username,
                'timestamp': timestamp,
                'iv': iv.hex(),
                'ciphertext': ciphertext.hex(),
                'signature': signature.hex()
            }
            data = json.dumps(payload).encode()
            sock.send(struct.pack('>I', len(data)) + data)
            self.display_message(f"[You] {timestamp}: {message}")
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            self.display_message(f"*** Failed to send message: {e} ***")
            self.disconnect()

    def receive_messages(self, sock):
        while True:
            try:
                header = sock.recv(4)
                if not header:
                    break
                    
                length = struct.unpack('>I', header)[0]
                data = self.recv_exact(sock, length)
                payload = json.loads(data.decode())

                if payload['type'] == 'message':
                    self.handle_incoming_message(payload)
                elif payload['type'] == 'file':
                    self.handle_incoming_file(payload)
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Receive error: {e}")
                break

        # Clean up on disconnect
        self.display_message("*** Disconnected from peer ***")
        with self.connection_lock:
            if self.sock == sock:
                self.sock = None
                self.session_aes_key = None
                self.status_label.config(text="Status: Disconnected")

    def handle_incoming_message(self, payload):
        try:
            username = payload['username']
            timestamp = payload['timestamp']
            iv = bytes.fromhex(payload['iv'])
            ciphertext = bytes.fromhex(payload['ciphertext'])
            signature = bytes.fromhex(payload['signature'])

            cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            message_data = decryptor.update(ciphertext) + decryptor.finalize()
            message = message_data.decode(errors='ignore')

            # Verify signature
            if self.current_peer and self.current_peer.public_key:
                try:
                    self.current_peer.public_key.verify(
                        signature,
                        message_data,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except:
                    print("Signature verification failed")
                    return

            self.display_message(f"[{username}] {timestamp}: {message}")
            self.log_message(username, message, timestamp)
            
        except Exception as e:
            print(f"Message handling error: {e}")

    def share_file(self):
        with self.connection_lock:
            if not self.sock or not self.session_aes_key:
                messagebox.showerror("Error", "Not connected!")
                return
            sock = self.sock

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            messagebox.showerror("Error", "File too large! Max 10MB.")
            return

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(file_data) + encryptor.finalize()

            payload = {
                'type': 'file',
                'username': self.username,
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'filename': os.path.basename(file_path),
                'iv': iv.hex(),
                'ciphertext': ciphertext.hex()
            }

            packet = json.dumps(payload).encode()
            sock.send(struct.pack('>I', len(packet)) + packet)
            self.display_message(f"Sent file: {os.path.basename(file_path)} ({file_size} bytes)")
            
        except Exception as e:
            messagebox.showerror("Error", f"File send failed: {e}")

    def handle_incoming_file(self, payload):
        try:
            filename = payload['filename']
            iv = bytes.fromhex(payload['iv'])
            ciphertext = bytes.fromhex(payload['ciphertext'])
            timestamp = payload['timestamp']
            username = payload['username']

            cipher = Cipher(algorithms.AES(self.session_aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            file_data = decryptor.update(ciphertext) + decryptor.finalize()

            save_path = filedialog.asksaveasfilename(
                initialfile=filename,
                title="Save received file"
            )
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                self.display_message(f"[{username}] {timestamp}: File received -> {os.path.basename(save_path)}")
            else:
                self.display_message(f"[{username}] {timestamp}: File transfer cancelled.")
                
        except Exception as e:
            print(f"File receive error: {e}")
            self.display_message(f"File receive failed: {e}")

    def on_close(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
            if self.discovery_sock:
                self.discovery_sock.close()
            if self.listen_sock:
                self.listen_sock.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
