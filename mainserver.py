import socketserver
import threading
import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

clients = {}  # 연결된 클라이언트를 저장할 딕셔너리

# AES 암호화 키 (32바이트 = 256비트)
SECRET_KEY = get_random_bytes(32)
SALT = get_random_bytes(16)

def initialize_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

initialize_database()

def encrypt(data):
    key = PBKDF2(SECRET_KEY, SALT, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(encrypted_data):
    key = PBKDF2(SECRET_KEY, SALT, dkLen=32)
    encrypted = base64.b64decode(encrypted_data.encode('utf-8'))
    nonce = encrypted[:16]
    tag = encrypted[16:32]
    ciphertext = encrypted[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError):
        return None

class TCPHandler(socketserver.BaseRequestHandler):
    def setup(self):
        print(f"Connected: {self.client_address[0]}")
        self.nickname = None

    def handle(self):
        while True:
            try:
                self.data = self.request.recv(1024).strip()
                if not self.data:
                    return
            except:
                self.finish()
                return

            message = self.data.decode()
            if message.startswith("REGISTER:"):
                _, username, password = message.split(":")
                encrypted_password = encrypt(password)
                if self.register_user(username, encrypted_password):
                    self.request.sendall(b"REGISTER_SUCCESS")
                else:
                    self.request.sendall(b"REGISTER_FAIL")
            elif message.startswith("LOGIN:"):
                _, username, password = message.split(":")
                if self.authenticate_user(username, password):
                    self.nickname = username
                    clients[self.request] = self.nickname
                    self.request.sendall(b"LOGIN_SUCCESS")
                    self.broadcast(f"SERVER: {self.nickname} has joined the chat.")
                else:
                    self.request.sendall(b"LOGIN_FAIL")
            elif self.nickname:  # 로그인된 사용자만 채팅 가능
                print(f"{self.nickname} wrote: {message}")
                self.broadcast(f"{self.nickname}: {message}")
            else:
                self.request.sendall(b"Please login first.")

    def finish(self):
        if self.nickname:
            del clients[self.request]
            self.broadcast(f"SERVER: {self.nickname} has left the chat.")
        print(f"Disconnected: {self.client_address[0]}")
        self.request.close()

    def register_user(self, username, encrypted_password):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_password))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
            
    def authenticate_user(self, username, password):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            stored_password = result[0]
            decrypted_password = decrypt(stored_password)
            return decrypted_password == password
        return False

    def broadcast(self, message, exclude=None):
        for client in clients:
            if client != exclude:
                try:
                    client.sendall(message.encode())
                except:
                    pass

if __name__ == "__main__":
    HOST, PORT = "", 2500
    server = socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler)

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print(f"Server running on port {PORT}")
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server.shutdown()
        server.server_close()
