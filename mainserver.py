import socketserver
import threading
import sqlite3
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

clients = {}  # 연결된 클라이언트를 저장할 딕셔너리: {소켓: 닉네임}

# AES 암호화 키 (32바이트 = 256비트)와 솔트 (16바이트) 생성 또는 로드
KEY_FILE = 'secret_key.bin'
SALT_FILE = 'salt.bin'

def get_or_create_key(filename, size):
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(size)
        with open(filename, 'wb') as f:
            f.write(key)
        return key

SECRET_KEY = get_or_create_key(KEY_FILE, 32)
SALT = get_or_create_key(SALT_FILE, 16)

# 관리자 목록(데모용)
ADMINS = {"admin"}

def initialize_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        receiver TEXT,
                        content TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        read INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

initialize_database()

def encrypt(data: str) -> str:
    """AES-GCM으로 문자열을 암호화하여 base64로 인코딩"""
    key = PBKDF2(SECRET_KEY, SALT, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt(encrypted_data: str) -> str:
    """AES-GCM으로 암호화된 base64 문자열을 복호화"""
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
                data = self.request.recv(4096).strip()
                if not data:
                    return  # 클라이언트 접속 끊김
            except:
                self.finish()
                return

            message = data.decode()
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
            elif self.nickname:
                if message.startswith("/"):
                    self.handle_command(message)
                else:
                    # 메시지 저장
                    self.save_message(self.nickname, None, message)
                    print(f"{self.nickname} : {message}")
                    self.broadcast(f"{self.nickname}: {message}")
                    # 메시지 ID를 클라이언트에게 전송
                    message_id = self.get_last_message_id()
                    self.request.sendall(f"MESSAGE_SENT:{message_id}".encode('utf-8'))
            else:
                self.request.sendall(b"Please login first.")

    def finish(self):
        """클라이언트 소켓 종료 시 처리"""
        if self.nickname:
            del clients[self.request]
            self.broadcast(f"SERVER: {self.nickname} has left the chat.")
        print(f"Disconnected: {self.client_address[0]}")
        self.request.close()

    def register_user(self, username, encrypted_password):
        """SQLite DB에 사용자 회원가입"""
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
        """아이디/비밀번호 검증"""
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
        """전체 사용자에게 메시지 전송"""
        for client in list(clients.keys()):
            if client != exclude:
                try:
                    client.sendall(message.encode('utf-8'))
                except:
                    del clients[client]

    def handle_command(self, message: str):
        """채팅 중 명령어 처리"""
        cmd_parts = message.strip().split(maxsplit=2)
        command = cmd_parts[0][1:].lower()  # "/" 제거 후 소문자로 변환

        if command == "list":
            # 현재 접속 중인 사용자 목록 반환
            self.send_msg("Currently connected users:")
            for nick in clients.values():
                self.send_msg(f"- {nick}")
        elif command == "whisper":
            # 귓속말: /whisper <상대유저> <메시지>
            if len(cmd_parts) < 3:
                self.send_msg("Usage: /whisper <username> <message>")
                return
            _, target_name, msg_body = cmd_parts
            target_client = self.find_client_by_name(target_name)
            if target_client:
                try:
                    target_client.sendall(f"[Whisper] {self.nickname}: {msg_body}".encode('utf-8'))
                    self.send_msg(f"[To {target_name}] {msg_body}")
                except:
                    self.send_msg("Failed to send whisper.")
            else:
                self.send_msg(f"User '{target_name}' not found.")
        elif command == "help":
            help_text = (

                    "🔹 /list - 현재 접속 중인 사용자 목록\n\n"

                    "🔹 /whisper <닉네임> <메시지> - 특정사용자에게만 메세지 전송\n\n"

                    "🔹 /logout - 서버와의 연결을 종료하고 로그아웃\n\n"

                    "🔹 /search <키워드> - 채팅 기록에서 키워드를 검색\n\n"

                    "🔹 /help - 이 도움말 메시지를 표시\n\n"
            )
            self.send_msg(help_text)
        elif command == "logout":
            # 사용자 자발적 로그아웃
            self.send_msg("You have been logged out.")
            self.finish()  # 연결 종료
        elif command == "typing":
            if len(cmd_parts) < 2:
                return
            status = cmd_parts[1]  
            self.broadcast(f"TYPING:{self.nickname}:{status}", exclude=self.request)
        elif command == "search":
            # 메시지 검색: /search <keyword>
            if len(cmd_parts) < 2:
                self.send_msg("Usage: /search <keyword>")
                return
            keyword = cmd_parts[1]
            results = self.search_messages(keyword)
            if results:
                self.send_msg(f"Search results for '{keyword}':")
                for msg in results:
                    formatted_msg = f"[{msg[4]}] {msg[1]}: {msg[3]}"
                    self.send_msg(formatted_msg)
            else:
                self.send_msg("No messages found.")
        else:
            self.send_msg(f"Unknown command: {command}. Try /help.")

    def find_client_by_name(self, nickname, return_both=False):
        """닉네임으로 클라이언트를 찾는다. return_both=True 면 (소켓, 닉네임)을 튜플로 반환"""
        for client_sock, user_nick in clients.items():
            if user_nick == nickname:
                return (client_sock, user_nick) if return_both else client_sock
        return (None, None) if return_both else None

    def send_msg(self, msg: str):
        """해당 사용자(본인)에게만 메시지 전송"""
        try:
            self.request.sendall(msg.encode('utf-8'))
        except:
            pass

    def save_message(self, sender, receiver, content):
        """메시지를 데이터베이스에 저장"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)',
                       (sender, receiver, content))
        conn.commit()
        conn.close()

    def get_last_message_id(self):
        """가장 최근 메시지 ID 반환"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT last_insert_rowid()')
        message_id = cursor.fetchone()[0]
        conn.close()
        return message_id

    def mark_message_as_read(self, message_id):
        """메시지를 읽음으로 표시"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE messages SET read = 1 WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()

    def get_message_sender(self, message_id):
        """특정 메시지 ID의 송신자 반환"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT sender FROM messages WHERE id = ?', (message_id,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    def search_messages(self, keyword):
        """키워드로 메시지를 검색"""
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT * FROM messages
                          WHERE content LIKE ? AND (receiver IS NULL OR receiver = ?)''',
                       (f'%{keyword}%', self.nickname))
        results = cursor.fetchall()
        conn.close()
        return results

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
