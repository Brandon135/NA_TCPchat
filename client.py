
#디자인 추가
import socket
import threading
import tkinter as tk
import datetime
import tkinter.font as tkFont
from tkinter import ttk, messagebox

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("NA_KakaoTalk")
        self.master.geometry("350x500")
        self.master.configure(bg="#b2c7d9")

        self.nickname = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.create_login_frame()
        self.create_chat_frame()

        self.current_frame = self.login_frame
        self.show_frame(self.login_frame)

    def create_login_frame(self):
        self.login_frame = tk.Frame(self.master, bg="#E8F0FE")
        self.login_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # 폰트 정의
        title_font = tkFont.Font(family="Arial", size=18, weight="bold")
        label_font = tkFont.Font(family="Arial", size=12)
        button_font = tkFont.Font(family="Arial", size=12, weight="bold")

        # 제목
        tk.Label(self.login_frame, text="로그인", font=title_font, bg="#E8F0FE", fg="#1A73E8").pack(pady=20)

        # 서버 주소
        tk.Label(self.login_frame, text="서버 주소:", font=label_font, bg="#E8F0FE", fg="#5F6368").pack(pady=5)
        self.server_entry = tk.Entry(self.login_frame, font=label_font, width=30)
        self.server_entry.insert(0, '127.0.0.1')
        self.server_entry.pack(pady=5)

        # 사용자 이름
        tk.Label(self.login_frame, text="사용자 이름:", font=label_font, bg="#E8F0FE", fg="#5F6368").pack(pady=5)
        self.username_entry = tk.Entry(self.login_frame, font=label_font, width=30)
        self.username_entry.pack(pady=5)

        # 비밀번호
        tk.Label(self.login_frame, text="비밀번호:", font=label_font, bg="#E8F0FE", fg="#5F6368").pack(pady=5)
        self.password_entry = tk.Entry(self.login_frame, show='*', font=label_font, width=30)
        self.password_entry.pack(pady=5)

        # 로그인 버튼
        self.login_button = tk.Button(self.login_frame, text="로그인", command=self.login,
                                    bg="#1A73E8", fg="white", font=button_font,
                                    activebackground="#1A73E8", activeforeground="white",
                                    relief=tk.FLAT, padx=20, pady=10)
        self.login_button.pack(pady=20)

        # 회원가입 버튼
        self.register_button = tk.Button(self.login_frame, text="회원가입", command=self.register,
                                        bg="#34A853", fg="white", font=button_font,
                                        activebackground="#34A853", activeforeground="white",
                                        relief=tk.FLAT, padx=20, pady=10)
        self.register_button.pack(pady=10)


    def create_chat_frame(self):
        self.chat_frame = tk.Frame(self.master, bg="#b2c7d9")

        self.chat_canvas = tk.Canvas(self.chat_frame, bg="#b2c7d9", highlightthickness=0)
        self.chat_canvas.pack(expand=True, fill='both', padx=10, pady=10)

        self.scrollbar = ttk.Scrollbar(self.chat_canvas, orient="vertical", command=self.chat_canvas.yview)
        self.scrollbar.pack(side="right", fill="y")

        self.chat_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.message_frame = tk.Frame(self.chat_canvas, bg="#b2c7d9")
        self.chat_canvas.create_window((50, 0), window=self.message_frame, anchor="nw")

        self.input_frame = tk.Frame(self.chat_frame, bg="#b2c7d9")
        self.input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        self.message_entry = tk.Entry(self.input_frame, bg="white", fg="black")
        self.message_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(self.input_frame, text="전송", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        self.message_frame.bind("<Configure>", self.on_frame_configure)

    def show_frame(self, frame):
        if self.current_frame:
            self.current_frame.pack_forget()
        frame.pack(expand=True, fill='both')
        self.current_frame = frame

    def on_frame_configure(self, event):
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))

    def connect_to_server(self):
        host = self.server_entry.get()
        try:
            self.sock.connect((host, 2500))
            return True
        except Exception as e:
            messagebox.showerror("연결 오류", f"서버 연결 실패: {str(e)}")
            return False
    def connect_to_server(self):
        host = self.server_entry.get()
        try:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, 2500))
            return True
        except Exception as e:
            messagebox.showerror("연결 오류", f"서버 연결 실패: {str(e)}")
            return False
        
    def login(self):
        if not self.connect_to_server():
            return

        username = self.username_entry.get()
        password = self.password_entry.get()
        self.sock.send(f"LOGIN:{username}:{password}".encode())
        response = self.sock.recv(1024).decode()
        if response == "LOGIN_SUCCESS":
            self.nickname = username
            self.show_frame(self.chat_frame)
            self.display_message(f"{username}님으로 로그인했습니다.", 'left', 'white')
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
        else:
            messagebox.showerror("로그인 실패", "아이디 또는 비밀번호가 올바르지 않습니다.")
            self.sock.close()
            self.sock = None

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("입력 오류", "사용자 이름과 비밀번호를 모두 입력해주세요.")
            return
        
        confirm = messagebox.askyesno("계정 생성 확인", f"'{username}' 계정을 생성하시겠습니까?")
        if not confirm:
            return
        
        if not self.connect_to_server():
            return

        self.sock.send(f"REGISTER:{username}:{password}".encode())
        response = self.sock.recv(1024).decode()
        if response == "REGISTER_SUCCESS":
            messagebox.showinfo("회원가입 성공", "회원가입이 완료되었습니다. 로그인해주세요.")
        else:
            messagebox.showerror("회원가입 실패", "이미 존재하는 사용자명입니다.")
        self.sock.close()
        self.sock = None

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message and self.nickname:
            try:
                self.sock.send(message.encode())
                self.message_entry.delete(0, tk.END)
            except:
                self.display_message("메시지 전송 실패", 'left', 'red')

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(1024)
                if data:
                    message = data.decode()
                    if message.startswith(f"{self.nickname}:"):
                        self.display_message(message, 'right', '#fee500')
                    else:
                        self.display_message(message, 'left', 'white')
            except:
                self.display_message("서버와의 연결이 끊겼습니다.", 'left', 'red')
                break


    def display_message(self, message, align, bg_color):
        frame = tk.Frame(self.message_frame, bg="#b2c7d9")
        frame.pack(side=tk.TOP, fill=tk.X, padx=2, pady=2)

        time_now = datetime.datetime.now().strftime("%H:%M")
        
        if align == 'left':
            msg_label = tk.Label(frame, text=message, bg=bg_color, fg="black", wraplength=200, justify=tk.LEFT, padx=5, pady=5)
            msg_label.pack(side=tk.LEFT)
            time_label = tk.Label(frame, text=time_now, bg="#b2c7d9", fg="gray", font=("Arial", 7))
            time_label.pack(side=tk.LEFT, padx=(2, 0), pady=(0, 2), anchor='s')
        else:
            inner_frame = tk.Frame(frame, bg="#b2c7d9")
            inner_frame.pack(side=tk.RIGHT)
            
            time_label = tk.Label(inner_frame, text=time_now, bg="#b2c7d9", fg="gray", font=("Arial", 7))
            time_label.pack(side=tk.LEFT, padx=(0, 2), pady=(0, 2), anchor='s')
            
            msg_label = tk.Label(inner_frame, text=message, bg=bg_color, fg="black", wraplength=200, justify=tk.RIGHT, padx=5, pady=5)
            msg_label.pack(side=tk.RIGHT)

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)



        
if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
