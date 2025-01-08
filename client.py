import socket
import threading
import datetime
import tkinter.messagebox as tkmb
import customtkinter as ctk

# customtkinter 테마/스타일 설정
ctk.set_appearance_mode("Dark")  # 혹은 "Light", "System"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

class ChatClient(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NA_KakaoTalk")
        self.geometry("400x600")

        self.nickname = None
        self.sock = None
        self.current_messages = {}  # 메세지 구조 {message_id: msg_label} 
        # typing(입력중) 상태 관리
        self.typing = False
        self.typing_timer = None
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.pack(expand=True, fill="both")
        self.create_login_frame()
        self.create_chat_frame()
        self.current_frame = None
        self.show_frame(self.login_frame)

    def create_login_frame(self):
        self.login_frame = ctk.CTkFrame(self.main_frame, corner_radius=15)
        title_label = ctk.CTkLabel(
            self.login_frame,
            text="로그인",
            text_color="#1A73E8",
            font=ctk.CTkFont("Arial", size=20, weight="bold")
        )
        title_label.pack(pady=(20, 10))

        # 서버 주소
        server_label = ctk.CTkLabel(
            self.login_frame,
            text="서버 주소:",
            text_color="#5F6368",
            font=ctk.CTkFont("Arial", size=12)
        )
        server_label.pack(pady=5)

        self.server_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="예) 127.0.0.1",
            width=220
        )
        self.server_entry.insert(0, "127.0.0.1")
        self.server_entry.pack(pady=5)

        # 사용자 이름
        username_label = ctk.CTkLabel(
            self.login_frame,
            text="사용자 이름:",
            text_color="#5F6368",
            font=ctk.CTkFont("Arial", size=12)
        )
        username_label.pack(pady=5)

        self.username_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="사용자 이름 입력",
            width=220
        )
        self.username_entry.pack(pady=5)


        password_label = ctk.CTkLabel(
            self.login_frame,
            text="비밀번호:",
            text_color="#5F6368",
            font=ctk.CTkFont("Arial", size=12)
        )
        password_label.pack(pady=5)

        self.password_entry = ctk.CTkEntry(
            self.login_frame,
            placeholder_text="비밀번호 입력",
            show="*",
            width=220
        )
        self.password_entry.pack(pady=5)

 
        self.login_button = ctk.CTkButton(
            self.login_frame,
            text="로그인",
            fg_color="#1A73E8",
            command=self.login
        )
        self.login_button.pack(pady=(15, 5))

        # 회원가입 버튼
        self.register_button = ctk.CTkButton(
            self.login_frame,
            text="회원가입",
            fg_color="#34A853",
            command=self.register
        )
        self.register_button.pack(pady=5)

    def create_chat_frame(self):
        self.chat_frame = ctk.CTkFrame(self.main_frame, corner_radius=15)

        # 채팅 메시지 표시 영역(스크롤 가능)
        self.message_frame = ctk.CTkScrollableFrame(
            self.chat_frame,
            label_text="채팅 기록",
            corner_radius=10,
            width=360,
            height=400
        )
        self.message_frame.pack(expand=True, fill="both", padx=10, pady=(10, 5))

        # typing 알림 레이블
        self.typing_label = ctk.CTkLabel(
            self.chat_frame,
            text="",
            text_color="gray",
            font=ctk.CTkFont("Arial", size=10)
        )
        self.typing_label.pack(anchor="w", padx=15, pady=(0, 5))

        # 메시지 입력 영역
        input_frame = ctk.CTkFrame(self.chat_frame, corner_radius=10)
        input_frame.pack(side="bottom", fill="x", padx=10, pady=10)

        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="메시지를 입력하세요",
            width=260
        )
        self.message_entry.pack(side="left", padx=(0, 5), pady=5, fill="x", expand=True)
        self.message_entry.bind("<Return>", self.send_message)
        self.message_entry.bind("<KeyPress>", self.on_typing)

        send_button = ctk.CTkButton(
            input_frame,
            text="전송",
            command=self.send_message
        )
        send_button.pack(side="left")

    def show_frame(self, frame: ctk.CTkFrame):
        if self.current_frame is not None:
            self.current_frame.pack_forget()
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        self.current_frame = frame

    def connect_to_server(self) -> bool:
        host = self.server_entry.get().strip()
        try:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, 2500))
            return True
        except Exception as e:
            tkmb.showerror("연결 오류", f"서버 연결 실패: {str(e)}")
            self.sock = None
            return False

    def login(self):
        if not self.connect_to_server():
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            tkmb.showerror("입력 오류", "사용자 이름과 비밀번호를 모두 입력해주세요.")
            return

        # 서버에 로그인 요청 전송
        send_data = f"LOGIN:{username}:{password}"
        self.sock.send(send_data.encode())
        response = self.sock.recv(1024).decode()

        if response == "LOGIN_SUCCESS":
            self.nickname = username
            self.show_frame(self.chat_frame)
            self.display_message(f"{username}님으로 로그인했습니다.", "left", "#D9E5FF")

            # 메시지 수신 스레드 시작
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
        else:
            tkmb.showerror("로그인 실패", "아이디 또는 비밀번호가 올바르지 않습니다.")
            self.sock.close()
            self.sock = None

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            tkmb.showerror("입력 오류", "사용자 이름과 비밀번호를 모두 입력해주세요.")
            return

        confirm = tkmb.askyesno("계정 생성 확인", f"'{username}' 계정을 생성하시겠습니까?")
        if not confirm:
            return

        if not self.connect_to_server():
            return

        # 서버에 회원가입 요청 전송
        send_data = f"REGISTER:{username}:{password}"
        self.sock.send(send_data.encode())
        response = self.sock.recv(1024).decode()

        if response == "REGISTER_SUCCESS":
            tkmb.showinfo("회원가입 성공", "회원가입이 완료되었습니다. 로그인해주세요.")
        else:
            tkmb.showerror("회원가입 실패", "이미 존재하는 사용자명입니다.")

        self.sock.close()
        self.sock = None

    def send_message(self, event=None):
        if not self.nickname or not self.sock:
            return

        message = self.message_entry.get().strip()
        if message:
            try:
                self.sock.send(message.encode())
                self.message_entry.delete(0, "end")
            except:
                self.display_message("메시지 전송 실패", "left", "red")

    def receive_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    raise ConnectionError
                message = data.decode()

                if message.startswith("TYPING:"):
                    # 예: "TYPING:<user>:<start/stop>" 형태
                    _, user, status = message.split(":")
                    self.display_typing_notification(user, status)

                else:
                    # 일반 채팅 메시지
                    if message.startswith(f"{self.nickname}:"):
                        # 본인 발화 표시 (오른쪽)
                        self.display_message(message, "right", "#fee500")
                    else:
                        self.display_message(message, "left", "#FFFFFF")
            except:
                self.display_message("서버와의 연결이 끊겼습니다.", "left", "red")
                break

    def display_message(self, text: str, align: str, bg_color: str):
        # 메시지 표시용 프레임
        msg_frame = ctk.CTkFrame(self.message_frame, corner_radius=8)
        msg_frame.pack(fill="x", padx=5, pady=2)

        # 시간정보
        time_now = datetime.datetime.now().strftime("%H:%M")

        if align == "left":
            msg_label = ctk.CTkLabel(
                msg_frame,
                text=text,
                fg_color=bg_color,
                corner_radius=6,
                text_color="black",
                wraplength=250,
                anchor="w"
            )
            msg_label.pack(side="left", padx=(2, 5), pady=5)
            time_label = ctk.CTkLabel(msg_frame, text=time_now, text_color="gray")
            time_label.pack(side="left", pady=(0, 5), anchor="s")

        else: 
            time_label = ctk.CTkLabel(msg_frame, text=time_now, text_color="gray")
            time_label.pack(side="right", pady=(0, 5), anchor="s")
            msg_label = ctk.CTkLabel(
                msg_frame,
                text=text,
                fg_color=bg_color,
                corner_radius=6,
                text_color="black",
                wraplength=250,
                anchor="e"
            )
            msg_label.pack(side="right", padx=(5, 2), pady=5)

        # 스크롤 최하단으로 이동
        self.message_frame.update_idletasks()
        self.message_frame._parent_canvas.yview_moveto(1.0)

    def display_typing_notification(self, user: str, status: str):
        if user == self.nickname:
            return  # 자기 자신은 표시 X
        
        if status == "start":
            self.typing_label.configure(text=f"{user}님이 입력 중...")
        elif status == "stop":
            self.typing_label.configure(text="")

    def on_typing(self, event=None):
        if not self.typing:
            self.typing = True
            if self.sock is not None:
                self.sock.send(f"/typing start".encode())

        if self.typing_timer:
            self.typing_timer.cancel()

        self.typing_timer = threading.Timer(1.0, self.stop_typing)
        self.typing_timer.start()

    def stop_typing(self):
        if self.typing:
            self.typing = False
            if self.sock is not None:
                self.sock.send(f"/typing stop".encode())


if __name__ == "__main__":
    app = ChatClient()
    app.mainloop()
