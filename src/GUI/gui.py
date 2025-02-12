import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading
import sys
import os
# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.protocol import *

# Server Configuration
HOST = "localhost"
PORT = 9999

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.root.geometry("600x500")
        self.root.configure(bg="#2C3E50")
        
        self.server_socket = None
        
        # Login Frame
        self.login_frame = tk.Frame(root, bg="#34495E", padx=20, pady=20)
        self.login_frame.pack(pady=20)
        
        tk.Label(self.login_frame, text="Username:", bg="#34495E", fg="white").grid(row=0, column=0, sticky="w")
        self.username_entry = tk.Entry(self.login_frame, width=25)
        self.username_entry.grid(row=0, column=1)
        
        tk.Label(self.login_frame, text="Password:", bg="#34495E", fg="white").grid(row=1, column=0, sticky="w")
        self.password_entry = tk.Entry(self.login_frame, show="*", width=25)
        self.password_entry.grid(row=1, column=1)
        
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login, bg="#1ABC9C", fg="white", width=20)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.register_button = tk.Button(self.login_frame, text="Register", command=self.register, bg="#E74C3C", fg="white", width=20)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Chat Frame (Initially Hidden)
        self.chat_frame = tk.Frame(root, bg="#2C3E50", padx=10, pady=10)
        
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', height=15, width=50, bg="#ECF0F1", fg="#2C3E50")
        self.chat_display.pack(pady=10)
        
        message_frame = tk.Frame(self.chat_frame, bg="#2C3E50")
        message_frame.pack()
        
        self.message_entry = tk.Entry(message_frame, width=40, bg="#ECF0F1", fg="#2C3E50")
        self.message_entry.pack(side=tk.LEFT, padx=5)
        
        self.send_button = tk.Button(message_frame, text="Send", command=self.send_message, bg="#3498DB", fg="white")
        self.send_button.pack(side=tk.RIGHT)
    
    def connect_to_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((HOST, PORT))
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            return False
        return True

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self):
        username = self.username_entry.get()
        password = self.hash_password(self.password_entry.get())
        if not self.connect_to_server():
            return
        
        packet = create_packet(REQ_LOG, f"{username}:{password}")
        self.server_socket.sendall(packet)
        response = self.server_socket.recv(1024)
        command, payload, status = parse_packet(response)
        
        if command == b"___OK___":
            self.show_chat()
        else:
            messagebox.showerror("Login Failed", payload)
    
    def register(self):
        username = self.username_entry.get()
        password = self.hash_password(self.password_entry.get())
        if not self.connect_to_server():
            return
        
        packet = create_packet(REQ_REG, f"{username}:{password}")
        self.server_socket.sendall(packet)
        response = self.server_socket.recv(1024)
        command, payload, status = parse_packet(response)
        
        if command == b"___OK___":
            messagebox.showinfo("Registration Success", "You can now login!")
        else:
            messagebox.showerror("Registration Failed", payload)
    
    def show_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack()
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def send_message(self):
        message = self.message_entry.get()
        if message and self.server_socket:
            packet = create_packet(b"MESSAGE_", message)
            self.server_socket.sendall(packet)
            self.message_entry.delete(0, tk.END)
    
    def receive_messages(self):
        while True:
            try:
                response = self.server_socket.recv(1024)
                if not response:
                    break
                command, payload, status = parse_packet(response)
                self.chat_display.config(state='normal')
                self.chat_display.insert(tk.END, f"{payload}\n")
                self.chat_display.config(state='disabled')
            except Exception as e:
                break
        
    def on_close(self):
        if self.server_socket:
            self.server_socket.sendall(create_packet(REQ_BYE, ""))
            self.server_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", client.on_close)
    root.mainloop()
