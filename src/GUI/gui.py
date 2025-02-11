import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import socket
import threading

# Server Configuration
HOST = "localhost"
PORT = 9999

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        
        self.username = None
        self.client_socket = None
        self.authenticate()
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20, width=50)
        self.chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        
        # Message entry
        self.msg_entry = tk.Entry(root, width=40)
        self.msg_entry.grid(row=1, column=0, padx=10, pady=5)
        self.msg_entry.bind("<Return>", self.send_message)
        
        # Send button
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=5, pady=5)
        
        # Start receiving messages
        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()
    
    def authenticate(self):
        choice = messagebox.askyesno("Authentication", "Do you have an account?")
        if choice:
            self.login()
        else:
            self.register()
        
        # Connect to server after successful authentication
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, "Connected to the server\n")
            self.chat_display.config(state='disabled')
        except Exception as e:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, f"Connection failed: {e}\n")
            self.chat_display.config(state='disabled')
            self.root.quit()
    
    def login(self):
        self.username = simpledialog.askstring("Login", "Enter username:")
        password = simpledialog.askstring("Login", "Enter password:", show='*')
        if not self.username or not password:
            self.root.quit()
            return
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            credentials = f"LOGIN {self.username} {password}"
            self.client_socket.sendall(credentials.encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            if response != "OK":
                messagebox.showerror("Error", "Authentication failed!")
                self.root.quit()
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            self.root.quit()
    
    def register(self):
        self.username = simpledialog.askstring("Register", "Choose a username:")
        password = simpledialog.askstring("Register", "Choose a password:", show='*')
        if not self.username or not password:
            self.root.quit()
            return
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((HOST, PORT))
            credentials = f"REGISTER {self.username} {password}"
            self.client_socket.sendall(credentials.encode('utf-8'))
            response = self.client_socket.recv(1024).decode('utf-8')
            if response == "OK":
                messagebox.showinfo("Success", "Registration successful! Please log in.")
                self.login()
            else:
                messagebox.showerror("Error", "Registration failed! Username might already be taken.")
                self.root.quit()
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            self.root.quit()
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if message:
            self.client_socket.sendall(f"{self.username}: {message}".encode('utf-8'))
            self.msg_entry.delete(0, tk.END)
    
    def receive_messages(self):
        while self.running:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    self.chat_display.config(state='normal')
                    self.chat_display.insert(tk.END, message + "\n")
                    self.chat_display.config(state='disabled')
            except Exception:
                break
    
    def close_connection(self):
        self.running = False
        self.client_socket.close()
        self.root.quit()
        
if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.close_connection)
    root.mainloop()
