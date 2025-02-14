"""
* File: client_gui.py
* Author: Áron Vékássy, Karen Li (adapted to GUI by you)
*
* This file contains a Tkinter-based GUI client for the chat application.
* In this version, individual chats appear in separate pages (tabs)
* that remain open even as new messages are polled.
"""

import socket
import sys
import os
import tkinter as tk
from tkinter import messagebox, ttk

# Add the parent directory to the module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.protocol import *  # Provides validate_length, LEN_UNAME, LEN_PASSWORD, LEN_MESSAGE, etc.
from client.requests import *         # Provides request_login, request_register, request_save_users, etc.

# Server Configuration
HOST = "localhost"
PORT = 9999  # Must match the server port

def connect_to_server():
    """Connect to the chat server and return the client socket."""
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"✅ Connected to server at {HOST}:{PORT}")
        return client_socket
    except ConnectionRefusedError:
        messagebox.showerror("Connection Failed", f"❌ Connection failed! Is the server running on {HOST}:{PORT}?")
        sys.exit(1)
    except Exception as e:
        messagebox.showerror("Error", f"❌ Error: {e}")
        sys.exit(1)

class ChatClientApp(tk.Tk):
    """Main application window for the chat client."""
    def __init__(self):
        super().__init__()
        self.title("Chat Application")
        self.geometry("600x400")

        # Connect to server (socket shared among frames)
        self.client_socket = connect_to_server()
        self.username = None  # Set after login
        self.password = None

        # Create frames for login and chat
        self.login_frame = LoginFrame(self)
        self.chat_frame = ChatFrame(self)
        self.login_frame.pack(fill="both", expand=True)

        # Bind the close event to gracefully disconnect
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_chat_frame(self):
        """Switch from the login frame to the chat frame."""
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        self.chat_frame.poll_messages()  # Start polling messages

    def show_login_frame(self):
        """Switch back to the login frame (e.g., after logout)."""
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def on_close(self):
        """Handle closing the application (logout if needed)."""
        if self.username:
            try:
                request_logout(self.client_socket, self.username)
            except Exception:
                pass
        try:
            self.client_socket.close()
        except Exception:
            pass
        self.destroy()

class LoginFrame(tk.Frame):
    """Frame for user login and registration."""
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        # Username Label and Entry
        tk.Label(self, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.entry_username = tk.Entry(self)
        self.entry_username.grid(row=0, column=1, padx=10, pady=10)

        # Password Label and Entry
        tk.Label(self, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)

        # Message label for errors/info
        self.label_message = tk.Label(self, text="", fg="red")
        self.label_message.grid(row=2, column=0, columnspan=2)

        # Buttons for Login and Register
        self.button_login = tk.Button(self, text="Login", width=12, command=self.login)
        self.button_login.grid(row=3, column=0, padx=10, pady=10)

        self.button_register = tk.Button(self, text="Register", width=12, command=self.register)
        self.button_register.grid(row=3, column=1, padx=10, pady=10)

    def login(self):
        """Handle the login process."""
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        # Validate input lengths
        if not validate_length(username, LEN_UNAME, "Username"):
            self.label_message.config(text="Invalid username length")
            return
        if not validate_length(password, LEN_PASSWORD, "Password"):
            self.label_message.config(text="Invalid password length")
            return

        # Check if the user exists
        user_exists_response = request_check_user_exists(self.master.client_socket, username)
        if user_exists_response[0] != RES_OK.strip('\x00'):
            self.label_message.config(text="User does not exist. Please register.")
            return

        # Attempt login
        login_response = request_login(self.master.client_socket, username, password)
        if login_response[0] == RES_OK.strip('\x00'):
            self.master.username = username
            self.master.password = password
            self.label_message.config(text="Login successful!", fg="green")
            self.master.show_chat_frame()
        else:
            self.label_message.config(text="Invalid password. Try again.", fg="red")

    def register(self):
        """Handle the registration process."""
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not validate_length(username, LEN_UNAME, "Username"):
            self.label_message.config(text="Invalid username length")
            return
        if not validate_length(password, LEN_PASSWORD, "Password"):
            self.label_message.config(text="Invalid password length")
            return

        # Check if user already exists
        user_exists_response = request_check_user_exists(self.master.client_socket, username)
        if user_exists_response[0] == RES_OK.strip('\x00'):
            self.label_message.config(text="User already exists. Please login.", fg="red")
            return

        # Register new user
        register_response = request_register(self.master.client_socket, username, password)
        if register_response[0] == RES_OK.strip('\x00'):
            # Save user data on the server
            save_response = request_save_users(self.master.client_socket, username)
            if save_response[0] == RES_OK.strip('\x00'):
                self.label_message.config(text="Account created. Please login.", fg="green")
            else:
                self.label_message.config(text="Error saving user data.", fg="red")
        else:
            self.label_message.config(text="Registration failed. Username may be taken.", fg="red")

class ChatFrame(tk.Frame):
    """Frame for the main chat interface using tabs (one per conversation)."""
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        # Notebook for individual conversation pages
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Dictionary mapping conversation partner (sender) to a tab info dict:
        # { "frame": tab frame, "listbox": Listbox widget, "message_indices": mapping of listbox index -> global message index }
        self.conversations = {}

        # Bottom button frame
        button_frame = tk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=5)

        self.button_send = tk.Button(button_frame, text="Send Message", width=12, command=self.open_send_message_window)
        self.button_send.pack(side="left", padx=5)

        self.button_delete = tk.Button(button_frame, text="Delete Message", width=12, command=self.delete_message)
        self.button_delete.pack(side="left", padx=5)

        self.button_delete_account = tk.Button(button_frame, text="Delete Account", width=12, command=self.delete_account)
        self.button_delete_account.pack(side="left", padx=5)

        self.button_logout = tk.Button(button_frame, text="Logout", width=12, command=self.logout)
        self.button_logout.pack(side="left", padx=5)

    def refresh_messages(self):
        """Retrieve messages from the server and update conversation tabs without closing them."""
        get_profile_response = request_get_profile(self.master.client_socket, self.master.username)
        messages_str = get_profile_response[1]
        new_data = {}  # Group messages by sender: {sender: list of (global_index, status, content)}
        if messages_str.strip() != "":
            lines = messages_str.strip().split('\n')
            for i, line in enumerate(lines):
                parts = line.split(',')
                if len(parts) >= 3:
                    status, content, sender = parts[0], parts[1], parts[2]
                    new_data.setdefault(sender, []).append((i, status, content))

        # For each conversation in new_data, update or create its tab
        for sender, messages in new_data.items():
            if sender not in self.conversations:
                # Create a new tab for this conversation
                frame = ttk.Frame(self.notebook)
                listbox = tk.Listbox(frame, activestyle="none", width=80)
                listbox.pack(fill="both", expand=True, padx=10, pady=10)
                self.conversations[sender] = {"frame": frame, "listbox": listbox, "message_indices": {}}
                self.notebook.add(frame, text=sender)
            conv = self.conversations[sender]
            listbox = conv["listbox"]
            listbox.delete(0, tk.END)
            conv["message_indices"].clear()
            for msg_idx, status, content in messages:
                text_line = f"[{status.capitalize()}] {content}"
                listbox.insert(tk.END, text_line)
                conv["message_indices"][listbox.size() - 1] = msg_idx

        # For conversations that exist but now have no messages, clear their listbox
        for sender in list(self.conversations.keys()):
            if sender not in new_data:
                conv = self.conversations[sender]
                conv["listbox"].delete(0, tk.END)
                conv["message_indices"].clear()

        # Update message statuses (if needed)
        request_update_profile(self.master.client_socket, self.master.username)

    def poll_messages(self):
        """Poll the server for new messages at regular intervals."""
        if self.master.username:
            self.refresh_messages()
            self.after(5000, self.poll_messages)

    def open_send_message_window(self):
        """Open a new window to send a message. Defaults to the current conversation partner if a tab is active."""
        send_window = tk.Toplevel(self)
        send_window.title("Send Message")

        # Default recipient is the currently selected tab (if any)
        current_tab = self.notebook.select()
        default_recipient = ""
        if current_tab:
            default_recipient = self.notebook.tab(current_tab, "text")

        # Retrieve list of available users
        get_users_response = request_list_users(self.master.client_socket, self.master.username)
        users_str = get_users_response[1]
        users = users_str.strip().split('\n') if users_str.strip() != "" else []

        tk.Label(send_window, text="Select recipient:").pack(padx=10, pady=5)
        recipient_var = tk.StringVar(send_window)
        if default_recipient and default_recipient in users:
            recipient_var.set(default_recipient)
        elif users:
            recipient_var.set(users[0])
        else:
            recipient_var.set("")
        recipient_menu = tk.OptionMenu(send_window, recipient_var, *users)
        recipient_menu.pack(padx=10, pady=5)

        tk.Label(send_window, text="Enter your message:").pack(padx=10, pady=5)
        message_entry = tk.Text(send_window, height=5, width=40)
        message_entry.pack(padx=10, pady=5)

        def send():
            recipient = recipient_var.get().strip()
            message_text = message_entry.get("1.0", tk.END).strip()
            if not recipient:
                messagebox.showerror("Error", "Please select a recipient.")
                return
            if not validate_length(message_text, LEN_MESSAGE, "Message"):
                messagebox.showerror("Error", "Invalid message length.")
                return
            # Send the message (record it on both sender and recipient)
            request_set_profile(self.master.client_socket, self.master.username, message_text, recipient)
            messagebox.showinfo("Success", "Message sent!")
            send_window.destroy()
            self.refresh_messages()

        tk.Button(send_window, text="Send", command=send).pack(padx=10, pady=10)

    def delete_message(self):
        """Delete the selected message from the active conversation tab."""
        current_tab = self.notebook.select()
        if not current_tab:
            messagebox.showerror("Error", "No conversation tab is selected.")
            return
        sender = self.notebook.tab(current_tab, "text")
        conv = self.conversations.get(sender)
        if not conv:
            messagebox.showerror("Error", "Conversation not found.")
            return
        listbox = conv["listbox"]
        selection = listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a message to delete.")
            return
        index = selection[0]
        global_index = conv["message_indices"].get(index)
        if global_index is None:
            messagebox.showerror("Error", "Unable to determine the selected message index.")
            return
        request_delete_messages(self.master.client_socket, self.master.username, global_index)
        messagebox.showinfo("Deleted", "Message deleted!")
        self.refresh_messages()

    def delete_account(self):
        """Delete the user account."""
        if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            request_delete_profile(self.master.client_socket, self.master.username)
            request_logout(self.master.client_socket, self.master.username)
            messagebox.showinfo("Account Deleted", "Your account has been deleted.")
            try:
                self.master.client_socket.close()
            except Exception:
                pass
            self.master.client_socket = connect_to_server()
            self.master.username = None
            self.master.show_login_frame()

    def logout(self):
        """Logout the user, close the connection, and reconnect to the server."""
        request_logout(self.master.client_socket, self.master.username)
        messagebox.showinfo("Logged Out", "You have been logged out.")
        try:
            self.master.client_socket.close()
        except Exception:
            pass
        self.master.client_socket = connect_to_server()
        self.master.username = None
        self.master.show_login_frame()

if __name__ == "__main__":
    app = ChatClientApp()
    app.mainloop()
