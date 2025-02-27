#!/usr/bin/env python3
"""
* File: gui.py
* Author: Áron Vékássy, Karen Li
*
* This file contains a Tkinter-based GUI client for the chat application using gRPC.
"""

import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk
import grpc

# Import gRPC generated classes and our shared protocol constants/functions.
from common import chat_pb2, chat_pb2_grpc
from common.protocol import *  # Provides validate_length, LEN_UNAME, LEN_PASSWORD, LEN_MESSAGE, etc.

# gRPC connection helper
def connect_to_server():
    """Creates a gRPC channel with keepalive settings and returns a ChatServiceStub."""
    options = [
        ("grpc.keepalive_time_ms", 10000),
        ("grpc.keepalive_timeout_ms", 5000),
        ("grpc.keepalive_permit_without_calls", 1),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.http2.min_time_between_pings_ms", 5000),
        ("grpc.http2.min_ping_interval_without_data_ms", 5000)
    ]
    channel = grpc.insecure_channel("localhost:50051", options=options)
    stub = chat_pb2_grpc.ChatServiceStub(channel)
    print("✅ Connected to gRPC server at localhost:50051")
    return stub

class ChatClientApp(tk.Tk):
    """Main application window for the chat client."""
    def __init__(self):
        super().__init__()
        self.title("Chat Application")
        self.geometry("600x500")

        # Create a gRPC stub for all communication.
        self.stub = connect_to_server()
        self.username = None  # Set after login

        # Create frames for login, landing, and chat
        self.login_frame = LoginFrame(self)
        self.landing_frame = LandingFrame(self, self.open_chat)
        self.chat_frame = ChatFrame(self)
        self.login_frame.pack(fill="both", expand=True)

        # Bind the close event to gracefully logout
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_landing_frame(self):
        """Switch from the login frame to the landing page."""
        self.login_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.landing_frame.pack(fill="both", expand=True)
        self.landing_frame.poll_messages()

    def show_chat_frame(self):
        """Switch from the landing page to the chat view."""
        self.landing_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        self.chat_frame.poll_messages()

    def open_chat(self, recipient):
        """Callback from LandingFrame to open a conversation with the given recipient."""
        self.show_chat_frame()
        self.chat_frame.open_chat(recipient)

    def show_login_frame(self):
        """Switch back to the login frame (e.g., after logout)."""
        self.landing_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)

    def on_close(self):
        """Handle closing the application (logout if needed)."""
        if self.username:
            try:
                self.stub.LogoutUser(chat_pb2.UsernameRequest(username=self.username))
            except Exception:
                pass
        self.destroy()

class LoginFrame(tk.Frame):
    """Frame for user login and registration."""
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        tk.Label(self, text="Username:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.entry_username = tk.Entry(self)
        self.entry_username.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.entry_password = tk.Entry(self, show="*")
        self.entry_password.grid(row=1, column=1, padx=10, pady=10)

        self.label_message = tk.Label(self, text="", fg="red")
        self.label_message.grid(row=2, column=0, columnspan=2)

        self.button_login = tk.Button(self, text="Login", width=12, command=self.login)
        self.button_login.grid(row=3, column=0, padx=10, pady=10)
        self.button_register = tk.Button(self, text="Register", width=12, command=self.register)
        self.button_register.grid(row=3, column=1, padx=10, pady=10)

    def login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not validate_length(username, LEN_UNAME, "Username"):
            self.label_message.config(text="Invalid username length")
            return
        if not validate_length(password, LEN_PASSWORD, "Password"):
            self.label_message.config(text="Invalid password length")
            return

        # Check if the user exists using gRPC.
        response = self.master.stub.CheckUserExists(chat_pb2.UsernameRequest(username=username))
        if response.exists:
            print("🔹 Username found. Proceeding to login...")
            login_response = self.master.stub.LoginUser(chat_pb2.LoginRequest(username=username, password=password))
            if login_response.status == "OK":
                self.master.username = username
                self.label_message.config(text="Login successful!", fg="green")
                self.master.show_landing_frame()
            else:
                self.label_message.config(text="Invalid password. Try again.", fg="red")
        else:
            self.label_message.config(text="User does not exist. Please register.", fg="red")

    def register(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not validate_length(username, LEN_UNAME, "Username"):
            self.label_message.config(text="Invalid username length")
            return
        if not validate_length(password, LEN_PASSWORD, "Password"):
            self.label_message.config(text="Invalid password length")
            return

        # Check for existence first.
        response = self.master.stub.CheckUserExists(chat_pb2.UsernameRequest(username=username))
        if response.exists:
            self.label_message.config(text="User already exists. Please login.", fg="red")
            return

        register_response = self.master.stub.RegisterUser(chat_pb2.RegisterRequest(username=username, password=password))
        if register_response.status == "OK":
            self.label_message.config(text="Account created. Please log in.", fg="green")
        else:
            self.label_message.config(text="Registration failed. Username may be taken.", fg="red")

class LandingFrame(tk.Frame):
    """
    Landing page showing a list of accounts you have chatted with,
    along with the number of unread messages.
    Double-click an entry to open that conversation.
    Includes Logout and Delete Account buttons and a section to start a new chat.
    """
    def __init__(self, master, open_chat_callback):
        super().__init__(master)
        self.master = master
        self.open_chat_callback = open_chat_callback

        tk.Label(self, text="Your Conversations:").pack(padx=10, pady=10)
        self.listbox = tk.Listbox(self, activestyle="none", width=50)
        self.listbox.pack(fill="both", expand=True, padx=10, pady=10)
        self.listbox.bind("<Double-Button-1>", self.on_double_click)
        self.refresh_button = tk.Button(self, text="Refresh", command=self.refresh)
        self.refresh_button.pack(pady=5)

        # New section to start a new chat.
        new_chat_frame = tk.Frame(self)
        new_chat_frame.pack(pady=10)
        tk.Label(new_chat_frame, text="Start New Chat:").grid(row=0, column=0, padx=5, pady=5)
        self.new_recipient_var = tk.StringVar(new_chat_frame)
        self.new_recipient_menu = tk.OptionMenu(new_chat_frame, self.new_recipient_var, "")
        self.new_recipient_menu.grid(row=0, column=1, padx=5, pady=5)
        self.start_chat_button = tk.Button(new_chat_frame, text="Start Chat", command=self.start_new_chat)
        self.start_chat_button.grid(row=0, column=2, padx=5, pady=5)

        # Logout and Delete Account buttons.
        self.button_frame = tk.Frame(self)
        self.button_frame.pack(pady=5)
        self.logout_button = tk.Button(self.button_frame, text="Logout", width=12, command=self.logout)
        self.logout_button.pack(side="left", padx=5)
        self.delete_account_button = tk.Button(self.button_frame, text="Delete Account", width=12, command=self.delete_account)
        self.delete_account_button.pack(side="left", padx=5)

    def update_new_recipient_menu(self):
        """Update the recipient drop-down with available users (excluding self)."""
        users_response = self.master.stub.ListUsers(chat_pb2.EmptyRequest())
        users = users_response.users
        users = [u for u in users if u != self.master.username]
        if not users:
            users = [""]
        menu = self.new_recipient_menu["menu"]
        menu.delete(0, "end")
        for user in users:
            menu.add_command(label=user, command=lambda value=user: self.new_recipient_var.set(value))
        if self.new_recipient_var.get() not in users:
            self.new_recipient_var.set(users[0])

    def refresh(self):
        # Fetch messages via gRPC.
        messages_response = self.master.stub.GetMessages(chat_pb2.UsernameRequest(username=self.master.username))
        messages = messages_response.messages  # Assume a list of strings like "STATUS,content,sender"
        conversation_dict = {}  # {sender: unread_count}
        if messages:
            for msg in messages:
                parts = msg.split(',')
                if len(parts) >= 3:
                    status, content, sender = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    if sender in conversation_dict:
                        if status.upper() == "UNREAD":
                            conversation_dict[sender] += 1
                    else:
                        conversation_dict[sender] = 1 if status.upper() == "UNREAD" else 0
        self.listbox.delete(0, tk.END)
        for sender, unread in conversation_dict.items():
            display_text = f"{sender} ({unread})" if unread else sender
            self.listbox.insert(tk.END, display_text)
        self.master.chat_frame.update_recipient_menu()
        self.update_new_recipient_menu()

    def poll_messages(self):
        self.refresh()
        self.after(5000, self.poll_messages)

    def on_double_click(self, event):
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            text = self.listbox.get(index)
            recipient = text.split(" (")[0] if " (" in text else text
            self.open_chat_callback(recipient)

    def start_new_chat(self):
        recipient = self.new_recipient_var.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Please select a recipient.")
            return
        self.open_chat_callback(recipient)

    def logout(self):
        try:
            self.master.stub.LogoutUser(chat_pb2.UsernameRequest(username=self.master.username))
        except Exception:
            pass
        messagebox.showinfo("Logged Out", "You have been logged out.")
        self.master.stub = connect_to_server()  # Reconnect the stub.
        self.master.username = None
        self.master.show_login_frame()

    def delete_account(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            self.master.stub.DeleteUser(chat_pb2.UsernameRequest(username=self.master.username))
            try:
                self.master.stub.LogoutUser(chat_pb2.UsernameRequest(username=self.master.username))
            except Exception:
                pass
            messagebox.showinfo("Account Deleted", "Your account has been deleted.")
            self.master.stub = connect_to_server()
            self.master.username = None
            self.master.show_login_frame()

class ChatFrame(tk.Frame):
    """
    Frame for the main chat interface with each conversation in its own tab.
    A persistent send message area with a recipient drop-down is integrated at the bottom.
    """
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Mapping normalized conversation partner (lowercase) to conversation data.
        self.conversations = {}

        self.send_frame = tk.Frame(self)
        self.send_frame.pack(fill="x", padx=10, pady=(0,5))
        tk.Label(self.send_frame, text="Recipient:").grid(row=0, column=0, padx=(0,5), pady=5, sticky="w")
        self.recipient_var = tk.StringVar(self.send_frame)
        self.recipient_menu = tk.OptionMenu(self.send_frame, self.recipient_var, "")
        self.recipient_menu.grid(row=0, column=1, padx=(0,5), pady=5, sticky="w")
        tk.Label(self.send_frame, text="Message:").grid(row=1, column=0, padx=(0,5), pady=5, sticky="nw")
        self.message_entry = tk.Text(self.send_frame, height=3, width=50)
        self.message_entry.grid(row=1, column=1, padx=(0,5), pady=5, sticky="we")
        self.button_send = tk.Button(self.send_frame, text="Send", width=10, command=self.send_message)
        self.button_send.grid(row=1, column=2, padx=(0,5), pady=5)

        self.button_frame = tk.Frame(self)
        self.button_frame.pack(fill="x", padx=10, pady=5)
        self.button_delete = tk.Button(self.button_frame, text="Delete Message", width=12, command=self.delete_message)
        self.button_delete.pack(side="left", padx=5)
        self.button_back = tk.Button(self.button_frame, text="Back", width=12, command=self.back_to_landing)
        self.button_back.pack(side="left", padx=5)
        self.button_logout = tk.Button(self.button_frame, text="Logout", width=12, command=self.logout)
        self.button_logout.pack(side="left", padx=5)
        self.button_delete_account = tk.Button(self.button_frame, text="Delete Account", width=12, command=self.delete_account)
        self.button_delete_account.pack(side="left", padx=5)

    def update_recipient_menu(self):
        users_response = self.master.stub.ListUsers(chat_pb2.EmptyRequest())
        users = users_response.users
        users = [u for u in users if u != self.master.username]
        if not users:
            users = [""]
        menu = self.recipient_menu["menu"]
        menu.delete(0, "end")
        for user in users:
            menu.add_command(label=user, command=lambda value=user: self.recipient_var.set(value))
        if self.recipient_var.get() not in users:
            self.recipient_var.set(users[0])

    def refresh_messages(self):
        messages_response = self.master.stub.GetMessages(chat_pb2.UsernameRequest(username=self.master.username))
        messages = messages_response.messages  # Assume messages are strings "STATUS,content,sender"
        new_data = {}  # {sender (lowercase): list of (global_index, status, content)}
        if messages:
            for i, msg in enumerate(messages):
                parts = msg.split(',')
                if len(parts) >= 3:
                    status, content, sender = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    norm_sender = sender.lower()
                    new_data.setdefault(norm_sender, []).append((i, status, content))
        for norm_sender, conv in self.conversations.items():
            msg_list = new_data.get(norm_sender, [])
            listbox = conv["listbox"]
            yview = listbox.yview()
            listbox.delete(0, tk.END)
            conv["message_indices"].clear()
            unread_count = 0
            for msg_idx, status, content in msg_list:
                text_line = f"[{status.capitalize()}] {content}"
                listbox.insert(tk.END, text_line)
                conv["message_indices"][listbox.size() - 1] = msg_idx
                if status.upper() == "UNREAD":
                    unread_count += 1
            new_title = f"{conv['display']} ({unread_count})" if unread_count else conv['display']
            self.notebook.tab(conv["frame"], text=new_title)
            listbox.yview_moveto(yview[0])
        # Mark messages as read after fetching.
        self.master.stub.MarkMessagesRead(chat_pb2.UsernameRequest(username=self.master.username))
        self.update_recipient_menu()

    def poll_messages(self):
        if self.master.username:
            self.refresh_messages()
            self.after(5000, self.poll_messages)

    def send_message(self):
        recipient = self.recipient_var.get().strip()
        if not recipient:
            messagebox.showerror("Error", "Please select a recipient.")
            return
        message_text = self.message_entry.get("1.0", tk.END).strip()
        if not message_text:
            messagebox.showerror("Error", "Please enter a message.")
            return
        if not validate_length(message_text, LEN_MESSAGE, "Message"):
            messagebox.showerror("Error", "Invalid message length.")
            return
        self.master.stub.SendMessage(chat_pb2.MessageRequest(sender=self.master.username,
                                                               recipient=recipient,
                                                               message=message_text))
        self.message_entry.delete("1.0", tk.END)
        norm_recipient = recipient.lower()
        if norm_recipient not in self.conversations:
            self.open_chat(recipient)
        self.refresh_messages()

    def delete_message(self):
        current_tab = self.notebook.select()
        if not current_tab:
            messagebox.showerror("Error", "No conversation tab is selected.")
            return
        tab_text = self.notebook.tab(current_tab, "text")
        sender_lookup = tab_text.split(" (")[0]
        norm_sender = sender_lookup.lower()
        conv = self.conversations.get(norm_sender)
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
        self.master.stub.DeleteMessage(chat_pb2.DeleteMessageRequest(username=self.master.username,
                                                                       message_id=global_index))
        messagebox.showinfo("Deleted", "Message deleted!")
        self.refresh_messages()

    def open_chat(self, recipient):
        recipient = recipient.strip()
        norm_recipient = recipient.lower()
        if not recipient:
            messagebox.showerror("Error", "Please select a recipient.")
            return
        if norm_recipient not in self.conversations:
            frame = ttk.Frame(self.notebook)
            listbox = tk.Listbox(frame, activestyle="none", width=80)
            listbox.pack(fill="both", expand=True, padx=10, pady=10)
            self.conversations[norm_recipient] = {
                "frame": frame,
                "listbox": listbox,
                "message_indices": {},
                "display": recipient
            }
            self.notebook.add(frame, text=recipient)
        # Select the tab corresponding to the recipient.
        for tab in self.notebook.tabs():
            if self.notebook.tab(tab, "text").startswith(recipient):
                self.notebook.select(tab)
                break

    def back_to_landing(self):
        self.pack_forget()
        self.master.landing_frame.pack(fill="both", expand=True)

    def delete_account(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone."):
            self.master.stub.DeleteUser(chat_pb2.UsernameRequest(username=self.master.username))
            self.master.stub.LogoutUser(chat_pb2.UsernameRequest(username=self.master.username))
            messagebox.showinfo("Account Deleted", "Your account has been deleted.")
            self.master.stub = connect_to_server()
            self.master.username = None
            self.master.show_login_frame()

    def logout(self):
        self.master.stub.LogoutUser(chat_pb2.UsernameRequest(username=self.master.username))
        messagebox.showinfo("Logged Out", "You have been logged out.")
        self.master.stub = connect_to_server()
        self.master.username = None
        self.master.show_login_frame()

if __name__ == "__main__":
    app = ChatClientApp()
    app.mainloop()
