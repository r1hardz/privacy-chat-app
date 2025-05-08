import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import tkinter as tk
from tkinter import scrolledtext, ttk

# network and encryption setup
HOST = '13.48.43.68'
PORT = 12345
DEBUG = False

# make and connect the client socket to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# RSA private and public keys for encryption
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

def send_public_key():
    # convert the public key to bytes for sending
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Send the public key to the server
    print(f"Sending public key: {public_key_bytes.decode()}")
    client_socket.send(public_key_bytes)

# send the public key to the server using the function
send_public_key()

other_public_keys = {}
current_room = None
current_username = None

def receive_message():
    global current_room, current_username, private_key, join_error
    joined_room = False
    try:
        while True:
            try:
                # receive data from the server
                data = client_socket.recv(1024)
                if not data:
                    print("[ERROR] No data received from server")
                    break

                # room joining process
                if not joined_room:
                    message = data.decode()
                    if message.startswith("Invalid password"):
                        print(f"[ERROR] {message}")
                        root.after(0, show_error, message)
                        join_error = True  
                        return  
                    else:
                        # succesfully joined the room
                        room_info = message.split('|')
                        if len(room_info) == 3:
                            current_room, current_username, message = room_info
                            joined_room = True
                            print(f"[INFO] Received room information: {message}")
                            update_window_title(current_room)
                        else:
                            print(f"[ERROR] Received invalid room information: {message}")
                            join_error = True  
                            break

                # try to load the senders public key
                try:
                    sender_public_key = serialization.load_pem_public_key(data)
                    sender_public_key_key = f"{current_room}|{sender_public_key.public_numbers().e}|{sender_public_key.public_numbers().n}"
                    other_public_keys[sender_public_key_key] = sender_public_key
                    if DEBUG:
                        print(f"[INFO] Received public key from {sender_public_key_key}")
                    else:
                        print(f"[INFO] Received public key from {current_room}")
                except ValueError:
                    try:
                        # try to decrypt the received message
                        encrypted_message = data
                        plaintext = private_key.decrypt(
                            encrypted_message,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                          # displaying the decrypted message
                        sender_name, message = plaintext.decode('utf-8').split('|', 1)
                        display_received_message(sender_name, message)
                    except (UnicodeDecodeError, ValueError):
                        if DEBUG:
                            print(f"[ERROR] Received invalid data from {client_socket}")
                        pass
            except OSError:
                print("[ERROR] Socket closed, terminating receive thread")
                break
    except ConnectionAbortedError as e:
        print("[ERROR] Connection aborted by the software in your host machine:")

def send_message(message, recipient=None, sender_name=None):
    if recipient is None or recipient == client_socket:
        recipient = client_socket
        if current_room is not None:
            # encode the message with the sender's name
            encoded_message = (sender_name + "|" + message).encode('utf-8')
            # encrypt and send the message to all known public keys
            for public_key in other_public_keys.values():
                encrypted_message = public_key.encrypt(
                    encoded_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                if DEBUG:
                    print(f"[INFO] Sending encrypted message: {encrypted_message}")
                else:
                    print(f"[INFO] Sending encrypted message")
                client_socket.send(encrypted_message)
        else:
            print('[INFO] Room information not received yet.')
    else:
        # generate the key to find the recipients public key
        recipient_public_key_key = f"{current_room}|{recipient.public_key().public_numbers().e}|{recipient.public_key().public_numbers().n}"
        recipient_public_key = other_public_keys.get(recipient_public_key_key)
        if recipient_public_key:
            if DEBUG:
                print(f"[INFO] Encrypting message with public key: {recipient_public_key}")
            else:
                print(f"[INFO] Encrypting message with public key")
            # encode the message with the senders name
            encoded_message = (sender_name + "|" + message).encode('utf-8')
            # encrypt and send the message to the specific recipient
            encrypted_message = recipient_public_key.encrypt(
                encoded_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if DEBUG:
                print(f"[INFO] Sending encrypted message: {encrypted_message}")
            else:
                print(f"[INFO] Sending encrypted message")
            client_socket.send(encrypted_message)
        else:
            print('[INFO] Public key not found.')

# display received messages in the text area
def display_received_message(sender_name, message):
    text_area.configure(state=tk.NORMAL)  
    text_area.insert(tk.END, f'{sender_name}: ', 'name')
    text_area.insert(tk.END, message + '\n', 'message')
    text_area.see(tk.END)  
    text_area.configure(state=tk.DISABLED)
# start the thread to receive messages
receive_thread = threading.Thread(target=receive_message)
receive_thread.start()

# handle sending messages from the GUI
def send_message_gui(event=None):
    message = message_entry.get()
    if message:
        message_entry.delete(0, tk.END)

        text_area.configure(state=tk.NORMAL)  
        text_area.insert(tk.END, f'{current_username}: ', 'user_message')
        text_area.insert(tk.END, message + '\n', 'user_message')
        text_area.see(tk.END)  
        text_area.configure(state=tk.DISABLED)  
        send_message(message, client_socket, sender_name=current_username)
        

def leave_chat():
    def do_leave():
        global client_socket, current_room, current_username, other_public_keys
        try:
            # encode and send the leave message to the server
            leave_message = f"LEAVE|{current_room}|{current_username}".encode()
            client_socket.send(leave_message)
            print(f"Sent leave message: {leave_message}")

            # timeout and wait for confirmation from the server
            client_socket.settimeout(5)
            try:
                data = client_socket.recv(1024)
                if data:
                    print(f"Received data: {data.decode()}")
                    if data.decode().startswith(f"LEAVE|{current_room}|confirmation"):
                        print(f"Received confirmation from server after leaving: {data.decode()}")
            except socket.timeout:
                # handle timeout waiting for server confirmation
                print("Timeout waiting for server confirmation")
                root.after(0, show_error, "Server confirmation timeout")
                return
        except Exception as e:
            # handle errors during the leave operation
            print(f"Error during leave operation: {e}")
            root.after(0, show_error, "Failed to leave the room properly.")
        finally:
            try:
                # shutdown and close the client socket
                client_socket.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print(f"Error shutting down socket: {e}")
            client_socket.close()
            client_socket = None
            other_public_keys.clear()  # clear the public keys

            # reset the GUI and setup a new connection
            root.after(0, reset_join_gui)
            root.after(0, setup_new_connection)
    
    # leave operation in a new thread
    threading.Thread(target=do_leave).start()


# reset the join GUI elements
def reset_join_gui():
    join_frame.grid()
    room_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    error_label.config(text="")
    join_button.config(state=tk.NORMAL)
    try:
        chat_frame.grid_remove()
    except NameError:
        pass
    global current_room, current_username
    current_room = None
    current_username = None

def setup_new_connection():
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        send_public_key()
    except Exception as e:
        print(f"Unable to reconnect: {e}")
        root.after(0, show_error, "Connection error. Please try reconnecting.")

def show_error(message):
    error_label.config(text=message, foreground='red')

def join_room():
    global client_socket, current_room, current_username, join_error, receive_thread
    room_id = room_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    try:
        room_id = int(room_id)
    except ValueError:
        error_label.config(text="Room ID must be a number",  foreground='#DC143C')
        return
    
    # validate username
    if not username:
        error_label.config(text="Username cannot be empty",  foreground='#DC143C')
        return
        
    elif len(username) > 40:
        error_label.config(text="Username cannot exceed 40 characters",  foreground='#DC143C')
        return
    
    # validate password
    if not password:
        error_label.config(text="Password cannot be empty",  foreground='#DC143C')
        return

    error_label.config(text="")
    join_error = False  
    join_button.config(state=tk.DISABLED)

    # close the existing socket connection if any
    if client_socket:
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
        except Exception as e:
            print(f"Error shutting down socket: {e}")

    if receive_thread and receive_thread.is_alive():
        receive_thread.join(timeout=1)  

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
    except Exception as e:
        error_label.config(text=f"Error connecting to server: {e}", foreground='red')
        join_button.config(state=tk.NORMAL)
        return
    send_public_key()

    # send room information
    room_info = f'{room_id}|{username}|{password}'.encode()
    print(f"Sending room information: {room_info.decode()}")
    client_socket.send(room_info)

    # clear the input fields
    room_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

    try:
        text_area.configure(state=tk.NORMAL)
        text_area.delete('1.0', tk.END)
        text_area.configure(state=tk.DISABLED)
    except NameError:
        pass

    receive_thread = threading.Thread(target=receive_message)
    receive_thread.daemon = True  
    receive_thread.start()

    root.after(1, check_join_status)

# check the join status and update the GUI 
def check_join_status():
    global join_error, receive_thread, client_socket, current_room, current_username
    if join_error:
        error_label.config(text="Failed to join. Please check your credentials.", foreground='#DC143C')
        join_button.config(state=tk.NORMAL)
        try:
            client_socket.close()
        except:
            pass
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if receive_thread and receive_thread.is_alive():
            receive_thread.join(timeout=0.1)  
        current_room = None
        current_username = None
        update_window_title(None)
    else:
        if current_room is None:
            root.after(1, check_join_status)
        else:
            open_chat_window()

#<---------------GUI section--------------->
def update_window_title(room_id):
    if room_id:
        root.title(f"Chat App - Room {room_id}")
    else:
        root.title("Chat App")

def open_chat_window():
    global chat_frame, message_entry, send_button, text_area, leave_button
    join_frame.grid_remove()
    try:
        chat_frame
    except NameError:
        
        # chat frame setup
        chat_frame = ttk.Frame(root, padding=(0, 0, 0, 0), style='Custom.TFrame')
        chat_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        
        # text area for displaying messages
        text_area = tk.Text(chat_frame, wrap=tk.WORD, width=50, height=20, background='#2c2c2c', foreground='#cccccc')
        text_area.grid(row=0, column=0, columnspan=2, padx=(10, 10), pady=10, sticky=(tk.N, tk.S, tk.E, tk.W))  # Adjust padx to move it to the right
        text_area.configure(state=tk.DISABLED) 

        # vertical scrollbar for the text area, not visable
        vertical_scrollbar = ttk.Scrollbar(chat_frame, orient='vertical', command=text_area.yview, style='Transparent.Vertical.TScrollbar')
        vertical_scrollbar.grid(row=0, column=1, sticky='ns')
        text_area.configure(yscrollcommand=vertical_scrollbar.set)
        vertical_scrollbar.grid_remove()\
        
        # message entry field
        message_entry = ttk.Entry(chat_frame, width=50, style='Custom.TEntry')
        message_entry.grid(row=1, column=0, sticky=(tk.EW), padx=(10, 0))
        message_entry.bind('<Return>', send_message_gui)

        # send message button
        send_button = ttk.Button(chat_frame, text="Send", command=send_message_gui, style='Custom.TButton')
        send_button.configure(width=10)
        send_button.grid(row=1, column=1, sticky=tk.E, padx=(0, 10))

        # leave chat button
        leave_button = ttk.Button(chat_frame, text="Leave Chat", command=leave_chat, style='Custom.TButton')
        leave_button.configure(width=15)
        leave_button.grid(row=2, column=0, sticky=tk.W, padx=10, pady=(10, 0))
        
        root.columnconfigure(0, weight=1)
        chat_frame.columnconfigure(0, weight=3)  
        chat_frame.columnconfigure(1, weight=0)  
        chat_frame.rowconfigure(0, weight=1)
    else:
        chat_frame.grid()

#<---------------Styling--------------->
root = tk.Tk()
root.title("Chat App")
root.configure(bg='#1c1c1c')
root.geometry("700x410")

style = ttk.Style()
style.configure('Custom.TButton', padding=(3, 1), relief='flat',
                foreground='#1f1e1e', background='#4d4d4d', borderwidth=0,
                font=('Helvetica', 10, 'bold'))

style.map('Custom.TButton',
          background=[('active', '#666666'), ('pressed', '#333333'), ('hover', '#222222')],
          relief=[('pressed', 'groove'), ('!pressed', 'ridge')])

style.configure('Custom.TEntry', fieldbackground='#f0f0f0', foreground='#000000',
                borderwidth=1, font=('Helvetica', 10))

style.map('Custom.TEntry',
          fieldbackground=[('focus', '#ffffff')],
          bordercolor=[('focus', '#4d4d4d')])

style.configure('Custom.TLabel', background='#1c1c1c', foreground='#ffffff',
                font=('Arial', 10, 'normal'))

style.configure('Custom.TFrame', background='#1c1c1c', relief='flat', borderwidth=0)

# join frame setup
join_frame = ttk.Frame(root, padding=(20, 20, 20, 20), style='Custom.TFrame')
join_frame.grid(row=0, column=0, sticky='nsew')
root.columnconfigure(0, weight=1)
join_frame.columnconfigure([0, 1], weight=1)
join_frame.rowconfigure([0, 6], weight=1)

# room ID label and entry
room_label = ttk.Label(join_frame, text="Room ID:", style='Custom.TLabel')
room_label.grid(row=1, column=0, padx=10, pady=(100, 0), sticky=tk.E)
room_entry = ttk.Entry(join_frame, style='Custom.TEntry', width=30)
room_entry.grid(row=1, column=1, padx=10, pady=(100, 0), sticky=tk.W)

# username label and entry
username_label = ttk.Label(join_frame, text="Username:", style='Custom.TLabel')
username_label.grid(row=2, column=0, padx=10, pady=10, sticky=tk.E)
username_entry = ttk.Entry(join_frame, style='Custom.TEntry', width=30)
username_entry.grid(row=2, column=1, padx=10, pady=10, sticky=tk.W)

# password label and entry
password_label = ttk.Label(join_frame, text="Password:", style='Custom.TLabel')
password_label.grid(row=3, column=0, padx=10, pady=10, sticky=tk.E)
password_entry = ttk.Entry(join_frame, show="*", style='Custom.TEntry', width=30)
password_entry.grid(row=3, column=1, padx=10, pady=10, sticky=tk.W)

# error label
error_label = ttk.Label(join_frame, text="", style='Custom.TLabel', foreground='dark red')
error_label.grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=(20, 10), pady=5)

# join room button
join_button = ttk.Button(join_frame, text="Join Room", command=join_room, style='Custom.TButton')
join_button.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky=tk.EW)

root.mainloop()
client_socket.close()
receive_thread.join()