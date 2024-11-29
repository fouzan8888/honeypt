# import socket
# import threading
# import logging
# from logging.handlers import RotatingFileHandler
# from pathlib import Path
# import time
# from paramiko import Transport, ServerInterface

# # Setup logging directory
# LOG_DIR = Path("logs")
# LOG_DIR.mkdir(exist_ok=True)

# # Logging setup
# creds_logger = logging.getLogger("CredentialsLogger")
# cmd_logger = logging.getLogger("CommandLogger")


# def setup_logger(logger, log_file):
#     handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=2)
#     formatter = logging.Formatter('%(asctime)s - %(message)s')
#     handler.setFormatter(formatter)
#     logger.addHandler(handler)
#     logger.setLevel(logging.INFO)


# setup_logger(creds_logger, LOG_DIR / "creds_audits.log")
# setup_logger(cmd_logger, LOG_DIR / "cmd_audits.log")

# # SSH server settings
# HOST = "127.0.0.1"
# PORT = 2200

# # Valid credentials
# VALID_USERNAME = "admin"
# VALID_PASSWORD = "password123"

# # Command responses
# COMMAND_RESPONSES = {
#     "pwd": "/home/user",
#     "ls": "file1.txt  file2.log  dir1/",
#     "cat file1.txt": "This is a dummy file content.",
#     "whoami": "root"
# }

# # Tarpit delay
# TARPIT_DELAY = 5


# class HoneypotSSHServer(ServerInterface):
#     def __init__(self):
#         self.authenticated = False

#     def check_auth_password(self, username, password):
#         creds_logger.info(f"Authentication attempt: {username}/{password}")
#         if username == VALID_USERNAME and password == VALID_PASSWORD:
#             self.authenticated = True
#             return True
#         return False

#     def get_allowed_auths(self, username):
#         return "password"

#     def check_channel_request(self, kind, chanid):
#         if kind == "session":
#             return True
#         return False

#     def check_channel_exec_request(self, channel, command):
#         cmd_logger.info(f"Command executed: {command}")
#         response = COMMAND_RESPONSES.get(command, f"Command '{command}' not found.")
#         channel.send(response + "\n")
#         return True


# # Handle individual SSH sessions
# def handle_ssh_client(client_socket, address):
#     transport = Transport(client_socket)
#     try:
#         transport.start_server(server=HoneypotSSHServer())
#         channel = transport.accept()
#         if channel:
#             banner = "Welcome to the Honeypot SSH Server!\nType commands below:\n"
#             channel.send(banner)
#             while True:
#                 channel.send("honeypot$ ")
#                 command = channel.recv(1024).decode("utf-8").strip()
#                 if command == "exit":
#                     break
#                 response = COMMAND_RESPONSES.get(command, f"Command '{command}' not found.")
#                 cmd_logger.info(f"Command executed: {command}")
#                 channel.send(response + "\n")
#     except Exception as e:
#         logging.error(f"Error handling SSH client: {e}")
#     finally:
#         transport.close()


# # Tarpit for delaying attacker connections
# def tarpit_connection(client_socket):
#     try:
#         client_socket.send(b"\nWelcome to Honeypot SSH!\n")
#         while True:
#             time.sleep(TARPIT_DELAY)
#             client_socket.send(b"\nStill loading...\n")
#     except Exception as e:
#         logging.error(f"Tarpit connection closed: {e}")
#     finally:
#         client_socket.close()


# # Main server function
# def start_honeypot():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     server_socket.bind((HOST, PORT))
#     server_socket.listen(5)
#     print(f"Honeypot server running on {HOST}:{PORT}")

#     while True:
#         client_socket, client_address = server_socket.accept()
#         print(f"Connection from {client_address}")
#         # Choose SSH or tarpit randomly (or based on a condition)
#         threading.Thread(target=handle_ssh_client, args=(client_socket, client_address)).start()


# if __name__ == "__main__":
#     try:
#         start_honeypot()
#     except KeyboardInterrupt:
#         print("\nHoneypot server shutting down.")





# import socket
# import threading
# import paramiko
# from paramiko import RSAKey
# from binascii import hexlify

# import logging
# from logging.handlers import RotatingFileHandler
# import paramiko
# import threading
# import socket
# import time
# LOG_FILE = "honeypot_log.txt"
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(message)s",
#     handlers=[
#         logging.FileHandler(LOG_FILE),
#         logging.StreamHandler()
#     ]
# )
# def log_attempt(ip, port, username=None, password=None):
#     message = f"Connection from IP: {ip}, Port: {port}"
#     if username and password:
#         message += f", Username: {username}, Password: {password}"
#     logging.info(message)


# # Log attempts to a file
# # def log_attempt(log_message):
# #     with open("honeypot_log.txt", "a") as log_file:  # Append mode to retain all logs
# #         log_file.write(log_message + "\n")
# from paramiko import RSAKey
# key = RSAKey.generate(2048)
# key.write_private_key_file("server_key")

# host_key = paramiko.RSAKey(filename='server_key')
# # Logging Format.
# # cmd_audits_log_local_file_path = "command_logs.txt"
# # creds_audits_log_local_file_path = "credentials_logs.txt"

# # logging_format = logging.Formatter('%(message)s')

# # # Funnel (catch all) Logger.
# # funnel_logger = logging.getLogger('FunnelLogger')
# # funnel_logger.setLevel(logging.INFO)
# # funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
# # funnel_handler.setFormatter(logging_format)
# # funnel_logger.addHandler(funnel_handler)

# # # Credentials Logger. Captures IP Address, Username, Password.
# # creds_logger = logging.getLogger('CredsLogger')
# # creds_logger.setLevel(logging.INFO)
# # creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
# # creds_handler.setFormatter(logging_format)
# # creds_logger.addHandler(creds_handler)
# def emulated_shell(channel):
#     """
#     Simulates a basic shell environment to interact with the client.
#     """

#     # Send the initial prompt to the client
#     channel.send(b"corporate-jumpbox2$ ")

#     while True:
#         # Receive input from the client (max 1024 bytes)
#         # Use `.strip()` to clean up any extra spaces or newline characters
#         command = channel.recv(1024).strip()

#         # If no command is received (e.g., client disconnects), close the channel
#         if not command:
#             channel.close()
#             break

#         # Simulate response to the `ls` command
#         if command == b"ls":
#             channel.send(b"usr\netc\nhome\nvar\n")

#         # Simulate response to the `pwd` command
#         elif command == b"pwd":
#             channel.send(b"/home/admin\n")

#         # Simulate response to the `whoami` command
#         elif command == b"whoami":
#             channel.send(b"admin\n")

#         # Simulate response to the `cat` command for a specific file
#         elif command.startswith(b"cat "):
#             filename = command.split(b" ", 1)[1]  # Extract the filename
#             if filename == b"readme.txt":
#                 channel.send(b"This is a simulated readme file.\n")
#             else:
#                 channel.send(b"cat: " + filename + b": No such file or directory\n")

#         # Simulate response to the `exit` command
#         elif command == b"exit":
#             channel.send(b"Goodbye!\n")
#             channel.close()
#             break

#         # Handle unknown commands with a generic response
#         else:
#             channel.send(b"bash: " + command + b": command not found\n")

#         # Send the shell prompt again after processing the command
#         channel.send(b"corporate-jumpbox2$ ")
# class SSHHoneypotServer(paramiko.ServerInterface):
#     def __init__(self):
#         self.event = threading.Event()

#     def check_channel_request(self, kind, chanid):
#         if kind == "session":
#             return paramiko.OPEN_SUCCEEDED
#         return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#     def check_auth_password(self, username, password):
#         # log_attempt(f"Password auth attempt - Username: {username}, Password: {password}")
#         # Accept "admin:admin" for simplicity, reject others
#         if username == "admin" and password == "admin":
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_channel_shell_request(self, channel):
#         self.event.set()
#         return True
# def handle_client(client_socket,addr, tarpit=False):
#     try:
#         # Initialize Paramiko Transport and add server key
#         client_ip, client_port = addr
#         print(client_ip,client_port)
#         log_attempt(client_ip, client_port)
#         transport = paramiko.Transport(client_socket)
#         # print(client_socket[1])
#         # host_key = paramiko.RSAKey.generate(2048)
#         transport.add_server_key(host_key)

#         # Start the SSH honeypot server
#         server = SSHHoneypotServer()
#         try:
#             transport.start_server(server=server)
#         except paramiko.SSHException as e:
#             print(f"SSH negotiation failed: {e}")
#             return

#         # Accept a channel within the timeout period
#         channel = transport.accept(20)  # Timeout in 20 seconds
#         if channel is None:
#             print("Client didn't open a channel.")
#             return

#         # Wait for the shell request
#         server.event.wait(60)  # Timeout in 60 seconds
#         if not server.event.is_set():
#             print("Client never requested a shell.")
#             return

#         # Send a banner message
#         standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
#         if tarpit:
#             endless_banner = standard_banner * 3
#             for char in endless_banner:
#                 try:
#                     channel.send(char)
#                     time.sleep(3)  # Delay for the tarpit effect
#                 except Exception as e:
#                     print(f"Error sending tarpit banner: {e}")
#                     return
#         else:
#             try:
#                 channel.send(standard_banner)
#             except Exception as e:
#                 print(f"Error sending banner: {e}")
#                 return

#         # Interact with the client
#         # channel.send("Welcome to the fake SSH server!\n")
#         # channel.send("Type 'exit' to disconnect.\n\n")
#         if channel:
#             banner = "Welcome to the Honeypot SSH Server!\nType 'help' for available commands.\n"
#             channel.send(banner)
#             emulated_shell(channel)  # Start the emulated shell for this connection
#     except Exception as e:
#         # funnel_logger.error(f"Error handling SSH client {client_ip}: {e}")
#         print(e)
#     finally:
#         try:
#             transport.close()
#         except Exception as e:
#             print(e)
#             # funnel_logger.error(f"Failed to close transport: {e}")
#         try:
#             client_socket.close()
#         except Exception as e:
#             print(e)
# def ssh_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(("127.0.0.1", 2200))  # Bind to port 2200
#     server_socket.listen(5)
#     print("SSH honeypot running on port 2200...")

#     try:
#         while True:
#             client_socket, addr = server_socket.accept()
#             print(f"Connection from {addr}")
#             logging.info(f"Connection established with {addr}")
#             threading.Thread(target=handle_client, args=(client_socket,addr)).start()
#     except KeyboardInterrupt:
#         print("Shutting down SSH honeypot...")
#     finally:
#         server_socket.close()

# if __name__ == "__main__":
#     ssh_server()




import socket
import threading
import paramiko
from paramiko import RSAKey
import logging
import time

# Generate and load server key
key = RSAKey.generate(2048)
key.write_private_key_file("server_key")
host_key = paramiko.RSAKey(filename='server_key')

# Set up the logging system
LOG_FILE = "honeypot_log.txt"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Function to log attack attempts
def log_attempt(ip, port, username=None, password=None):
    message = f"Connection from IP: {ip}, Port: {port}"
    if username and password:
        message += f", Username: {username}, Password: {password}"
    logging.info(message)

# Emulated shell function
def emulated_shell(channel):
    channel.send(b"corporate-jumpbox2$ ")
    while True:
        command = channel.recv(1024).strip()
        if not command:
            channel.close()
            break
        if command == b"ls":
            channel.send(b"usr\netc\nhome\nvar\n")
        elif command == b"pwd":
            channel.send(b"/home/admin\n")
        elif command == b"whoami":
            channel.send(b"admin\n")
        elif command.startswith(b"cat "):
            filename = command.split(b" ", 1)[1]
            if filename == b"readme.txt":
                channel.send(b"This is a simulated readme file.\n")
            else:
                channel.send(b"cat: " + filename + b": No such file or directory\n")
        elif command == b"exit":
            channel.send(b"Goodbye!\n")
            channel.close()
            break
        else:
            channel.send(b"bash: " + command + b": command not found\n")
        channel.send(b"corporate-jumpbox2$ ")

# SSH honeypot server class
class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_attempt(self.client_ip, self.client_port, username, password)
        return paramiko.AUTH_SUCCESSFUL if username == "admin" and password == "admin" else paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# Function to handle client connections
def handle_client(client_socket, addr):
    client_ip, client_port = addr
    log_attempt(client_ip, client_port)
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        server = SSHHoneypotServer(client_ip, client_port)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logging.error(f"SSH negotiation failed with {client_ip}:{client_port} - {e}")
            return

        channel = transport.accept(20)
        if channel is None:
            logging.warning(f"Client {client_ip}:{client_port} didn't open a channel.")
            return

        server.event.wait(60)
        if not server.event.is_set():
            logging.warning(f"Client {client_ip}:{client_port} never requested a shell.")
            return

        channel.send(b"Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n")
        emulated_shell(channel)
    except Exception as e:
        logging.error(f"Error handling client {client_ip}:{client_port} - {e}")
    finally:
        try:
            client_socket.close()
        except Exception as e:
            logging.error(f"Failed to close client socket {client_ip}:{client_port} - {e}")

# Function to start the SSH honeypot server
def ssh_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 2200))
    server_socket.listen(5)
    logging.info("SSH honeypot running on port 2200...")
    try:
        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Connection established with {addr}")
            threading.Thread(target=handle_client, args=(client_socket, addr)).start()
    except KeyboardInterrupt:
        logging.info("Shutting down SSH honeypot...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    ssh_server()
