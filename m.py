# import socket
# print("Socket library imported successfully")
# import socket
# print("Socket library imported successfully")
# # import paramiko
# # print(paramiko.__version__)

# import socketserver
# import paramiko
# import telnetlib
# import ssl
# import asyncio
# import pyshark
# import logging

# print("All libraries imported successfully!")








# # class MyTCPHandler(socketserver.BaseRequestHandler):
# #     def handle(self):
# #         # self.request is the TCP socket connected to the client
# #         self.data = self.request.recv(1024).strip()
# #         print("Received from {}:".format(self.client_address[0]))
# #         print(self.data)
# #         # just send back the same data, but upper-cased
# #         self.request.sendall(self.data.upper())

# # if __name__ == "__main__":
# #     HOST, PORT = "localhost", 9999

# #     # Create the server, binding to localhost on port 9999
# #     with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
# #         # Activate the server; this will keep running until you
# #         # interrupt the program with Ctrl-C
# #         server.serve_forever()

# import socketserver
# import logging

# # Configure logging
# logging.basicConfig(
#     filename="honeypot.log",
#     level=logging.INFO,
#     format="%(asctime)s - %(levelname)s - %(message)s"
# )

# class HoneypotHandler(socketserver.BaseRequestHandler):
#     def handle(self):
#         try:
#             # Log the attacker's IP and connection info
#             logging.info(f"Connection from {self.client_address[0]}:{self.client_address[1]}")
#             print(f"Connection from {self.client_address[0]}:{self.client_address[1]}")

#             # Simulate an SSH welcome banner
#             banner = "SSH-2.0-OpenSSH_7.4\n"
#             self.request.sendall(banner.encode('utf-8'))
#             logging.info(f"Sent banner to {self.client_address[0]}")

#             # Interaction loop
#             while True:
#                 # Receive input from the client
#                 data = self.request.recv(1024).strip()
#                 if not data:
#                     break

#                 # Log the received data
#                 logging.info(f"Received from {self.client_address[0]}: {data.decode('utf-8')}")
#                 print(f"Received: {data.decode('utf-8')}")

#                 # Simulate command response
#                 response = f"Command '{data.decode('utf-8')}' not found\n"
#                 self.request.sendall(response.encode('utf-8'))

#         except Exception as e:
#             logging.error(f"Error handling request: {e}")
#             print(f"Error: {e}")

# if __name__ == "__main__":
#     HOST, PORT = "127.0.0.1", 2222  # Listen on all interfaces, port 2222

#     # Create and run the server
#     with socketserver.ThreadingTCPServer((HOST, PORT), HoneypotHandler) as server:
#         logging.info(f"Honeypot started on {HOST}:{PORT}")
#         print(f"Honeypot started on {HOST}:{PORT}")

#         try:
#             server.serve_forever()
#         except KeyboardInterrupt:
#             logging.info("Honeypot shutting down.")
#             print("Honeypot shutting down.")
#             server.shutdown()
# import paramiko
# hostname="127.0.0.1"
# port =2222
# user="fouzan"
# passwd="fouzan2004"
# try:
#     client=paramiko.SSHClient()
#     client.load_system_host_keys()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect(hostname,port=port,username=user,password=passwd)
#     while True:
#         try:
#             cmd= input("$> ")
#             if cmd =="exit":break
#             stdin,stdout,stderr= client.exec_command(cmd)
#         except KeyboardInterrupt:
#             break

# except Exception as err:
#     print(str(err))
# import paramiko

# hostname = "0.0.0.0"
# port = 8080
# user = "fouzan"
# passwd = "fouzan2004"

# try:
#     client = paramiko.SSHClient()
#     client.load_system_host_keys()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#     client.connect(hostname, port=port, username=user, password=passwd)
    
#     while True:
#         try:
#             cmd = input("$> ")
#             if cmd == "exit":
#                 break
#             stdin, stdout, stderr = client.exec_command(cmd)
#             print(stdout.read().decode())  # Print command output
#         except KeyboardInterrupt:
#             break

# except paramiko.ssh_exception.NoValidConnectionsError as e:
#     print(f"Connection error: {e}")
# except Exception as err:
#     print(f"Error: {err}")

# import socket as socket
# server_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# server_socket.bind(("127.0.0.1",2222))
# server_socket.listen(6)



# while True:
#     print("server waiting for connections")
#     client_socket,adrss=server_socket.accept()
#     print("client connetd",adrss)
#     while True:
#         data=client_socket.recv(1024)
#         if not data or data.decode('utf-8')=='END':
#             break
#         print("recieved data client")

#     try:
#         client_socket.send(bytes("hi client",'utf-8'))
#     except:
#         print("exited by user")

# client_socket.close()

# import socket
# import threading

# # server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # server_socket.bind(("127.0.0.1", 8080))
# # server_socket.listen(6)

# def sshserver():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(("127.0.0.1", 8080))
#     return server_socket
# def handle_client(client_socket,adrss):
#     while True:
#             # Receive data from client
#         data = client_socket.recv(1024)
#         if not data or data.decode('utf-8').lower() == 'end':
#             print("Ending connection with client")
#             break
#         print("Received data from client:", data.decode('utf-8'))
            
#         try:
#                 # Respond to client
#             client_socket.send(bytes("Hi client", 'utf-8'))
#             client_socket.send(b"usrnme: ")
#             client_socket.recv(1024)  # Simulate receiving the username
#             client_socket.send(b"Password: ")
#             client_socket.recv(1024)  # Simulate receiving the password

#         # Simulate a command prompt after successful login
#             client_socket.send(b"$ ")

#         except Exception as e:
#             print("Error sending response to client:", str(e))
#             break
        
#     client_socket.close()
# server_socket = sshserver()
# try:
#     while True:
#         print("Server waiting for connections...")
#         try:
#             server_socket.listen(6)
#             client_socket, adrss = server_socket.accept()
#             print("Client connected:" ,client_socket, adrss)
#             client_handler = threading.Thread(target=handle_client, args=(client_socket,adrss))
#             client_handler.start()
#         except Exception as e:
#             print("Error accepting connection:", e)
#             # print("bbbbbbbbbbbb")
#     print("Client connected:", adrss)
        
# # def handle_client(client_socket):
# #     while True:
# #             # Receive data from client
# #         data = client_socket.recv(1024)
# #         if not data or data.decode('utf-8').lower() == 'end':
# #             print("Ending connection with client")
# #             break
# #         print("Received data from client:", data.decode('utf-8'))
            
# #         try:
# #                 # Respond to client
# #             client_socket.send(bytes("Hi client", 'utf-8'))
# #         except Exception as e:
# #             print("Error sending response to client:", str(e))
# #             break
        
# #         client_socket.close()

# except KeyboardInterrupt:
#     print("\nServer shutting down...")


# server_socket.close()









# import socket
# import threading
# import paramiko
# from paramiko import RSAKey
# from binascii import hexlify

# # Load host key (generate using `ssh-keygen` or dynamically if needed)
# # host_key = RSAKey.generate(2048)  # You can save this key for reuse

# # Logging attempts
# def log_attempt(log_message):
#     with open("honeypot_log.txt", "w") as log_file:
#         log_file.write(log_message + "\n")

# # SSH Server Interface
# class SSHHoneypotServer(paramiko.ServerInterface):
#     def __init__(self):
#         self.event = threading.Event()

#     def check_channel_request(self, kind, chanid):
#         if kind == "session":
#             return paramiko.OPEN_SUCCEEDED
#         return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

#     def check_auth_password(self, username, password):
#         log_attempt(f"Password auth attempt - Username: {username}, Password: {password}")
#         if username == "admin" and password == "admin":
#             return paramiko.AUTH_SUCCESSFUL
#         return paramiko.AUTH_FAILED

#     def check_auth_publickey(self, username, key):
#         log_attempt(f"Public key auth attempt - Username: {username}, Key fingerprint: {hexlify(key.get_fingerprint()).decode()}")
#         # Simulate rejecting all keys for now
#         return paramiko.AUTH_FAILED

#     def get_allowed_auths(self, username):
#         return "password,publickey"

#     def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
#         return True

#     def check_channel_shell_request(self, channel):
#         self.event.set()
#         return True


  
# # Handle SSH connection

       
#         #     print("SSH negotiation failed:", e)
#         #     print("Client didn't open a channel.")
#         #     print("Client never requested a shell.")
#         # print("Exception:", e)
  

# def handle_client(client_socket):
#     try:
#         transport = paramiko.Transport(client_socket)
#         # print(transport)
#         host_key = paramiko.RSAKey.generate(2048)
#         transport.add_server_key(host_key)
#         # print("Waiting for client to open a channel...")
#         server = SSHHoneypotServer()
#         # print(server)

#         try:
#             transport.start_server(server=server)
#             # print("Waiting for client to open a channel...")
#         except paramiko.SSHException as e:
#             print("SSH negotiation failed:", e)
#             client_socket.close()
#             return

#         channel = transport.accept(20)  # Wait for a channel
#         # print(channel)
#         if channel is None:
#             print("Client didn't open a channel.")
#             client_socket.close()
#             return

#         server.event.wait(60)  # Wait fo    r shell request
#         # print("Waiting for client to open a channel...")
#         if not server.event.is_set():
#             print("Client never requested a shell.")
#             client_socket.close()
#             return

#         channel.send("Welcome to the fake SSH server!\n")
#         channel.send("Type 'exit' to disconnect.\n\n")
#         while True:
#             channel.send("$ ")
#             command = channel.recv(1024).decode('utf-8').strip()
#             if command.lower() == "exit":
#                 channel.send("Goodbye!\n")
#                 break
#             log_attempt(f"Command executed: {command}")
#             channel.send(f"Command '{command}' not found.\n")

#     except Exception as e:
#         print("Exception:", e)
#     finally:
#         try:
#             client_socket.close()
#         except Exception as e:
#             print("Failed to close socket:", e)

# # Main server loop
# def ssh_server():
#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     print(server_socket)
#     server_socket.bind(("127.0.0.1", 2200))  # Listen on port 2200 for SSH
#     server_socket.listen(5)
#     print("SSH honeypot running on port 2200...")

#     try:
#         while True:
#             client_socket, addr = server_socket.accept()
#             print(f"Connection from {addr,client_socket}")
#             threading.Thread(target=handle_client, args=(client_socket,)).start()
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
from binascii import hexlify

import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time


# Log attempts to a file
# def log_attempt(log_message):
#     with open("honeypot_log.txt", "a") as log_file:  # Append mode to retain all logs
#         log_file.write(log_message + "\n")
from paramiko import RSAKey
key = RSAKey.generate(2048)
key.write_private_key_file("server_key")

host_key = paramiko.RSAKey(filename='server_key')

# Logging Format.
# cmd_audits_log_local_file_path = "command_logs.txt"
# creds_audits_log_local_file_path = "credentials_logs.txt"

# logging_format = logging.Formatter('%(message)s')

# # Funnel (catch all) Logger.
# funnel_logger = logging.getLogger('FunnelLogger')
# funnel_logger.setLevel(logging.INFO)
# funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
# funnel_handler.setFormatter(logging_format)
# funnel_logger.addHandler(funnel_handler)

# # Credentials Logger. Captures IP Address, Username, Password.
# creds_logger = logging.getLogger('CredsLogger')
# creds_logger.setLevel(logging.INFO)
# creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
# creds_handler.setFormatter(logging_format)
# creds_logger.addHandler(creds_handler)
# def emulated_shell(channel, client_ip):
    # channel.send(b"corporate-jumpbox2$ ")
    # command = b""
    # while True:  
    #     char = channel.recv(1)
    #     channel.send(char)
    #     if not char:
    #         channel.close()

    #     command += char
    #     # Emulate common shell commands.
    #     if char == b"\r":
    #         if command.strip() == b'exit':
    #             response = b"\n Goodbye!\n"
    #             channel.close()
    #         elif command.strip() == b'pwd':
    #             response = b"\n" + b"\\usr\\local" + b"\r\n"
    #             funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
    #         elif command.strip() == b'whoami':
    #             response = b"\n" + b"corpuser1" + b"\r\n"
    #             funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
    #         elif command.strip() == b'ls':
    #             response = b"\n" + b"jumpbox1.conf" + b"\r\n"
    #             funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
    #         elif command.strip() == b'cat jumpbox1.conf':
    #             response = b"\n" + b"Go to deeboodah.com" + b"\r\n"
    #             funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
    #         else:
    #             response = b"\n" + bytes(command.strip()) + b"\r\n"
    #             funnel_logger.info(f'Command {command.strip()}' + "executed by " f'{client_ip}')
    #         channel.send(response)
    #         channel.send(b"corporate-jumpbox2$ ")
    #         command = b""
import logging
import time

# Configure logging
# funnel_logger = logging.getLogger("FunnelLogger")
# funnel_logger.setLevel(logging.INFO)

# Sample responses for common commands
# COMMAND_RESPONSES = {
#     b'pwd': b"\n\\usr\\local\\bin\r\n",
#     b'whoami': b"\ncorpuser1\r\n",
#     b'ls': b"\njumpbox1.conf  logs/  config/\r\n",
#     b'cat jumpbox1.conf': b"\nGo to deeboodah.com\r\n",
#     b'help': b"\nAvailable commands: pwd, whoami, ls, cat jumpbox1.conf\r\n",
# }

# Emulate shell behavior
# def emulated_shell(channel):
#     channel.send(b"corporate-jumpbox2$ ")
#     while True:
#         # Receive input from the client
#         command = channel.recv(1024).strip()  # Read and strip any extra spaces or newline
        
#         if not command:
#             channel.close()
#             break

#         # Respond based on the received command
#         if command == b"ls":
#             channel.send(b"usr\n") 
#         channel.send(b"corporate-jumpbox2$ ")  # Echo character back to user

        # if char == b"\r":  # End of command (Enter key)
        #     if command == b'exit\r':  # Check if the command is 'exit'
        #         response = b"\nGoodbye!\n"
        #         channel.send(response)
        #         channel.close()
        #         break
        #     else:
        #         response = b"\nCommand not found.\r\n"
        #         channel.send(response)
        #         channel.send(b"corporate-jumpbox2$ ")  # Prompt for the next command
        #         command = b""  # Reset command after execution


# Example function that starts listening and accepts SSH client connections
# def handle_ssh_client(client_socket, client_ip):
#     transport = Transport(client_socket)
#     try:
#         transport.start_server(server=HoneypotSSHServer())
#         channel = transport.accept()
#         if channel:
#             banner = "Welcome to the Honeypot SSH Server!\nType 'help' for available commands.\n"
#             channel.send(banner)
#             emulated_shell(channel, client_ip)  # Start the emulated shell for this connection
#     except Exception as e:
#         funnel_logger.error(f"Error handling SSH client {client_ip}: {e}")
#     finally:
#         try:
#             transport.close()
#         except Exception as e:
#             funnel_logger.error(f"Failed to close transport: {e}")
#         try:
#             client_socket.close()
#         except Exception as e:
#             funnel_logger.error(f"Failed to close client socket: {e}")



# SSH Server Interface
class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # log_attempt(f"Password auth attempt - Username: {username}, Password: {password}")
        # Accept "admin:admin" for simplicity, reject others
        if username == "admin" and password == "admin":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# Handle each client connection
# def handle_client(client_socket):
#     try:
#         transport = paramiko.Transport(client_socket)
#         host_key = paramiko.RSAKey.generate(2048)  # Generate temporary RSA host key
#         transport.add_server_key(host_key)

#         server = SSHHoneypotServer()
#         try:
#             transport.start_server(server=server)
#         except paramiko.SSHException as e:
#             print("SSH negotiation failed:", e)
#             return

#         channel = transport.accept(20)  # Timeout after 20 seconds
#         if channel is None:
#             print("Client didn't open a channel.")
#             return
#         server.event.wait(60)  # Timeout after 60 seconds
#         if not server.event.is_set():
#             print("Client never requested a shell.")
#             return

#         standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
#         try:
#             # Endless Banner: If tarpit option is passed, then send 'endless' ssh banner.
#             if tarpit:
#                 endless_banner = standard_banner * 100
#                 for char in endless_banner:
#                     channel.send(char)
#                     time.sleep(8)
#             # Standard Banner: Send generic welcome banner to impersonate server.
#             else:
#                 channel.send(standard_banner)
#                 print(error)
#     # Generic catch all exception error code.
#         except Exception as error:
#             print(error)
#             print("!!! Exception !!!")
    
#     # Once session has completed, close the transport connection.
#         finally:
#             try:
#                 transport.close()
#             except Exception:
#                 pass
        
           

#         channel.send("Welcome to the fake SSH server!\n")
#         channel.send("Type 'exit' to disconnect.\n\n")
#         while True:
#             channel.send("root@honeypot:~# ")
#             command = channel.recv(1024).decode('utf-8').strip()
#             if command.lower() == "exit":
#                 channel.send("Goodbye!\n")
#                 break
#             log_attempt(f"Command executed: {command}")
#             channel.send(f"Command '{command}' not found.\n")

#     except Exception as e:
#         print("Exception:", e)
#     finally:
#         try:
#             client_socket.close()
#         except Exception as e:
#             print("Failed to close socket:", e)
# def handle_client(client_socket):
#     try:
#         transport = paramiko.Transport(client_socket)
#         host_key = paramiko.RSAKey.generate(2048)
#         transport.add_server_key(host_key)

#         server = SSHHoneypotServer()

#         # Start SSH negotiation
#         try:
#             transport.start_server(server=server)
#         except paramiko.SSHException as e:
#             print("SSH negotiation failed:", e)
#             return

#         # Wait for the client to open a channel
#         try:
#             channel = transport.accept(20)  # Timeout after 20 seconds
#             if channel is None:
#                 print("Client didn't open a channel.")
#                 return
#         except Exception as e:
#             print("Channel opening failed:", e)
#             return

#         # Wait for a shell request
#         try:
#             server.event.wait(60)  # Timeout after 60 seconds
#             if not server.event.is_set():
#                 print("Client never requested a shell.")
#                 return
#         except Exception as e:
#             print("Shell request failed:", e)
#             return

#         # Interact with the client
#         try:
#             channel.send("Welcome to the fake SSH server!\n")
#             channel.send("Type 'exit' to disconnect.\n\n")
#             while True:
#                 channel.send("$ ")
#                 command = channel.recv(1024).decode('utf-8').strip()
#                 if command.lower() == "exit":
#                     channel.send("Goodbye!\n")
#                     break
#                 log_attempt(f"Command executed: {command}")
#                 channel.send(f"Command '{command}' not found.\n")
#         except Exception as e:
#             print("Error during client interaction:", e)

#     except Exception as e:
#         print("Exception:", e)
#     finally:
#         try:
#             client_socket.close()
#         except Exception as e:
#             print("Failed to close socket:", e)


        # t=server.check_channel_request()
        # print(t)
    # except:

    #     print()

    #     try:
    #         transport.start_server(server=server)
    #     except paramiko.SSHException as e:
    #         log_attempt(f"SSH negotiation failed: {e}")
    #         client_socket.close()
    #         return

    #     # Wait for the client to open a channel
    #     channel = transport.accept(20)
    #     if channel is None:
    #         log_attempt("Client didn't open a channel.")
    #         client_socket.close()
    #         return

    #     # Wait for shell request
    #     server.event.wait(60)
    #     if not server.event.is_set():
    #         log_attempt("Client never requested a shell.")
    #         client_socket.close()
    #         return

    #     # Simulate shell interaction
    #     channel.send("Welcome to the fake SSH server!\n")
    #     channel.send("Type 'exit' to disconnect.\n\n")
    #     while True:
    #         channel.send("$ ")
    #         command = channel.recv(1024).decode('utf-8').strip()
    #         if not command:  # Handle abrupt disconnects
    #             log_attempt("Client disconnected abruptly.")
    #             break
    #         if command.lower() == "exit":
    #             channel.send("Goodbye!\n")
    #             break
    #         log_attempt(f"Command executed: {command}")
    #         channel.send(f"Command '{command}' not found.\n")

    # except Exception as e:
    #     log_attempt(f"Exception: {e}")
    # finally:
    #     try:
    #         client_socket.close()
    #     except Exception as e:
    #         log_attempt(f"Failed to close socket: {e}")
def handle_client(client_socket,addr, tarpit=False):
    try:
        # Initialize Paramiko Transport and add server key
        client_ip, client_port = addr
        print(client_ip,client_port)
        transport = paramiko.Transport(client_socket)
        # print(client_socket[1])
        # host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)

        # Start the SSH honeypot server
        server = SSHHoneypotServer()
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"SSH negotiation failed: {e}")
            return

        # Accept a channel within the timeout period
        channel = transport.accept(20)  # Timeout in 20 seconds
        if channel is None:
            print("Client didn't open a channel.")
            return

        # Wait for the shell request
        server.event.wait(60)  # Timeout in 60 seconds
        if not server.event.is_set():
            print("Client never requested a shell.")
            return

        # Send a banner message
        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        if tarpit:
            endless_banner = standard_banner * 3
            for char in endless_banner:
                try:
                    channel.send(char)
                    time.sleep(3)  # Delay for the tarpit effect
                except Exception as e:
                    print(f"Error sending tarpit banner: {e}")
                    return
        else:
            try:
                channel.send(standard_banner)
            except Exception as e:
                print(f"Error sending banner: {e}")
                return

        # Interact with the client
        # channel.send("Welcome to the fake SSH server!\n")
        # channel.send("Type 'exit' to disconnect.\n\n")
        if channel:
            banner = "Welcome to the Honeypot SSH Server!\nType 'help' for available commands.\n"
            channel.send(banner)
            emulated_shell(channel)  # Start the emulated shell for this connection
    except Exception as e:
        # funnel_logger.error(f"Error handling SSH client {client_ip}: {e}")
        print(e)
    finally:
        try:
            transport.close()
        except Exception as e:
            print(e)
            # funnel_logger.error(f"Failed to close transport: {e}")
        try:
            client_socket.close()
        except Exception as e:
            print(e)
            # funnel_logger.error(f"Failed to close client socket: {e}")
        















































    #     while True:
    #         try:
    #             # channel.send("root@honeypot:~# ")
    #             emulated_shell(channel, client_ip=client_ip)
    #             command = channel.recv(1024).decode("utf-8").strip()
    #             if command.lower() == "exit":
    #                 channel.send("Goodbye!\n")
    #                 break
    #             # log_attempt(f"Command executed: {command}")
    #             channel.send(f"Command '{command}' not found.\n")
    #         except Exception as e:
    #             print(f"Error during command interaction: {e}")
    #             break

    # except Exception as e:
    #     print(f"Exception: {e}")
    # finally:
    #     # Close resources gracefully
    #     try:
    #         transport.close()
    #     except Exception as e:
    #         print(f"Failed to close transport: {e}")
    #     try:
    #         client_socket.close()
    #     except Exception as e:
    #         print(f"Failed to close socket: {e}")


# Main SSH honeypot server loop
def ssh_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 2200))  # Bind to port 2200
    server_socket.listen(5)
    print("SSH honeypot running on port 2200...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=handle_client, args=(client_socket,addr)).start()
    except KeyboardInterrupt:
        print("Shutting down SSH honeypot...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    ssh_server()
