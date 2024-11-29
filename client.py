# import socket as socket
# client3_socket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
# client3_socket.connect(("127.0.0.1",2222))
# payload="hey server"
# try:
#     while True:

#         client3_socket.send(payload.encode('utf-8'))
#         data=client3_socket.recv(1024)






#         print(str(data))
#         data6=input("want to end data")
#         if data6.lower()=='y':
#             payload=input("payload")
#         else:

#             break
        

# except KeyboardInterrupt:
#     print("exited by usr")

# client3_socket.close()
# import socket

# client3_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print(client3_socket)
# # print(
# client3_socket.connect(("127.0.0.1", 8080))
# payload = "hey server"

# try:
#     while True:
#         # Send payload to server
#         client3_socket.send(payload.encode('utf-8'))
#         # print(client3_socket.connect(("127.0.0.1", 2222)))
#         data = client3_socket.recv(1024)  # Receive response
#         print("Server:", data.decode('utf-8'))
        
#         # Ask user to continue or break the loop
#         # data6 = input("Want to send another payload? (y/n): ")
#         # if data6.lower() == 'y':
#         data=client3_socket.recv(1024)
#         if data:
        


        
#         input("Enter new payload: ")
#         else:
#             break

# except KeyboardInterrupt:
#     print("\nExited by user")




# client3_socket.close()








# import socket

# # Create a client socket
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print(client_socket)

# # Connect to the server
# server_address = ("127.0.0.1", 2200)
# try:
#     t=client_socket.connect(server_address)
#     print(t)
#     print(f"Connected to server at {server_address}")
# except Exception as e:
#     print(f"Failed to connect to server: {e}")
#     exit()

# try:
#     while True:
#         # Get payload from the user
#         payload = input("Enter message to send to the server (or type 'exit' to quit): ")
        
#         if payload.lower() == "exit":
#             print("Exiting...")
#             break
        
#         # Send payload to the server
#         client_socket.send(payload.encode('utf-8'))
        
#         # Receive and print response from the server
#         data = client_socket.recv(1024)  # Buffer size of 1024 bytes
#         if data:
#             print("Server:", data.decode('utf-8'))
#         else:
#             print("No response from server. Connection might be closed.")
#             break

# except KeyboardInterrupt:
#     print("\nExited by user.")

# finally:
#     client_socket.close()
#     print("Connection closed.")













# import paramiko

# client = paramiko.SSHClient()
# client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# try:
#     client.connect("127.0.0.1", port=2200, username="admin", password="password123")
#     stdin, stdout, stderr = client.exec_command("ls")
#     print(stdout.read().decode('utf-8'))
# except Exception as e:
#     print(f"Error: {e}")
# finally:
#     client.close()


import paramiko

# Client Configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 2200
USERNAME = "admin"
PASSWORD = "password123"

def main():
    # Initialize the SSH client
    client = paramiko.SSHClient()
    # Automatically add the server's host key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the server
        print(f"Connecting to server at {SERVER_IP}:{SERVER_PORT}...")
        client.connect(SERVER_IP, port=SERVER_PORT, username=USERNAME, password=PASSWORD)
        print("Connection established!")

        # Execute a command on the server
        command = "ls"
        print(f"Executing command: {command}")
        stdin, stdout, stderr = client.exec_command(command)

        # Read the command output
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        if output:
            print("Command output:")
            print(output)
        if error:
            print("Command error:")
            print(error)

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your username and password.")
    except paramiko.SSHException as e:
        print(f"SSH connection error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Close the connection
        client.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
