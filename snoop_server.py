import socket
import time
import binascii
import os
import sys
import threading

# Local imports
my_modules_path = os.getcwd()+"/includes"
if sys.path[0] != my_modules_path:
    sys.path.insert(0, my_modules_path)

from slip import *

forward_to_hostname = 'fujinet-vm.local'
port_forward_to 	= 1985

message_in_hostname = socket.gethostname()
message_in_port 	= 1985  

global communicating

def client_receive_thread():
    pass

def threaded_forward(in_connection, out_connection, in_msg, out_msg):

    while True:
        # get message from client
        try:
            slip_message = in_connection.recv(packet_size)
            if slip_message != b'':
                print(f"from {str(in_msg).rjust(23)}: {binascii.hexlify(slip_message, ' ')} -> {str(out_msg)}")
                out_connection.sendall(slip_message)
            else:
                break
        except socket.error as error:
            print(error)
            break


if __name__ == "__main__":
    
    global communicating
    
    communicating = True
    
    print("Python Protocol Snooper\n")
    
    print(f"Messages received at: {message_in_hostname}:{message_in_port}\nwill be forwarded to: {forward_to_hostname}:{port_forward_to}\nand vice versa\n\n")
    
    
    # Connect to the original server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_to:
        try:
            forward_to.connect((forward_to_hostname, port_forward_to))
            print(f"Connected to {forward_to_hostname}:{port_forward_to}")
        except Exception as e:
            print(f"Failed to connected to {forward_to_hostname}:{port_forward_to}\n{e}")
            exit(-1)


        print(f"Waiting for connections on {message_in_hostname}:{message_in_port}")
        # Connections in
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as message_in:
            try:
                message_in.bind((message_in_hostname, message_in_port))
                message_in.listen()
                in_connection, ip_address = message_in.accept()
                print(f"Received connection from {ip_address}")
            except Exception as error:
                print(error)

            thread1 = threading.Thread(target = threaded_forward, args = (in_connection, forward_to, ip_address,  'to server'))
            thread2 = threading.Thread(target = threaded_forward, args = (forward_to, in_connection, 'server', ip_address))
            
            
            thread1.start()
            thread2.start()
            
            thread1.join()
            thread2.join()
                