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

Spoofed_AppleWin_hostname  	= 'Ubuntu24.local'
Spoofed_AppleWin_port 		= 1986

Real_AppleWin_hostname 		= 'localhost'
Real_AppleWin_port			= 1985  

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
    
    print(f"Messages received at: {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port}\nwill be forwarded to: {Real_AppleWin_hostname}:{Real_AppleWin_port}\nand vice versa\n\n")
    
    
    print(f"Waiting for connections on {Real_AppleWin_hostname}:{Real_AppleWin_port} <Spoofed AppleWin>")
    # fujinet will try and connect to me
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spoofed_applewin:
        try:
            spoofed_applewin.bind((Spoofed_AppleWin_hostname, Spoofed_AppleWin_port))
            spoofed_applewin.listen()
            fujinet_connection, fujinet_address = spoofed_applewin.accept()
            print(f"Received connection from Fujinet {fujinet_address}")
        except Exception as error:
            print(error)
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as real_applewin:
            try:
                real_applewin.bind((Real_AppleWin_hostname, Real_AppleWin_port))
                real_applewin.listen()
                real_applewin_connection, real_applewin_address = real_applewin.accept()
                print(f"Received connection from Fujinet {fujinet_address}")
            except Exception as error:
                print(error)
        
            """
            # We will connect to the real 
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as real_applewin:
                try:
                    real_applewin.connect((Real_AppleWin_hostname, Real_AppleWin_port))
                    print(f"Connected to {Real_AppleWin_hostname}:{Real_AppleWin_port}")
                except Exception as e:
                    print(f"Failed to connected to {Real_AppleWin_hostname}:{Real_AppleWin_port}\n{e}")
                    exit(-1)
            """
            fujinet  = f"{fujinet_address[0]}:{fujinet_address[1]}"
            applewin = f"{real_applewin_address[0]}:{real_applewin_address[1]}"

            thread1 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin_connection, fujinet,  applewin))
            thread2 = threading.Thread(target = threaded_forward, args = (real_applewin_connection, fujinet_connection, applewin, fujinet))
                
                
            thread1.start()
            thread2.start()
            
            thread1.join()
            thread2.join()
                    
