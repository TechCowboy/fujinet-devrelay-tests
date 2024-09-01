import socket
import time
import binascii
import os
import sys
import threading


hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

packet_size = 512

if local_ip[0:3] == "127":
    hostname = socket.gethostname() + ".local"
    local_ip = socket.gethostbyname(hostname) 

Spoofed_AppleWin_hostname  	= hostname
Spoofed_AppleWin_port 		= 1986

Real_AppleWin_hostname 		= 'localhost'
Real_AppleWin_port			= 1985  

global communicating


def threaded_forward(in_connection, out_connection, in_msg, out_msg):

    print(f"Started forward {in_msg} -> {out_msg}")
    while True:
        # get message from client
        try:
            slip_message = in_connection.recv(packet_size)
            print(slip_message)
            if slip_message != b'':
                print(f"from {str(in_msg).rjust(23)}: {binascii.hexlify(slip_message, ' ')}", end='')
                if out_connection != None:
                    out_connection.sendall(slip_message)
                else:
                    print(f" -> {str(out_msg)}")      
        except socket.error as error:
            print(error)
            break


if __name__ == "__main__":
    
    global communicating
    
    communicating = True
    
    print("Python Protocol Snooper\n")
    
    print(f"Messages received at: {Real_AppleWin_hostname}:{Real_AppleWin_port}")
    print(f"will be forwarded to: {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port}\nand vice versa\n")
    print(f"hostname: {hostname}   IP: {local_ip}\n\n")
    
    fujinet  = f"{Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port}"
    applewin = f"{Real_AppleWin_hostname}:{Real_AppleWin_port}"
            
    print(f"Waiting for connections on {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port} <Spoofed AppleWin>")
    # fujinet will try and connect to me
    spoofed_applewin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        spoofed_applewin.bind((Spoofed_AppleWin_hostname, Spoofed_AppleWin_port))
        spoofed_applewin.listen()
        fujinet_connection, fujinet_address = spoofed_applewin.accept()
        print(f"\n*** Received connection from Fujinet {fujinet_address} ***\n\n")
    except Exception as error:
        print(error)
        exit(-1)
        
    real_applewin_connection = None
    thread1 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin_connection, fujinet,  "LOST"))
    thread1.start()

    print(f"Attempting to connect to REAL AppleWin {Real_AppleWin_hostname}:{Real_AppleWin_port}")
    # We will connect to the real AppleWin
    

           
    while True:
        real_applewin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        old_timeout = real_applewin.gettimeout()
        real_applewin.settimeout(3)
        
        try:
            real_applewin_connection.connect((Real_AppleWin_hostname, Real_AppleWin_port))
            real_applewin.settimeout(old_timeout)
            print(f"\nConnected to {Real_AppleWin_hostname}:{Real_AppleWin_port}\n\n")
        except Exception as e:
            print(".", end='')
            time.sleep(1)
            continue
        
            print("\n\n**** Snooping has begun! ****\n\n")
            
            

            thread1.stop()
            
            thread2 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin_connection, fujinet,  applewin))
            thread3 = threading.Thread(target = threaded_forward, args = (real_applewin_connection, fujinet_connection, applewin, fujinet))
            
            thread2.start()
            thread3.start()
        
            thread2.join()
            thread3.join()
            
                
                    
