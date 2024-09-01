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

Spoofed_AppleWin_hostname  	= 'localhost'
Spoofed_AppleWin_port 		= 1986

Real_AppleWin_hostname 		= 'ARIEL-AMD7'
Real_AppleWin_port			= 1985  

run  = [1]
stop = [0]

"""
real fujinet (random port) connects to
   spoofed applewin (1985)
   
spoofed applewin (1985) will connect to
   real applewin (1986)
   
message flow

fujinet -> spoofed applewin [ display hex ] -> real applewin

real applewin -> spoofed applewin [ display hex] -> fujinet


"""

def threaded_forward(in_connection, out_connection, in_msg, out_msg, state):

    print(f"Started forward {in_msg} -> {out_msg}\n")
    while state == run :
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

    print(f"\nStop.\n")

if __name__ == "__main__":
    
    global communicating
    
    communicating = True
    
    print("Python Protocol Snooper\n")
    
    print(f"Messages received at: {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port} (fujinet connects here, thinking it's AppleWin)")
    print(f"will be forwarded to: {Real_AppleWin_hostname}:{Real_AppleWin_port} (This software connects to Real AppleWin)")
    print(f"and vice versa\n")
    print(f"hostname: {hostname}   IP: {local_ip}\n\n")
    
    fujinet  = f"{Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port}"
    applewin = f"{Real_AppleWin_hostname}:{Real_AppleWin_port}"
            
    print(f"Waiting for connections here from fujinet {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port} <Spoofed AppleWin>")
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
        
    real_applewin = None
    thread1_state = run
    thread1 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin, fujinet,  "LOST", thread1_state, ))
    thread1.start()

    print(f"Attempting to connect to REAL AppleWin {Real_AppleWin_hostname}:{Real_AppleWin_port}")
    # We will connect to the real AppleWin
           
    while True:
        real_applewin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        old_timeout = real_applewin.gettimeout()
        real_applewin.settimeout(3)
        
        try:
            real_applewin.connect((Real_AppleWin_hostname, Real_AppleWin_port))
            real_applewin.settimeout(old_timeout)
            print(f"\nConnected to {Real_AppleWin_hostname}:{Real_AppleWin_port}\n\n")
            break
        except Exception as e:
            print(str(e), end='')
            print(".", end='')
            time.sleep(1)
            continue
        
    print("\n\n**** Snooping has begun! ****\n\n")
    
    thread1_state = stop
    
    thread2_state = run
    thread2 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin, spoofed_applewin, applewin, thread2_state, ))
    
    thread3_state = run
    thread3 = threading.Thread(target = threaded_forward, args = (real_applewin, fujinet_connection, applewin, spoofed_applewin, thread3_state, ))
    
    thread2.start()
    thread3.start()

    thread2.join()
    thread3.join()
        