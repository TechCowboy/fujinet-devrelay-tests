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
Spoofed_AppleWin_port 		= 1985

Real_AppleWin_hostname 		= 'fujinet-vm.local'
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

    print(f"Forward messages from {in_msg.strip()} -> {out_msg.strip()}")
    while state == run :
        # get message from client
        try:
            slip_message = in_connection.recv(packet_size)
            if slip_message != b'':
                print(f"{in_msg} -> {out_msg} : {binascii.hexlify(slip_message, ' ')}")
                if out_connection != None:
                    out_connection.sendall(slip_message)
     
        except socket.error as error:
            print(error)
            break

    print(f"\nClose {in_msg}")
    in_connection.close()
    print(f"\nStop.\n")

if __name__ == "__main__":
    
    global communicating
    
    communicating = True
    
    print("Python Protocol Snooper\n")

    fujinet  = f"{Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port}".ljust(20)
    applewin = f"{Real_AppleWin_hostname}:{Real_AppleWin_port}".ljust(20)
    
    print(f"Messages received at: {fujinet} (fujinet connects here, thinking it's AppleWin)")
    print(f"will be forwarded to: {applewin} (Real AppleWin)")
    print(f"and vice versa\n")
    print(f"hostname: {hostname}   IP: {local_ip}\n")
    

            
    print(f"Waiting for fujinet to connect here: {Spoofed_AppleWin_hostname}:{Spoofed_AppleWin_port} <Spoofed AppleWin - this application>")
    # fujinet will try and connect to me

    while(True):
        try:
            spoofed_applewin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as error:
            print(f"1Error: '{error}'")
            time.sleep(10)
            continue
        
        try:
            spoofed_applewin.bind((Spoofed_AppleWin_hostname, Spoofed_AppleWin_port))
            spoofed_applewin.listen()
            fujinet_connection, fujinet_address = spoofed_applewin.accept()
            print(f"\n*** Received connection from Fujinet {fujinet_address} ***\n\n")
            break
        except Exception as error:
            print(f"2Error: '{error}'")
            time.sleep(10)
            continue
        
    real_applewin = None
    #thread1_state = run
    #thread1 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin, fujinet,  "LOST", thread1_state, ))
    #thread1.start()

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
        
    print("**** Snooping has begun! ****\n")
    
    try:
        thread2_state = run
        thread2 = threading.Thread(target = threaded_forward, args = (fujinet_connection, real_applewin, "FujiNet", "AppleWin", thread2_state, ))
        
        thread3_state = run
        thread3 = threading.Thread(target = threaded_forward, args = (real_applewin, fujinet_connection, "AppleWin", "FujiNet", thread3_state, ))
        
        thread2.start()
        thread3.start()

        thread2.join()
        thread3.join()
    except Expection as error:
        print(f"\nException: {error}")
        thread2_state = stop
        thread3_state = stop
        print(f"\n10 second delay before stopping.")
        time.sleep(10)


"""
**** Snooping has begun! ****

Forward messages from FujiNet -> AppleWin
Forward messages from AppleWin -> FujiNet
AppleWin -> FujiNet : b'c0 24 05 01 c0'
FujiNet -> AppleWin : b'c0 24 00 c0'
AppleWin -> FujiNet : b'c0 25 05 02 c0'
FujiNet -> AppleWin : b'c0 25 00 c0'
AppleWin -> FujiNet : b'c0 26 05 03 c0'
FujiNet -> AppleWin : b'c0 26 00 c0'
AppleWin -> FujiNet : b'c0 27 05 04 c0'
FujiNet -> AppleWin : b'c0 27 00 c0'
AppleWin -> FujiNet : b'c0 28 05 05 c0'
FujiNet -> AppleWin : b'c0 28 00 c0'
AppleWin -> FujiNet : b'c0 29 05 06 c0'
FujiNet -> AppleWin : b'c0 29 00 c0'
AppleWin -> FujiNet : b'c0 2a 05 07 c0'
FujiNet -> AppleWin : b'c0 2a 00 c0'
AppleWin -> FujiNet : b'c0 2b 05 08 c0'
FujiNet -> AppleWin : b'c0 2b 00 c0'
AppleWin -> FujiNet : b'c0 2c 05 09 c0'
FujiNet -> AppleWin : b'c0 2c ff c0'
AppleWin -> FujiNet : b'c0 f2 00 0a 03 c0'
AppleWin -> FujiNet : b'c0 f3 00 0b 03 c0'
AppleWin -> FujiNet : b'c0 f4 00 0c 03 c0'
AppleWin -> FujiNet : b'c0 f5 00 0d 03 c0'
AppleWin -> FujiNet : b'c0 f6 00 0e 03 c0'
AppleWin -> FujiNet : b'c0 f7 00 0f 03 c0'
AppleWin -> FujiNet : b'c0 f8 00 10 03 c0'
AppleWin -> FujiNet : b'c0 f9 00 11 03 c0'
AppleWin -> FujiNet : b'c0 fa 00 12 03 c0'
AppleWin -> FujiNet : b'c0 05 00 0a 03 c0'
AppleWin -> FujiNet : b'c0 06 00 0b 03 c0'
AppleWin -> FujiNet : b'c0 07 00 0c 03 c0'
AppleWin -> FujiNet : b'c0 08 00 0d 03 c0'
AppleWin -> FujiNet : b'c0 09 00 0e 03 c0'
AppleWin -> FujiNet : b'c0 0a 00 0f 03 c0'
AppleWin -> FujiNet : b'c0 0b 00 10 03 c0'
AppleWin -> FujiNet : b'c0 0c 00 11 03 c0'
AppleWin -> FujiNet : b'c0 0d 00 12 03 c0'
AppleWin -> FujiNet : b'c0 18 00 0a 03 c0'
AppleWin -> FujiNet : b'c0 19 00 0b 03 c0'
AppleWin -> FujiNet : b'c0 1a 00 0c 03 c0'
"""