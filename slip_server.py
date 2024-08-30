import socket
import time
import binascii
import os
import sys


# Local imports
my_modules_path = os.getcwd()+"/includes"
if sys.path[0] != my_modules_path:
    sys.path.insert(0, my_modules_path)

from slip import *

hostname = 'localhost'
port = 1985



endian = 'big'



"""
  sp_payload[0] = (strlen(url) & 0xFF) + 2;
  sp_payload[1] = (strlen(url) >> 8);
  sp_payload[2] = 0x0C; // GET
  sp_payload[3] = 0x80; // No translation
  memcpy(&sp_payload[4], url, strlen(url));
  
  
"""

if __name__ == "__main__":
    global sequence_num

    device_id = 1
    sequence_num = 1
    
    url = "https://icanhazip.com"
    
    print("Python to Fujinet SLIP Smartport Protocol Server")
    print(f"Server on: {hostname}:{port}") 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((hostname, port))
            s.listen()
            conn, ip_address = s.accept()
            with conn:
                print(f"Client Connected to Server: {ip_address}")
                while True:
                    try:
                        slip_message = conn.recv(packet_size)
                        if slip_message != b'':
                            print(binascii.hexlify(slip_message, ' '))
            
                            sp_data = raw_data(slip_message) 
                            print(binascii.hexlify(sp_data, ' '))
                        else:
                            break
                    except socket.error as error:
                        print(error)
                        if error.errno in [errno.EPIPE, errno.ECONNRESET]:
                            s.close()
                            break
                        
        except Exception as error:
            print(error)

