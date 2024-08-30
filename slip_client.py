import socket
import time
import datetime
import os
import sys
import binascii

hostname = 'localhost'
port = 1985
packet_size = 512

global sequence_num


# Local imports
my_modules_path = os.getcwd()+"/includes"
if sys.path[0] != my_modules_path:
    sys.path.insert(0, my_modules_path)

from slip import *


# device id
# command number
# sequence number
# data

def fujinet_open(device_id, url, size):
    
    """
    2 bytes - size
    1 byte  - command
    1 byte  - translation
    ? bytes - url
    """
    sp_payload = size.to_bytes(2, 'big') + \
                 0x0C.to_bytes(1, 'big') + \
                 0x80.to_bytes(1, 'big') + \
                 url.encode(encoding="utf-8") 
    return sp_payload
    
def fujinet_time(device_id):
    return pad_to_packet_size( 	device_id.to_bytes(1, 'big') +
                                0xD2.to_bytes(1, 'big') +
                                sequence_number())
             
                     
    return 






if __name__ == "__main__":
    global sequence_num

    device_id = 1
    sequence_num = 1
    
    url = "https://icanhazip.com"
    
    print("Python to Fujinet Smartport Protocol Client")
    print(f"{hostname}:{port}") 
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((hostname, port))
            print(f"Connected to fujinet-pc on {hostname}:{port}")
        except Exception as e:
            print(f"Failed to connected to fujinet-pc on {hostname}:{port}\n{e}")
            exit(-1)
        
        while True:
                   
            print("Sending data")
            
            size   = len(url) + 2
            sp_data = fujinet_open(device_id, url, size)
            print(binascii.hexlify(sp_data,' '))

            slip_data = frame_end + sequence_number() + escaped_data(sp_data) + frame_end
            print(binascii.hexlify(slip_data,' '))

            s.sendall(slip_data)
            
            print("Receiving data")
            
            data = s.recv(packet_size)      
            print(binascii.hexlify(data, ' '))
            
            sp_data = raw_data(data)
            
            print(binascii.hexlify(sp_data, ' '))
 
            time.sleep(60)