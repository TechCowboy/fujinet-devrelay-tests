import socket
import time
import binascii

hostname = 'fujinet-vm.local'

port = 1985
packet_size = 512

global sequence_num

endian = 'big'



"""
  sp_payload[0] = (strlen(url) & 0xFF) + 2;
  sp_payload[1] = (strlen(url) >> 8);
  sp_payload[2] = 0x0C; // GET
  sp_payload[3] = 0x80; // No translation
  memcpy(&sp_payload[4], url, strlen(url));
  
  
"""


# device id
# command number
# sequence number
# data

def pad_to_packet_size(buffer):
    size = len(buffer)
    return buffer + bytearray(512-size)

def sequence_number():
    global sequence_num
    b = sequence_num.to_bytes(1, endian)
    sequence_num += 1
    return b

"""
  sp_payload[0] = (strlen(url) & 0xFF) + 2;
  sp_payload[1] = (strlen(url) >> 8);
  sp_payload[2] = 0x0C; // GET
  sp_payload[3] = 0x80; // No translation
  memcpy(&sp_payload[4], url, strlen(url));
"""

frame_end                 = 0xC0.to_bytes(1, endian)
frame_escape              = 0xDB.to_bytes(1, endian)
escape_terminator_in_data = 0xDBDC.to_bytes(2, 'little')
escape_escape_in_data     = 0xDBDD.to_bytes(2, 'little')

def escaped_data(data):
    
    escape_data = bytearray()
    
    for i in range(len(data)):
        
        if data[i].to_bytes(1, endian) == frame_end:
            escape_data += escape_terminator_in_data
        elif data[i].to_bytes(1, endian) == frame_escape:
            escape_data += escape_escape_in_data
        else:
            escape_data += data[i].to_bytes(1, endian)
    
    return escape_data
    
def raw_data(data):
    converted_data = bytearray()
    skip_next_byte = False;
    
    start_found = False
    
    for i in range(len(data)):
        if not start_found:
            if data[i].to_bytes(1, endian) == frame_end:
                start_found = True
                continue
        
        if not start_found:
            continue
        
        if skip_next_byte:
            skip_next_byte = False
            continue
        
        if data[i:i+2] == escape_terminator_in_data:
            converted_data += frame_end
            skip_next_byte = True
        elif data[i:i+2] == escape_escape_in_data:
            converted_data += frame_escape
            skip_next_byte = True
        elif data[i].to_bytes(1, endian) == frame_end:
            break
        else:
            converted_data += data[i].to_bytes(1, endian)
            
    return converted_data

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
    
    print("Python to Fujinet Smartport Protocol Test")
    print(f"{hostname}:{port}") 
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((hostname, port))
            print(f"Connected to fujinet-pc on {hostname}:{port}")
        except:
            print(f"Failed to connected to fujinet-pc on {hostname}:{port}")
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
            
            data = s.recv(512)      
            print(binascii.hexlify(data, ' '))
            
            sp_data = raw_data(data)
            
            print(binascii.hexlify(sp_data, ' '))
 
            time.sleep(60)
