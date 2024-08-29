import socket
import time
import datetime

hostname = 'fujinet-vm.local'

PORT = 1985

def request_time():
    pass


if __name__ == "__main__":
    
    print("Python to Fujinet Smartport Protocol Test")
    print(f"{hostname}:{PORT}") 
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((hostname, PORT))
            print(f"Connected to fujinet-pc on {hostname}")
        except:
            print(f"Failed to connected to fujinet-pc on {hostname}")
            exit(-1)
        
        while True:

                       
            print("Sending data")
            
            now = datetime.datetime.now()
            current_time = now.strftime('%Y %m %d %H:%M:%S')
            current_time = bytearray(current_time.encode("ascii")) 
            s.sendall(current_time)
            print("Receiving data")
            
            data = s.recv(1024)
            print('Echoing: ', repr(data))
            
            time.sleep(60)
