import socket
import time
import datetime
import os
import sys
import binascii

hostname = 'fujinet-vm.local'
port = 1985
packet_size = 512

global sequence_num

"""
### Init Request $05
The Init command forces the firmware to reinitialize the SCSI bus.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($05)    |
|   1   | AdamNet Device ID   |

### Init Response $05

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |


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
"""

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

def devrelay_status(device_id, status_code):
    status_cmd = 0.to_bytes(1, 'big')
    status_code = status_code.to_bytes(1, 'big')
    return status_cmd + device_id.to_bytes(1, 'big') + status_code

clock_str = "FN_CLOCK"

"""
;*******************************
; SP_FIND_DEVICE
;   Looks for the specified smartport device
; INPUT
;   Put NULL terminated string of device to
;   search for in FIND_DEVICE_STR
; RETURNS
;   A = High byte address of string
;   Y = Low byte address of string
;   X = Device number or $FF on failure
;*********************************

SP_FIND_DEVICE:

                DISPLAY_EXT2_TRACE_NO_UNIT SP_FIND_DEVICE_STR_ADDR       ; "SP_FIND_DEVICE:"

                STA ZP1_HI                              ; STORE THE STRING ADDRESS
                STY ZP1_LO
                
                LDX #$00
                LDY #$00
LOOK_FOR_NULL:
                LDA (ZP1),Y                             ; START OF STRING WITHOUT LENGTH
                STA FIND_DEVICE_BUF,X                   
                BEQ GOT_LENGTH                          ; STOP WHEN WE GET TO NULL
                INY
                INX
                CLC
                BCC LOOK_FOR_NULL
GOT_LENGTH:     
                STX FIND_DEVICE_BUF_LEN                 ; SAVE THE LENGTH INCLUDES NULL

.IF .NOT STRIP_TRACE
.IF EXT2_TRACE
                LDA TRACE_FLAG
                BEQ NO_TRACE19
                PRINT_STR FIND_DEVICE_BUF_ADDR          ; DISPLAY THE STRING WE COLLECTED
                JSR CROUT                               ; CARRIAGE RETURN
NO_TRACE19:                
.ENDIF
.ENDIF

                LDX #$00
                LDY #SP_CMD_STATUS                      ; ASK FOR SMARTPORT STATUS
                JSR SP_STATUS
                
 ;               BCC GOT_DEVICE_COUNT                    ; GOT AN ERROR
 ;               PRINT_STR SP_NO_DCOUNT_STR_ADDR
 ;               SEC
 ;               BCS ERROR_OUT2

GOT_DEVICE_COUNT:
                LDX DCOUNT                              ; THE NUMBER OF DEVICES
                INX
                STX NUM_DEVICES

                LDX #$01                                ; START AT DEVICE #1

NEXT_DEV2: 
                TXA
                PHA 

.IF .NOT STRIP_TRACE
.IF EXT2_TRACE
                JSR PRTX
                PLA
                PHA
                TAX
.ENDIF
.ENDIF

                LDY #SP_STATUS_DIB                      ; X IS DEVICE 
                JSR SP_STATUS                           ; GET INFO
                BCS ERROR_OUT                           ; QUIT IF WE GET AN ERROR
                
                LDA SP_PAYLOAD+4                        ; LENGTH OF STRING
                CMP FIND_DEVICE_BUF_LEN                 ; IS IT THE SAME SIZE AS THE STRING WE'RE LOOKING FOR?
                BNE NEXT_DEVICE                         ; NOPE, CHECK NEXT DEVICE

                ; SAME SIZE STRING, NOW CHECK AND SEE IF IT
                ; IS THE DEVICE WE'RE LOOKING FOR

.IF .NOT STRIP_TRACE
.IF EXT2_TRACE
                LDA #'>'
                JSR COUT
                JSR DUMP_SP_PAYLOAD
.ENDIF
.ENDIF

                LDX #$00        
SCAN_CHAR:

                LDA SP_PAYLOAD+5,X                      ; INFO STRING
                CMP FIND_DEVICE_BUF,X                   ; DEVICE WE'RE LOOKING FOR
                BNE NEXT_DEVICE                         ; NOT THE SAME, CHECK NEXT DEVICE

                INX                                     ; MOVE TO NEXT DEVICE
                CPX SP_PAYLOAD+4                        ; HAVE WE FINISHED LOOKING AT THE SAME NUMBER OF CHARACTERS?
                BNE SCAN_CHAR                           ; NOPE, KEEP GOING                           

                CLC
                BCC FOUND_DEVICE                        ; WE FOUND OUR DEVICE
NEXT_DEVICE:
                PLA                                     ; REMOVE THE DEVICE NUMBER OFF STACK
                TAX                                     
                INX                                     ; AND INCREMENT IT
                CPX NUM_DEVICES                         ; HAVE WE CHECKED ALL DEVICES?
                BNE NEXT_DEV2                           ; NOPE, KEEP GOING

                ; EXHAUSTED OUR LIST

                LDX #SP_ERR                                ; NOT FOUND
                LDA #SP_ERROR_NOT_FOUND
                CLC
                BCC FOUND_DONE

ERROR_OUT:      
                PLA
ERROR_OUT2:
                ; ERROR STRING HERE

                LDX #SP_ERR                               ; ERROR
                RTS

FOUND_DEVICE:
                PLA
                TAX

FOUND_DONE:    
                RTS


"""
def fujinet_find_device_id(name):
    
def fujinet_slip_start():
    devrelay_status(
    
def fujinet_time(device_id):
    time = devrelay_status(fn_clock_id, 'T')
    
    #status = pad_to_packet_size( 	device_id.to_bytes(1, 'big') +
    #                            0xD2.to_bytes(1, 'big') +
    #                            sequence_number())
             
                     
    return raw_message






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