endian = 'big'
sequence_num = 0
packet_size = 512

def pad_to_packet_size(buffer, packet_size):
    size = len(buffer)
    return buffer + bytearray(packet_size-size)

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
  
  size_lo size_hi 0x0C 0x80 url...
  
"""

"""
SP_OPEN:

                DISPLAY_EXT2_TRACE SP_OPEN_STR_ADDR

                LDA #SP_OPEN_PARAM_COUNT        ; 3
                STA CMD_LIST                    ; PARAMETER COUNT
                STX CMD_LIST+1                  ; DESTINATION DEVICE
                JSR CALL_DISPATCHER

cmd_open:       .BYTE $EA       ; SP_CMD_OPEN
cmd_list0:      .WORD $EAEA     ; CMD_LIST
                
                BCC SP_OPEN_DONE

OPEN_ERROR:
.IF EXT2_TRACE
                PHA
                PRINT_STR SP_ERROR_STR_ADDR
                PLA
                TAX
                JSR PRTX
                JSR CROUT
.ENDIF
SP_OPEN_DONE:

                RTS
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


