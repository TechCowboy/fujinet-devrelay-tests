# DevRelay for the Coleco ADAM

This is an implementation of Coleco Adam version of DeRelay.  It's roots are from the SmartPort over SLIP implementation. 

## Resources
SmartPort over SLIP :  https://github.com/FujiNetWIFI/fujinet-firmware/wiki/Apple-II-SP-over-SLIP \
AdamNet             :  https://github.com/FujiNetWIFI/fujinet-config/blob/main/notes/all-about-adamnet.md \
AdamNet Device IDs
```
    Devices (15 max):
        Device 00 = Master 6801 ADAMnet controller (uses the adam_pcb as DCB)
        Device 01 = Keyboard
        Device 02 = ADAM printer
        Device 03 = Copywriter (projected)
        Device 04 = Disk drive 1
        Device 05 = Disk drive 2
        Device 06 = Disk drive 3 (third party)
        Device 07 = Disk drive 4 (third party)
        Device 08 = Tape drive 1
        Device 09 = FUJINET N1
        Device 0A = FUJINET N2
        Device 0B = FUJINET N3
        Device 0C = FUJINET N4
        Device 0D = ADAM parallel interface (never released)
        Device 0E = ADAM serial interface (never released)
        Device 0F = FUJINET DEVICE
        Device 18 = Tape drive 2 (share DCB with Tape1)
        Device 19 = Tape drive 4 (projected, may have share DCB with Tape3)
        Device 20 = Expansion RAM disk drive (third party ID, not used by Coleco)
        Device 52 = Disk
```

## Important Differences
The Protocol for devrelay is the same for both versions, only field names have changed
- SmartPort Unit Number is now AdamNet Device ID
- The Apple II implementation, all block sizes are 512 bytes, but on the ADAM implementation the block size can vary.


## IMPLEMENTED




## UNIMPLEMENTED

### Status Request $00
The Status command returns information about a specific device

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number         |
|   1   | Command Number ($00)    |
|   1   | AdamNet Device ID       |
|   1   | Status Code             |

|Status Code|  Meaning|
|:----:|--------------------------|
|$00|Return device status|
|$01|Not supported|
|$02|Not supported|
|$03|Return Device Information Block (DIB)|
|$04|Return Device Information Block (DIB), extra|
|$05|Return last error status|
|$06|Return bytes/block parameter for device|








### Status Response $00

| Size  | Content                        |
|:-----:|--------------------------------|
|   1   | Sequence Number                |
|   1   | Status                         |
|  [n]  | Status List (if Status == $00) |

### ReadBlock Request $01
The Read Block command reads a specified size chunk from the target device specified
in the AdamNet Device ID parameter.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number         |
|   1   | Command Number ($01)    |
|   1   | AdamNet Device ID       |
|   2   | Block Size*             |
|   3   | Block Number            |

### ReadBlock Response $01

| Size  | Content                       |
|:-----:|-------------------------------|
|   1   | Sequence Number      |
|   1   | Status                        |
|  [N]  | Block Data (if Status == $00) |

### WriteBlock Request $02
The Write Block command writes oa specified size chunk to the target device specified
in the AdamNet Device ID parameter.
| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($02)    |
|   1   | AdamNet Device ID   |
|   2   | Block Size*             |
|   3   | Block Number            |
|   N   | Block Data              |

### WriteBlock Response $02

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

### Format Request $02
The Format command prepares all the blocks on the device specified in the unit
number parameter for read/write use.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($03)    |
|   1   | AdamNet Device ID   |

### Format Response $02

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

### Control Request $04
The Control command provides two basic functions. The first is to execute device
control routines designed by Apple. The second is to execute SCSI commands.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($04)    |
|   1   | AdamNet Device ID   |
|   n   | Control List            |

### Control Request $04
The Control command provides two basic functions. The first is to execute device
control routines designed by Apple. The second is to execute SCSI commands.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($04)    |
|   1   | AdamNet Device ID   |
|   n   | Control List            |

### Control Response $04

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

### Control Response $04

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

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

### Open Request $06
The Open command opens a logical me on the target device for data I/0.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($06)    |
|   1   | AdamNet Device ID   |

### Open Response $06

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

### Close Request $07
The Close command closes a logical file on the target device after a data VO
sequence is completed.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($07)    |
|   1   | AdamNet Device ID   |

### Close Response $07

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

### Read Request $08
The Read command reads a specified number of bytes from the target device
specified in the unit number parameter. The bytes read by this command are
written into RAM, beginning at the address specified in the data buffer pointer. The
number of bytes to be read is specified in the byte count parameter.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($08)    |
|   1   | AdamNet Device ID   |
|   2   | Byte Count              |
|   3   | Address                 |

### Read Response $08

| Size  | Content                      |
|:-----:|------------------------------|
|   1   | Sequence Number     |
|   1   | Status                       |
|  [n]  | Read Data (if Status == $00) |

### Write Request $09
The Write command writes a specified number of bytes to the target device
specified in the unit number p4rameter. The bytes written by this command are
read from RAM, beginning at the address specified in the data buffer pointer. The
number of bytes to be written is specified in the byte count parameter.

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($09)    |
|   1   | AdamNet Device ID   |
|   2   | Byte Count              |
|   3   | Address                 |
|   n   | Write Data              |

### Write Response $09

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |

The Apple II side of SP-over-SLIP is supposed to be implemented using some processor beside the 6502 main processor. This allows the Apple II - in contrast to CBus - to inform the connected devices about a 6502 reset. This can i.e. have a modem drop an active connection or a printer eject a partially printed page. 

### Reset Request $0A

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Command Number ($0A)    |
|   1   | AdamNet Device ID   |

### Reset Response $0A

| Size  | Content                 |
|:-----:|-------------------------|
|   1   | Sequence Number|
|   1   | Status                  |



```
;******************************************************************
; FN_CLOCK
;   Get the current time from the Fujinet Clock
;
;******************************************************************
FN_CLOCK:

                JSR WIPE_PAYLOAD 

                LDX FN_CLOCK_CACHE
                CPX #FN_ERR_NO_DEVICE
                BEQ @skip

                LDY #'T'
                JSR SP_STATUS
@skip:
                LDA SP_PAYLOAD
                STA CENTURY 
                LDA SP_PAYLOAD+1
                STA YEAR 
                LDA SP_PAYLOAD+2
                STA MONTH
                LDA SP_PAYLOAD+3
                STA DAY 
                LDA SP_PAYLOAD+4
                STA HOUR 
                LDA SP_PAYLOAD+5
                STA MINUTE 
                LDA SP_PAYLOAD+6
                STA SECOND 
NO_CLOCK:
                RTS




;******************************************************************
; SP_STATUS
;   The Status command returns information about a specific device.
; The information returned by this command is determined by status code.
; On return from a Status call, the microprocessor X and Y registers are set to
; indicate the number of bytes transferred to the Apple II by the command. The X
; register is set to the low byte of the count, and the Y register is set to the high byte.
; The parameter list for this call is as follows:
; Byte Definition
;  0   parameter list length
;  1   unit number
; 2-3  status list pointer (lsb-msb)
;  4   status code
; INPUT
;   X - UNIT DESTINATION
;   Y - STATUS CODE
;       Y='S' return SP[0..1] = Bytes waiting, SP[2] & 0x02 = connected 
;******************************************************************
; examples
;          Params
;               dest
;                      storage
;                                 status code
; CMD_LIST: 03   07    36 3c         53    
;        
; CMD_LIST: 03 07 36 3c 53 
; payload:  00 02 01 01 4e 3a 48 54 54
;                        N  :  H  T  T
;
; CMD_LIST: 03 00 36 3c 00
; payload:  09
;
; CMD_LIST: 03 01 36 3c 03
; payload:  fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53
;                           F  U  J  I  N  E  T  _  D  I  S
; this program
;
; CMD_LIST: 03 00 60 27 00
; payload:  09
;
; CMD_LIST: 03 01 36 3c 03
; payload:  fc 18 01 00 0e 46 55 4a 49 4e 45 54 5f 44 49 53

SP_STATUS:

                DISPLAY_EXT2_TRACE SP_STATUS_STR_ADDR

                LDA #SP_STATUS_PARAM_COUNT
                STA CMD_LIST                    ; PARAMETER COUNT

                STX CMD_LIST+1                  ; X = DESTINATION DEVICE

                LDA SP_PAYLOAD_ADDR             
                STA CMD_LIST+2                  ; STATUS LIST POINTER LO
                LDA SP_PAYLOAD_ADDR+1    
                STA CMD_LIST+3                  ; STATUS LIST POINTER HI

                STY CMD_LIST+4                  ; Y = STATUS CODE

                JSR CALL_DISPATCHER

cmd_status:     .BYTE $EA       ; SP_CMD_STATUS             ; STATUS CALL COMMAND NUMBER
cmd_list5:      .WORD $EAEA     ; CMD_LIST

                STX SP_COUNT
                STY SP_COUNT+1
                STA LAST_SP_ERR

                BCC SP_STATUS_DONE

ERROR3:

SP_STATUS_DONE:
                RTS



```