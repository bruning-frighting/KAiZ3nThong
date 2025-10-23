---
title: Sliver-C2 framework
published: 2024-06-20
updated: 2024-11-29
description: "Read more about Sliver Framework C2 detection"
image: ""
tags: [C2 framework, Malware Analysis]
category: "Sliver-C2"
draft: false
---
# Sliver-C2 framework



Nhận chall với 2 file DMP và pcap
check signature thì file DMP là file minidump 

```
└─$ ./Quesion
[1] What is the name of the framework used? (use lowercase letters)  sliver
Correct! Moving to the next question.
[2] What is the IP of the attacker's C2 server?  192.168.1.108
Correct! Moving to the next question.
[3] What is the session key of the C2 used to encrypt data during communication?  11f4e5b7e21870c8f44143464b1b80b7b03f9852d782ef6d90b81f626f291401
Correct! Moving to the next question.
[4] Two files were deleted. What are their names? (in alphabetical order, format: abc-def)  781724.png-secret.txt
Correct! Moving to the next question.
[5] A screenshot from the victim's machine was sent. What application is the victim using? (use lowercase letters)  notepad
Correct! Moving to the next question.
[6] An executable file was uploaded from the server to the victim's machine. What is the name of the file?   temp.exe
Correct! Moving to the next question.
[7] What is the extension of the encrypted file changed to by the executable file in question 6?   enc
Correct! Moving to the next question.
[8] What is the path where the message left by the hacker is located?   C:\Users\Administrator\Downloads
Correct! Moving to the next question.
You Winnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn
Flag is Flag{Yeu_em_la_dieu_anh_khong_the_ngo_1a1e70ba17ae145c73c2f403d29304b97ede240987e8850d9643924dc05e00d2}
Press Enter to exit...

```

**Question 1**
ta sử dụng Windbg để debug file minidump
![image](https://hackmd.io/_uploads/r1yhusor1x.png)
chương trình đã bị crash tại process AMUSED_MILKSHAKE
tiến hành dump process đó ra kiểm tra với 

![image](https://hackmd.io/_uploads/HyVNYioSkg.png)
đây là thông tin của module
dùng lệnh **.writemem '%USER PROFILE%\outputfolder\...' start end**
```
.writemem C:\Users\Username\Downloads\AMUSED_MILKSHAKE.bin 00920000 01a11000
```
Khi có file ta đưa vào virustotal để quick scan
![image](https://hackmd.io/_uploads/BJOE5ojSkl.png)
ta có thể thấy đây là một trojan sliver 
search google sliver framework
![image](https://hackmd.io/_uploads/HyQq5ooSye.png)

**Đáp án 1 :** sliver

**Question2:** 
Check file pcap ta thấy được các gói http nghi vấn đến từ 192.169.1.108 chứa các chuỗi hex, base64, words lạ
![image](https://hackmd.io/_uploads/B1hZojoryx.png)
![image](https://hackmd.io/_uploads/SJM7iisS1x.png)
![image](https://hackmd.io/_uploads/rkSVjsjBkg.png)
**Đáp án 2 :** 192.168.1.108

**Question3:**
sau khi đã biết được attacker sử dụng Sliver-C2 framework
tìm các bài blog có liên quan
https://www.immersivelabs.com/blog/detecting-and-decrypting-sliver-c2-a-threat-hunters-guide

![image](https://hackmd.io/_uploads/Hy_Z2osS1g.png)
trong blog có nói rõ về cách extract session key từ memory dump
session key dùng để decrypt các payload trên network traffic
![image](https://hackmd.io/_uploads/HkX8hosBke.png)
Không may mắn là ta phải tìm key theo cách thủ công với Hex
và thu nhỏ phạm vi tìm kiếm với Pattern
```
Filter:
- Pattern : 00 00 [32 bytes key] ?? ?? ?? 00 C0 00 00
- Trong bài viết nói chuỗi sha256 key sẽ hiếm khi có 3 byte null liền kề trong 10 million SHA256 random được tạo ra
(bỏ đi các sha256 filter nếu có 3 byte null liền kề)
- Và cũng nói là sẽ hiếm khi có mã sha256 có byte null ở cuối hash
```
với các thông tin này ta viết script 
chuyển file DMP => sang dạng hex
```
def print_hex(filename):
    with open(filename, 'rb') as file:
        hex_data = file.read()
        return hex_data.hex()

hex_data=print_hex("AMUSED_MILKSHAKE.DMP")
f=open("hex.txt","w")
f.write(hex_data)
f.close()
```
Lọc pattern
```
$ cat hex.txt | grep -oE '0000([a-fA-F0-9]{70})00c00000' > pattern.txt
```
```
f=open("pattern.txt","r")
data=f.readlines()
f.close()
possible_keys = []
for i in data:
    possible_keys.append(i[4:68])
filter_keys = []
for i in possible_keys:
    if not("000000") in i:
    	if not ( i[62:] == "00" ):
    		filter_keys.append(i)
for i in filter_keys:
	print(f"Possible key : {i}")
```

output
```
└─$ python b.py
Possible key : 200810200810200a10200a302009102008902000002004002004402000002001
Possible key : 6d653a20696e76616c6964206475726174696f6e206a2de3cbe5bb8fa9c2b297
Possible key : 4e4f5f50524f58594e4f5f50524f58596e6f5f70726f78796e6f5f70726f7879
Possible key : 4e4f5f50524f58594e4f5f50524f58596e6f5f70726f78796e6f5f70726f7879
Possible key : 11f4e5b7e21870c8f44143464b1b80b7b03f9852d782ef6d90b81f626f291401
Possible key : 00000f4050cffffffffff850a00000a0c0a0000ee2c18e2620300f5050bfffff
Possible key : eb3a837d102e750644396d387430488b542470488bcde891fbffff8bf085c074
Possible key : a3320000d42507001a230a0009060a0615011b0009f007e00570046003300250
Possible key : 004c8d442420488d5424288b0883e1f8897c2428894c2420488d4c2420e8043f
Possible key : 644710001001000019260a0014011b000df00be009d007c00570046003500230
Possible key : 0ff004585ed750f498b06f6c3027405668910eb02881033c0eb1de8e142fcff3
Possible key : 009941f7f88945ac448bf040f6c7010f85f70100004c8b45e84d85c00f84ea01
Possible key : 0005bc3cccccccccccccccc40534881ecd00c0000488b05e85e0b004833c4488
Possible key : 50500300e5500300804215001922080010011b0009f007e00570046003500230

```

**Đáp án 3 : 11f4e5b7e21870c8f44143464b1b80b7b03f9852d782ef6d90b81f626f291401**

**Question 4:**
Sau khi có được session key ta tiến hành xử lý payload trong file pcap với tool được đề cập trong blog
```
https://github.com/Immersive-Labs-Sec/SliverC2-Forensics/tree/main
```

sử dụng
silver-pcap-parse.py để lấy payload ra
do không có dấu hiệu payload ở DNS nên ta chỉ filter cho http
```
$ python sliver_pcap_parser.py --pcap ~/Desktop/extract.pcapng --filter http --domain_name 192.168.1.108

```
xong sử dụng sliver_decrypt.py cùng với key session để decrypt file http_message.json

như có vẻ không hoạt động tốt
sau vài giờ kiểm tra tôi biết vấn đề nằm ở các định dạng file http-message.json 

![image](https://hackmd.io/_uploads/rkZ3F2sBJg.png)
ta thấy các định dạng đã được đưa về hex không đúng như định dạng trong script decrypt
ở chỗ words tôi bôi đỏ 
![image](https://hackmd.io/_uploads/rkgMqhoHye.png)
đúng định dạng phải như này
và gzip-b64 tôi sẽ đưa về b64 để dễ cho script decrypt hoạt động tốt tránh lỗi trong việc xử lý gunzip
![image](https://hackmd.io/_uploads/ry0U93jryx.png)
lúc này tôi sẽ sử dụng file http-message.json
![image](https://hackmd.io/_uploads/SJIj5hoHJx.png)
làm tương tự với các process trong file http-message.json
sau khi đã sửa file http-message ta decrypt được
```
─$ python sliver_decrypt.py --key 11f4e5b7e21870c8f44143464b1b80b7b03f9852d782ef6d90b81f626f291401 --transport http --file_path fixed_http-sessions.json > file_payload

```
ta có được payload
![image](https://hackmd.io/_uploads/B1g2nhjrkg.png)


sau xong ta lấy tất cả hex của message data đem đi decode probobuf 
https://protobuf-decoder.netlify.app/

![image](https://hackmd.io/_uploads/BkOPp3jSye.png)
file payload chưa được decode protobuf
bây giờ vào link trên để decode 
khi decode ta thấy đây là một cuộc tấn công ransomware
folder dc nhắm tới C:\Users\Administrator\Downloads


![image](https://hackmd.io/_uploads/BJ1EA2iryx.png)
khi chưa encrypt ransomware
các file
```
C:\Users\Administrator\Downloads
│
├── 0106_hinh-nen-4k-may-tinh6.jpg -rw-rw-rw-
├── 0106_hinh-nen-may-tinh-full-hd88.jpg -rw-rw-rw-
├── 0106_hinh-nen-may-tinh-full-hd88.jpg -rw-rw-rw-
├── 1330526.png -rw-rw-rw-
├── 1337222.jpeg -rw-rw-rw-
├── 404-error-glitch-3840x2160-18144.jpg -rw-rw-rw-
├── 575156.jpg -rw-rw-rw-
├── 641968.jpg -rw-rw-rw-
├── 781724.png -rw-rw-rw-
├── _linkvortex.htb (folder) drwxrwxrwx
├── _youtube.com (folder) drwxrwxrwx
├── a.sh -rw-rw-rw-
├── desktop.ini -rw-rw-rw-
├── mini_flag.txt -rw-rw-rw-
├── secret.txt -rw-rw-rw-
├── vcruntime140 (folder) drwxrwxrwx
└── vcruntime140.zip -rw-rw-rw-

```

khi đã encrypt
```
C:\Users\Administrator\Downloads
│
├── 0106_hinh-nen-4k-may-tinh61.jpg.enc -rw-rw-rw-
├── 0106_hinh-nen-may-tinh-full-hd88.jpg.enc -rw-rw-rw-
├── 0106_hinh-nen-may-tinh-full-hd88.jpg.enc -rw-rw-rw-
├── 1330526.png.enc -rw-rw-rw-
├── 1337222.jpeg.enc -rw-rw-rw-
├── 404-error-glitch-3840x2160-18144.jpg.enc -rw-rw-rw-
├── 575156.jpg.enc -rw-rw-rw-
├── 641968.jpg.enc -rw-rw-rw-
├── YOU HAVE BEEN HACKED. IF YOU WANT TO RECOVER YOUR DATA, PLEASE CONTACT ME VIA DISCORD tr0n9_t4m (folder) drwxrwxrwx
├── _linkvortex.htb (folder) drwxrwxrwx
├── _youtube.com (folder) drwxrwxrwx
├── a.sh.enc -rw-rw-rw-
├── desktop.ini.enc -rw-rw-rw-
├── mini_flag.txt.enc -rw-rw-rw-
├── temp.exe -rw-rw-rw-
├── temp.exe.enc -rw-rw-rw-
├── temp_wallpaper.png -rw-rw-rw-
├── vcruntime140 (folder) drwxrwxrwx
└── vcruntime140.zip.enc -rw-rw-rw-

```

 ta thấy đã bị xóa 2 file 781724.png-secret.txt
** đáp án câu 4: 781724.png-secret.txt**

Question 5 : có file sample.png

![image](https://hackmd.io/_uploads/SJt1WpiHye.png)
ta thấy dưới có payload được attacker gửi về server thông qua lệnh POST với request url http://192.168.1.108/oauth2/api/namespaces/oauth/oauth2/oauth2/samples.php?s=94728974
![image](https://hackmd.io/_uploads/HkB3Waorye.png)
**đáp án : notepad**
Question 6 : temp.exe
Question 7: enc
Question 8 : YOU HAVE BEEN HACKED. IF YOU WANT TO RECOVER YOUR DATA, PLEASE CONTACT ME VIA DISCORD tr0n9_t4m (folder) drwxrwxrwx
** Đáp án : C:\Users\Administrator\Downloads**
