---
title: Anti ChatGPT PRO (PTITCTF)
published: 2025-09-21
description: ""
image: ""
tags: ["Reverse Engineering", "Shellcode"]
category: "Malware Analysis"
draft: false
lang: "VI"
---
# Anti ChatGPT PRO (PTITCTF)
>Anti ChatGPT Pro ⭐️🧠
500
hard reverse noGPT
 0 (0% liked)  1
Chào mừng trở lại, Nhà thám hiểm.
Bạn đã vượt qua mê cung, nhưng phía trước không phải là lối thoát, mà là một căn phòng phủ kín gương.
Mọi thứ bạn thấy đều là phản chiếu – nửa thật, nửa giả, trộn lẫn trong trò chơi của ảo giác.
Những manh mối có thể xuất hiện ở khắp nơi, nhưng cũng có thể chỉ là bẫy để đánh lừa trực giác của bạn.
Ở đây, không chỉ đôi mắt bị thử thách, mà cả niềm tin vào lý trí của chính bạn.
Bạn có dám phá vỡ những chiếc gương để tìm ra sự thật, hay sẽ bị giam cầm trong mê cung của ảo ảnh?
pass: ptitctf2025


Bắt đầu với một mô tả khá chill chill :))
## Start
Tại entry (Hàm start) Có gọi một số hàm lạ 
![image](https://hackmd.io/_uploads/HkvkfCAigx.png)
![image](https://hackmd.io/_uploads/r1LaW0Asex.png)

Ta thấy logic khá đơn giản:
- Mở socket với IP **127.0.0.1:1337** Send gửi data đi
- Check Flag (nhận data gửi về và kiểm tra nếu chuỗi là "True" thì print ra Amazing good job ngược lại print ra "Wrong")
## Sub_1400248E0 (hàm khởi tạo)
Sau khi check các hàm có một số hàm bị lỗi stack frame too long khiến IDA không thể compiled được nhưng ở hàm **sub_1400248E0** dương như là một hàm khởi tạo cho runtime chứa:
![image](https://hackmd.io/_uploads/r1sSXRRjxe.png)
**&unk_14002F030** trỏ tới duy nhất một offset 
![image](https://hackmd.io/_uploads/BJ_F70Rolx.png)
![image](https://hackmd.io/_uploads/rJQnmCAogl.png)
![image](https://hackmd.io/_uploads/SknmcARjel.png)

**&unk_14002F030 -> sub_140001900 ->  sub_140001740** Hàm này đáng chú ý vì nằm ngoài luồng logic kiểm tra flag, đồng thời chứa nhiều đoạn mã bất thường.
> Note : Ban đầu mình đã reverse trước và rename lại tên hàm 
## Xor_DEADBEEF
Hàm **xor_DEADBEEF** là một hàm xor với key hardcode là **b"\xDE\xAD\xBE\xEF"**
```
unsigned __int64 __fastcall sub_140023FA0(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+0h] [rbp-28h]
  _BYTE v5[4]; // [rsp+Ch] [rbp-1Ch]
  __int64 v6; // [rsp+10h] [rbp-18h]
  unsigned __int64 v7; // [rsp+18h] [rbp-10h]
  __int64 v8; // [rsp+20h] [rbp-8h]

  v8 = a1;
  v7 = a2;
  v6 = a3;
  v5[0] = 0xDE;
  v5[1] = 0xAD;
  v5[2] = 0xBE;
  v5[3] = 0xEF;
  for ( i = 0LL; ; ++i )
  {
    result = i;
    if ( i >= v7 )
      break;
    *(_BYTE *)(v6 + i) = v5[i & 3] ^ *(_BYTE *)(v8 + i);
  }
  return result;
}
```
Tiến hành giải mã chuỗi bytes bằng hàm **Xor_DEADBEEF**
![image](https://hackmd.io/_uploads/HJPoPAAoxl.png)
Theo tài liệu [Microsoft](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/beginthread-beginthreadex?view=msvc-170), API _beginthreadex được sử dụng để tạo một thread mới tại một routine thực thi, và trong trường hợp này hàm GetProcAddress được dùng để lấy địa chỉ từ msvcrt.dll.
Hàm sub_140024100 đóng vai trò là start address được truyền vào _beginthreadex.

## sub_140024100
Qua phân tích, có thể thấy hàm sub_140024100 thực chất hoạt động như một shellcode loader.
```
__int64 __fastcall sub_140024100(__int64 a1)
{
  _CONTEXT Context; // [rsp+50h] [rbp-798h] BYREF
  HANDLE hThread; // [rsp+528h] [rbp-2C0h]
  DWORD dwThreadId; // [rsp+530h] [rbp-2B8h]
  DWORD dwProcessId; // [rsp+534h] [rbp-2B4h]
  char v6[8]; // [rsp+538h] [rbp-2B0h] BYREF
  unsigned __int64 v7; // [rsp+540h] [rbp-2A8h] BYREF
  LPCVOID lpBuffer; // [rsp+548h] [rbp-2A0h]
  LPVOID lpBaseAddress; // [rsp+550h] [rbp-298h]
  __int64 v10; // [rsp+558h] [rbp-290h]
  unsigned int v11; // [rsp+560h] [rbp-288h]
  _BYTE ResumeThread[13]; // [rsp+566h] [rbp-282h] BYREF
  unsigned __int64 v13; // [rsp+573h] [rbp-275h] BYREF
  int v14; // [rsp+57Bh] [rbp-26Dh]
  char v15; // [rsp+57Fh] [rbp-269h]
  __int64 v16; // [rsp+580h] [rbp-268h]
  unsigned int v17; // [rsp+58Ch] [rbp-25Ch]
  _BYTE SetThreadContentA[32]; // [rsp+590h] [rbp-258h] BYREF
  _QWORD v19[2]; // [rsp+5B0h] [rbp-238h] BYREF
  char v20; // [rsp+5C0h] [rbp-228h]
  __int64 v21; // [rsp+5D0h] [rbp-218h]
  unsigned int v22; // [rsp+5DCh] [rbp-20Ch]
  _BYTE GetThreadContentA[32]; // [rsp+5E0h] [rbp-208h] BYREF
  _QWORD v24[2]; // [rsp+600h] [rbp-1E8h] BYREF
  char v25; // [rsp+610h] [rbp-1D8h]
  __int64 v26; // [rsp+618h] [rbp-1D0h]
  unsigned int v27; // [rsp+624h] [rbp-1C4h]
  _BYTE OpenThread[11]; // [rsp+62Ah] [rbp-1BEh] BYREF
  unsigned __int64 v29; // [rsp+635h] [rbp-1B3h] BYREF
  __int16 v30; // [rsp+63Dh] [rbp-1ABh]
  char v31; // [rsp+63Fh] [rbp-1A9h]
  __int64 v32; // [rsp+640h] [rbp-1A8h]
  unsigned int v33; // [rsp+64Ch] [rbp-19Ch]
  _BYTE WriteProcessMemory[32]; // [rsp+650h] [rbp-198h] BYREF
  _QWORD v35[2]; // [rsp+670h] [rbp-178h] BYREF
  __int16 v36; // [rsp+680h] [rbp-168h]
  char v37; // [rsp+682h] [rbp-166h]
  __int64 v38; // [rsp+688h] [rbp-160h]
  unsigned int v39; // [rsp+694h] [rbp-154h]
  _BYTE VirtualAlloc[15]; // [rsp+69Ah] [rbp-14Eh] BYREF
  unsigned __int64 v41; // [rsp+6A9h] [rbp-13Fh] BYREF
  int v42; // [rsp+6B1h] [rbp-137h]
  __int16 v43; // [rsp+6B5h] [rbp-133h]
  char v44; // [rsp+6B7h] [rbp-131h]
  __int64 v45; // [rsp+6B8h] [rbp-130h]
  unsigned int v46; // [rsp+6C4h] [rbp-124h]
  _BYTE CreateProcessA[15]; // [rsp+6CAh] [rbp-11Eh] BYREF
  unsigned __int64 v48; // [rsp+6D9h] [rbp-10Fh] BYREF
  int v49; // [rsp+6E1h] [rbp-107h]
  __int16 v50; // [rsp+6E5h] [rbp-103h]
  char v51; // [rsp+6E7h] [rbp-101h]
  __int64 v52; // [rsp+6E8h] [rbp-100h]
  unsigned int v53; // [rsp+6F0h] [rbp-F8h]
  _BYTE kernel32[13]; // [rsp+6F6h] [rbp-F2h] BYREF
  unsigned __int64 v55; // [rsp+703h] [rbp-E5h] BYREF
  int v56; // [rsp+70Bh] [rbp-DDh]
  char v57; // [rsp+70Fh] [rbp-D9h]
  CHAR CommandLine[32]; // [rsp+710h] [rbp-D8h] BYREF
  _QWORD v59[5]; // [rsp+730h] [rbp-B8h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+758h] [rbp-90h] BYREF
  struct _STARTUPINFOA StartupInfo; // [rsp+770h] [rbp-78h] BYREF
  __int64 v62; // [rsp+7D8h] [rbp-10h]
  unsigned int v63; // [rsp+7E4h] [rbp-4h]

  v62 = a1;
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  StartupInfo.cb = 104;
  memset(&ProcessInformation, 0, sizeof(ProcessInformation));
  v59[0] = 0x80DAC3B7B8E2979DuLL;
  v59[1] = 0x8ACADEA7BCE2DEA9uLL;
  v59[2] = 0x87DDDBADB38C9EB3uLL;
  v59[3] = 0xEFDBD5BBC1CADEB1uLL;
  xor_DEADBEEF((__int64)v59, 0x20uLL, (__int64)CommandLine);// C:\Windows\System32\svchost.exe
  v55 = 0xDD8DC1BB81CCC8B5uLL;
  v56 = 0x83D2C9F0;
  v57 = 0xDE;
  xor_DEADBEEF((__int64)&v55, 0xDuLL, (__int64)kernel32);// kernel32
  v53 = hash(kernel32);
  v52 = PEB_ldr(v53);
  v48 = 0x9DEEC8AA8EDBDF9DuLL;
  v49 = 0x9CDBCEB1;
  v50 = 0xECAD;
  v51 = 0xBE;
  xor_DEADBEEF((__int64)&v48, 0xFuLL, (__int64)CreateProcessA);// CreateProcess
  v46 = hash(CreateProcessA);
  v45 = parser_returnAddrAPI(v52, v46);
  v41 = 0xAED2CCAB9BCCC488uLL;
  v42 = 0x8CD1C1B2;
  v43 = 0xD59B;
  v44 = 0xBE;
  xor_DEADBEEF((__int64)&v41, 0xFuLL, (__int64)VirtualAlloc);// VirtualAlloc
  v39 = hash(VirtualAlloc);
  v38 = parser_returnAddrAPI(v52, v39);
  v35[0] = 0x80CCFDBB9BD7DF89uLL;
  v35[1] = 0x80D3C8939CCDC8BDuLL;
  v36 = -11092;
  v37 = -66;
  xor_DEADBEEF((__int64)v35, 0x13uLL, (__int64)WriteProcessMemory);// WriteProcessMemory
  v33 = hash(WriteProcessMemory);
  v32 = parser_returnAddrAPI(v52, v33);
  v29 = 0x8ACCC58A81DBDD91uLL;
  v30 = 0xC9BF;
  v31 = 0xBE;
  xor_DEADBEEF((__int64)&v29, 0xBuLL, (__int64)OpenThread);// OpenThread
  v27 = hash(OpenThread);
  v26 = parser_returnAddrAPI(v52, v27);
  v24[0] = 0x8EDBDFB6BBCAC899uLL;
  v24[1] = 0x9BC6C8AA81D1EEBAuLL;
  v25 = -34;
  xor_DEADBEEF((__int64)v24, 0x11uLL, (__int64)GetThreadContentA);// GetThreadContentA
  v22 = hash(GetThreadContentA);
  v21 = parser_returnAddrAPI(v52, v22);
  v19[0] = 0x8EDBDFB6BBCAC88DuLL;
  v19[1] = 0x9BC6C8AA81D1EEBAuLL;
  v20 = -34;
  xor_DEADBEEF((__int64)v19, 0x11uLL, (__int64)SetThreadContentA);// SetThreadContentA
  v17 = hash(SetThreadContentA);
  v16 = parser_returnAddrAPI(v52, v17);
  v13 = 0x87EAC8B39ACDC88CuLL;
  v14 = 0x8BDFC8AC;
  v15 = 0xDE;
  xor_DEADBEEF((__int64)&v13, 0xDuLL, (__int64)ResumeThread);// ResumeThread
  v11 = hash(ResumeThread);
  v10 = parser_returnAddrAPI(v52, v11);
  if ( ::CreateProcessA(0LL, CommandLine, 0LL, 0LL, 1, 4u, 0LL, 0LL, &StartupInfo, &ProcessInformation) )
  {
    lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, 0LL, (unsigned int)Size, 0x3000u, 0x40u);
    lpBuffer = malloc((unsigned int)Size);
    if ( lpBuffer )
    {
      memcpy((void *)lpBuffer, byte_140030FB0, (unsigned int)Size);
      v7 = 0xEFEAFD99BBFFE59DuLL;
      xor_DEADBEEF((__int64)&v7, 8uLL, (__int64)v6);
      xor((__int64)lpBuffer, Size, v6);
      ::WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, lpBuffer, (unsigned int)Size, 0LL);
      free((void *)lpBuffer);
    }
    dwProcessId = ProcessInformation.dwProcessId;
    dwThreadId = sub_140001910(ProcessInformation.dwProcessId);
    hThread = ::OpenThread(0x1FFFFFu, 0, dwThreadId);
    memset(&Context, 0, sizeof(Context));
    Context.ContextFlags = 1048587;
    GetThreadContext(hThread, &Context);
    Context.Rip = (DWORD64)lpBaseAddress + 2432;
    SetThreadContext(hThread, &Context);
    ::ResumeThread(hThread);
  }
  else
  {
    return (unsigned int)-1;
  }
  return v63;
}
```

**Hành vi chính của hàm bao gồm việc chuẩn bị target process và resolve API (thông qua kỹ thuật obfuscation + API hashing).**
- Giải mã chuỗi lệnh "C:\\Windows\\System32\\svchost.exe" bằng xor_DEADBEEF → lưu vào CommandLine.
- Giải mã chuỗi "kernel32" → băm (hash) → PEB_ldr(hash) duyệt PEB->Ldr để lấy base kernel32.
- Lần lượt giải mã tên API và lấy địa chỉ qua export-table + hàm băm:
```
CreateProcessA, VirtualAlloc(Ex), WriteProcessMemory, OpenThread,

GetThreadContext/SetThreadContext 

ResumeThread.
(Tất cả tên API đều đang bị XOR-encode rồi hash-lookup thay vì dùng IAT.)
```
- Tạo tiến trình con ở trạng thái treo
- CreateProcessA(NULL, "…\\svchost.exe", …, CREATE_SUSPENDED) → nhận ProcessInformation (PID/TID, handle process/thread).
- Cấp phát & giải mã payload rồi nhét vào tiến trình con
- VirtualAllocEx(process, …, Size, MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE) → lpBaseAddress.
- Cấp buffer tạm (malloc), copy payload thô từ byte_140030FB0 (kích thước Size).

**Giải mã payload:**
- Giải mã 8-byte key từ hằng 0xEFEAFD99BBFFE59D → v6[8].
- Gọi xor((__int64)lpBuffer, Size, v6) để XOR toàn bộ payload bằng key 8B (lặp theo vòng).
- WriteProcessMemory(process, lpBaseAddress, lpBuffer, Size, NULL) rồi free.
- Đổi entrypoint thread để nhảy vào payload
- Lấy TID của tiến trình con (sub_140001910(PID)), OpenThread(THREAD_ALL_ACCESS, …, TID).
- GetThreadContext(hThread, &Context), sửa Context.Rip = lpBaseAddress + 2432 (offset 0x980),
rồi SetThreadContext(hThread, &Context). (Tức entrypoint của thread sẽ “đâm” thẳng vào shellcode đã viết.)

**Chạy payload**
- ResumeThread(hThread) → thread tiếp tục thực thi từ RIP mới (payload).
- Trả về v63 (biến trạng thái/garbage), thất bại thì trả -1.

>NOTE:
Tất cả string/API name đều bị che bằng XOR (xor_DEADBEEF) rồi so khớp bằng hàm băm hash().
PEB_parser/parser_returnAddrAPI là PEB->ldr + export-resolver từ PEB để IAT.
Key **XOR 8 byte** dùng để giải mã **payload** trước khi **WriteProcessMemory**.
**Offset +2432** là entry bên trong khối payload (tránh nhảy từ đầu).
Tóm lại: hàm này thực hiện process injection kiểu create-remote-thread-hijack trên svchost.exe bị treo: giải mã tên API và payload, ghi shellcode vào tiến trình con, chỉnh RIP của thread chính đến shellcode, rồi resume để chạy

Tính toán key 
![image](https://hackmd.io/_uploads/BJfbA00sex.png)
Từ đó, ta tính được key giải mã là **b"CHATGPT"**, dùng để dump và giải mã shellcode.
![image](https://hackmd.io/_uploads/HyBN0CAjgx.png)
Tôi nạp phần shellcode vào BinaryNinja và thiết lập base address là 0x1B000.
Khi thực thi, hàm sub_140024100 đặt con trỏ lệnh (RIP) đến địa chỉ lpBaseAddress + 2432. Với cấu hình base address = 0x1B000, địa chỉ này trỏ đến offset 0x1B980, chính là vị trí bắt đầu của main code để phân tích.
![image](https://hackmd.io/_uploads/HkXhkkkngg.png)

Với các logic code quen thuộc đã được sử dụng ở file ban đầu giúp ta dễ dàng phân tích hơn vẫn sử dụng lại các hàm như Xor_DEADBEEF và PEB_ldr, parser_returnAddrAPI
>Note: trong hình trên tôi đã rename lại tất cả biến với việc xor_deadbeef với các byteraw

Đầu tiên, shellcode load hai thư viện ws2_32.dll và kernel32.dll để resolve các API cần thiết.
Mở socket với các API như (WSASTARTUP, socket, inet_addr, htons, bind, listen, recv, send)
![image](https://hackmd.io/_uploads/SJZwW1khll.png)
Tiếp theo, shellcode load msvcrt.dll, tạo key RC4 thông qua sub_1b520, và dùng nó để giải mã payload đã được hardcode.
![image](https://hackmd.io/_uploads/HkF1fJJhll.png)

**Tóm tắt lại tiến trình con svchost.exe:**
- Resolve DLL/API bằng PEB + tên bị XOR
- Giải mã (Xor_DEADBEEF) các chuỗi: "kernel32", "WS2_32.dll", rồi băm (hash) và tra qua PEB_ldr(...) + parser_returnAddrAPI(...) để lấy địa chỉ các API mạng:
**WSAStartup, socket, setsockopt, inet_addr, htons, bind, listen, accept, recv, send, closesocket, WSACleanup.**
- Đây là kỹ thuật né IAT (API hashing + PEB walker).
- Khởi tạo Winsock + tạo socket bound về localhost
- **WSAStartup()**; tạo SOCKET qua socket().
- Có gọi setsockopt() với optlen=4 (biến output = 4) — khả năng đặt timeout/SO_RCVTIMEO hoặc reuse addr (không thấy cụ thể option id trong snippet, nhưng pattern giống setsockopt(s, SOL_SOCKET, X, &val, 4)).
- Dùng inet_addr("127.0.0.1") và htons(...) để điền sockaddr_in (family = AF_INET = 2, IP loopback).

Lắng nghe và nhận kết nối
- **bind()** rồi listen(); nếu cả hai đều OK (khác 0xFFFFFFFF), nó lặp accept() cho đến khi nhận được socket hợp lệ (khác INVALID_SOCKET).
Nhận dữ liệu và xử lý “gói” RC4
- **recv()** vào buffer 0x400. Nếu nhận > 0, Nó từ tiến trình cha đã mở socket và gửi qua cổng 1337:
- Giải mã tên "msvcrt.dll" và hàm "strcpy" 
- Có một “input blob” 0x1E bytes (3 qword + 1 word): 

Gọi **sub_1b520("546423423634")** để tạo key RC4:
- Hàm đó giải mã tên "kernel32", "msvcrt.dll", "LoadLibrary", "sscanf_s" rồi dùng sscanf_s/parser để biến chuỗi hexa "546423423634" thành dãy byte, trả về độ dài/2 (nếu số ký tự hex chẵn) hoặc -1 nếu lẻ. → Kết luận: key RC4 = bytes của chuỗi hex "54 64 23 42 36 34".
- Gọi RC4_decryption(key, keyLen, input, input_len, output) để giải mã blob nói trên vào buffer output (đã zero).
- Sau đó shellcode sẽ lấy dữ liệu được nhận và so sánh với output decryption và trả kết quả ‘Wrong’ hoặc ‘True'.
- Sau đó nó sẽ gửi lại Tiến trình cha là "Wrong" hay "True"
**-> Hardcode buffer sau khi decryption RC4 là flag dùng để kiểm tra input từ tiến trình cha.**
## Decryption blob (0x1e)
![code](https://hackmd.io/_uploads/Sko87J1ngl.png)
```
Output:
Cipher (hex): 7a5c600ca5d7e7480316ed0e5bb2d9bf01eec9bdbcc1b94c0dc67fb3a1eb
Key (hex)   : 546423423634  / ASCII: Td#B64
Plain (hex) : 505449544354467b346e74695f636834745f6750745f5072305f6b6b6b7d
Plain (ascii): PTITCTF{4nti_ch4t_gPt_Pr0_kkk}
```
![image](https://hackmd.io/_uploads/rkfyTQW3xl.png)

**Tóm tắt toàn bộ chương trình:**
- Tiến trình cha khởi tạo tiến trình con svchost.exe (chứa logic check flag input)
- Mở connection 127.0.0.1:1337 để tiến trình cha và tiến trình con giao tiếp với nhau gửi input và trả kết quả
**-> FLAG: PTITCTF{4nti_ch4t_gPt_Pr0_kkk}**
