---
title: Candle - bounty PTIT HN-HCM CTF Finals 2025 forensic
published: 2025-10-21
description: ''
image: ''
tags: ['Forensics']
category: 'Forensics'
draft: false 
lang: 'vi'
---

# Candle - bounty PTIT HN-HCM CTF Finals 2025 forensic
![image](https://hackmd.io/_uploads/ryKvW80jxx.png)

Nhận một file rawdata PEPPER và file mp4 
- Ở file mp4 Thấy file mp3 khá lớn khi check strings có các header lạ
![image](https://hackmd.io/_uploads/H1lKdwRjxl.png)
- Dùng binwalk để dump file mp4 ra vì
![image](https://hackmd.io/_uploads/SJU6dwAoxg.png)
![image](https://hackmd.io/_uploads/HJgAdwRsxl.png)
có điểm đáng chú ý là file manifest.json (nó làm một file cấu hình cho việc lấy flag)
```
└─$ strings a/out_tiles/manifest.json
  "rows": 5,
  "cols": 6,
  "tile_w": 82,
  "tile_h": 98,
  "orig_w": 490,
  "orig_h": 490,
  "padded_w": 492,
  "padded_h": 490,
  "pad_right": 2,
  "pad_bottom": 0,
  "pieces": [
    {
      "file": "piece_00.png",
      "r": 0,
      "c": 0
    },
    {
      "file": "piece_01.png",
      "r": 0,
      "c": 1
    },
    {
      "file": "piece_02.png",
      "r": 0,
      "c": 2
    },
    {
      "file": "piece_03.png",
      "r": 0,
      "c": 3
    },
    {
      "file": "piece_04.png",
      "r": 0,
      "c": 4
    },
    {
      "file": "piece_05.png",
      "r": 0,
      "c": 5
    },
    {
      "file": "piece_06.png",
      "r": 1,
      "c": 0
    },
    {
      "file": "piece_07.png",
      "r": 1,
      "c": 1
    },
    {
      "file": "piece_08.png",
      "r": 1,
      "c": 2
    },
    {
      "file": "piece_09.png",
      "r": 1,
      "c": 3
    },
    {
      "file": "piece_10.png",
      "r": 1,
      "c": 4
    },
    {
      "file": "piece_11.png",
      "r": 1,
      "c": 5
    },
    {
      "file": "piece_12.png",
      "r": 2,
      "c": 0
    },
    {
      "file": "piece_13.png",
      "r": 2,
      "c": 1
    },
    {
      "file": "piece_14.png",
      "r": 2,
      "c": 2
    },
    {
      "file": "piece_15.png",
      "r": 2,
      "c": 3
    },
    {
      "file": "piece_16.png",
      "r": 2,
      "c": 4
    },
    {
      "file": "piece_17.png",
      "r": 2,
      "c": 5
    },
    {
      "file": "piece_18.png",
      "r": 3,
      "c": 0
    },
    {
      "file": "piece_19.png",
      "r": 3,
      "c": 1
    },
    {
      "file": "piece_20.png",
      "r": 3,
      "c": 2
    },
    {
      "file": "piece_21.png",
      "r": 3,
      "c": 3
    },
    {
      "file": "piece_22.png",
      "r": 3,
      "c": 4
    },
    {
      "file": "piece_23.png",
      "r": 3,
      "c": 5
    },
    {
      "file": "piece_24.png",
      "r": 4,
      "c": 0
    },
    {
      "file": "piece_25.png",
      "r": 4,
      "c": 1
    },
    {
      "file": "piece_26.png",
      "r": 4,
      "c": 2
    },
    {
      "file": "piece_27.png",
      "r": 4,
      "c": 3
    },
    {
      "file": "piece_28.png",
      "r": 4,
      "c": 4
    },
    {
      "file": "piece_29.png",
      "r": 4,
      "c": 5
    }
```
"rows": 5, "cols": 6
→ Ảnh gốc được chia thành 5 hàng × 6 cột = 30 mảnh.

"tile_w": 82, "tile_h": 98
→ Mỗi mảnh (tile) có kích thước 82 × 98 px.

"orig_w": 490, "orig_h": 490
→ Kích thước ảnh gốc (chưa cắt, chưa pad): 490 × 490 px.

"padded_w": 492, "padded_h": 490
→ Để chia đều, ảnh gốc được padding thành 492 × 490 px
(tức là thêm 2 px bên phải, "pad_right": 2, "pad_bottom": 0).

"pieces"
→ Danh sách các mảnh.
Mỗi entry gồm:

"file": tên file PNG chứa mảnh.

"r": chỉ số hàng (row index).

"c": chỉ số cột (column index).
## Cách ghép lại ảnh gốc
Tạo một canvas trống kích thước padded_w × padded_h = 492 × 490 px.
Với từng entry trong "pieces":
- Đọc ảnh piece_xx.png (82×98).
- Dán vào vị trí (c * tile_w, r * tile_h).
Ví dụ: piece_19.png có {r:3, c:1} → dán vào tọa độ (1×82, 3×98) = (82, 294).
Sau khi ghép đủ 30 mảnh, crop bỏ phần padding (2 px bên phải) → còn lại 490 × 490 px đúng kích thước gốc.
Nhưng sau khi tôi làm vậy viết script vẫn không recovery lại được ảnh gốc tôi nghi ngờ các file name đã bị scamble tôi đã thử kiểm tra file với exiftool thì thấy mỗi file đều có một trường Pos dường như tương ứng với các tọa độ
![image](https://hackmd.io/_uploads/Skp7qDRseg.png)
Dùng exiftol -pos để truy xuất các POS tương tứng với mỗi file
![image](https://hackmd.io/_uploads/HJvXivRoex.png)
Lấy được tọa độ ma trận rồi giờ ta tiến hành ghép lại ảnh
![code](https://hackmd.io/_uploads/SJkhivAjlx.png)

```
┌──(thong㉿DESKTOP-SD4MBKE)-[/mnt/c/users/tttho/downloads/a/out_tiles]
└─$ python e.py
Done.
- padded.png:        492x490
- reconstructed.png: 490x490
- grid:              5 rows x 6 cols; tile=82x98
```
![reconstructed](https://hackmd.io/_uploads/HJEZaw0sex.png)
đây là image sau khi recovery là một mã QR quét thì ra được một link 
truy cập vào có một bài post
![image](https://hackmd.io/_uploads/BJNPaDCiel.png)
decryption base64 chuỗi ra flag fake
```
─$ echo "VGhpcyBpcyBmbGFnOiBQVElUQ1RGe1ZpZXROYW1NdW9uTmFtfQ==" | base64 -d
This is flag: PTITCTF{VietNamMuonNam}
```
còn một chuỗi ký tự rất lạ tôi đoán làm một url đã bị scamble
![image](https://hackmd.io/_uploads/H16gADRoxl.png)
check nhanh với trang dcode oke no đã bị ROT13
![image](https://hackmd.io/_uploads/Skr7RD0jee.png)
một link github download một file exe 
Download file về và nhận diện signature file với die
![image](https://hackmd.io/_uploads/HJAi0v0sex.png)

## Phân tích file candlegame.exe

Hàm start sẽ gọi sub_140001180() -> sub_140189EE0 (main code)
Logic hàm Sub_140001180 như một hàm init dùng để check ngoại lệ và xử lý nếu không sẽ gọi tới maincode (sub_140189EE0)
![image](https://hackmd.io/_uploads/SJQxSLRoxl.png)
Tại ô khoanh đó đang xây dựng một mảng argv[] để truyền vào main code
=> v14 là *argv
=> qword_14020E020 là argc
## maincode ( application GUI )
Tại hàm maincode dựng một application GUI do hàm main này khá phức tạp nên tôi sẽ không đi theo hướng phân tích hàm này tôi sẽ tìm kiếm các API nghi ngờ 
![image](https://hackmd.io/_uploads/SJl7IUCoxg.png)
thấy chương trình sử dụng bcrypt.dll và các API liên quan đến việc decryption/ derived key
xref tới API BcryptDecrypt -> trỏ về hàm gọi nó
![image](https://hackmd.io/_uploads/HJnv8LAixe.png)
Hàm được gọi từ sub_1400E6960+253
## sub_1400E6960 (decryption AES)
```
_BOOL8 __fastcall sub_1400E6960(PUCHAR pbSecret, const __m128i *a2, UCHAR *a3, __int64 a4, _QWORD *a5)
{
  ULONG v8; // ebx
  BOOL v9; // ebx
  __int64 v11; // r12
  UCHAR *v12; // rax
  UCHAR *v13; // rbp
  ULONG v14; // r9d
  __m128i v15; // xmm1
  UCHAR *v16; // r9
  size_t cbOutput; // r13
  NTSTATUS v18; // eax
  __int64 v19; // rsi
  UCHAR *v20; // r14
  UCHAR *v21; // r13
  size_t v22; // rdi
  UCHAR *v23; // r13
  unsigned __int64 v24; // rdx
  UCHAR *v25; // r13
  unsigned __int64 v26; // r15
  UCHAR *v27; // rcx
  size_t v28; // rax
  _BYTE *v29; // r9
  size_t v30; // r8
  size_t v31; // r14
  UCHAR *v32; // r9
  UCHAR *v33; // [rsp+50h] [rbp-98h]
  PUCHAR v34; // [rsp+50h] [rbp-98h]
  PUCHAR v35; // [rsp+50h] [rbp-98h]
  PUCHAR v36; // [rsp+50h] [rbp-98h]
  size_t Size; // [rsp+58h] [rbp-90h]
  size_t v38; // [rsp+60h] [rbp-88h]
  unsigned __int64 v39; // [rsp+68h] [rbp-80h]
  _BYTE *v40; // [rsp+68h] [rbp-80h]
  _BYTE *v41; // [rsp+68h] [rbp-80h]
  UCHAR pbOutput[4]; // [rsp+74h] [rbp-74h] BYREF
  ULONG pcbResult; // [rsp+78h] [rbp-70h] BYREF
  ULONG v44; // [rsp+7Ch] [rbp-6Ch] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [rsp+80h] [rbp-68h] BYREF
  BCRYPT_KEY_HANDLE phKey; // [rsp+88h] [rbp-60h] BYREF
  UCHAR pbIV[16]; // [rsp+90h] [rbp-58h] BYREF

  v8 = a4;
  if ( !a4 )
    return 0;
  phAlgorithm = 0LL;
  if ( BCryptOpenAlgorithmProvider(&phAlgorithm, L"AES", 0LL, 0) < 0 )
    return 0;
  if ( BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0) < 0
    || (*(_DWORD *)pbOutput = 0, pcbResult = 0, BCryptGetProperty(phAlgorithm, "O", pbOutput, 4u, &pcbResult, 0) < 0) )
  {
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    return 0;
  }
  v11 = *(unsigned int *)pbOutput;
  if ( *(_DWORD *)pbOutput )
  {
    v12 = (UCHAR *)sub_140189220(*(unsigned int *)pbOutput);
    v13 = v12;
    *v12 = 0;
    if ( v11 != 1 )
      memset(v12 + 1, 0, v11 - 1);
    v14 = *(_DWORD *)pbOutput;
  }
  else
  {
    v14 = 0;
    v13 = 0LL;
  }
  phKey = 0LL;
  if ( BCryptGenerateSymmetricKey(phAlgorithm, &phKey, v13, v14, pbSecret, 0x20u, 0) >= 0 )
  {
    v15 = _mm_loadu_si128(a2);
    v44 = 0;
    *(__m128i *)pbIV = v15;
    if ( BCryptDecrypt(phKey, a3, v8, 0LL, pbIV, 0x10u, 0LL, 0, &v44, 1u) >= 0 )
    {
      v16 = (UCHAR *)a5[1];
      Size = v44;
      cbOutput = (size_t)&v16[-*a5];
      v33 = (UCHAR *)*a5;
      if ( cbOutput >= v44 )
      {
        if ( v44 < cbOutput && v16 != &v33[v44] )
        {
          LODWORD(cbOutput) = v44;
          a5[1] = &v33[v44];
        }
        goto LABEL_17;
      }
      v24 = v44 - cbOutput;
      v39 = v24;
      if ( a5[2] - (_QWORD)v16 >= v24 )
      {
        *v16 = 0;
        v25 = v16 + 1;
        v34 = v16;
        if ( v24 != 1 )
        {
          memset(v16 + 1, 0, v24 - 1);
          v25 = &v34[v39];
        }
        a5[1] = v25;
        v33 = (UCHAR *)*a5;
        cbOutput = (size_t)&v25[-*a5];
LABEL_17:
        *(__m128i *)pbIV = _mm_loadu_si128(a2);
        v18 = BCryptDecrypt(phKey, a3, v8, 0LL, pbIV, 0x10u, v33, cbOutput, &v44, 1u);
        v9 = v18 >= 0;
        if ( v18 < 0 )
        {
LABEL_22:
          BCryptDestroyKey(phKey);
          BCryptCloseAlgorithmProvider(phAlgorithm, 0);
          goto LABEL_23;
        }
        v19 = v44;
        v20 = (UCHAR *)a5[1];
        v21 = (UCHAR *)*a5;
        v22 = (size_t)&v20[-*a5];
        if ( v22 >= v44 )
        {
          if ( v44 < v22 )
          {
            v23 = &v21[v44];
            if ( v20 != v23 )
              a5[1] = v23;
          }
          goto LABEL_22;
        }
        v26 = v44 - v22;
        if ( a5[2] - (_QWORD)v20 >= v26 )
        {
          *v20 = 0;
          v27 = v20 + 1;
          if ( v26 != 1 )
          {
            memset(v27, 0, v26 - 1);
            v27 = &v20[v26];
          }
          a5[1] = v27;
          goto LABEL_22;
        }
        if ( 0x7FFFFFFFFFFFFFFFLL - v22 < v26 )
          sub_14018D5F0("vector::_M_default_append");
        v31 = 2 * v22;
        if ( v22 < v26 )
          v31 = v44;
        v32 = (UCHAR *)sub_140189220(v31);
        v32[v22] = 0;
        if ( v26 != 1 )
        {
          v35 = v32;
          memset(&v32[v22 + 1], 0, v26 - 1);
          v32 = v35;
        }
        if ( v22 )
        {
          v32 = (UCHAR *)memmove(v32, v21, v22);
        }
        else if ( !v21 )
        {
LABEL_52:
          a5[2] = &v32[v31];
          *(__m128i *)a5 = _mm_unpacklo_epi64((__m128i)(unsigned __int64)v32, (__m128i)(unsigned __int64)&v32[v19]);
          goto LABEL_22;
        }
        v36 = v32;
        j_j_free_2_4(v21);
        v32 = v36;
        goto LABEL_52;
      }
      if ( 0x7FFFFFFFFFFFFFFFLL - cbOutput < v24 )
        sub_14018D5F0("vector::_M_default_append");
      v28 = 2 * cbOutput;
      if ( cbOutput < v24 )
        v28 = v44;
      v38 = v28;
      v29 = (_BYTE *)sub_140189220(v28);
      v29[cbOutput] = 0;
      v30 = v39 - 1;
      if ( v39 != 1 )
      {
        v40 = v29;
        memset(&v29[cbOutput + 1], 0, v30);
        v29 = v40;
      }
      if ( cbOutput )
      {
        v29 = memmove(v29, v33, cbOutput);
      }
      else if ( !v33 )
      {
LABEL_44:
        LODWORD(cbOutput) = Size;
        v33 = v29;
        *(__m128i *)a5 = _mm_unpacklo_epi64((__m128i)(unsigned __int64)v29, (__m128i)(unsigned __int64)&v29[Size]);
        a5[2] = &v29[v38];
        goto LABEL_17;
      }
      v41 = v29;
      j_j_free_2_4(v33);
      v29 = v41;
      goto LABEL_44;
    }
    BCryptDestroyKey(phKey);
  }
  BCryptCloseAlgorithmProvider(phAlgorithm, 0);
  v9 = 0;
LABEL_23:
  if ( v13 )
    j_j_free_2_4(v13);
  return v9;
}
```

Hàm này nhận vào:
- pbSecret: khóa bí mật (32 bytes = AES-256 key).
- a2: con trỏ đến IV (16 bytes, kiểu __m128i).
- a3: dữ liệu mã hóa cần giải mã.
- a4: kích thước dữ liệu mã hóa.
- a5: một struct giống như std::vector<UCHAR> (3 phần tử: begin, end, capacity_end).
Nhiệm vụ: giải mã chuỗi bằng AES-256-CBC với khóa pbSecret và IV a2, rồi ghi dữ liệu plaintext vào buffer mà a5 trỏ tới.
Toi sẽ rename hàm lại Dec_AES cho tiện việc phân tích
hàm này được gọi từ sub_1400037B0
    
## sub_1400037B0 (config cấu hình)
Nhìn vào hàm sub_1400037B0, đây là một hàm khởi tạo / giải mã dữ liệu cấu hình được mã hóa và nhúng sẵn trong chương trình.
Mình tóm tắt logic của nó như sau:

![image](https://hackmd.io/_uploads/Hy4sPICjgg.png)

**1. Chuỗi base64**
- Đây là một chuỗi Base64 rất dài.
- Vòng lặp đầu tiên (while ( v7 > ... )) là code tự viết để giải mã base64 → byte array.
- Kết quả lưu vào buffer v3 (kiểu std::vector<unsigned char>).

```
while ( v7 > 0x5Au )
  {
    v9 = v7 - 71;
    if ( (unsigned __int8)(v7 - 97) > 0x19u )
      goto LABEL_8;
LABEL_6:
    v6 = v9 | (v6 << 6);
    v10 = v5 + 6;
    if ( v5 + 6 >= 0 )
    {
LABEL_16:
      v14 = v6 >> v10;
      if ( v1 != v2 )
      {
        *v2++ = v14;
LABEL_18:
        v5 -= 2;
        goto LABEL_8;
      }
      Size = v1 - (UCHAR *)v3;
      v15 = 0x7FFFFFFFFFFFFFFFLL;
      if ( v1 - (UCHAR *)v3 == 0x7FFFFFFFFFFFFFFFLL )
        sub_14018D5F0("vector::_M_realloc_insert");
      if ( Size )
      {
        v16 = 0x7FFFFFFFFFFFFFFFLL;
        v17 = 2 * (v1 - (UCHAR *)v3);
        if ( v17 <= 0x7FFFFFFFFFFFFFFFLL )
          v16 = 2 * (v1 - (UCHAR *)v3);
        if ( v17 >= v1 - (UCHAR *)v3 )
          v15 = v16;
        v62 = v15;
        v18 = (_BYTE *)sub_140189220(v15);
        v19 = v18;
        v18[Size] = v14;
        if ( Size > 0 )
        {
          Sizea = (size_t)&v18[Size + 1];
          v20 = memmove(v18, v3, v1 - (UCHAR *)v3);
          v2 = (UCHAR *)Sizea;
          v19 = v20;
          goto LABEL_32;
        }
      }
      else
      {
        v19 = (_BYTE *)sub_140189220(1uLL);
        *v19 = v14;
        v62 = 1LL;
      }
      v2 = &v19[Size + 1];
      if ( v3 )
      {
LABEL_32:
        pbSecret = v2;
        Sizeb = (size_t)v19;
        j_j_free_2_4(v3);
        v19 = (_BYTE *)Sizeb;
        v2 = pbSecret;
        v3 = (_DWORD *)Sizeb;
      }
      else
      {
        v3 = v19;
      }
      v1 = &v19[v62];
      goto LABEL_18;
    }
LABEL_7:
    v5 = v10;
LABEL_8:
    v7 = *++v4;
    if ( !v7 )
      goto LABEL_9;
  }
  if ( v7 <= 0x2Au )
    goto LABEL_8;
  switch ( v7 )
  {
    case '+':
      v9 = 62;
      goto LABEL_6;
    case '/':
      v9 = 63;
      goto LABEL_6;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      v6 = (v7 + 4) | (v6 << 6);
      v10 = v5 + 6;
      if ( v5 + 6 >= 0 )
        goto LABEL_16;
      goto LABEL_7;
    case '=':
      break;
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
      v9 = v7 - 65;
      goto LABEL_6;
    default:
      goto LABEL_8;
  }
LABEL_9:
  v11 = v2 - (UCHAR *)v3;
  LOBYTE(v81[0]) = 0;
  v80 = 0LL;
  Block = v81;
  if ( v11 <= 0x53 )
  {
    *(_QWORD *)(a1 + 8) = 0LL;
    *(_QWORD *)a1 = a1 + 16;
    *(_BYTE *)(a1 + 16) = 0;
    if ( v3 )
      goto LABEL_13;
    return a1;
  }
```
Lưu kết quả vào v3 sau khi giải mã base64
                 
**2. Kiểm tra header**
```
if (*v3 != 877020995) ...
```
Giá trị 877020995 = 0x34544643 (ASCII: "CFT4").
Tức là dữ liệu sau khi base64 decode phải bắt đầu bằng một magic header "CFT4" (hay "CandleFT4"?).
Nếu sai → return rỗng.
![image](https://hackmd.io/_uploads/ryCTqURiel.png)
check header và bỏ quá 0x44 bytes lấy phần cipher check các block 16bytes xem đủ không
![image](https://hackmd.io/_uploads/SyxSsICogx.png)
chỉ định các Provider bước init trước khi tạo ***hash và decryption***

**3. Tính & kiểm tra HMAC**
Sau đó, nó dùng SHA256 để derived key (pbSecret 32bytes) với salt/nonce trong cipher
![image](https://hackmd.io/_uploads/Bk8DlwAieg.png)
![image](https://hackmd.io/_uploads/BkkZZwCsxg.png)
pbInput giống với file PEPPER => file này là file cấu hình cho chương trình lấy key nhưng do file đã được chạy rồi hoặc được dump từ memory nên hardcode hoặc file đã được nhúng hardcode từ trước
Derived Key
Chương trình đọc file PEPPER (32 bytes secret). Từ secret này và Salt trong cipher, nó sinh ra key bằng cách băm:
v82 = SHA256(PEPPER || salt)
K1 = SHA256(v82 || 0x01)
K2 = SHA256(v82 || 0x02)
Trong đó:
K1 = key dùng cho AES-CBC decrypt.
K2 = key dùng cho HMAC-SHA256 verify.

**4.Tính HMAC để xác thực**
Nó không decrypt ngay, mà hash kiểm tra trước:
![image](https://hackmd.io/_uploads/H1PyGDCixe.png)

Tại đây ta quay lai một chút ở phần ciphertext
Format header cipher
```
[0x00..0x03]  Magic   ("CGF4")    = 877020995
[0x04..0x13]  Salt/Nonce (16 bytes)
[0x14..0x23]  IV (16 bytes, dùng cho AES-CBC)
[0x24..0x43]  Tag (32 bytes – HMAC lưu kèm để xác thực)
[0x44..end]   Ciphertext (payload đã mã hoá)

```
Tính HMAC-SHA256 với key = K2 trên dữ liệu:
```
"CandleGame-AES-CBC-v1" || IV || Ciphertext
```
So sánh kết quả với Tag (32 bytes) embed sẵn trong file ở offset 0x24..0x43.
Nếu mismatch → reject, return chuỗi rỗng.
Nếu match → tiếp tục decrypt.

Decrypt AES
Khi HMAC hợp lệ, nó gọi Dec_AES với:
Key = K1 (32 bytes)
IV = block 16 bytes trong file
Ciphertext = phần sau offset 0x44
Giải mã theo chuẩn AES-256-CBC. Plaintext kết quả được trả về trong vùng nhớ Block.

Viết script giải mã
![code](https://hackmd.io/_uploads/HynVDDRjle.png)

## Quay trở lại hàm maincode ban đầu đưa ra kết luận
Đọc tham số bet

Lấy string input từ a1 (argv-like) → convert sang số (strtoll).

Kiểm tra lỗi (errno, overflow, <=0).

Nếu bet ≤ 0 → in [ERR] Bet must be > 0.

Nếu bet > bankroll hiện tại → in [ERR] Bet exceeds bankroll.

Trừ tiền trong bankroll

Nếu đủ tiền → bankroll -= bet.

Xác định kết quả random / tính toán

Gọi RNG (sub_1400063D0, sub_1400064C0, sub_1400DC0E0).

Tạo ra mấy giá trị ngẫu nhiên: odds, bias, multiplier…

So sánh với tham số a2 (SHORT/LONG) để quyết định thắng/thua.

Khi thắng/thua

Nếu win: cộng tiền (2×bet hoặc nhiều hơn). In ra message:

```
[WIN-SHORT] O=... | bank=...
```

hoặc
```
[WIN-LONG] ...
```

Nếu lose: không hoàn lại, in
```
[LOSE-SHORT] O=...
```

hoặc LONG.

Nếu kết quả “push/refund” (draw): hoàn tiền →
```
[PUSH] O=... | refund ... | bank=...
```

Trigger điều kiện đặc biệt (FLAG)

Nếu bankroll vượt 99,999,999 (100 triệu) và byte_14020EA48 == 0:

Set byte_14020EA48 = 1.

In [INFO] Target reached!.

Gọi hàm sub_1400037B0 để giải mã chuỗi Base64 → config/FLAG.

Nếu thành công: in [FLAG] <plaintext>.

Nếu fail: in [WARN] Decrypt failed.

Cleanup

Free các buffer tạm (nhiều lần gọi j_j_free_2_4).

Nếu bankroll ≤ 0 → set quit flag (*(_BYTE**)(a1+56)=1, *(_BYTE*)(a1+64)=...).

    
>PS: Cảm ơn mọi người đã đọc!!!