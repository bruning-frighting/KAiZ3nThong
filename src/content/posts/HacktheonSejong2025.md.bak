---
title: HACKTHEON SEJONG FINALS 2025 RANSOM
published: 2025-07-11
tags: [Traffic analysis, Reversing, EFS, Foresic FileSystem]
category: FOR AND RESVERSING
draft: true
---

# HACKTHEON SEJONG
## RANSOM
>author: kAiZ3n


![image](https://hackmd.io/_uploads/S1pIOBUUgg.png)
![image](https://hackmd.io/_uploads/B1Jd_BIIex.png)
![image](https://hackmd.io/_uploads/SkpF_B8Uxx.png)


File Important.vhd là NTFS file system trong đó có tệp meeting bị encryption file system (EFS)
đọc wiki ta biết được luồng hoạt động của cơ chế mã hóa này của Windows áp dụng cho Windows 7 trở lên
Cơ chế mã hóa sẽ encryption file thông qua AES CBC và sau đó key sẽ được encryption key với RSA User's Private Key
Để decryption ngược lại ta cần
- user password (or smart card private key): used to generate a decryption key to decrypt the user's DPAPI Master Key
- DPAPI Master Key: used to decrypt the user's RSA private key(s)
- RSA private key: used to decrypt each file's FEK
- File Encryption Key (FEK): used to decrypt/encrypt each file's data (in the primary NTFS stream)
- SYSKEY: used to encrypt the cached domain verifier and the password hashes stored in the SAM

Đầu tiên ta phân tích file meeting.txt một chút 
và EFS metadata được chứa trong ADBSTREAM
### Phân tích sơ bộ file system bằng Sleuth Kit
```
PS D:\CTFchall> D:\CTFchall\tools\sleuthkit-4.14.0-win32\bin\mmls .\Important5.vhd
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000127   0000000128   Unallocated
002:  000:000   0000000128   0000198783   0000198656   NTFS / exFAT (0x07)
003:  -------   0000198784   0000204799   0000006016   Unallocated


PS D:\CTFchall> D:\CTFchall\tools\sleuthkit-4.14.0-win32\bin\fls -o 128 .\Important5.vhd
r/r 4-128-1:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-6:    $MFT
r/r 1-128-1:    $MFTMirr
d/d 39-144-1:   $RECYCLE.BIN
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-11:   $Secure:$SDH
r/r 9-144-14:   $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 10-128-4:   $UpCase:$Info
r/r 3-128-3:    $Volume
r/r 38-128-7:   meeting.txt
d/d 36-144-1:   System Volume Information
V/V 256:        $OrphanFiles


PS D:\CTFchall> D:\CTFchall\tools\sleuthkit-4.14.0-win32\bin\istat -o 128 .\Important5.vhd 38
MFT Entry Header Values:
Entry: 38        Sequence: 1
$LogFile Sequence Number: 1080689
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute Values:
Flags: Archive, Encrypted
Owner ID: 0
Security ID: 264  (S-1-5-21-80072447-1058360311-2986813321-1000)
Created:        2025-06-07 07:32:04.379533000 (SE Asia Standard Time)
File Modified:  2025-06-07 07:33:35.885219700 (SE Asia Standard Time)
MFT Modified:   2025-06-07 07:34:17.617097900 (SE Asia Standard Time)
Accessed:       2025-06-07 07:34:13.388641200 (SE Asia Standard Time)

$FILE_NAME Attribute Values:
Flags: Archive
Name: meeting.txt
Parent MFT Entry: 5     Sequence: 5
Allocated Size: 0       Actual Size: 0
Created:        2025-06-07 07:32:04.379533000 (SE Asia Standard Time)
File Modified:  2025-06-07 07:32:04.379533000 (SE Asia Standard Time)
MFT Modified:   2025-06-07 07:32:04.379533000 (SE Asia Standard Time)
Accessed:       2025-06-07 07:32:04.379533000 (SE Asia Standard Time)

$OBJECT_ID Attribute Values:
Object Id: 8c6096d9-4332-11f0-9247-e8fb1caf749f

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident   size: 72
Type: $FILE_NAME (48-3)   Name: N/A   Resident   size: 88
Type: $OBJECT_ID (64-4)   Name: N/A   Resident   size: 16
Type: $DATA (128-7)   Name: N/A   Non-Resident, Encrypted   size: 124  init_size: 124
1419
Type: $LOGGED_UTILITY_STREAM (256-6)   Name: $EFS   Non-Resident   size: 688  init_size: 688
1417
```
Phân tích chi tiết:

$DATA (128-7)   Name: N/A   Non-Resident, Encrypted   size: 124
\$LOGGED_UTILITY_STREAM (256-6)   Name \$EFS   Non-Resident   size: 688
Dữ liệu thực ($DATA) được mã hóa.

EFS metadata được lưu ở $LOGGED_UTILITY_STREAM tên $EFS, dùng để chứa FEK được mã hóa bằng khóa công khai của user.(FEK là encrypted key AES by RSA user's privatekey)

dump $LOGGED_UNTILITY_STREAM  và $DATA ra phân tích với 010_EDITOR cùng với template
```
PS D:\CTFchall> D:\CTFchall\tools\sleuthkit-4.14.0-win32\bin\icat -o 128 .\Important5.vhd 38-256-6 > encrypted_FEK.bin
PS D:\CTFchall> D:\CTFchall\tools\sleuthkit-4.14.0-win32\bin\icat -o 128 .\Important5.vhd 38-128-7 > encrypted_data.bin
```
![image](https://hackmd.io/_uploads/BkUZkvB8xe.png)

có được username: user@DESKTOP-EMMENVK được phép đọc file

check username ở SAM bên file Ransom.ad1 để lấy UUID
ta có S-1-5-21-80072447-1058360311-2986813321-1000
### Trích xuất Encrypted FEK
![image](https://hackmd.io/_uploads/HJ7ClPrUxe.png)
sau khi trích xuất xong ta cần phải có được User's RSA PrivateKey để decrypt lấy key AES 
### Trích RSA Private Key và RSA Public Key

Từ EFSblob ta có được pUniqueName = 6918800d-353b-49e5-8d24-ad2f398d4c1

Ta dùng pUniqueName để tìm guidMasterKey trong folder AppData\Roaming\Microsoft\Crypto\RSA\<SID> của user
ta có được file bccd3883a0e4079440c3e01f1dabc363_0e81a3b6-c958-4a7e-ae5f-778aef9f5ac6 chứa pUniqueName và cũng tìm được RSA public key sẽ được lưu trữ trong %Username%\AppData\Roaming\Microsoft\SystemCertificates\Certificates\F6E2973AB94A8DDBDDEF5A95CD8531F54E41BA96 chứa pUniqueName

Để giải mã lấy MasterKey được encryption trong E:\EvanCarter_DISK.E01_NONAME [NTFS]\[root]\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-80072447-1058360311-2986813321-1000\fc901760-7d3c-4e67-a987-e80f876d9086 ta cần phải có user's password 

crack user's password với DPAPImk2john

![image](https://hackmd.io/_uploads/B1-L8z8Ile.png)
![image](https://hackmd.io/_uploads/r1hULG8Ull.png)
Ta có được user's password là "user1234"
Dùng user's password lấy masterkey
![image](https://hackmd.io/_uploads/SJEoYVULge.png)
Có masterkey rồi dùng nó để lấy RSA privatekey
Lệnh lấy RSA Privatekey
```
mimikatz # dpapi::capi /in:"E:\EvanCarter_DISK.E01_NONAME [NTFS]\[root]\Users\user\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-80072447-1058360311-2986813321-1000\bccd3883a0e4079440c3e01f1dabc363_0e81a3b6-c958-4a7e-ae5f-778aef9f5ac6" /masterkey:222ee001341a7cefe498cc14e9523777246b31868d1277d239c854ed122cfd9755dcae1bd9bb9ab64dfa7d9278ddb24cc0e337fbfbe7c16f5baa338f82fca93b
```
![image](https://hackmd.io/_uploads/BJMzY4UIxl.png)

tiếp theo trích xuất public key từ SystemCertificate
đây là     guidMasterKey      : {fc901760-7d3c-4e67-a987-e80f876d9086} và pUniqueName 
dựa theo xác định file trong Certificate


![image](https://hackmd.io/_uploads/BJyTcEULxx.png)

Dùng openssl để covert các cert thành pem
```
PS C:\Users\tttho> openssl x509 -inform DER -outform PEM -in D:\CTFchall\mimikatz-master\mimikatz-master\x64\F6E2973AB94A8DDBDDEF5A95CD8531F54E41BA96.der -out D:\CTFchall\htb\public.pem

PS C:\Users\tttho> openssl rsa -inform PVK -outform PEM -in D:\CTFchall\mimikatz-master\mimikatz-master\x64\dpapi_exchange_capi_0_6918800d-353b-49e5-8d24-ad2f398d4c12.keyx.rsa.pvk -out D:\CTFchall\htb\private.pem
writing RSA key
PS C:\Users\tttho> openssl pkcs12 -in D:\CTFchall\htb\public.pem -inkey D:\CTFchall\htb\private.pem -password pass:user1234 -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Để hiểu rõ hơn về bản chất Symmetric encryption tôi sẽ giải mã manual sau đó sẽ giải mã tự động sau

### Decryption manual
có RSA private key tôi sẽ decyption FEK blob trong file encrypted_FEK.bin
```
PS C:\Users\tttho> openssl pkeyutl -decrypt -inkey  D:\CTFchall\htb\private.pem  -in D:\CTFchall\reserved_encrypted_FEK.bin -out D:\CTFchall\keyAES.bin
```
![image](https://hackmd.io/_uploads/HyUWErIUee.png)
16 bytes đầu là pData blob chứa metadata của key

#### Decrypt data enc EFS 
![image](https://hackmd.io/_uploads/B1SqBBUUgg.png)

có vẻ bị thiếu gì đó tôi đã cố gắn dùng Active Editor Disk để khôi phục cluster của file mã hóa đầy đủ nhưng không được

### Decryption automation
Sau khi có file cert.pfx ta import nó vào user của mình để thực hiện giải mã 
dùng certutil
```
PS C:\Users\tttho> certutil -user -p user1234 -importpfx cert.pfx
The object or property already exists. 0x80092005 (-2146885627 CRYPT_E_EXISTS)

Certificate "user" already in store.

CertUtil: -importPFX command completed successfully.
```
do tôi đã import trước đó bây giờ bạn vào properties -> advance 
![image](https://hackmd.io/_uploads/ByX1vBUIle.png)
Bỏ chọn Encrypt contents to secure data
![image](https://hackmd.io/_uploads/SJQfDSIIxg.png)
