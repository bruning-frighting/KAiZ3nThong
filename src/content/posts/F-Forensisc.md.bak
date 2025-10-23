---
title: F-Forensisc
published: 2025-08-01
description: How code blocks look in Markdown using Expressive Code.
tags: [DeadSec2025, Linux Memory Analysis]
category: Memory Analysis
draft: false
---

# F - Forensics
>Decriptions:
>https://drive.google.com/file/d/1aQ4lWR_vrqWwPLwf6gJj2FDFbbfyGNHB/view?usp=drive_link
>The chall name says it all !
>https://www.deadsec.xyz/instances/f-forensics
![image](https://hackmd.io/_uploads/B1bAkVIDex.png)

Trong team của tôi đã không có thời gian để solve challenge này vì ngày hôm sau chúng tôi có một cuộc thi CTF onsite supper guessy :))
Nên bây giờ tôi sẽ làm lại 

Đập vào mắt tôi là một file linux memory , oh shit i hate it, Cá nhân tôi thì không được ổn trong việc linux memory lắm :v 

Việc đầu tiên nên làm là check kernel của file dump đó 
```
Linux version 5.15.0-138-generic (buildd@lcy02-amd64-014) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #148-Ubuntu SMP Fri Mar 14 19:05:48 UTC 2025 (Ubuntu 5.15.0-138.148-generic 5.15.178)
```
Đây là kernel version của file tôi đã thử build profiles của volatility2 nhưng tôi không hiểu tại sao lại không dùng được vì thói quen tôi vẫn là volatility2 hơn là volatility3 nếu ai build được profile này trên vol2 có thể share với tôi với 
## Build profile dùng cho volatility3
Đây là một bài [blog](https://www.hackthebox.com/blog/how-to-create-linux-symbol-tables-volatility) rất chi tiết về symbols và kernel trong volatility3 linux và cách build

cài đặt dwarf2json
```
┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ python ubuntu_symbols_finder.py "Linux version 5.15.0-138-generic (buildd@lcy02-amd64-014) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #148-Ubuntu SMP Fri Mar 14 19:05:48 UTC 2025 (Ubuntu 5.15.0-138.148-generic 5.15.178)"
Debug symbols should be available at http://launchpadlibrarian.net/781907576/linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64.ddeb. Here is a typical procedure to create the ISF :

wget http://launchpadlibrarian.net/781907576/linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64.ddeb
dpkg-deb -x linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64.ddeb linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64/
dwarf2json linux --elf linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64/usr/lib/debug/boot/vmlinux-5.15.0-138-generic | xz > linux-image-unsigned-5.15.0-138-generic-dbgsym_5.15.0-138.148_amd64.json.xz
```
Sau khi build xong mọi thứ có vẻ ổn trừ việc sử dụng các plugins liên quan đến dump files như **linux.RecoverFs** và **linux.pslist --dump**

vài câu đầu khá dễ
```
┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ nc nc.deadsec.quest 31722

Answer all the questions and you'll get the flag. Good Luck !! :3

We'll start with a little sanity check, what's the sha256 hash of the file ?
> 9f9d089ad84173dc40e910ad1ba1d584bb5c9b2e82ae2164d6bd22d3b37a7588
[+] Correct!

What is the full path to the malicious elf file ?
> /root/malware-f
[+] Correct!

The malware checks for virtual environments through a system file, what is it ? (full path)
> /proc/cpuinfo
[+] Correct!

The malware installed a fake service as a persistence mechanism, what was the service name ?
> .dbus.service
[+] Correct!

The malware connects to two C2 IPs, what are they ? (ip1 - ip2)
> 185.143.223.107-45.133.216.219
[-] Wrong Answer.

The malware connects to two C2 IPs, what are they ? (ip1 - ip2)
> 185.143.223.107 - 45.133.216.219
[+] Correct!

The malware copies itself and imitates a library, where is it stored ?
> /lib/.X11-unix/.X1
[+] Correct!

What command does the malware use to make the new copied file immutable ?
> chattr +i
[+] Correct!

What three debugging techniques does the malware specifically check for in its anti-debug routine ? (1-2-3)
> LD_PRELOAD-strace-ltrace
[+] Correct!

Looks like the malware is injecting an ssh key, what type is this key ?
> ssh-ed25519
[+] Correct!

Where is that key being injected ? (full path)
> /root/.ssh/authorized_keys
[+] Correct!

What command is the malware using to clear all traces of executed commands ?
> history -c
[-] Wrong Answer.

What command is the malware using to clear all traces of executed commands ?
> history -c
[+] Correct!

How often is the log cleaning function being executed ? (in seconds)
> 3600
[+] Correct!

[+] Here is the flag:
DEAD{You_still_like_memory_dumps_4c914fa51685e7b6}
```
### Answer 1 và 2
Để trả lời cho câu 2 sử dụng plugin linux.bash
nhưng tới câu 3 đã tốn rất nhiều thời gian vì các plugin liên quan đến dump file đều không hoạt động tốt vì thế tôi đã sử dụng volshell để dump và biết được các page khi được volatility load từ physical address sang virtual address đã không được mapping đủ page dẫn đến lỗi khi dump file

### using volshell to dump raw data ELF
Thông thường trong Volatility 3:
- Physical (Contains the Physical Address Space: ELF, RAW, VMware, LiME)
- Virtual (Contains Virtual Addresses (and their Data))
- File Layer (Responsible for operating on the snapshot file)
- Swap (Implements analysis for the swap partition)

![image](https://hackmd.io/_uploads/ryc9RBUvgx.png)
**The Kernel Layer is just a Virtual Layer (a layer that contains virtual addresses)**
![image](https://hackmd.io/_uploads/r17T0SUvex.png)
kiểm tra các lớp layers của file memory
![image](https://hackmd.io/_uploads/B1bEgLLPel.png)

**-> đây là một file ELF snapshort**
**RAW vs ELF snapshot**
- Với ELF snapshot (được dump qua core dump hay gdb, hoặc plugin tạo ELF), layer đầu tiên là FileLayer, vì ELF là định dạng file.
- Với RAW memory dump, file chính là physical memory → không cần FileLayer, bắt đầu luôn bằng PhysicalMemoryLayer.
**Điểm hội tụ là Virtual Layer**, nơi các plugin truy cập để đọc địa chỉ ảo của tiến trình hoặc kernel.
### Ý nghĩa kỹ thuật của Virtual Layer trong Volatility 3
1. Virtual Address Space
Trong hệ điều hành hiện đại, mỗi process có một Virtual Address Space (VAS) riêng.
VAS này được ánh xạ (translated) tới Physical Memory (RAM) thông qua Page Tables, mà gốc là CR3 hoặc PGD (Page Global Directory).
2. Layer in memory
Với một file dump từ RAM (🔸RAW Snapshot) như bạn đang dùng (dump.mem), file chính là không gian địa chỉ vật lý (Physical Address Space).
Theo hình, Volatility sẽ thiết lập các lớp sau:
```
[File Layer] → [Memory Layer] → [Virtual Layer]
```
Vậy "Virtual Layer" là gì trong ngữ cảnh này?
➤ Virtual Layer là lớp ánh xạ Virtual Address Space của hệ điều hành (VD: địa chỉ của code trong process, stack, heap) → tới Memory Layer (địa chỉ vật lý RAM thực tế).

➤ Đối với từng process, mỗi process có một Page Table riêng (CR3), tức mỗi process có ánh xạ riêng giữa địa chỉ ảo và địa chỉ vật lý.(Kiểu như thế giới quan khác nhau)
Dựa vào sơ đồ:

🟧 Virtual Layer (cho kernel): được tạo sẵn để các plugin như linux.pslist, linux.lsmod, … có thể truy cập địa chỉ ảo của kernel.

✅ Để đọc đúng Virtual Address của từng process (như start_code, vm_area_struct, …), **ta cần tạo thêm một Virtual Layer riêng biệt cho process đó**

Và file memory mà ta đang phân tích là định dạng ELFSnapshort nên nó sẽ đi sang một lớp trung gian mới tới lớp memory layer là lớp base layer
như khái niệm trên memory layer mới phản ánh đúng offset address trên disk

![image](https://hackmd.io/_uploads/SJZbBD8vle.png)

![image](https://hackmd.io/_uploads/Hy_ufd8vgx.png)

![image](https://hackmd.io/_uploads/BJF9dwLDxg.png)




Tiến hành xác định malicious process "malware-f"
![image](https://hackmd.io/_uploads/Hk3ZiSIvlg.png)
So sánh offset address từ pslist
![image](https://hackmd.io/_uploads/H14UoSUwxx.png)

### Dump process 
Trong Linux kernel, task_struct là cấu trúc dữ liệu đại diện cho một process. Trường mm (memory descriptor) là con trỏ tới một cấu trúc mm_struct, đại diện cho không gian địa chỉ ảo của process. Đây là nơi kernel lưu thông tin về mappings (code, data, stack, v.v.).

Xác định địa chỉ bắt đầu và địa chỉ cuối của file 
![image](https://hackmd.io/_uploads/H18Ot8UPxx.png)



Lấy raw data ở layer_name
![image](https://hackmd.io/_uploads/S1jgpSUvxl.png)
Đã bị error PagedInvalidAddressExcaption chuyển sang base_layer
![image](https://hackmd.io/_uploads/S1IU6H8wlg.png)
Chuyển sang memory layer
![image](https://hackmd.io/_uploads/ryYYTrIvll.png)


### Vì sao lỗi xảy ra?
Các khái niệm trước đã nói rõ mỗi process trong virtual address space sẽ được mapping qua memory một cách khác nhau (cũng như là thế giới quan khác nhau) xem lại **Virtual Layer Diagram**

**Kết luận:**
Giải pháp khắc phục, thay vì đọc tự động từ layer_name ra ta nên dùng Volatility 3 API đúng cách để tạo layer không gian địa chỉ người dùng của tiến trình:

![image](https://hackmd.io/_uploads/SkEOZILDlx.png)
lúc này ta đã có thêm một layer của process sử dụng layer này để dump file 
demo:

```
layer = self.context.layers[proc_layer].mapp
         ...: ing(0x55bde0168000,16)

[layer_name]> print(layer)
<generator object Intel.mapping at 0x7d046328bc40>

[layer_name]> print(list(layer))
[(94273996750848, 16, 587874304, 16, 'memory_layer')]


ý nghĩa:
(va_start, va_len, pa_start, pa_len, layer_name)
va_start : Virtual Address bạn yêu cầu ánh xạ
va_len : 	Độ dài vùng bạn yêu cầu
pa_start : 	Địa chỉ physical tương ứng trong layer 'memory_layer'
pa_len : Độ dài physical mapping
layer_name: Tên layer vật lý chứa dữ liệu thực tế
Check nhanh với 16 bytes đầu
```
Kiểm tra thử data tại memory layer
![image](https://hackmd.io/_uploads/BJ34kdLvlg.png)

Tiến hành dump file 
![image](https://hackmd.io/_uploads/B1pbfUUPex.png)

![image](https://hackmd.io/_uploads/rkaXMUUwlx.png)

bây giờ đã không còn lỗi nữa check file 

```
┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ file malware-f
malware-f: data
```
![image](https://hackmd.io/_uploads/rkACdI8Pgl.png)

file đã bị mất đi header kiểm tra lại offset address file với plugin linux.proc.Maps để xác định các offset sau khi mapping

Plugin linux.proc.Maps hiển thị Virtual Memory Mappings của từng tiến trình giống với nội dung /proc/[pid]/maps

![image](https://hackmd.io/_uploads/BkB-d88Plx.png)

Clearly the base address of this file is started at 0x55bde0168000 but When I trace start address in volshell it displayed at 0x55bde0169000 we have lost 1000 bytes at header ELF files, We dump it again from 0x55bde0168000-0x55bde016e0000
```
[layer_name]> elf_data = layer.read(0x55bde0168000,0x6000)
         ...:

[layer_name]> with open("malware-f","wb") as f:
         ...:     f.write(elf_data)
         
┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ file malware-f
malware-f: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```
Đây là cách dump mapping tự động theo virtual address space riêng của process như cơ chế của volatility3
vậy ta thử mapping tự động riêng một cách bình thường
```
[layer_name]> proc_layer = proc_target.add_process_layer()
         ...:

[layer_name]> data = self.context.layers[proc_layer].mappi
         ...: ng(0x55bde0168000,0x6000)

[layer_name]> print(list(data))
[(94273996750848, 4096, 587874304, 4096, 'memory_layer'), (94273996754944, 4096, 456658944, 4096, 'memory_layer'), (94273996759040, 4096, 620683264, 4096, 'memory_layer'), (94273996763136, 4096, 597250048, 4096, 'memory_layer'), (94273996767232, 4096, 630095872, 4096, 'memory_layer'), (94273996771328, 4096, 597127168, 4096, 'memory_layer')]

[layer_name]> dump = b''

[layer_name]> for va_start, va_len, pa_start, pa_len, layer in self.context.
         ...: layers[proc_layer].mapping(0x55bde0168000, 0x6000):
         ...:     chunk = self.context.layers[layer].read(pa_start, pa_len)
         ...:     dump += chunk
         ...:

[layer_name]> with open("malware-f2","wb") as f:
         ...:     f.write(dump)
         
         
┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ sha256sum malware-f2
b6e7756044984f2f5a0de3be9e6f2dbaf26ef1d0d4ebaddd35a7c1e21cf8a9c1  malware-f2

┌──(thong㉿MSI)-[/mnt/c/users/tttho/downloads/CTFchall/hacktheon/mem]
└─$ sha256sum malware-f
b6e7756044984f2f5a0de3be9e6f2dbaf26ef1d0d4ebaddd35a7c1e21cf8a9c1  malware-f
```
reverse file with IDAPro
![image](https://hackmd.io/_uploads/HkxP9ILPle.png)
thấy các string liên quan đến sandbox như hypervisor and VMware xref tới kiểm tra
![image](https://hackmd.io/_uploads/HyCFc8IDlg.png)
đây rõ ràng là anti sandbox 
### Answer 3 : /proc/cpuinfo

### 4. The malware installed a fake service as a persistence mechanism, what was the service name ?
![image](https://hackmd.io/_uploads/Hk2kiIIwgg.png)
tiếp tục check string 
![image](https://hackmd.io/_uploads/HyLQoLUvxe.png)
→ Malware tạo một file service systemd giả mạo tên: **dbus.service**
Sau đó nó tạo symbolic link từ file đó sang:
```
/etc/systemd/system/.dbus.service
```
→ Cuối cùng dùng lệnh:
```
systemctl enable --now .dbus.service
```
để kích hoạt service giả mạo đó.

### Answer 4 : .dbus.service

### 5. The malware connects to two C2 IPs, what are they ? (ip1 - ip2)

![image](https://hackmd.io/_uploads/rJuQh8Ivxx.png)
### Answer 5 : 185.143.223.107 - 45.133.216.219

### 6.The malware copies itself and imitates a library, where is it stored ?
copy chính nó chúng ta sẽ target đến /proc/self/exe
![image](https://hackmd.io/_uploads/HJZs28Ivlx.png)
### Answer 6: /lib/.X11-unix/.X1

### 7. What command does the malware use to make the new copied file immutable ?
![image](https://hackmd.io/_uploads/BkIR28Lvee.png)

```
sub_1886("/lib/.X11-unix/.X1", 1LL);
```
Đây là khi gọi hàm truyền 1 -> chattr +i
### Answer 7 : chattr +i
### 8. What three debugging techniques does the malware specifically check for in its anti-debug routine ? (1-2-3)

![image](https://hackmd.io/_uploads/rk5s68Lwge.png)
### Answer 8 : LD_PRELOAD-strace-ltrace
### 9. Looks like the malware is injecting an ssh key, what type is this key ?
![image](https://hackmd.io/_uploads/HyUR6UUDge.png)
### Answer 9: ssh-ed25519
### 10. Where is that key being injected ? (full path)
![image](https://hackmd.io/_uploads/rygGCLUPel.png)
### Answer 10 : /root/.ssh/authorized_keys
### 11. What command is the malware using to clear all traces of executed commands ?
```
__int64 sub_1E27()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  sub_1040("/var/log/auth.log");
  sub_1040("/var/log/secure");
  sub_1040("/var/log/wtmp");
  v1 = sub_1220("/var/log/syslog", "w");
  if ( v1 )
    sub_1080(v1);
  return sub_10E0("history -c");
}
```
### Answer 11: history -c


### 12. How often is the log cleaning function being executed ? (in seconds)
Hàm ở câu trên là hàm xóa log vì vậy ở hàm main có một vòng lập while true
![image](https://hackmd.io/_uploads/rJtJJwLPxe.png)
sleep(3600) trước khi xóa
-> 3600
### Answer 12 : 3600
