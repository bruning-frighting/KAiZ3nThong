---
title: Diskfiltrate
published: 2025-04-17
description: ''
image: ''
tags: ['DFIR']
category: 'Disk Analysis'
draft: false 
lang: 'en'
---


# DiskFiltration 
>author: KAiZ3n
>Category : DFIR Live Endpoint
>Artifact: C:\Users\Administrator\Documents\New Folder\Liam's Disk
>Description: 
>Tech THM discovered their critical data had been leaked to the competitors. After an internal investigation, the company suspects Liam, a recently terminated employee who was working as a system engineer with Tech THM. This suspicion was raised as Liam had access to the leaked data in his company-provided workstation. He often worked late hours without clear justification for his extended presence. He was also caught roaming around the critical server room and taking pictures of the entry gate. Following these suspicions, Liam’s workstation (provided by the company) was investigated. The initial investigation suggests that an external entity was also helping Liam.
![image](/images/hackmd/ryYEYpSyxl.png)

## Question 1: What is the serial number of the USB device Liam used for exfiltration? 
check file disk.E01 with autopsy 
USB details Information
HKLM\SYSTEM\ControlSet001\Enum\USBTOR\ --> Serial Number : 2651931097993496666 , DiskID : {de87ecc0-d706-11ef-beb9-000c29b3a97f} 

HKLM\SYSTEM\MountedDevices\??\Volume{de87ecc0-d706-11ef-beb9-000c29b3a97f} 
- \DosDevices\E:
USB đc mount vào ở E
## Question 2: What is the profile name of the personal hotspot Liam used to evade network-level detection?
Check registry hive : HKLM\SOFTWARE\
>Answer: Liam's Iphone
## Question 3:What is the name of the zip file Liam copied from the USB to the machine for exfiltration instructions?
Check data transfer between USB and disk
After identifying that the USB is mounted to drive E, check the RecentDocs in Autopsy to see if there are any suspicious files belonging to E:.

![image](/images/hackmd/SynGtAHJxx.png)
Access the path to check: /img_dis.E01/vol_vol3/Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms/Exfiltration Plan.lnk
Using LECmd.exe to check, this .lnk file points to the folder E:\Exfiltration Plan.

Information LNK folder Exfiltration Plan
```
Processing D:\CTFchall\tools\Exfiltration Plan.lnk

Source file: D:\CTFchall\tools\Exfiltration Plan.lnk
  Source created:  2025-04-23 03:13:38
  Source modified: 2025-04-23 03:13:04
  Source accessed: 2025-04-23 04:22:48

--- Header ---
  Target created:  2025-01-18 08:27:03
  Target modified: 2025-01-29 11:04:04
  Target accessed: 2025-01-29 11:04:07

  File size (bytes): 0
  Flags: HasTargetIdList, HasLinkInfo, IsUnicode, DisableKnownFolderTracking, AllowLinkToLink
  File attributes: FileAttributeDirectory
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)


--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Removable storage media (Floppy, USB)
  Serial number: 66D6D7DD
  Label: Liam's USB
  Local path: E:\Exfiltration Plan

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: This PC\E:\Exfiltration Plan

  -Root folder: GUID ==> This PC

  -Drive letter ==> E:

  -Directory ==> Exfiltration Plan
    Short name: Exfiltration Plan
    Modified:    2025-01-29 11:04:06
    Extension block count: 1

    --------- Block 0 (Beef0004) ---------
    Long name: Exfiltration Plan
    Created:     2025-01-18 08:27:04
    Last access: 2025-01-29 11:04:08
    MFT entry/sequence #: 39/6 (0x27/0x6)

--- End Target ID information ---

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  win-tssjnps56jv
   MAC Address: 98:fa:9b:4c:20:39
   MAC Vendor:  LCFC
   Creation:    2025-01-16 12:10:59

   Volume Droid:       00000000-0000-0000-0000-000000000000
   Volume Droid Birth: 00000000-0000-0000-0000-000000000000
   File Droid:         f280157e-d402-11ef-93d4-98fa9b4c2039
   File Droid birth:   f280157e-d402-11ef-93d4-98fa9b4c2039

>> Property store data block (Format: GUID\ID Description ==> Value)
   9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3\7      App User Model Is DestList Link     ==> True
   446d16b1-8dad-4870-a748-402ea43d788c\104    Volume Id                           ==> Unmapped GUID: de87ecc0-d706-11ef-beb9-000c29b3a97f


---------- Processed D:\CTFchall\tools\Exfiltration Plan.lnk in 0.19707700 seconds ----------
```


Here is LNK information of Shadow_plan.lnk
```
Processing D:\CTFchall\tools\Shadow_Plan.lnk

Source file: D:\CTFchall\tools\Shadow_Plan.lnk
  Source created:  2025-04-23 04:16:56
  Source modified: 2025-04-23 04:15:58
  Source accessed: 2025-04-23 04:17:14

--- Header ---
  Target created:  2025-01-29 11:18:59
  Target modified: 2025-01-29 11:19:00
  Target accessed: 2025-01-29 11:19:00

  File size (bytes): 4,096
  Flags: HasTargetIdList, HasLinkInfo, HasRelativePath, IsUnicode, DisableKnownFolderTracking
  File attributes: FileAttributeDirectory
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)

Relative Path: ..\..\..\..\..\Desktop\Shadow_Plan
--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: F47DB76F
  Label: (No label)
  Local path: C:\Users\Administrator\Desktop\Shadow_Plan

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: Shadow_Plan

  -Directory ==> Shadow_Plan
    Short name: SHADOW~1

    --------- Block 0 (Beef0004) ---------
    Long name: Shadow_Plan
    Created:     2025-01-29 11:19:00
    Last access: 2025-01-29 11:19:02
    MFT entry/sequence #: 129918/4 (0x1FB7E/0x4)

--- End Target ID information ---

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  win-tssjnps56jv
   MAC Address: 00:0c:29:b3:a9:7f
   MAC Vendor:  VMWARE
   Creation:    2025-01-20 08:16:37

   Volume Droid:       19932c3c-be4d-4049-9724-fd6d3e9d6ce7
   Volume Droid Birth: 19932c3c-be4d-4049-9724-fd6d3e9d6ce7
   File Droid:         de87ecd0-d706-11ef-beb9-000c29b3a97f
   File Droid birth:   de87ecd0-d706-11ef-beb9-000c29b3a97f

>> Property store data block (Format: GUID\ID Description ==> Value)
   446d16b1-8dad-4870-a748-402ea43d788c\104    Volume Id                           ==> Unmapped GUID: 31ace70e-0000-0000-0000-602200000000


---------- Processed D:\CTFchall\tools\Shadow_Plan.lnk in 0.19649880 seconds ----------
```
With the Property Store Data Block:
446d16b1-8dad-4870-a748-402ea43d788c\104 Volume Id ==> Unmapped GUID: de87ecc0-d706-11ef-beb9-000c29b3a97f

And the LNK information of Shadow_plan.lnk and Property Store Data Block:
446d16b1-8dad-4870-a748-402ea43d788c\104 Volume Id ==> Unmapped GUID: 31ace70e-0000-0000-0000-602200000000

As a result, both GUIDs on the original disk for the Exfiltration Plan and Shadow_Plan folder are the same, with only the Unmapped GUID being different. This indicates that Shadow_Plan was copied to the Exfiltration Plan.
>Answer: Shadow_plan.zip
## Question 4:What is the password for this zip file?
checking pass.lnk
```
Source file: D:\CTFchall\tools\Pass.lnk
  Source created:  2025-04-23 04:16:56
  Source modified: 2025-04-23 04:16:40
  Source accessed: 2025-04-23 04:38:13

--- Header ---
  Target created:  2025-01-20 07:51:49
  Target modified: 2025-01-20 07:51:49
  Target accessed: 2025-01-20 07:51:49

  File size (bytes): 10
  Flags: HasTargetIdList, HasLinkInfo, HasRelativePath, HasWorkingDir, IsUnicode, DisableKnownFolderTracking
  File attributes: FileAttributeArchive
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)

Relative Path: ..\..\..\..\..\Documents\Pass.txt
Working Directory: C:\Users\Administrator\Documents

--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Fixed storage media (Hard drive)
  Serial number: F47DB76F
  Label: (No label)
  Local path: C:\Users\Administrator\Documents\Pass.txt

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: This PC\Documents\Pass.txt

  -Root folder: GUID ==> This PC

  -Root folder: GUID ==> Documents

  -File ==> Pass.txt
    Short name: Pass.txt
    Modified:    2025-01-20 07:51:50
    Extension block count: 1

    --------- Block 0 (Beef0004) ---------
    Long name: Pass.txt
    Created:     2025-01-20 07:51:50
    Last access: 2025-01-20 07:51:50
    MFT entry/sequence #: 132605/1 (0x205FD/0x1)

--- End Target ID information ---

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  win-tssjnps56jv
   MAC Address: 00:0c:29:b3:a9:7f
   MAC Vendor:  VMWARE
   Creation:    2025-01-20 07:17:11

   Volume Droid:       19932c3c-be4d-4049-9724-fd6d3e9d6ce7
   Volume Droid Birth: 19932c3c-be4d-4049-9724-fd6d3e9d6ce7
   File Droid:         910782f9-d6fe-11ef-beb8-000c29b3a97f
   File Droid birth:   910782f9-d6fe-11ef-beb8-000c29b3a97f

>> Property store data block (Format: GUID\ID Description ==> Value)
   446d16b1-8dad-4870-a748-402ea43d788c\104    Volume Id                           ==> Unmapped GUID: 31ace70e-0000-0000-0000-602200000000
```
Local path: C:\Users\Administrator\Documents\Pass.txt
check this file for pasword unzip file Shadow_Plan.zip
>Answer: Qwerty@123
## Question 5:Time to reveal the external entity helping Liam! Who is the author of the PDF file stored in the zip file?
Conducting unzip file with password and check signature metadata của file pdf

![image](/images/hackmd/rk-hZgL1eg.png)

>Answer: Henry
## Question 6:What is the correct extension of the file that has no extension in the zip folder?
```
file confidential 
confidential: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced

```
>Answer: png
## Question 6:It looks like Liam searched for some files inside the file explorer. What are the names of these files? (alphabetical order)
Artifact :\Users\Administrator\NTUSER.DAT\Software\Windows\Microsoft\CurrentVersion\Explorer\WordWheelQuery
>Answer: Financial,Revenue

## Question 7: What are the names of the folders that were present on the USB device? (alphabetical order)
At the Question 1, we identified to USB mounting into E:\ on local Disk
the one of them which we found out in Question 3 : E:\Exfiltration Plan
the other which we'll check it in RecentDocs of  AutoPsy
![image](/images/hackmd/rk5KBx8kel.png)
```
--- Header ---
  Target created:  2025-01-18 08:28:07
  Target modified: 2025-01-29 11:20:44
  Target accessed: 2025-01-29 11:20:44

  File size (bytes): 0
  Flags: HasTargetIdList, HasLinkInfo, IsUnicode, DisableKnownFolderTracking, AllowLinkToLink
  File attributes: FileAttributeDirectory
  Icon index: 0
  Show window: SwNormal (Activates and displays the window. The window is restored to its original size and position if the window is minimized or maximized.)


--- Link information ---
Flags: VolumeIdAndLocalBasePath

>> Volume information
  Drive type: Removable storage media (Floppy, USB)
  Serial number: 66D6D7DD
  Label: Liam's USB
  Local path: E:\Critical Data TECH THM

--- Target ID information (Format: Type ==> Value) ---

  Absolute path: This PC\E:\Critical Data TECH THM

  -Root folder: GUID ==> This PC

  -Drive letter ==> E:

  -Directory ==> Critical Data TECH THM
    Short name: Critical Data TECH THM
    Modified:    2025-01-29 11:20:46
    Extension block count: 1

    --------- Block 0 (Beef0004) ---------
    Long name: Critical Data TECH THM
    Created:     2025-01-18 08:28:08
    Last access: 2025-01-29 11:20:46
    MFT entry/sequence #: 40/5 (0x28/0x5)

--- End Target ID information ---

--- Extra blocks information ---

>> Tracker database block
   Machine ID:  win-tssjnps56jv
   MAC Address: 98:fa:9b:4c:20:39
   MAC Vendor:  LCFC
   Creation:    2025-01-16 12:10:59

   Volume Droid:       00000000-0000-0000-0000-000000000000
   Volume Droid Birth: 00000000-0000-0000-0000-000000000000
   File Droid:         f2801588-d402-11ef-93d4-98fa9b4c2039
   File Droid birth:   f2801588-d402-11ef-93d4-98fa9b4c2039

>> Property store data block (Format: GUID\ID Description ==> Value)
   9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3\7      App User Model Is DestList Link     ==> True
   446d16b1-8dad-4870-a748-402ea43d788c\104    Volume Id                           ==> Unmapped GUID: de87ecc0-d706-11ef-beb9-000c29b3a97f


---------- Processed D:\CTFchall\tools\Critical Data TECH THM.lnk in 0.20393990 seconds ----------

```
>Answer : Critical Data TECH THM
>Answer : Exfiltration Plan
## Question 8 :The external entity didn't fully trust Liam for the exfiltration so they asked him to execute file_uploader.exe, through the instructions in PDF. When was this file last executed and how many times was it executed? (YYYY-MM-DD HH:MM:SS, number of execution times)

To answer the question "When was file_uploader.exe last executed and how many times was it executed?", you’ll need to analyze artifacts that record program executions on Windows systems. Here are the most relevant forensic sources to examine: Prefetch
I found FILE_UPLOADER.EXE.pf and used PECmd.exe tool for analysis
```
Command line: -f C:\Users\Administrator\Documents\New Folder\Liam's Disk\Export\FILE_UPLOADER.EXE-FCDB89C7.pf

Keywords: temp, tmp

Processing C:\Users\Administrator\Documents\New Folder\Liam's Disk\Export\FILE_UPLOADER.EXE-FCDB89C7.pf

Created on: 2025-04-23 09:57:59
Modified on: 2025-04-23 09:57:59
Last accessed on: 2025-04-23 09:57:59

Executable name: FILE_UPLOADER.EXE
Hash: FCDB89C7
File size (bytes): 70,730
Version: Windows 10 or Windows 11

Run count: 2
Last run: 2025-01-29 11:26:09
Other run times: 2025-01-29 11:26:11

Volume information:

#0: Name: \VOLUME{01db6b1f7da8db1d-f47db76f} Serial: F47DB76F Created: 2025-01-20 09:41:33 Directories: 11 File references: 39

Directories referenced: 11

00: \VOLUME{01db6b1f7da8db1d-f47db76f}\$EXTEND
01: \VOLUME{01db6b1f7da8db1d-f47db76f}\USERS
02: \VOLUME{01db6b1f7da8db1d-f47db76f}\USERS\ADMINISTRATOR
03: \VOLUME{01db6b1f7da8db1d-f47db76f}\USERS\ADMINISTRATOR\APPDATA
04: \VOLUME{01db6b1f7da8db1d-f47db76f}\USERS\ADMINISTRATOR\APPDATA\LOCAL
```
>Answer: 2025-01-29 11:26:09,2
## Question 9:Liam received a hidden flag inside a file (in the zip folder) from the external entity helping him. What was that?
Checking file confidential at Question 6 for answering It'll locate in comment of picture we can see it by using exiftool tool
```
exiftool confidential  
ExifTool Version Number         : 13.10
File Name                       : confidential
Directory                       : .
File Size                       : 706 kB
File Modification Date/Time     : 2025:04:23 00:49:03-04:00
File Access Date/Time           : 2025:04:23 00:49:03-04:00
File Inode Change Date/Time     : 2025:04:23 00:49:03-04:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 800
Image Height                    : 600
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Pixels Per Unit X               : 13780
Pixels Per Unit Y               : 13780
Pixel Units                     : meters
Modify Date                     : 2020:08:24 19:50:21
Comment                         : FLAGT{THM_TECH_DATA}
Image Size                      : 800x600
Megapixels                      : 0.480
                                                  
```
>Answer : FLAGT{THM_TECH_DATA}
## Question 10: It seems like Liam caused one last damage before leaving. When did Liam delete "Tax Records.docx"? (YYYY-MM-DD HH:MM:SS)

I dumped $LogFile and $UsnJrnl Log to analysis activity of attacker about deleted, created, modified files

![image](/images/hackmd/SkeMev4L1ee.png)
```
0x00CF8A40|128574|128574||244969960|244969935|DeleteIndexEntryAllocation|AddIndexEntryAllocation|0|Tax Records.docx|$INDEX_ALLOCATION:$I30|;MftRef=132649;MftSeqNo=1;See LogFile_INDX_I30.csv|||||||2025-01-17 12:47:20.0000000|2025-01-17 12:47:19.7822537|2025-01-20 08:17:47.9082253|2025-01-20 08:17:47.9082253|||||||||||||16384|15445|archive|WIN32|||||||||0|0|120|0x00000000|1|0x00000068|0x0003|0x0B80|0x0001|1616|0x0000|0x00000000|0x0024E2E3|0|0|0
0x00CF9050|132649|||244969994|244969960|DeallocateFileRecordSegment|InitializeFileRecordSegment|0|Tax Records.docx||||||||||||||||||||||||||||||||||||||0|24|0x00000000|1|0x00000068|0x0002|0x0018|0x0001|0|0x0002|0x0000818A|0x000C818A|-1|0|0
0x00CF91B8|90831|90831||244970039|244970020|UpdateNonResidentValue|Noop|1792|Tax Records.docx|$DATA:$J|;$UsnJrnl|Tax Records.docx|132649|128574|2025-01-29 11:29:02.6974651|FILE_DELETE+CLOSE|7612160||||||||||||||||||||||||||||||96|0|0x00000000|1|0x00000068|0x0004|0x0068|0x0001|0|0x0000|0x00000742|0x000181BD|0|0|0
0x00CF8E78|128574|128574||244969935|244969923|DeleteIndexEntryAllocation|AddIndexEntryAllocation|0|TAXREC~1.DOC|$INDEX_ALLOCATION:$I30|;MftRef=132649;MftSeqNo=1;See LogFile_INDX_I30.csv|||||||2025-01-17 12:47:20.0000000|2025-01-17 12:47:19.7822537|2025-01-20 08:17:47.9082253|2025-01-20 08:17:47.9082253|||||||||||||16384|15445|archive|DOS|||||||||0|0|112|0x00000000|1|0x00000068|0x0002|0x0B80|0x0001|1736|0x0000|0x00000000|0x0024E2E3|0|0|0
```
As a Result I conclude that : 
**Key Events:
$INDEX_ALLOCATION (Directory Entry Deletion)**

DeleteIndexEntryAllocation → Tax Records.docx
Timestamp: 2025-01-17 12:47:20
This indicates the file was removed from the directory listing (first sign of deletion).

**$MFT Entry Deallocation**
DeallocateFileRecordSegment → Tax Records.docx
Timestamp not directly provided, but occurs *after* the DeleteIndexEntryAllocation.
The file record is marked as unallocated in the Master File Table (MFT), further confirming deletion.

**$UsnJrnl Log (Final Deletion Confirmation)**

FILE_DELETE+CLOSE
File: Tax Records.docx
Timestamp: 2025-01-29 11:29:02.6974651
This shows that the file was definitively deleted and closed at this later timestamp, logged by the $UsnJrnl.

Forensic Interpretation:
Initial deletion action (removal from directory):
2025-01-17 12:47:20

Confirmed final deletion (via $UsnJrnl):
2025-01-29 11:29:02
> Answer : 2025-01-29 11:29:02

## Question 12: Which social media site did Liam search for using his web browser? Likely to avoid suspicion, thinking somebody was watching him. (Full URL)
Checking it in WebCategory AutoPsy
>Answer: http://www.facebook.com

## Question 13 : What is the PowerShell command Liam executed as per the plan?
As per plan attack in pdf file
```
1. Connect to your Personal Hotspot.
2. Copy the critical files to the folder we created specifically for this data.
3. Execute the file_uploader.exe.
4. Get all the Network Shares.
```
And in history powershell in C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PsReadline\Console History.
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f
Enable-MMAgent –OperationAPI`

Enable-MMAgent –OperationAPI
net start sysmain
Get-WmiObject -Class Win32_Share | Select-Object Name, Path
```
>Answer: Get-WmiObject -Class Win32_Share | Select-Object Name, Path