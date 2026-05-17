# HTB and TryHackMe Writeups — Jay Patel

Building toward a penetration testing career through HTB Academy CPTS and hands-on lab work.
Every writeup in this repo documents the full attack path — enumeration, exploitation, and
privilege escalation — with the exact commands, reasoning, and lessons learned at each step.

HTB writeups are only published after a machine is confirmed retired.

---

## Progress

| Category | Completed | Target |
|---|---|---|
| HTB Linux | 8 | 15+ |
| HTB Windows | 3 | 10+ |
| HTB Active Directory | 0 | 10+ |
| HTB Web Challenges | 0 | 9+ |
| TryHackMe Rooms | 9 | Ongoing |
| **Total** | **20** | **40+** |

---

## HTB Machines — Linux · 8 completed

<details>
<summary>View writeups</summary>

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Valentine | Easy | Heartbleed (CVE-2014-0160) memory leak → SSH key decryption → tmux root socket | April 2026 | [writeup](HTB-Machines/Linux/Valentine.md) |
| Underpass | Easy | UDP scan → SNMP default community string → daloRADIUS default creds → MD5 crack → mosh-server sudo privesc | April 2026 | [writeup](HTB-Machines/Linux/Underpass.md) |
| Postman | Easy | Redis unauthenticated file write, SSH key injection, ssh2john, Webmin 1.910 RCE (CVE-2019-12840) | April 2026 | [writeup](HTB-Machines/Linux/Postman.md) |
| Lame | Easy | distcc CVE-2004-2687 unauthenticated RCE → SUID nmap --interactive GTFOBins shell escape | May 2026 | [writeup](HTB-Machines/Linux/Lame.md) |
| Bashed | Easy | phpbash webshell → sudo lateral move to scriptmanager → root cron job overwrites writable test.py | May 2026 | [writeup](HTB-Machines/Linux/Bashed.md) |
| Codify | Easy | vm2 CVE-2023-30547 sandbox escape → SQLite bcrypt crack → bash [[ ]] pattern match bypass + pspy root cred sniff | May 2026 | [writeup](HTB-Machines/Linux/Codify.md) |
| Shocker | Easy | Shellshock CVE-2014-6271 via CGI User-Agent → shelly reverse shell → sudo perl GTFOBins root | May 2026 | [writeup](HTB-Machines/Linux/Shocker.md) |
| Knife | Easy | PHP 8.1.0-dev backdoor CVE-2021-39165 (User-Agentt header RCE) → james reverse shell → sudo knife GTFOBins root | May 2026 | [writeup](HTB-Machines/Linux/Knife.md) |

</details>

---

## HTB Machines — Windows · 3 completed

<details>
<summary>View writeups</summary>

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Legacy | Easy | MS08-067 (CVE-2008-4250) — pre-auth RCE via SMB netapi32.dll stack overflow → NT AUTHORITY\SYSTEM | May 2026 | [writeup](HTB-Machines/Windows/Legacy.md) |
| Blue | Easy | MS17-010 / EternalBlue (CVE-2017-0143) — pre-auth SMB kernel pool corruption → NT AUTHORITY\SYSTEM | May 2026 | [writeup](HTB-Machines/Windows/Blue.md) |
| Jerry | Easy | Default Tomcat credentials (tomcat:s3cret) → WAR reverse shell deploy → NT AUTHORITY\SYSTEM | May 2026 | [writeup](HTB-Machines/Windows/Jerry.md) |

</details>

---

## HTB — Active Directory · 0 completed

<details>
<summary>View writeups</summary>

| Machine | Key Technique | Date | Writeup |
|---|---|---|---|
| — | — | — | — |

</details>

---

## HTB — Web Challenges · 0 completed

<details>
<summary>View writeups</summary>

| Challenge | Key Technique | Date | Writeup |
|---|---|---|---|
| — | — | — | — |

</details>

---

## TryHackMe — Rooms · 9 completed

<details>
<summary>View writeups</summary>

| Room | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Simple CTF | Easy | FTP anon, SQLi CVE-2019-9053, sudo vim | March 2026 | [writeup](TryHackMe/Rooms/Simple-CTF.md) |
| Bounty Hacker | Easy | FTP anon, Hydra SSH brute force, sudo tar | March 2026 | [writeup](TryHackMe/Rooms/Bounty-Hacker.md) |
| Basic Pentesting | Easy | SMB enum, SSH brute force, world-readable id_rsa, ssh2john | March 2026 | [writeup](TryHackMe/Rooms/Basic-Pentesting.md) |
| Fowsniff CTF | Easy | OSINT, POP3 brute force, MOTD cube.sh privesc | March 2026 | [writeup](TryHackMe/Rooms/Fowsniff-CTF.md) |
| Kenobi | Easy | SMB anon, NFS enum, ProFTPD mod_copy CVE-2015-3306, SUID PATH hijack | April 2026 | [writeup](TryHackMe/Rooms/Kenobi.md) |
| CMesS | Medium | VHost fuzzing, Gila CMS file upload RCE, world-readable .password.bak, tar wildcard injection | April 2026 | [writeup](TryHackMe/Rooms/CMesS.md) |
| UltraTech | Medium | Full port scan, JS source review, OS command injection (backtick), SQLite exfil via nc, MD5 cracking, Docker group privesc | April 2026 | [writeup](TryHackMe/Rooms/UltraTech.md) |
| Anonymous | Medium | FTP anon login + world-writable cron script → reverse shell, LXD group privesc (Alpine image build → privileged container → host filesystem mount) | April 2026 | [writeup](TryHackMe/Rooms/Anonymous.md) |
| TomGhost | Easy | GhostCat CVE-2020-1938 AJP file read → web.xml credentials → SSH → GPG crack (gpg2john + john) → sudo zip GTFOBins root | May 2026 | [writeup](TryHackMe/Rooms/TomGhost.md) |

</details>
