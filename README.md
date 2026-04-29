# HTB and TryHackMe Writeups — Jay Patel

Building toward a penetration testing career through HTB Academy CPTS and hands-on lab work.
Every writeup in this repo documents the full attack path — enumeration, exploitation, and
privilege escalation — with the exact commands, reasoning, and lessons learned at each step.

HTB writeups are only published after a machine is confirmed retired.

---

## Progress

| Category | Completed | Target |
|---|---|---|
| HTB Linux | 1 | 15+ |
| HTB Windows | 0 | 10+ |
| HTB Active Directory | 0 | 10+ |
| HTB Web Challenges | 0 | 9+ |
| TryHackMe Rooms | 8 | Ongoing |
| **Total** | **9** | **40+** |

---

## HTB Machines — Linux · 1 completed

<details>
<summary>View writeups</summary>

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Postman | Easy | Redis unauthenticated file write, SSH key injection, ssh2john, Webmin 1.910 RCE (CVE-2019-12840) | April 2026 | [writeup](HTB-Machines/Linux/Postman.md) |

</details>

---

## HTB Machines — Windows · 0 completed

<details>
<summary>View writeups</summary>

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| — | — | — | — | — |

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

## TryHackMe — Rooms · 8 completed

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

</details>
