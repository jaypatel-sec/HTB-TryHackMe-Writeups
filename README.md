# HTB and TryHackMe Writeups — Jay Patel

I am a penetration tester working through HTB Academy CPTS toward OSCP.
Every writeup in this repo documents the full attack path — enumeration,
exploitation, and privilege escalation — with the commands, reasoning, and
lessons learned at each step.

HTB writeups are only published after a machine is confirmed retired.

---

## HTB Machines — Linux

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Postman | Easy | Redis unauthenticated file write, SSH key injection, ssh2john, Webmin 1.910 RCE (CVE-2019-12840) | April 2026 | [writeup](HTB-Machines/Linux/Postman.md) |

---

## HTB Machines — Windows

| Machine | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| — | — | — | — | — |

---

## HTB — Active Directory

| Machine | Key Technique | Date | Writeup |
|---|---|---|---|
| — | — | — | — |

---

## HTB — Web Challenges

| Challenge | Key Technique | Date | Writeup |
|---|---|---|---|
| — | — | — | — |

---

## TryHackMe — Rooms

| Room | Difficulty | Key Technique | Date | Writeup |
|---|---|---|---|---|
| Simple CTF | Easy | FTP anon, SQLi CVE-2019-9053, sudo vim | March 2026 | [writeup](TryHackMe/Rooms/Simple-CTF.md) |
| Bounty Hacker | Easy | FTP anon, Hydra SSH brute force, sudo tar | March 2026 | [writeup](TryHackMe/Rooms/Bounty-Hacker.md) |
| Basic Pentesting | Easy | SMB enum, SSH brute force, world-readable id_rsa, ssh2john | March 2026 | [writeup](TryHackMe/Rooms/Basic-Pentesting.md) |
| Fowsniff CTF | Easy | OSINT, POP3 brute force, MOTD cube.sh privesc | March 2026 | [writeup](TryHackMe/Rooms/Fowsniff-CTF.md) |
| Kenobi | Easy | SMB anon, NFS enum, ProFTPD mod_copy CVE-2015-3306, SUID PATH hijack | April 2026 | [writeup](TryHackMe/Rooms/Kenobi.md) |
| CMesS | Medium | VHost fuzzing, Gila CMS file upload RCE, world-readable .password.bak, tar wildcard injection | April 2026 | [writeup](TryHackMe/Rooms/CMesS.md) |
| UltraTech | Medium | Full port scan, JS source review, OS command injection (backtick), SQLite exfil via nc, MD5 cracking, Docker group privesc | April 2026 | [writeup](TryHackMe/Rooms/UltraTech.md) |

---

## Progress

| Category | Completed | Target |
|---|---|---|
| HTB Linux | 1 | 15+ |
| HTB Windows | 0 | 10+ |
| HTB Active Directory | 0 | 10+ |
| HTB Web Challenges | 0 | 9+ |
| TryHackMe Rooms | 7 | Ongoing |
| **Total** | **8** | **40+** |
