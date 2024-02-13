---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Anthem - Fácil
date: 2024-02-12 23:47:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, windows, web, facil, RDP, crackmapexec]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/Anthem.gif){: w="100" h="100" .left}

---
# **CTF - Blueprint**
---
---
## **Enumeração**


### nmap

```shell
╭─      ~/thm/anthem         INT ✘  14s      
╰─ sudo nmap -sV -Pn -sS --min-rate 5000 -stats-every 5 -p- -oN nmap 10.10.56.228
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-09 23:26 -03
Nmap scan report for 10.10.56.228
Host is up (0.22s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.46 seconds
```
{: .nolineno }

Porta 80 blog:
![alt text](/assets/img/anthem1.png)

### ffuf

```shell
╭─      ~/thm/anthem            
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 200 -u http://10.10.56.228/FUZZ -e .html,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.56.228/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Blog                    [Status: 200, Size: 5394, Words: 1311, Lines: 127, Duration: 760ms]
Archive                 [Status: 301, Size: 123, Words: 6, Lines: 4, Duration: 1778ms]
RSS                     [Status: 200, Size: 1873, Words: 240, Lines: 30, Duration: 1087ms]
Search                  [Status: 200, Size: 3468, Words: 520, Lines: 93, Duration: 866ms]
SiteMap                 [Status: 200, Size: 1041, Words: 94, Lines: 30, Duration: 1824ms]
archive                 [Status: 301, Size: 123, Words: 6, Lines: 4, Duration: 3680ms]
authors                 [Status: 200, Size: 4115, Words: 769, Lines: 112, Duration: 3017ms]
blog                    [Status: 200, Size: 5394, Words: 1311, Lines: 127, Duration: 5874ms]
categories              [Status: 200, Size: 3541, Words: 561, Lines: 104, Duration: 959ms]
install                 [Status: 302, Size: 126, Words: 6, Lines: 4, Duration: 2122ms]
robots.txt              [Status: 200, Size: 192, Words: 17, Lines: 11, Duration: 1935ms]
robots.txt              [Status: 200, Size: 192, Words: 17, Lines: 11, Duration: 2169ms]
rss                     [Status: 200, Size: 1873, Words: 240, Lines: 30, Duration: 4459ms]
search                  [Status: 200, Size: 3468, Words: 520, Lines: 93, Duration: 8148ms]
sitemap                 [Status: 200, Size: 1041, Words: 94, Lines: 30, Duration: 5927ms]
tags                    [Status: 200, Size: 3594, Words: 579, Lines: 105, Duration: 9615ms]
umbraco                 [Status: 200, Size: 4078, Words: 710, Lines: 96, Duration: 527ms]
```
{: .nolineno }

### robots.txt
A primeira linha aparenta ser uma senha.
![alt text](/assets/img/anthem2.png){: .normal}

Acessando `http://10.10.56.228/umbraco/` tem a tela de login.
![alt text](/assets/img/anthem3.png)

Em `http://10.10.56.228/authors` tem uma flag !
![alt text](/assets/img/anthem4.png)

Flag no código fonte da pagina inicial
![alt text](/assets/img/anthem5.png){: .normal}

Outra flag no código fonte do post `http://10.10.56.228/archive/we-are-hiring/`  
![alt text](/assets/img/anthem6.png){: .normal}

No outro post também tem no código fonte.  
![alt text](/assets/img/anthem7.png){: .normal}

Pra obter o nome de admin precisa pesquisar por esse poema que está no segundo post.
Odeio esses CTFS que envolvem esses tipos de coisas fora da realidade. XD  
![alt text](/assets/img/anthem8.png){: .normal}  
`Solomon Grundy`  

## **Acesso**
Tentativas de Login via RDP com usuário
SG deu certo junto da possível senha que estava em robots.txt
![alt text](/assets/img/anthem9.png)

### Primeira Flag no desktop
![alt text](/assets/img/anthem10.png)

## **Exploração e Escalação de Privilégio**

Alterando opções de pasta pra mostrar arquivos ocultos; encontrado pasta `backup` no c:/, sem permissões de acesso, contornado adicionado o usuário com permissão total na pasta.  

![alt text](/assets/img/anthem11.png){: .normal}  

Arquivo contem um texto que pode ser possível senha do admin:  

![alt text](/assets/img/anthem12.png){: .normal}  

Executei o comando `runas /user:administrator cmd.exe` pra abrir um novo terminal como admin.
![alt text](/assets/img/anthem13.png)

### Segunda Flag
E ai está a ultima flag:
![alt text](/assets/img/anthem14.png)

Pra estudo criei um usuário backdoor chamado pentest:senha123
Criar usuário.  
`net user /add pentest senha123`  

Adicionando ao grupo Admin  
`net localgroup administrators /add pentest`  

Adicionado ao grupo RDP pra poder logar via RDP  
`net localgroup "Remote Desktop Users" /add pentest`  

Logado nos 2 usuários via rdp.
![alt text](/assets/img/anthem15.png)