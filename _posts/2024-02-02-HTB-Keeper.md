---
description: CTF do Hack The Box como fiz e anotações.
title: HackTheBox - Keeper - Fácil
date: 2024-02-02 01:48:00 +/-0300
categories: [CTF, HackTheBox]
tags: [ctf, hackthebox, linux, keepass, web, facil, ]     # TAG names should always be lowercase
show_image_post: true
---
![logo](/assets/img/keeper.png){: w="100" h="100" .left}

---
# **CTF - Hospital**
---
---
## **Enumeração**

### nmap

```shell
─ sudo nmap -sV -Pn -sS --min-rate 10000 --stats-every=7s 10.10.11.227 -p- -oN nmap     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-31 20:51 -03
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for 10.10.11.227
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.20 seconds
```
{: .nolineno }

Dominios adicionados ao `/etc/hosts`  
`tickets.keeper.htb`  
`keeper.htb`  
### Aplicação Web
Página inicial contém link para  -> `http://tickets.keeper.htb/rt/`
![Alt text](/assets/img/keeper1.png)
![Alt text](/assets/img/keeper2.png)

Pesquisando sobre no google sugeriu uma pesquisa, default password, <https://docs.bestpractical.com/rt/4.4.4/README.html> e aqui na documentação diz 
`root:password`

Conseguimos acesso a aplicação.

Encontrado um usuário na aplicação:  
`lnorgaard:Welcome2023!`  
`lnorgaard@keeper.htb`
![Alt text](/assets/img/keeper3.png)

## **Acesso/Exploração**

Com as credenciais foi possível logar via ssh
![Alt text](/assets/img/keeper5.png)

`You Have mail` diz ao logar na ssh.
Rodei o linpeas, e mostrou a pasta dos email
Lendo o arquivo de email lá faz referencia a um ticket da aplicação
> `http://keeper.htb/rt/Ticket/Display.html?id=300000`
Attached to this ticket is a crash dump of the keepass program. Do I need to
update the version of the program first...?
{: .prompt-tip}
Acessando o ticket
![Alt text](/assets/img/keeper4.png)

O usuário diz que removeu o anexo do ticket e colocou em sua pasta home.
Encontrado arquivos:  
`RT30000.zip -> KeePassDumpFull.dmp `  
`passcodes.kdbx `  

Pesquisando no google:  
`KeePassDumpFull.dmp` provavelmente foi obtido usando do exploit https://github.com/vdohney/keepass-password-dumper provavelmente o root testou se o keepass estava vulnerável a isso e no ticket diz sobre update da versão do keepass.  
`passcodes.kdbx` é o DB do keepass, pesquisando é possível obter a hash dele e tentar crackear no john.

```shell
keepass2john passcodes.kdbx > hash.txt 
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
{: .nolineno }
Sem sucesso
### Crackeando a senha
Pesquisa por “read keepassdump”
<https://github.com/matro7sh/keepass-dump-masterkey>
![Alt text](/assets/img/keeper7.png)

Funcionaria fazer uma mascara no john, rodei um pouco mas desisti. ChatGPT fez o caculo e disse -Essa multiplicação resultará em um número extremamente grande, que não é prático calcular aqui.  
`john hash.txt --mask="?l?u?s?d?l?u?s?ddgr?l?u?s?dd med fl?l?u?s?dde"`  

Pesquisando em writeup: você deve pesquisar por essas senhas no google que vai resultar nome de um site ou um prato.  
![Alt text](/assets/img/keeper8.png)  

## **Escalando privilégio**
Abrindo o keepass usando a senha:  
`rødgrød med fløde`  
Encontramos chave ssh do root
![Alt text](/assets/img/keeper9.png)  

Salvei os dados em putty.ppk
E pra converter o comando:  
`puttygen putty.ppk -O private-openssh -o sshroot`  
Não vem no kali tem que instalar com    
`sudo apt install putty-tools`  
![Alt text](/assets/img/keeper10.png)

### Logando via ssh com root
![Alt text](/assets/img/keeper11.png)
![Alt text](/assets/img/keeper12.png)

**Conhecimento adquiridos:**
- Pesquisar qualquer coisa no google, no caso as possíveis senhas.
- Ferramentas e exploits
- Converter chave ssh putty

![Alt text](/assets/img/keeper13.png)
