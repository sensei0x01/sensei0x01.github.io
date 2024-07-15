---
title: "FRISTILEAKS 1.3: Boot-to-Root"
date: 2024-06-28 17:17 +0300
categories: [VulnHub, Easy-VulnHub]
tags: [CTF, Walkthrough, Weak Encryption, Stored Credentials, Kernel Exploit, Cron Jobs, Unrestricted File Upload]
author: sensei0x01
image: "/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/banner.png"
---

## Description

FRISTILEAKS 1.3 is a vulnerable virtual machine available on VulnHub, designed for security enthusiasts and penetration testers to practice and enhance their skills. The machine simulates a realistic environment with various security flaws, requiring users to explore and exploit vulnerabilities to gain root access. The challenges include discovering hidden directories, exploiting web vulnerabilities, and using privilege escalation techniques. FRISTILEAKS 1.3 is ideal for those looking to test their knowledge in a controlled and legal setting while preparing for real-world scenarios.

|**Box**|FRISTILEAKS 1.3|
|:---:|:---:|
|**OS**|Linux|
|**Difficulty**|Easy|
|**Creator**|[Ar0xA](https://www.vulnhub.com/author/ar0xa,203/) |

---

## 🖥️Lab Setup

- VMware workstation
- Kali Linux VM
- [FRISTILEAKS 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/) VM

---

## ⬇️Installation

The VM file for this machine is an `.ova` file, which is an open standard that contains multiple files packaged together. To open it, use VMware Workstation:

### Step 1: Open the OVA File

From tabs bar Go to the **File** > **Open**.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic1.png)

### Step 2: Browse to the OVA File

1. In the open file dialog, navigate to your OVA file's location.
2. Select the OVA file and click **Open**.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic2.png)

### Step 3: Import the OVA

1. VMware Workstation will start the import process.
2. You may be prompted to accept the license agreement if the OVA file includes one.
3. Choose the location where you want to store the virtual machine files.
4. Click **Import**.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic3.png)

### Step 4: Change network adapter settings

1. Change Network connection type to `NAT`.
2. Change MAC address to this value `08:00:27:A5:A6:76`.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic4.png)

### Step 5: Power on the machine

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic5.png)

---

## 🔍Host Discovery

We already know the IP address assigned to this machine from the previous screenshot. However, let’s assume we don’t know it. `netdiscover` is a great tool to identify active hosts on your network.

```shell
sudo netdiscover -i eth0 -r 192.168.109.0/24
```

**"192.168.109.0/24"** is the subnet address of the NAT virtual network in my VMware Workstation. It might be different on your device. This command will show all active devices on your network.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic6.png)

As can be seen from the scanning results above, **"192.168.109.149"** is the target IP address. The other active hosts are the DNS server, DHCP server, and the VMware default gateway.

---

## 🕵🏼Enumeration

Now that we know the IP address of the target machine, it’s time to scan the ports to gain a deeper understanding of the attack surface. `nmap` is a very handy tool for this purpose.

```shell
target=192.168.109.149
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
# Nmap 7.94SVN scan initiated Fri Jun 28 03:31:11 2024 as: nmap -sS -T4 -p- -sVC -O -oN scan-result.txt 192.168.109.149
Nmap scan report for 192.168.109.149
Host is up (0.00056s latency).
Not shown: 65396 filtered tcp ports (no-response), 138 filtered tcp ports (host-prohibited)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
MAC Address: 08:00:27:A5:A6:76 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc|media device|webcam
Running (JUST GUESSING): Linux 2.6.X|3.X|4.X (97%), Drobo embedded (89%), Synology DiskStation Manager 5.X (89%), LG embedded (88%), Tandberg embedded (88%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/h:drobo:5n cpe:/a:synology:diskstation_manager:5.2
Aggressive OS guesses: Linux 2.6.32 - 3.10 (97%), Linux 2.6.32 - 3.13 (97%), Linux 2.6.39 (94%), Linux 2.6.32 - 3.5 (92%), Linux 3.2 (91%), Linux 3.2 - 3.16 (91%), Linux 3.2 - 3.8 (91%), Linux 2.6.32 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.9 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 28 03:33:34 2024 -- 1 IP address (1 host up) scanned in 143.50 seconds
```
From the results above, we have identified only one open port, which is port **80** (HTTP). Additionally, the **robots.txt** file has revealed three directories: `/cola`{: .filepath}, `/sisi`{: .filepath}, and `/beer`{: .filepath}. Let’s visit them:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic7.png)

I didn’t find anything but the above picture. So I’ll fuzz for any directory that could be useful. To do this I’ll use `gobuster`:

```shell
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u http://$target -o site-dir.txt
```

Output:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic8.png)

Let’s check `/images`{: .filepath} directory and see its content:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic9.png)

The findings are illustrated in the two attached pictures:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic10.png)

Let’s download them and check their metadata perhaps we will find something useful. I’ll use `exiftool` for this purpose.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic11.png)

After inspecting the metadata without finding anything of interest, I continued investigating and discovered that the word **"fristi"** mentioned in the first picture is actually a directory. Upon visiting it, I found this page:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic12.png)

---

## 👨🏻‍💻Exploitation

From the previous section, we have found a login page. Typically, I attempt default credentials on any login page, such as:

- admin: admin
- admin: password

But none of them worked for me. Therefore, I attempted an SQL injection to bypass authentication:

- admin: `' or 1=1-- -`

But unfortunately, it didn’t work as well. I was always redirected to this page:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic13.png)

Next, I checked the page source hoping to find commented credentials or other helpful information. I discovered something intriguing: the picture used on the login page was base64 decoded, and I found another commented base64 data. Besides that, I found a potential username **"eezeepz"**.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic14.png)

I created a simple HTML page to decode this data and see its content.

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Display Image</title>
  </head>
  <body>
    <img src='data:image/png;base64, iVBORw0KGg... <!-- Base64 data -->' />
  </body>
</html>
```

After decoding the data, I found this message:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic15.png)

Initially, I thought it might be trolling, which frustrated me. However, after reconsidering, I wondered if this could be the password. I decided to try it out with the potential username **"eezeepz"**.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic16.png)

Thankfully, the assumption was correct, and I successfully logged in.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic17.png)

After logging in, I discovered an upload functionality, so I attempted to upload a PHP reverse shell code. You can find a PHP reverse shell code preinstalled on Kali Linux at this path: `/usr/share/webshells/php/php-reverse-shell.php`{: .filepath}. Remember to modify the IP address and port to suit your requirements before using it. This can be done using any text editor.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic18.png)

There are some validations that we need to bypass. The easiest and most direct way is to add one of these extensions to the file’s name:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic19.png)

After that, I attempted to upload the file, and it was successful.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic20.png)

Now the file has been successfully uploaded to this path: `/uploads/<file_name>`{: .filepath}. To establish the reverse shell, I needed to run a listener. For this, I used `nc`.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic21.png)

Consequently, I visited the next URL to execute the payload embedded in the uploaded file on the target machine:

```
http://192.168.109.149/fristi/uploads/shell.php.jpg
```

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic22.png)

Bingo! Now that the shell is established, I upgraded it to an interactive shell. This process has been explained in a previous write-up of mine; you can check it out there: [Kioptrix 2: Boot-to-Root](https://sensei0x01.github.io/posts/kioptrix-2-boot-to-root/).

---

## 💥Post-Exploitation

After obtaining an interactive shell, I checked the `/var/www`{: .filepath} directory and found a file named **"notes.txt"**. Its contents were as follows:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic23.png)

After checking the home directory of `/home/eezeepz`{: .filepath}, I found another **"notes.txt"** file that held a message saying:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic24.png)

To clarify, there is a crontab script that runs every minute with admin privileges. This script executes commands from the file `/tmp/runthis`{: .filepath}. The command inside it must start with `/home/admin`{: .filepath}.


The `/home/admin`{: .filepath} directory includes the following 7 binaries: `chmod`, `df`, `cat`, `echo`, `ps`, `grep`, and `egrep`.

So, what I’ll do is insert a command inside `/tmp/runthis`{: .filepath} file to copy the `/bin/bash` binary to `/tmp/bash` using the cat command:

```shell
echo "/home/admin/cat /bin/bash > /tmp/bash" > /tmp/runthis
```

Next, adding the commad that will change the permissions of the copied file to SUID:

```shell
echo "/home/admin/chmod 4777 /tmp/bash" >> /tmp/runthis
```

After waiting for a minute I had a copy with SUID privileges:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic25.png)

Now If I run this binary with the `-p` argument I’ll have admin privileges:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic26.png)

Consequently, I tried to see if I could run any binary with `root` privileges using `sudo -l` but I got asked to enter a password :/

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic27.png)

Since we couldn't check the sudo list, let’s check `/home/admin`{: .filepath} directory:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic28.png)

As shown in the screenshot above, there are two text files. Let’s check their content:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic29.png)

It looks like the contents of the text files are encrypted. Let’s take a look at `cryptpass.py` as it is most likely the script used to encrypt them.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic30.png)

According to the code shown, the function `encodeString` takes a string, applies `base64` encoding, reverses it, and finally applies `rot13` encoding. 

To reverse this process I built the next Python script:

```python
import base64, codecs, sys

def decodeString(encoded_str):
    # Decode the ROT13 encoding
    rot13_decoded = codecs.decode(encoded_str, 'rot13')
    # Reverse the string
    reversed_string = rot13_decoded[::-1]
    # Decode the base64 string
    base64_decoded = base64.b64decode(reversed_string)
    return base64_decoded

if __name__ == "__main__":
    encoded_str = sys.argv[1]
    original_str = decodeString(encoded_str)
    print(original_str.decode('utf-8'))
```

Applying this code on the content of **"whoisyourgodnow.txt"** yielded the password **"LetThereBeFristi!"** Similarly, using the same approach on **"cryptedpass.txt"** gave the password **"thisisalsopw123"**. Based on the file ownership, it is likely that the first password belongs to the user **"fristigod"**, and the second one to the user **"admin"**.

- fristigod : LetThereBeFristi!
- admin : thisisalsopw123

Let’s log in with **"admin"** and list if there is any command that could be run as `root`.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic31.png)

Since there is no sudo permissions for the user **"admin"** let’s switch to **"fristigod"**:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic32.png)

From the previous screenshot, there are two points to focus on.
1. User **"fristigod"** can run `doCom` file as `root`.
2. In the last line, the name is shortened to `fristi`.

I’m going to use the `doCom` file to execute `/bin/bash`, which will grant me root privileges.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic33.png)

Now that we have root privileges, let’s check the root directory for the flag file.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic34.png)

![Alt Text](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExbXVwemNjM24xbmVzOXlvazFpcHA0ZmJybGtscHM0cDNzOWk5ZTRkbyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/iioMvMjYxLRWPTH1km/giphy.gif)

## ➕Bonus

During my enumeration, I found that the Kernel version was vulnerable to [DirtyCow](https://github.com/firefart/dirtycow) and [PERF_EVENTS](https://www.exploit-db.com/exploits/25444) Local Privilege Escalation.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic35.png)

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic36.png)

We have already exploited the PERF_EVENTS In a previous write-up: [Kioptrix 2: Boot-to-Root](https://sensei0x01.github.io/posts/kioptrix-2-boot-to-root/).

This time let’s try to exploit the DitryCow vulnerability.

### Step 1: Create a simple web server to transfer data

This could be done using Python. Go to the directory where the exploitation code is located and run this command:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic37.png)

### Step 2: Download the exploitation code on victim machine

The command used for this purpose was `wget`. Go to a directory where you have write permission and use this commnad:

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic38.png)

### Step 3: Compile the exploitation code

Since the exploitation code is written in `C`, you must compile it uisng `gcc`.

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic39.png)

### Step 4: Run the exploitation

Run the exploitation binary and watch the magic!

![Desktop View](/assets/img/posts/2024-06-28-fristileaks-1-3-boot-to-root/pic40.png)

That’s it for today. I hope this writeup was useful for you folks; stay safe and keep pinging :)

3NGnyAaoyAUr 🤔😜