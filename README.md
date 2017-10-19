# PoC
misc PoC 

Axis
---
2017-10-19
One old forgotten fuzzing back in Q3/2016 that lead to RCE (PoC: Remote connect back shell) and remote read of /etc/shadow.
Reported to Axis and fixed in Q3/2016, still posting here now as it may be good hint.

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

