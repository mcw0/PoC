#!/usr/bin/env python2.7
#
# Dahua Enable / Disable Telnetd (JSON request for newer firmware)
# Author: bashis <mcw noemail eu> 2017
#
# You will need to know login/password for the Dahua device to get this code running
#
# Can't gurantee that this will work with all Dahua, working with my IPC and should work with DVR/NVR/HDVR (with newer FW)... etc
# (I know Dahua has been killing telnetd hard, deleted telnetd... and done lots of stupid stuff)
#

import sys
import socket
import urllib, urllib2, httplib
import json
import hashlib
import commentjson # pip install commentjson
import select
import string
import argparse
import base64
import ssl
import json
import os
import re

from pwn import *

#
# From: https://github.com/tothi/pwn-hisilicon-dvr
# Xiongmaitech and Dahua share same 48bit password hash
#
def sofia_hash(msg):
	h = ""
	m = hashlib.md5()
	m.update(msg)
	msg_md5 = m.digest()
	for i in range(8):
		n = (ord(msg_md5[2*i]) + ord(msg_md5[2*i+1])) % 0x3e
		if n > 9:
			if n > 35:
				n += 61
			else:
				n += 55
		else:
			n += 0x30
		h += chr(n)
	return h

#
# Dahua random MD5 on MD5 password hash
#
def dahua_md5_hash(Dahua_random, Dahua_realm, username, password):

	PWDDB_HASH = hashlib.md5(username + ':' + Dahua_realm + ':' + password + '').hexdigest().upper()
	PASS = ''+ username + ':' + Dahua_random + ':' + PWDDB_HASH + ''
	RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()

#	print "[i] MD5 hash:",PWDDB_HASH
#	print "[i] Random value to encrypt with:",Dahua_random
#	print "[i] Built password:",PASS
#	print "[i] MD5 generated login hash:",RANDOM_HASH
	return RANDOM_HASH

class HTTPconnect:

	def __init__(self, host, proto, verbose, credentials, Raw, noexploit):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.Raw = Raw
		self.noexploit = False
		self.noexploit = noexploit
	
	def Send(self, uri, query_headers, query_data,ID):
		self.uri = uri
		self.query_headers = query_headers
		self.query_data = query_data
		self.ID = ID

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
				print "[Verbose] User:",Basic_Auth[0],"password:",Basic_Auth[1]
			try:
				pwd_mgr = urllib2.HTTPpasswordMgrWithDefaultDahua_realm()
				pwd_mgr.add_password(None, url, Basic_Auth[0], Basic_Auth[1])
				auth_handler = urllib2.HTTPBasicAuthHandler(pwd_mgr)
				opener = urllib2.build_opener(auth_handler)
				urllib2.install_opener(opener)
			except Exception as e:
				print "[!] Basic Auth Error:",e
				sys.exit(1)

		if self.noexploit and not self.verbose:
			print "[<] 204 Not Sending!"
			html =  "Not sending any data"
			return html
		else:
			if self.query_data:
				req = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
				if self.ID:
					Cookie = 'DhWebClientSessionID={}'.format(self.ID)
					req.add_header('Cookie', Cookie)
			else:
				req = urllib2.Request(url, None, headers=self.query_headers)
				if self.ID:
					Cookie = 'DhWebClientSessionID={}'.format(self.ID)
					req.add_header('Cookie', Cookie)
			rsp = urllib2.urlopen(req)
			if rsp:
				print "[<] {} OK".format(rsp.code)

		if self.Raw:
			return rsp
		else:
			html = rsp.read()
			return html


class Dahua_Functions:

	def __init__(self, rhost, proto, verbose, credentials, raw_request, headers, User, SessionID):
		self.rhost = rhost
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.raw_request = raw_request
		self.noexploit = False
		self.headers = headers
		self.SessionID = SessionID
		self.User = User


	def Telnetd(self,cmd):
		self.cmd = cmd

		if self.cmd == 'enable':
			self.cmd = True
		elif self.cmd == 'disable':
			self.cmd = False
		else:
			print "[!] Telnetd: Invalid CMD ({})".format(self.cmd)
			return self.cmd

		query_args = {"method":"configManager.setConfig",
			"params": {
				"name":"Telnet",
				"table": {
					"Enable" : self.cmd,
					},
				},
			"session":self.SessionID,
			"id":1}

		print "[>] Enable telnetd: {}".format(self.cmd)
		result = json.load(self.JsonSendRequest(query_args))
		if not result['result']:
			print "Resp: ",result
			print "Error CMD: {}".format(self.string_request)
			return
		print result

	def logout(self):

		print "[i] Logging out"
		query_args = {"method":"global.logout",
			"params":"null",
			"session":self.SessionID,
			"id":10001}
		result = json.load(self.JsonSendRequest(query_args))
		if not result['result']:
			print result
			return
		elif result['result']:
			print result
		return result

	def JsonSendRequest(self,query_args):
		self.query_args = query_args

		URI = '/RPC2'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.raw_request,self.noexploit).Send(URI,self.headers,self.query_args,self.SessionID)
		return response

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
	INFO =  '[Dahua Telnetd enable/disable [JSON] (2017 bashis <mcw noemail eu>)]\n'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	noexploit = False
	raw_request = True
	rhost = '192.168.5.21'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	telnetd = 'enable'
#	creds = 'root:pass'
	credentials = False


#
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=True, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
		arg_parser.add_argument('--telnetd', required=False, help='Telnetd enable/disble [Default: '+ telnetd +']')
		arg_parser.add_argument('--username', required=True, help='Username [Default: None]')
		arg_parser.add_argument('--password', required=True, help='password [Default: None]')
		if credentials:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ credentials + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
		arg_parser.add_argument('--noexploit', required=False, default=False, action='store_true', help='Simple testmode; With --verbose testing all code without exploiting [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: {}\n".format(str(e))
		sys.exit(1)

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

	if credentials and args.auth:
		credentials = args.auth

	if args.telnetd:
		telnetd = args.telnetd

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

	# Check if RPORT is valid
	if not Validate(verbose).Port(rport):
		print "[!] Invalid RPORT - Choose between 1 and 65535"
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

	rhost = rhost + ':' + rport

	headers = {
		'Connection': 'close',
		'Content-Type'	:	'application/x-www-form-urlencoded; charset=UTF-8',
		'Accept'	:	'*/*',
		'X-Requested-With'	:	'XMLHttpRequest',
		'X-Request'	:	'JSON',
		'User-Agent':'DAHUA-dhdev/1.0'
		}


	try:

		#
		# Request SessionID
		#
		print "[>] Requesting session ID"
		query_args = {"method":"global.login",
			"params":{
				"userName":username,
				"password":"",
				"clientType":"Web3.0"},
			"id":10000}

		URI = '/RPC2_Login'
		response = HTTPconnect(rhost,proto,verbose,credentials,raw_request,noexploit).Send(URI,headers,query_args,None)
		Dahua_json = json.load(response)
		if verbose:
			print json.dumps(Dahua_json,sort_keys=True,indent=4, separators=(',', ': '))

		SessionID = Dahua_json['session']

		#
		# Gen3 login
		#

		if Dahua_json['params']['encryption'] == 'Default':
			print "[i] Detected generation 3 encryption"

			RANDOM_HASH = dahua_md5_hash(Dahua_json['params']['random'],Dahua_json['params']['realm'], username, password)
			print "[>] Logging in"

			query_args = {"method":"global.login",
				"session":SessionID,
				"params":{
					"userName":username,
					"password":RANDOM_HASH,
					"clientType":"Web3.0",
					"authorityType":"Default"},
				"id":10000}

			URI = '/RPC2_Login'
			response = HTTPconnect(rhost,proto,verbose,credentials,raw_request,noexploit).Send(URI,headers,query_args,SessionID)
			Dahua_json = json.load(response)
			if verbose:
				print Dahua_json
			if Dahua_json['result'] == True:
				print "[<] Login OK"
			elif Dahua_json['result'] == False:
				print "[<] Login failed: {} ({})".format(Dahua_json['error']['message'],Dahua_json['params']['error'])
				sys.exit(1)

		#
		# Gen2 login
		#

		elif Dahua_json['params']['encryption'] == 'OldDigest':
			print "[i] Detected generation 2 encryption"

			HASH = sofia_hash(password)

			print "[>] Logging in"

			query_args = {"method":"global.login",
				"session":SessionID,
				"params":{
					"userName":username,
					"password":HASH,
					"clientType":"Web3.0",
					"authorityType":"Default"},
				"id":10000}

			URI = '/RPC2_Login'
			response = HTTPconnect(rhost,proto,verbose,credentials,raw_request,noexploit).Send(URI,headers,query_args,SessionID)
			Dahua_json = json.load(response)
			if verbose:
				print Dahua_json

			if Dahua_json['result'] == True:
				print "[<] Login OK"
			elif Dahua_json['result'] == False:
				print "[<] Login failed: {}".format(Dahua_json['error']['message'])
				sys.exit(1)

		elif Dahua_json['params']['encryption'] == 'Basic':
			print "LDAP / AD not supported"
			sys.exit(1)
		elif Dahua_json['params']['encryption'] == 'WatchNet':
			print "Watchnet not supported"
			sys.exit(1)
		else:
			print "Unknown encryption {}".format(Dahua_json['params']['encryption'])
			sys.exit(1)

		# Enable / Disable Telnetd
		response = Dahua_Functions(rhost,proto,verbose,credentials,raw_request,headers,username,SessionID).Telnetd(telnetd)
		# Logout
		responce = Dahua_Functions(rhost,proto,verbose,credentials,raw_request,headers,username,SessionID).logout()

	except Exception as e:
		print "[!] What happen? ({})".format(e)
		try:
			# Something screwed up, try to logout
			Dahua_Functions(rhost,proto,verbose,credentials,raw_request,headers,username,SessionID).logout()
			sys.exit(1)
		except Exception as e:
			# Not even logout working... wtf?
			print "[!] What happen again? ({})".format(e)
			sys.exit(1)


