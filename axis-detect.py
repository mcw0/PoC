#!/usr/bin/env python2.7
# 
# [SOF]

import sys
import string
import socket
import time
import argparse
import urllib, urllib2, httplib
import base64
import ssl
import re

class HTTPconnect:

	def __init__(self, host, proto, verbose, creds, noexploit):
		self.host = host
		self.proto = proto
		self.verbose = verbose
		self.credentials = creds
		self.noexploit = noexploit
	
	def Send(self, uri):

		# The SSI daemon are looking for this, and opens a new FD (5), but this doesn't actually
		# matter for the functionality of this exploit, only for future references.
		headers = { 
			'User-Agent' : 'MSIE',
		}

		# Connect-timeout in seconds
		timeout = 5
		socket.setdefaulttimeout(timeout)

		url = '%s://%s%s' % (self.proto, self.host, uri)

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
		else:
			data = None
			req = urllib2.Request(url, data, headers)
			rsp = urllib2.urlopen(req)
			if rsp:
				print "[<] %s OK" % rsp.code
				html = rsp.read()
		return html

class DetectTarget:
#
# Detect Model and Firmware version of target.
# Using the most common files for detection that cover most of targets.
# thirdpartysoftwarelicense.txt could be used as well, but it's +260 kb, and don't work with all older targets.
#

	def __init__(self,targetIP,proto,verbose,creds):
		self.targetIP = targetIP
		self.verbose = verbose
		self.proto = proto
		self.creds = creds

	def Version(self,e,verbose=False):
		self.e = e
		Vendor = False
		Product = False
		Version = False

		
		# Define what URI we will use for detection
		URI = [
		'/incl/top_incl.shtml',		# MPQT/PACS
		'/httpDisabled.shtml',		# MPQT/PACS
		'/incl/version.shtml',		# MPQT/PACS
		'/incl/top_incl_popup.shtml',	# MPQT/PACS
		'/axis-cgi/prod_brand_info/getbrand.cgi',	# AXIS Companion Recorder/MPQT/PACS
		'/axis-release/releaseinfo',			# Version: x.xx.x
		'/',
		'/index.shtml',
		# Default l/p modem1/modem1
		#'/cgi-bin/webdvr.cgi', # DGI-DVR board, Axis Developer Board LX release 2.1.0'
		# Default l/p root/pass
		#'/admin-bin/editcgi.cgi?file=/usr/html/RELEASENOTES', # VertX boards, Axis Developer Board LX release 2.2.0
		#'/user/scan/scan.shtml', # Axis 70U Network Documents Server
		'/thirdpartysoftwarelicenses.txt' # Last resource of detection as it's big file
		]

		#
		# Detects Product number and Firmware version on almost all Axis MPQT, PACS and older products
		#
		for tmp in range(0,len(URI)):
			try:
				if Vendor and Product:
					print "[>] Trying to detect firmware version...(%d)" % int(tmp+1)
				else:
					print "[>] Trying to detect target...(%d)" % int(tmp+1)

				html = HTTPconnect(self.targetIP,self.proto,self.verbose,self.creds,False).Send(URI[tmp])

				# Let's split up the html and remove somce chars, so we can find the info... 
				html = re.split('[()<>?="\n_& ]',html)[0:500]
#				if self.verbose:
#					print "[Verbose] Details",html

				for axis in range (0,len(html)):
					# Search for identification, from oldest printservers to newest cam's
					# (Old cams has all needed info in '/incl/version.shtml')
					if html[axis] == 'AXIS' or html[axis] == 'Axis' or html[axis] == 'axis':
						if not Vendor and not Product and html[axis+1] != ',':
							Vendor = 'AXIS'
							Product = html[axis+1]
							print "[i] Target found:",Vendor,Product
							print "[i] Trying to detect firmware version...(%d)" % int(tmp+1)

						for axis in range (axis,len(html)):
							if Vendor and Product and Version:
								break
							if html[axis] == 'ver':
								# Version must have dots
								if html[axis+1].find('.') == True:
									Version = html[axis+1]
									print "[i] Version found:",Version
									break
							# First entry with dots found after 'Vendor' and 'Products'
							# in 'thirdpartysoftwarelicenses.txt' is Version
							elif html[axis].find('.') == True:
								Version = html[axis]
								print "[i] Version found:",Version
								break
							else:
								continue
						else:
							print "[i] Version not found..."
							continue

					# More or less for testing, actually no use for this..
					elif html[axis] == 'version:':
					# Version must have dots
						if html[axis+1].find('.') == True:
							Version = html[axis+1]
							print "[i] Version found:",Version
							break
					elif html[axis] == '16Ch':
						#'16Ch', 'DVR', '', 'Ver', '0.6.0.1',
						if html[axis+1] == 'DVR':
							Vendor = 'AXIS'
							Product = 'Developer Board LX release 2.1.0 - DGI-DVR'
							Version = html[axis+4]
							print "[i] Target found:",Vendor,Product,Version
							continue
						else:
							continue

				else:
					# /incl/version.shtml, most common with Version only
					# split is 2, since we split with \n too. (x.xx.x\n -> 'x.xx.x','')
					if len(html) == 2 and html[0].find('.') == True:
						Version = html[0]
						print "[i] Version found:",Version
					if Vendor and Product and Version:
						target = Vendor
						target += " "
						target += Product
						target += " "
						target += Version
						print "[i] Verbose: {}".format(target.split())
						return
					continue
			except urllib2.HTTPError as e:
				print "[<]",e.reason
				continue
			except Exception as e:
				print "[!] Detect of target failed: %s" % str(e)
				sys.exit(1)

		print "[!] Remote target are not supported!"
		sys.exit(0)

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
	INFO = '[Axis Communications detect of remote target 2016 bashis <mcw noemail eu>]'
	INFO1 = '[Detection technique/dictionary recognising products from < 1998 to > 2019]'
	HTTP = "http"
	HTTPS = "https"
	proto = HTTP
	verbose = False
	rhost = '192.168.57.20'	# Default Remote HOST
	rport = '80'		# Default Remote PORT
#	creds = 'root:pass'
	creds = False

#
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
                description=('[*]' + INFO + '\n[*]' + INFO1 + '\n'))
		arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
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
	print "[*]",INFO1

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
	print "[i] Remote IP:",rhost
	print "[i] Remote PORT:",rport

	rhost = rhost + ':' + rport

#
# Try to detect remote target
#
	DetectTarget(rhost,proto,verbose,creds).Version(0)

#
# [EOF]
#
