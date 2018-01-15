#!/usr/bin/env python2.7
#
# Deobfuscate strings/login/password/cryptokey in misc Foscam IPC binaries and libs
#
# //bashis 2018
#
import sys
import os
import StringIO
import subprocess
import argparse

#
# raw objdump to demo how it works
#
EXAMPLE = StringIO.StringIO("""
	1dcf8:	e3a02080 	mov	r2, #128	; 0x80
	1dcfc:	e1a00007 	mov	r0, r7
	1dd00:	e1a0100a 	mov	r1, sl
	1dd04:	ebffd502 	bl	13114 <memset@plt>
	1de58:	e59f1bfc 	ldr	r1, [pc, #3068]	; 1ea5c <_start@@Base+0xb294>
	1de5c:	ea00004d 	b	1df98 <_start@@Base+0xa7d0>
	1de60:	e3a0c002 	mov	ip, #2
	1de64:	e58dc024 	str	ip, [sp, #36]	; 0x24
	1de68:	e58dc05c 	str	ip, [sp, #92]	; 0x5c
	1de6c:	e58dc064 	str	ip, [sp, #100]	; 0x64
	1de70:	e28cc008 	add	ip, ip, #8
	1de74:	e3a0e004 	mov	lr, #4
	1de78:	e58dc070 	str	ip, [sp, #112]	; 0x70
	1de7c:	e28cc011 	add	ip, ip, #17
	1de80:	e58de004 	str	lr, [sp, #4]
	1de84:	e3a0300b 	mov	r3, #11
	1de88:	e58de01c 	str	lr, [sp, #28]
	1de8c:	e58da03c 	str	sl, [sp, #60]	; 0x3c
	1de90:	e58de040 	str	lr, [sp, #64]	; 0x40
	1de94:	e3a0a03c 	mov	sl, #60	; 0x3c
	1de98:	e28ee031 	add	lr, lr, #49	; 0x31
	1de9c:	e58dc078 	str	ip, [sp, #120]	; 0x78
	1dea0:	e28cc00e 	add	ip, ip, #14
	1dea4:	e3a01012 	mov	r1, #18
	1dea8:	e3a0204d 	mov	r2, #77	; 0x4d
	1deac:	e3a0000d 	mov	r0, #13
	1deb0:	e3a0900f 	mov	r9, #15
	1deb4:	e58d3014 	str	r3, [sp, #20]
	1deb8:	e58de04c 	str	lr, [sp, #76]	; 0x4c
	1debc:	e2833052 	add	r3, r3, #82	; 0x52
	1dec0:	e28ee001 	add	lr, lr, #1
	1dec4:	e58da054 	str	sl, [sp, #84]	; 0x54
	1dec8:	e58dc080 	str	ip, [sp, #128]	; 0x80
	1decc:	e3a0b003 	mov	fp, #3
	1ded0:	e28cc021 	add	ip, ip, #33	; 0x21
	1ded4:	e3a0a001 	mov	sl, #1
	1ded8:	e58d0008 	str	r0, [sp, #8]
	1dedc:	e58d100c 	str	r1, [sp, #12]
	1dee0:	e58d1010 	str	r1, [sp, #16]
	1dee4:	e58d0020 	str	r0, [sp, #32]
	1dee8:	e58d202c 	str	r2, [sp, #44]	; 0x2c
	1deec:	e58d2038 	str	r2, [sp, #56]	; 0x38
	1def0:	e58d1044 	str	r1, [sp, #68]	; 0x44
	1def4:	e58d2048 	str	r2, [sp, #72]	; 0x48
	1def8:	e58d2058 	str	r2, [sp, #88]	; 0x58
	1defc:	e58d206c 	str	r2, [sp, #108]	; 0x6c
	1df00:	e58d9000 	str	r9, [sp]
	1df04:	e58d3018 	str	r3, [sp, #24]
	1df08:	e58d3028 	str	r3, [sp, #40]	; 0x28
	1df0c:	e58db030 	str	fp, [sp, #48]	; 0x30
	1df10:	e58d3034 	str	r3, [sp, #52]	; 0x34
	1df14:	e58de050 	str	lr, [sp, #80]	; 0x50
	1df18:	e58da060 	str	sl, [sp, #96]	; 0x60
	1df1c:	e58d3068 	str	r3, [sp, #104]	; 0x68
	1df20:	e58d3074 	str	r3, [sp, #116]	; 0x74
	1df24:	e58d907c 	str	r9, [sp, #124]	; 0x7c
	1df28:	e58dc084 	str	ip, [sp, #132]	; 0x84
	1df2c:	e3a0c02b 	mov	ip, #43	; 0x2b
	1df30:	e58dc08c 	str	ip, [sp, #140]	; 0x8c
	1df34:	e58d20a0 	str	r2, [sp, #160]	; 0xa0
	1df38:	e08cc001 	add	ip, ip, r1
	1df3c:	e3a02008 	mov	r2, #8
	1df40:	e58dc090 	str	ip, [sp, #144]	; 0x90
	1df44:	e58d20a4 	str	r2, [sp, #164]	; 0xa4
	1df48:	e28cc009 	add	ip, ip, #9
	1df4c:	e282203b 	add	r2, r2, #59	; 0x3b
	1df50:	e58d00a8 	str	r0, [sp, #168]	; 0xa8
	1df54:	e58d10b4 	str	r1, [sp, #180]	; 0xb4
	1df58:	e280004a 	add	r0, r0, #74	; 0x4a
	1df5c:	e58d10c8 	str	r1, [sp, #200]	; 0xc8
	1df60:	e59f1af4 	ldr	r1, [pc, #2804]	; 1ea5c <_start@@Base+0xb294>
	1df64:	e58dc094 	str	ip, [sp, #148]	; 0x94
	1df68:	e58d20b0 	str	r2, [sp, #176]	; 0xb0
	1df6c:	e3a0c02a 	mov	ip, #42	; 0x2a
	1df70:	e58d00bc 	str	r0, [sp, #188]	; 0xbc
	1df74:	e58d20c4 	str	r2, [sp, #196]	; 0xc4
	1df78:	e1a00007 	mov	r0, r7
	1df7c:	e3a02034 	mov	r2, #52	; 0x34
	1df80:	e58de088 	str	lr, [sp, #136]	; 0x88
	1df84:	e58dc098 	str	ip, [sp, #152]	; 0x98
	1df88:	e58d309c 	str	r3, [sp, #156]	; 0x9c
	1df8c:	e58d30ac 	str	r3, [sp, #172]	; 0xac
	1df90:	e58d30b8 	str	r3, [sp, #184]	; 0xb8
	1df94:	e58d30c0 	str	r3, [sp, #192]	; 0xc0
	1df98:	e3a0300e 	mov	r3, #14
	1df9c:	ebffd366 	bl	12d3c <_Z12ReformStringPcPKcjz@plt>
	1dfa0:	e1a00008 	mov	r0, r8
	1dfa4:	e28d8db5 	add	r8, sp, #11584	; 0x2d40
	1dfa8:	e1a03006 	mov	r3, r6
	1dfac:	e1a01007 	mov	r1, r7
	1dfb0:	e1a02004 	mov	r2, r4
	1dfb4:	e288801c 	add	r8, r8, #28
	1dfb8:	ebffd4a9 	bl	13264 <sprintf@plt>
	1dfbc:	e1a00008 	mov	r0, r8
	1dfc0:	ebffd1e9 	bl	1276c <system@plt>
	""")

def is_number(s):
	try:
		float(s)
		return True
	except ValueError:
		pass
	return False


if __name__ == "__main__":


	INFO = '[bashis 2018 <mcw noemail eu>]'

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
					 description=(''+INFO+'\n'))
		arg_parser.add_argument('--infile', required=True, help='Input file [DEMO for demo]')
		arg_parser.add_argument('--outfile', required=False, help='Output file')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: %s\n" % str(e)
		sys.exit(1)

	if args.infile:
		infile = args.infile
		if infile == 'DEMO' or infile == 'demo':
			DUMP = EXAMPLE.readlines()
		else:
			#
			# https://www.yoctoproject.org/downloads
			# [My version is 2.4, change accordingly below]
			CMD = "/opt/poky/2.4/sysroots/x86_64-pokysdk-linux/usr/bin/arm-poky-linux-gnueabi/arm-poky-linux-gnueabi-objdump -d " + infile + ""
			p = subprocess.Popen(CMD, shell=True,stdout=subprocess.PIPE)
			DUMP = p.stdout.readlines()

	if args.outfile:
		outfile = args.outfile
	else:
		outfile = ''

	DB = {}
	LINE = 0
	for line in DUMP:
		line = line.split()
#		print line
		DB[LINE] = line
		LINE += 1

	ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+|`-={}[]:;'<>?,./\" \\"

	TEMP_DB_CNT = 0
	PREV_MEMSET = ''
	TEMP_DB = {}
	for who in DB.keys():
		if len(DB[who]) > 4:
			if DB[who][4] == '<_Z12ReformStringPcPKcjz@plt>' or DB[who][4] == '<ReformString>' or DB[who][4] == '<_Z12ReformStringPcPKcjz>': #
#				print "({}) Found: ReformString>".format(who)
				ReformString = who-1 # We dont need the 'bl'
				TEMP_DB[TEMP_DB_CNT] = {}
				TEMP_DB[TEMP_DB_CNT]['ReformString'] = who-1
				TEMP_DB[TEMP_DB_CNT]['memset'] = MEMSET
				TEMP_DB_CNT += 1
#				break # Uncomment this to only look for the first found code
			#
			# Normally there is 'memset' or some other asm branch before the code we are interested into.
			# however, i've noticed some rare 'reuse' of values from before the 'memset' / asm branch.
			# So these will be deobfuscated as 'a'... It's known issue.
			#
			elif DB[who][4] == '<memset@plt>' or DB[who][2] == 'b' or DB[who][2] == 'bl' or DB[who][2] == 'bne' or DB[who][2] == 'beq' or DB[who][2] == 'bhi':
#				print "({}) Found: <memset@plt>".format(who)
				MEMSET = who

	for RUN in TEMP_DB.keys():
		MEMSET = TEMP_DB[RUN]['memset']
		ReformString = TEMP_DB[RUN]['ReformString']
#		print MEMSET, ReformString

		DSM_CODE = {}
		DSM_CODE_NO = 0
		while MEMSET != ReformString:
			MEMSET += 1
			if DB[MEMSET][2] == 'str' or DB[MEMSET][2] == 'add' or DB[MEMSET][2] == 'mov':
				DSM_CODE[DSM_CODE_NO] = DB[MEMSET]
				DSM_CODE[DSM_CODE_NO][3] = DSM_CODE[DSM_CODE_NO][3].replace(",","")
				if not is_number(DSM_CODE[DSM_CODE_NO][4]):
					DSM_CODE[DSM_CODE_NO][4] = DSM_CODE[DSM_CODE_NO][4].replace("#","")
					DSM_CODE[DSM_CODE_NO][4] = DSM_CODE[DSM_CODE_NO][4].replace("[","")
					DSM_CODE[DSM_CODE_NO][4] = DSM_CODE[DSM_CODE_NO][4].replace("]","")
					DSM_CODE[DSM_CODE_NO][4] = DSM_CODE[DSM_CODE_NO][4].replace(",","")

				if len(DSM_CODE[DSM_CODE_NO]) > 5:
					if not is_number(DSM_CODE[DSM_CODE_NO][5]):
						DSM_CODE[DSM_CODE_NO][5] = DSM_CODE[DSM_CODE_NO][5].replace("#","")
						DSM_CODE[DSM_CODE_NO][5] = DSM_CODE[DSM_CODE_NO][5].replace("]","")
					if DSM_CODE[DSM_CODE_NO][2] == 'str':
						DSM_CODE[DSM_CODE_NO][5] = int(DSM_CODE[DSM_CODE_NO][5])

				if DSM_CODE[DSM_CODE_NO][2] == 'add' and is_number(DSM_CODE[DSM_CODE_NO][5]):
					DSM_CODE[DSM_CODE_NO][5] = int(DSM_CODE[DSM_CODE_NO][5])

				if DSM_CODE[DSM_CODE_NO][2] == 'mov' and is_number(DSM_CODE[DSM_CODE_NO][4]):
#					print DSM_CODE[DSM_CODE_NO][4] 
					DSM_CODE[DSM_CODE_NO][4] = int(DSM_CODE[DSM_CODE_NO][4])

#				print DSM_CODE[DSM_CODE_NO]
				DSM_CODE_NO += 1
#
# Calling this 'STACK' & 'REG', as we writing/reading to these based on the DSM CODE.
#
		STACK_TABLE = 0
		for who in DSM_CODE.keys():
			if DSM_CODE[who][2] == 'str' and DSM_CODE[who][4] == 'sp':
				STACK_TABLE += 1

		STACK = [0] * (STACK_TABLE+1)
		REG = {'r0':0,'r1':0,'r2':0,'r3':0,'r4':0,'r5':0,'r6':0,'r7':0,'r8':0,'r9':0,'r10':0,'r11':0,'r12':0,'ip':0,'lr':0,'sl':0,'fp':0 }

		for who in DSM_CODE.keys():
#			print DSM_CODE[who]
			if DSM_CODE[who][2] == 'add':

				if is_number(DSM_CODE[who][5]):
#					print "ADD1 {}".format(TEMP)
					REG[DSM_CODE[who][3]] += DSM_CODE[who][5]	# Number
				else:
					REG[DSM_CODE[who][3]] += REG[DSM_CODE[who][5]]	# From a REG

			elif DSM_CODE[who][2] == 'mov':
				if is_number(DSM_CODE[who][4]):
#					print "MOV {}".format(DSM_CODE[who][4])
					REG[DSM_CODE[who][3]] = DSM_CODE[who][4]

			elif DSM_CODE[who][2] == 'str' and DSM_CODE[who][4] == 'sp':
#				print DSM_CODE[who]
				if len(DSM_CODE[who]) == 5:
					STACK[1] = REG[DSM_CODE[who][3]]	# 1st SP + 4
				else:
					if not len(STACK) <= ((DSM_CODE[who][5] + 4) / 4):
						STACK[(DSM_CODE[who][5] + 4) / 4] = REG[DSM_CODE[who][3]]	# (SP + 4) / 4
			else:
				print "UNKNOWN DSM CODE: {}".format(DSM_CODE[who])	# SUB... etc.


		for who in range(len(DSM_CODE)-1,0,-1):	# 1st SP
			if DSM_CODE[who][2] == 'mov' and is_number(DSM_CODE[who][4]) and DSM_CODE[who][4] != (STACK_TABLE+1):
				STACK[0] = DSM_CODE[who][4]
				break
#		print "REG: {}".format(REG)
#		print "STACK: {}".format(STACK)

		OUT = ''
		for key in STACK:
			if not key > len(ASCII)-1:
				OUT += ASCII[key]
		print "\nFile: {}\nDeobfuscated: {}\n".format(infile,OUT)

		if outfile:
			with open(outfile,'a') as Foscam_Strings:
				Foscam_Strings.write("File: ")
				Foscam_Strings.write(infile)
				Foscam_Strings.write("\nDeobfuscated:")
				Foscam_Strings.write(OUT)
				Foscam_Strings.write("\n")
				Foscam_Strings.close()





