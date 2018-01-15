#!/usr/bin/env python2.7
#
# Small OpenSSL wrapper to looping different encryption keys/digest and cipher on Foscam IPC Firmware images.
#
# //bashis 2018
#
import os
import subprocess
import sys
import argparse

CMD = "openssl enc -d CIPHER -in IN_FILE -out OUT_FILE -md DIGEST -k 'OPENSSL_KEY'"

if __name__ == "__main__":

	INFO = '[bashis 2018 <mcw noemail eu>]'

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=(''+INFO+'\n'))
		arg_parser.add_argument('--infile', required=True, help='Encrypted file')
		arg_parser.add_argument('--outfile', required=False, help='Decrypted file')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: %s\n" % str(e)
		sys.exit(1)

	if args.infile:
		infile = args.infile

	if args.outfile:
		outfile = args.outfile
	else:
		outfile = 'decrypted.tgz'

	# Firmware, Config and log keys
	#
	# >> Missing keys!
	# 'F' model AKA R4, R2, C2
	# 
	# 
	ENC_KEYS = { 
		0:'Wxift*',		# Decrypt: HI3518A_ddr256M_sys_ver 1.4.1.7 / 1.4.1.8 + FI9x Ver 1, recovertool
		1:'Wxift*v2',	# FW Decrypt 'B' AKA 'FosBaby'
		2:'WWxift*',
		3:'WWxift*v2',	# FW Decrypt 'B' AKA 'FosBaby'

		4:'Wyift*',
		5:'Wyift*v2',	# FW Decrypt 'C' AKA FI9903P
		6:'WWyift*',
		7:'WWyift*v2',	# FW Decrypt 'C' AKA FI9903P

		8:'Wzift*',
		9:'Wzift*v2',
		10:'WWzift*',
		11:'WWzift*v2',	# FW Decrypt 'E' AKA 'C1'

		12:'Weift*',
		13:'Weift*v2',
		14:'WWeift*',
		15:'WWeift*v2',	# FW Decrypt 'G' AKA 'C1-Lite'

		16:'Pxift*',	# exist (config)
		17:'Pxift*v2',
		18:'PPxift*',
		19:'PPxift*v2',

		20:'Xti1f*',	# recovertool
		21:'Xti1f*v2',
		22:'XXti1f*',	
		23:'XXti1f*v2',

		24:'Ktf1g*',	# exist (config)
		25:'Ktf1g*v2',
		26:'KKtf1g*',
		27:'KKtf1g*v2',

		28:'WT8Nk*',	# Decyrypt: HI3518A_ddr256M_sys_onvif_ver1.4.1.8.bin  + FI9x Ver 1, recovertool
		29:'WT8Nk*v2',	# FW Decrypt 'A', recovertool
		30:'WWT8Nk*',
		31:'WWT8Nk*v2',	# FW Decrypt 'A'

		32:'XT8Nk*',	# FW Decrypt: FI9x Ver1 'One To All', recovertool
		33:'XT8Nk*v2',	# FW Decrypt: FI9x Ver2
		34:'XXT8Nk*',
		35:'XXT8Nk*v2',

		36:'U0i*P2jK_',	# exist (config) - encrypt/decrypt
		37:'M0i*P2jK_',	# exist (config) - encrypt/decrypt
		38:'BpP+2R9*Q',	# exist (config) - encrypt/decrypt
		39:'Ak47@99',	# l: factory~, p: Ak47@99 @ webService
		40:'rizhi6789', # dd if=ipcLog.bin | openssl des3 -d -k rizhi6789 [...]
		41:'foscam'	# l: admin, p: foscam @ UDTMediaServer
		}

	CIPHER = {
		0:'-aes-128-cbc',
#		1:'-aes-256-cbc',
#		2:'-aes-128-ecb',
#		3:'-aes-256-ecb',
#		4:'-des3',
#
#		5:'-idea',
#		6:'-idea-cbc',
#		7:'-idea-cfb',
#		8:'-idea-ecb',
#		9:'-idea-ofb',
#
#		10:'-bf-cbc',
#		11:'-camellia-128-cbc',
#		12:'-camellia-256-cbc',
#		13:'-cast5-cbc',
#		14:'-des',
#		15:'-des-ede',
#		16:'-des-ede3',
#		17:'-des-ofb',
#		18:'-rc2-40-cbc',
#		19:'-rc2-ecb',
#		20:'-seed',
#		21:'-seed-ofb',
#		22:'-bf-cfb',
#		23:'-camellia-128-ecb',
#		24:'-camellia-256-ecb',
#		25:'-cast5-cfb',
#		26:'-des-cbc',
#		27:'-des-ede-cbc',
#		28:'-des-ede3-cbc',
#		29:'-des3',
#		30:'-rc2-64-cbc',
#		31:'-rc2-ofb',
#		32:'-seed-cbc',
#		33:'-aes-192-cbc',
#		34:'-base64',
#		35:'-bf-ecb',
#		36:'-camellia-192-cbc',
#		37:'-cast',
#		38:'-cast5-ecb',
#		39:'-des-cfb',
#		40:'-des-ede-cfb',
#		41:'-des-ede3-cfb',
#		42:'-desx',
#		43:'-rc2-cbc',
#		44:'-rc4',
#		45:'-seed-cfb',
#		46:'-aes-192-ecb',
#		47:'-bf',
#		48:'-bf-ofb',
#		49:'-camellia-192-ecb',
#		50:'-cast-cbc',
#		51:'-cast5-ofb',
#		52:'-des-ecb',
#		53:'-des-ede-ofb',
#		54:'-des-ede3-ofb',
#		55:'-rc2',
#		56:'-rc2-cfb',
#		57:'-rc4-40',
#		58:'-seed-ecb'
	}

	DIGEST = {
		0:'md5',
#		1:'mdc2',
#		2:'gost',
#		3:'rmd160',

#		4:'sha1',
#		5:'sha224',
#		6:'sha256',
#		7:'sha384',
#		8:'sha512',
#		9:'md4',
#		10:'blake2s256',
#		11:'blake2b512'
	}

	DECRYPTED = 0
	for chipher in CIPHER.keys():
		for digest in DIGEST.keys():
			for key in ENC_KEYS.keys():

				TEMP = CMD
				TEMP = TEMP.replace("IN_FILE",infile)
				TEMP = TEMP.replace("OUT_FILE",outfile)
				TEMP = TEMP.replace("CIPHER",CIPHER[chipher])
				TEMP = TEMP.replace("DIGEST",DIGEST[digest])
				TEMP = TEMP.replace("OPENSSL_KEY",ENC_KEYS[key])

				p = subprocess.Popen(TEMP, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
				p_stderr = p.stderr.readlines()
				if not len(p_stderr):
					p = subprocess.Popen("gzip -t " + outfile + "", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
					p_stderr = p.stderr.read()
					if not (p_stderr):
						print "Decrypted with: {}".format(TEMP)
						sys.exit(0)
					else:
						print "Decryption NOT OK: {}".format(TEMP)
						os.remove(outfile)
				else:
					print p_stderr[0],
	print "Cleaning up..."
	os.remove(outfile)
	sys.exit(1)







