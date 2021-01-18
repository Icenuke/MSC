#!/usr/bin/python3
# -*- coding:utf-8 -*-

from hashlib import md5, sha1, sha256
from os import getcwd, walk, path
from sys import argv, exit
from requests import post, Session

BLOCKSIZE = 65536

def Helper():
	print('''
		Usage: MSC [ -h | -hl | -md5 | -sha1 | -sha256 | -vt | -b <BlackList> ] <Path2Check>
			Description:
				This script check all files to see if is present in blacklist
				The blacklist must contain the hash of files. (md5/sha1/sha256)
				The file can be check with VirusTotal with the API.
				A Whitelist can be generated.
			Options:
				-h 				Show this message
				-hl 			Generate a Hashlist of all file in system, md5.txt, sha1.txt, sha256.txt
				-md5 			Precise the hashes contain in blacklist are md5
				-sha1 			Precise the hashes contain in blacklist are sha1
				-sha256			Precise the hashes contain in blacklist are sha256
				-vt 			Hash all file and check in VirusTotal
								Add the vt api key in vt.conf
				-b <blacklist>	The file which contain the hash (md5 or sha1 or sha256)

	''')


def Hasher(fl, tp):
	try: 
		hasher = ''

		if tp == 'md5':
			hasher = md5()
		
		elif tp == 'sha1':
			hasher = sha1()

		elif tp == 'sha256':
			hasher = sha256()

		else:
			print('\t[!] Error!! ')
			exit(1)

		with open(fl, 'rb') as afl:
		    buf = afl.read(BLOCKSIZE)
		    
		    while len(buf) > 0:
		        hasher.update(buf)
		        buf = afl.read(BLOCKSIZE)
		
		return hasher.hexdigest()

	except Exception as e:
		print('\t[!] %s - %s' %(fl, e))


def VT(path):
	try:
		apikey = ''
		with open(apiconf, 'r') as keyfile:
			apikey = keyfile.readlines()[0]

		hsha256 = Hasher(path, 'sha256')
		url = 'https://www.virustotal.com/api/v3/files/%s' %(hsha256)
		head = {'X-Apikey': '%s' %(apikey)}
		sess = Session()
		sess.headers = head
		res = sess.get(url)
		
		if res.status_code == 200:
			print('\t\t[!] %s Present in VirusTotal!')
			print('\t\t\t|> See the export: %s.json' %(path))
			with open('%s.json' %(path), 'a') as json:
				json.write(res.text)

	except Exception as e:
		print('\t[!] %s' %(e))


def Hashlist(md5lst, sha1lst, sha256lst):
	lstfl = ['md5.txt', 'sha1.txt', 'sha256.txt']

	for f in lstfl:
		if f.find('md5') != -1:
			data = md5lst

		if f.find('sha1') != -1:
			data = sha1lst

		if f.find('sha256') != -1:
			data = sha256lst

		with open(f, 'a') as fl:
			for d in data:
				fl.writelines('%s\n' % (d))
		
		print('\t\t\t[>] %s Created!!' %(f))
	print('\t\t[>] All hash files created!!')


def ReadFile(fl):
	with open(fl, 'r') as hl:
		lshash = [ h for h in hl.readlines() ]

	return lshash


if __name__ == '__main__':
	print('''
		Welcome to...
					 __    ___
			  /\/\  / _\  / __\\
			 /    \ \ \  / /   
			/ /\/\ \_\ \/ /___ 
			\/    \/\__/\____/
						Developed by Icenuke

	''')


	if len(argv) >= 2:
		blacklist = 'blacklist.txt'
		apiconf = 'vt.conf'
		apikey = ''
		lstBl = []
		lstmd5 = []
		lstsha1 = []
		lstsha256 = []

		try:
			if '-h' in argv:
				Helper()

			if '-b' in argv:
				blacklist = argv[argv.index('-b')+1]
				lstBl = ReadFile(blacklist)

			else:
				lstBl = ReadFile(blacklist)

			print('\t[+] Start script:')
			for root, dirs, files in walk(argv[-1], topdown=True):
				for file in files:
					pathF = path.join(root, file)
			
					if '-hl' in argv:
						lstmd5.append(Hasher(pathF, 'md5'))
						lstsha1.append(Hasher(pathF, 'sha1'))
						lstsha256.append(Hasher(pathF, 'sha256'))
					
					if '-md5' in argv:
						hmd5 = Hasher(pathF, 'md5')
						if hmd5 in lstBl:
							print('\t\t[!] %s -- %s' %(pathF, hmd5))

					if '-sha1' in argv:
						hsha1 = Hasher(pathF, 'sha1')
						if hsha1 in lstBl:
							print('\t\t[!] %s -- %s' %(pathF, hsha1))

					if '-sha256' in argv:
						hsha256 = Hasher(pathF, 'sha256')
						if hsha256 in lstBl:
							print('\t\t[!] %s -- %s' %(pathF, hsha256))

					if '-vt' in argv:
						VT(pathF)
						

			if len(lstmd5) > 0 and len(lstsha1) > 0 and len(lstsha256) > 0:
				print('\t\t[+] Start export hash:')
				Hashlist(lstmd5, lstsha1, lstsha256)

			print('\t[+] End of script!!')
			

		except Exception as e:
			print('\t[!] %s!!' %(e))

	else:
		Helper()

