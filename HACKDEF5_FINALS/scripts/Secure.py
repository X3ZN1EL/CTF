
from Crypto.Util.number import *
from Crypto import Random
from Crypto.Cipher import AES
import base64
from pathlib import Path
from os import walk
from pwn import xor
import sys
from tqdm import tqdm
from time import sleep


def banner():
	ban="""
	------------------------------------------------------
	#                                                    #
	#      ¡Tus archivos nunca han estado mas seguros!   #
	#                   RSA + AES + XOR                  #
	#                                                    #
	------------------------------------------------------
	"""
	print (ban)
def ls(ruta):
	return next(walk(ruta))[2]


def encrypt(message, passphrase):
	BLOCK_SIZE=16
	passphrase = passphrase
	IV = Random.new().read(BLOCK_SIZE)
	aes = AES.new(passphrase, AES.MODE_CFB, IV)
	return base64.b64encode(IV + aes.encrypt(message))

###
def decrypt(encrypted, passphrase):
	BLOCK_SIZE=16
	passphrase = passphrase
	encrypted = base64.b64decode(encrypted)
	IV = encrypted[:BLOCK_SIZE]
	aes = AES.new(passphrase, AES.MODE_CFB, IV)
	return aes.decrypt(encrypted[BLOCK_SIZE:])


def recuperar(_k_xor,_k_aes,_ruta):
	_xor_=_k_xor.encode()#
	_key=_k_aes.encode()#
	_ruta=_ruta
	AES_key=xor(_xor_,_key)
	if (AES_key[8:10]==b'B\x0c'):
		if(AES_key[10:13]==b'F\ng'):
			if(AES_key[13:16][::-1]==b'/JK'):
				print ("ok")
				ext_s=['.wav.secure','.mp4.secure']
				_files=[]
				if not(ls(_ruta)):
					print("\n[!]No se encotraton archivos, verifica la ruta.")
					exit()
				print("[+]Buscando archivos...\n")
				for i in tqdm(ls(_ruta)):
					sleep(0.2)
					print ("\n[#]Descifrando archivos ;)\n")
					for j in ext_s:
						if (j in i):
							_files.append(i)
							_data=open(str(i),"rb").read()
							name_encrypt=i
							C=decrypt(_data,AES_key)
							_temp=open(_ruta+"\\"+name_encrypt.replace(".secure",""),"wb")
							_temp.write(C)


##Super secure funtion -> para cifrar los archivos super valiosos
def secure_vault(_k_xor,_k_aes,_ruta):
	_xor_=_k_xor.encode()
	_key=_k_aes.encode()
	_ruta=_ruta
	AES_key=xor(_xor_,_key)
	if (AES_key[:8][::-1]== b'\x0f\x16\x1c6(<J7'):
		if(AES_key[0]== 55):
			print ("ok")
			ext_s=['.wav','.mp4']
			_files=[]
			if not(ls(_ruta)):
					print("\n[!]No se encotraton archivos, verifica la ruta.")
					exit()
			print("[+]Buscando archivos...\n")
			for i in tqdm(ls(_ruta)):
				sleep(0.2)
				for j in tqdm(ext_s):
					print ("\n[#]Cifrando archivos...\n")
					if (j in i):
						sleep(0.2)
						_files.append(i)
						_data=open(str(i),"rb").read()
						name_encrypt=i
						C=encrypt(_data,AES_key)
						_temp=open(_ruta+"\\"+name_encrypt+".secure","wb")
						_temp.write(C)
					

def main():
	banner()
	if len(sys.argv) == 5:
		_option = sys.argv[1]
		_AES_key = sys.argv[2]
		_XOR_key = sys.argv[3]
		_Ruta_file = sys.argv[4]
		if(_option=="-d"):
			recuperar(_XOR_key,_AES_key,_Ruta_file)
		if(_option=="-c"):
			secure_vault(_XOR_key,_AES_key,_Ruta_file)
	else:
		print("\nHelp: python3 SecureVaul.py <opcion> <AES Key> <XOR Key> <Ruta_Carpeta>")
		print("Opciones:\n\t-d	-> Descifrar\n\t-c	-> Cifrar\n")
		print('Ejemplo: python3 Secure.py -c "nO_P41n" "N0_VIcT0ry" "C:\\Users\\pwned\\Desktop"\n')

if __name__ == "__main__":
	main()

##TU FLAG ES AES_KEY+XOR_KEY###
##NO PAIN NO FLAG###
##NO PAIN NO WIN###
##NO PAIN NO VICTORY###