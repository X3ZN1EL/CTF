#!/usr/bin/env python3
# DarkSide
# xen was here

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from base64 import b64decode
import math
from pwn import *

with open('old_key.pub') as a:
    key_old = RSA.importKey(a.read())

with open('new_key.pub') as b:
    key_new = RSA.importKey(b.read())

n1 = key_old.n
n2 = key_new.n

e = 65537

gcd = math.gcd(n1,n2)

q1 = n1 // gcd
q2 = n2 // gcd

t = (gcd-1)*(q2-1)
d = inverse(e,t)

ciphertext = open("llave.encrypt","r").read().strip()
c = bytes_to_long(b64decode(ciphertext))

msg = long_to_bytes(pow(c,d,n2))
crypt_key = msg.decode()
# hackdef{rS4_+x0R+_a3S__APT-57170

AES_key = b'7J<(6\x1c\x16\x0fB\x0cF\ngKJ/'

def check_aes_key(k):

    if (k[:8][::-1]== b'\x0f\x16\x1c6(<J7'):
        print('ok1')
    else:
        print('nope1')
    
    if(k[8:10]==b'B\x0c'):
        print('ok2')
    else:
        print('nope2')

    if(k[10:13]==b'F\ng'):
        print('ok3')
    else:
        print('nope3')
    
    if(k[13:16][::-1]==b'/JK'):
	    print('ok4')
    else:
        print('nope4')

    if(k[0]== 55):
        print('ok5')
    else:
        print('nope5')
    
# check_aes_key(AES_key)

flag = (xor(AES_key,crypt_key)).decode('utf-8')
# print(flag.decode('utf-8'))
# _+_CRypt0_rUL3z}
XOR_key = crypt_key + flag
print(XOR_key[:48])
# hackdef{rS4_+x0R+_a3S__APT-57170_+_CRypt0_rUL3z}
# python3 Secure.py -d 'hackdef{rS4_+x0R+_a3S__APT-57170' '_+_CRypt0_rUL3z}' '/home/xen/CTF/final/crypto/370/audio/'
