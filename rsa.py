#Andre Barajas
#CECS 378
#File Encryption program using AES standard and HMAC hashing solution  
#March 2019

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import os
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256


key = "00000000000000123456789101112!90"
HMACkey = b"12345656700000123456789101134564"
#Sixteen byte Initialization Vector 
iv = "Initialization V" 
#Users/baraj/Desktop/Csulb.Spring.19/Cs.328.ComputerSec/
dir = "CryptographyPython/"

def MyRSAEncrypt(filepath, RSA_Public_Publickey_filepath):
	key = RSA.generate(2048)
	f = open('myprivatekey.pem','wb')
	print(key)
	privatekey = key.exportKey('PEM')
	f.write(privatekey)
	print(privatekey)
	f.close()

	f = open('mypublickey.pem','wb')
	publickey = key.publickey()
	print(publickey)
	publickey = publickey.exportKey('PEM')
	f.write(publickey)
	print(publickey)
	f.close()

def MyencryptMAC(plaintext, key, HMACkey):
#if(len(key) < 32):
#return "ERROR: Key must be 32 Bytes or bigger"
#HMAC: maybe replace plaintext to key.encode() according to lab instructions 
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(plaintext)
	h = HMAC(HMACkey, hashes.SHA256(), backend=default_backend())
	h.update(plaintext.encode())
	tag = h.finalize()
	return (ciphertext, iv, tag)

def MyfileEncryptMAC(filepath):
	f = open(filepath, "r")
	contents = f.read()
	inittuple = MyencryptMAC(contents, key, HMACkey)
	filename, fileext = os.path.split(filepath)
	return (inittuple[0], inittuple[1], inittuple[2], key, HMACkey, fileext)
	f.close()

def MyfileDecryptMAC(ciphertext):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.decrypt(ciphertext)

ptxtinput = input("Enter a Full File Path: ")
print(MyfileEncryptMAC(ptxtinput))
