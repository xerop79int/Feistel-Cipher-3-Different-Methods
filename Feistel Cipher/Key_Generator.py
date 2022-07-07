#!/usr/bin/python

# from os import urandom
# from hashlib import *
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
# import json
# import binascii



# class KeyGenerator:

#     def __init__(self, _pass, mode, _file):
#         self.salt = ""
#         self.validator = ""
#         self.original_key = ""
#         self.mac = ""
#         self.key = ""
#         self.keys = ""
#         #self.salt, self.key = self.generate_key(_pass, mode)
#         self.generate_key(_pass, mode, _file)
#         #self.keys = self.generateKeys(self.original_key)

#     def AES_Block(self, key1, key2):
        
#         iv = key2
#         iv = pad(iv, AES.block_size)

#         cipher_config = AES.new(key1, AES.MODE_ECB)
#         result = cipher_config.encrypt(iv)

#         return result

#     # Generating 16 bit Salt and 32 bit HMAC-256 Key
#     def srng(bytes=16):
#         return urandom(bytes)

#     def generate_key(self, _pass, mode, _file):
#         if mode == "-e":
#             salt = KeyGenerator.srng()
#         else:
#             f = open(_file.strip("\\ .txt") + '.fenc-meta.F')
#             data = json.load(f)
#             salt = data["Salt"].encode()
#             salt = binascii.unhexlify(salt)
#             f.close()

#         key = pbkdf2_hmac('sha256', _pass, salt, 250000)

#         self.salt = salt
#         self.key = key

#         key1 = key[:16]
#         key2 = key[16:]


#         self.validator = self.AES_Block(key1, key2)
#         feistel_keys = []
#         for i in range(1,7):
#             key2 = key2 + bytes(i)
#             if i == 5:
#                 self.mac = self.AES_Block(key1, key2)
#             elif i == 6:
#                 search = self.AES_Block(key1, key2)
#             else:
#                 feistel_keys.append(self.AES_Block(key1, key2))
        
#         # print(feistel_keys)

#         self.keys = feistel_keys
    
#     def Feistel_keys(self):
#         return self.keys
    
#     def mac(self):
#         return self.mac
    
#     def key(self):
#         print(self.key)
#         return binascii.hexlify(self.key)
    
#     def SaltandValidator(self):
#         return binascii.hexlify(self.salt), binascii.hexlify(self.validator)


#         # key = str(key[2:-1])
#         # key2 = ""
#         # for x in key:
#         #     key2 += format(ord(x), "02x")

#         # self.original_key = int(key2, 16)
#         #return salt, key