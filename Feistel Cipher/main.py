#!/usr/bin/env python3

from argparse import ArgumentParser
from getpass import getpass
from sys import stderr
import binascii
from os import urandom
from hashlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import hmac
from Crypto.Util import Counter
import hashlib

class Cipher:

    def decrypt(self, cipher_text, keys, Mac, checkmac):
        left = cipher_text[:16]
        right = cipher_text[16:]

        Mac = hmac.new(Mac, cipher_text, hashlib.sha256).hexdigest()[:16].encode()

        if Mac != checkmac:
            print("Mac didn't Match")
            exit(1)

        # Round 4
        mac = hmac.new(keys[3][:16], right, hashlib.sha256).hexdigest()[:16].encode()
        left = bytes([_a ^ _b for _a, _b in zip(mac, left)])

         # Round 3
        iv = left

        cipher_config = AES.new(keys[2][:16], AES.MODE_CTR, counter=Counter.new(128))
        round_3 = cipher_config.encrypt(iv)

        temp_right_2 = []

        for i in range(len(right)):
            if i == 0 and len(right) > len(round_3):
                temp = right[:len(round_3)] 
                begin_count = len(round_3)
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                end_count = len(round_3) + len(round_3) 
            elif len(right) < end_count:
                temp = right[begin_count:]
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                break
            else:
                temp = right[begin_count: end_count]
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                begin_count = end_count
                end_count += len(round_3)

        
        
        right = "".encode()
        for i in range(len(temp_right_2)):
            right += temp_right_2[i]
        
        # Round 2
        mac = hmac.new(keys[1][:16], right, hashlib.sha256).hexdigest()[:16].encode()
        left = bytes([_a ^ _b for _a, _b in zip(left, mac)])

        # Round 1
        iv = left
        
        cipher_config = AES.new(keys[0][:16], AES.MODE_CTR, counter=Counter.new(128))
        round_1 = cipher_config.encrypt(iv)


        temp_right = []

        for i in range(len(right)):
            if i == 0 and len(right) > len(round_1):
                temp = right[:len(round_1)] 
                begin_count = len(round_1)
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                end_count = len(round_1) + len(round_1) 
            elif len(right) < end_count:
                temp = right[begin_count:]
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                break
            else:
                temp = right[begin_count: end_count]
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                begin_count = end_count
                end_count += len(round_1)
            
        right = "".encode()
        for i in range(len(temp_right)):
            right += temp_right[i]
        
        plain_text = left + right  

        return plain_text
    
    
    def Encrypt(self, plain_text, keys, Mac):
        print(len(plain_text))

        left = plain_text[:16]
        right = plain_text[16:]

        # Round 1
        iv = left
        
        cipher_config = AES.new(keys[0][:16], AES.MODE_CTR, counter=Counter.new(128))
        round_1 = cipher_config.encrypt(iv)


        temp_right = []

        for i in range(len(right)):
            if len(right) <= len(round_1):
                temp = right
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
            elif i == 0 and len(right) > len(round_1):
                temp = right[:len(round_1)] 
                begin_count = len(round_1)
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                end_count = len(round_1) + len(round_1) 
            elif len(right) < end_count:
                temp = right[begin_count:]
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                break
            else:
                temp = right[begin_count: end_count]
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
                begin_count = end_count
                end_count += len(round_1)
            
        right = "".encode()
        for i in range(len(temp_right)):
            right += temp_right[i]
        
       
        # Round 2
        mac = hmac.new(keys[1][:16], right, hashlib.sha256).hexdigest()[:16].encode()
        left = bytes([_a ^ _b for _a, _b in zip(left, mac)])


        # Round 3
        iv = left

        cipher_config = AES.new(keys[2][:16], AES.MODE_CTR, counter=Counter.new(128))
        round_3 = cipher_config.encrypt(iv)

        temp_right_2 = []

        for i in range(len(right)):
            if len(right) <= len(round_1):
                temp = right
                temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
            elif i == 0 and len(right) > len(round_3):
                temp = right[:len(round_3)] 
                begin_count = len(round_3)
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                end_count = len(round_3) + len(round_3) 
            elif len(right) < end_count:
                temp = right[begin_count:]
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                break
            else:
                temp = right[begin_count: end_count]
                temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
                begin_count = end_count
                end_count += len(round_3)

        
        
        right = "".encode()
        for i in range(len(temp_right_2)):
            right += temp_right_2[i]

        # Round 4

        mac = hmac.new(keys[3][:16], right, hashlib.sha256).hexdigest()[:16].encode()
        left = bytes([_a ^ _b for _a, _b in zip(mac, left)])

        cipher_text = left + right

        Mac = hmac.new(Mac, cipher_text, hashlib.sha256).hexdigest()[:16].encode()
 
        return cipher_text, Mac

class KeyGenerator:

    def __init__(self, _pass, mode, _file):
        self.salt = ""
        self.validator = ""
        self.original_key = ""
        self.mac = ""
        self.checkmac = ""
        self.key = ""
        self.keys = ""
        #self.salt, self.key = self.generate_key(_pass, mode)
        self.generate_key(_pass, mode, _file)
        #self.keys = self.generateKeys(self.original_key)

    def AES_Block(self, key1, key2):
        
        iv = key2
        iv = pad(iv, AES.block_size)

        cipher_config = AES.new(key1, AES.MODE_ECB)
        result = cipher_config.encrypt(iv)

        return result

    # Generating 16 bit Salt and 32 bit HMAC-256 Key
    def srng(bytes=16):
        return urandom(bytes)

    def generate_key(self, _pass, mode, _file):
        if mode == "-e":
            salt = KeyGenerator.srng()
        else:
            f = open('.fenc-meta.' + _file.strip(".\\"))
            data = json.load(f)
            salt = data["salt"].encode()
            self.checkmac = data["mac"].encode()
            salt = binascii.unhexlify(salt)

            f.close()

        key = pbkdf2_hmac('sha256', _pass, salt, 250000)

        self.salt = salt
        self.key = key

        key1 = key[:16]
        key2 = key[16:]


        self.validator = self.AES_Block(key1, key2)[:16]
        feistel_keys = []
        for i in range(1,7):
            key2 = key2 + bytes(i)
            if i == 5:
                self.mac = self.AES_Block(key1, key2)
            elif i == 6:
                search = self.AES_Block(key1, key2)
            else:
                feistel_keys.append(self.AES_Block(key1, key2))
        
        print(len(self.salt))
        print(len(self.validator))
        # print(feistel_keys)

        self.keys = feistel_keys
    
    def Feistel_keys(self):
        return self.keys
    
    def key(self):
        return binascii.hexlify(self.key)
    
    def SaltandValidator(self):
        return self.salt, self.validator


        # key = str(key[2:-1])
        # key2 = ""
        # for x in key:
        #     key2 += format(ord(x), "02x")

        # self.original_key = int(key2, 16)
        #return salt, key

def print_err(*args, **kwargs):
    print(*args, file=stderr, **kwargs)


class Args:
    ''' Parses all the arguments and returns a dictionary. '''
    def get_args():
        parser = ArgumentParser()
        subparser = parser.add_mutually_exclusive_group()
        subparser.add_argument(
            "-e", "--encrypt", help="Encrypts the file specified", nargs='+')
        subparser.add_argument(
            "-d", "--decrypt", help="Decrypts the file specified", nargs='+')
        subparser.add_argument(
            "-s", "--search", help="Search for a specific keyword in the encrypted files")
        parser.add_argument(
            "-j", "--json", help="Output the data to stdout as a JSON Object", action='store_true')
        args = parser.parse_args()
        return vars(args)


class File_handling:

    def saveResultsToFile(dest_file, results, mode):
        try:
            with open(dest_file, "w") as file:
                if mode == '-e':
                    file.write(str(binascii.hexlify(results))[2:-1])
                else:
                    file.write(results.decode())
            file.close()
            
        except:
            print("Error: Can't open the \"" + dest_file + "\" file.")
        # try:
        #     file = open(dest_file, 'w')
        # except IOError:
        #     print("Error: Can't create the \"" + dest_file + "\" file.")
        # with file:
        #     counter = 0
        #     char_tup = ""
        #     for r in results:
        #         if mode == "-e":
        #             file.write(r)
        #         else:
        #             for c in r:
        #                 char_tup += c
        #                 counter += 1
        #                 if(counter == 2):
        #                     value = int(char_tup, 16)
        #                     if value != 0:
        #                         char_tup = chr(value)
        #                         file.write(char_tup)
        #                     counter = 0
        #                     char_tup = ""
            

    def readbinaryFile(src_file):
        try:
            file = open(src_file, "rb")
            binary_data = file.read()
            file.close()
            return binary_data
        except:
            print("Error: Can't open the \"" + src_file + "\" file.")
    
    def writebinaryFile(src_file, results):
        try:
            with open(src_file, "wb") as binary_file:
                binary_file.write(results)
        except:
            print("Error: Can't open the \"" + src_file + "\" file.")

    def getSrcFromFile(src_file):
        try:
            with open(src_file) as file:
                lines = file.readlines()
            file.close()
        except:
            print("Error: Can't open the \"" + src_file + "\" file.")
        
        return ''.join(lines)
        # try:
        #     file = open(src_file, 'r')
        # except IOError:
        #     print("Error: Can't open the \"" + src_file + "\" file.")
        # with file:
        #     hex_strings = []
        #     counter = 0
        #     i = -1
        #     while True:
        #         c = file.read(1)
        #         if not c:
        #             break
        #         if counter % 16 == 0:
        #             hex_strings.append("")
        #             i += 1
        #         if mode == "-e":
        #             c = format(ord(c), "02x")
        #             counter += 1
        #         counter += 1
        #         hex_strings[i] += c

        #     if i < 0:
        #         raise ValueError("Error: the source file is empty!")
        #     hex_strings[i] = format(int(hex_strings[i], 16), "016x")
        #     return hex_strings

        

        
    def saveMetaData(salt, validator, Mac, _file):
        metadata = {
            "salt": str(binascii.hexlify(salt))[2:-1],
            "validator": str(binascii.hexlify(validator))[2:-1],
            "mac": str(Mac)[2:-1],
            "terms": []
        }

        out_file = open( ".fenc-meta." + _file.strip(".\\"), "w")
        json.dump(metadata, out_file, indent=1)
        out_file.close()

    def Search(results, search_term):
        search_string = ""

        counter = 0
        char_tup = ""
        for r in results:
            for c in r:
                char_tup += c
                counter += 1
                if(counter == 2):
                    value = int(char_tup, 16)
                    if value != 0:
                        char_tup = chr(value)
                        search_string += char_tup
                    counter = 0
                    char_tup = ""
        
        if search_term in search_string:
            print("Search Term Found!!")
        else:
            print("Search Term not Found!!")



if __name__ == "__main__":

    # A Dictionary object of all the arguments
    args = Args.get_args()
    _pass = getpass().encode()

    if args["encrypt"] != None and args["decrypt"] == None:
        mode = "-e"
        name = args["encrypt"]
    elif args["encrypt"] == None and args["decrypt"] != None:
        mode = "-d"
        name = args["decrypt"]
    


    for file_name in name:

        Key_Gen = KeyGenerator(_pass, mode, file_name)
        cipher = Cipher()
        results = ""
        
        if mode == "-e":
            if not ".txt" in file_name:
                src = File_handling.readbinaryFile(file_name)
                results, Mac = cipher.Encrypt(src, Key_Gen.Feistel_keys(), Key_Gen.mac)
            else:
                src = File_handling.getSrcFromFile(file_name).encode("UTF-8")
                results, Mac = cipher.Encrypt(src, Key_Gen.Feistel_keys(), Key_Gen.mac)
        else:
            if not ".txt" in file_name:
                src = File_handling.readbinaryFile(file_name)
                results, Mac = cipher.Encrypt(src, Key_Gen.Feistel_keys(), Key_Gen.mac)
            else:
                src = File_handling
                results = cipher.decrypt(binascii.unhexlify(src), Key_Gen.Feistel_keys(), Key_Gen.mac, Key_Gen.checkmac)

        if args["search"] != None:
            search_term = args["search"]
            File_handling.Search(results, search_term) 
   
        if mode == "-e":
            salt, validator = Key_Gen.SaltandValidator()
            File_handling.saveMetaData(salt, validator, Mac, file_name)

        if not ".txt" in file_name:
            File_handling.writebinaryFile(file_name, results)
        else:
            File_handling.saveResultsToFile(file_name, results, mode)
            

        #key = Key_Gen.key()
        # if args["json"]:
        #     print(key)
            # json_obj = {
            #     str(file_name).strip(".\\"): str(key)[2:-1]
            # }
            # print(json_obj)
