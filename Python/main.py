#!/usr/bin/python

from argparse import ArgumentParser
from getpass import getpass
import json
from sys import stderr
from os.path import exists
from key_generator import KeyGenerator
from Cipher import Cipher
import binascii


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
            file = open(dest_file, 'w')
        except IOError:
            print("Error: Can't create the \"" + dest_file + "\" file.")
        with file:
            counter = 0
            char_tup = ""
            for r in results:
                if mode == "-e":
                    file.write(r)
                else:
                    for c in r:
                        char_tup += c
                        counter += 1
                        if(counter == 2):
                            value = int(char_tup, 16)
                            if value != 0:
                                char_tup = chr(value)
                                file.write(char_tup)
                            counter = 0
                            char_tup = ""
            

    
    def getSrcFromFile(src_file, mode):
        try:
            file = open(src_file, 'r')
        except IOError:
            print("Error: Can't open the \"" + src_file + "\" file.")
        with file:
            hex_strings = []
            counter = 0
            i = -1
            while True:
                c = file.read(1)
                if not c:
                    break
                if counter % 16 == 0:
                    hex_strings.append("")
                    i += 1
                if mode == "-e":
                    c = format(ord(c), "02x")
                    counter += 1
                counter += 1
                hex_strings[i] += c

            if i < 0:
                raise ValueError("Error: the source file is empty!")
            hex_strings[i] = format(int(hex_strings[i], 16), "016x")
            return hex_strings
        
    def saveMetaData(salt, key, _file):
        metadata = {
            "Salt": str(salt)[2:-1],
            "Key": str(key)[2:-1],
            "searchTerm": []
        }

        out_file = open(_file.strip("\\ .txt") + ".fenc-meta.F", "w")
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

    # File Handling
    file_handling = File_handling
    

    for file_name in name:
        Key_Gen = KeyGenerator(_pass, mode, file_name)
        cipher = Cipher(Key_Gen)

        src = file_handling.getSrcFromFile(file_name, mode)
        results = []
        
        for s in src:
            if mode == "-e":
                results.append(cipher.encrypt(s))
            else:
                results.append(cipher.decrypt(s))
                
        if args["search"] != None:
            search_term = args["search"]
            File_handling.Search(results, search_term) 

        salt, key = Key_Gen.getSaltAndKey()       
        if mode == "-e":
            file_handling.saveResultsToFile(file_name, results, mode)
            file_handling.saveMetaData(salt, key, file_name)
        
        elif mode == "-d":
            file_handling.saveResultsToFile(file_name, results, mode)

        if args["json"]:
            json_obj = {
                str(file_name).strip(".\\"): str(key)[2:-1]
            }
            print(json_obj)
                


    # # Encryption 
    # cipher = Cipher(args['json'])
    # if args["encrypt"] == None and args["decrypt"] == None:
    #     print("File is not Specified")
    # else:
    #     cipher.check_if_file_exists(args['encrypt'])
