#!/usr/bin/python

# import hmac
# from Crypto.Cipher import AES
# from Crypto.Util import Counter
# import hashlib

# class Cipher:

#     def decrypt(self, cipher_text, keys):
#         left = cipher_text[:16]
#         right = cipher_text[16:]

#         # Round 4
#         mac = hmac.new(keys[3][:16], right, hashlib.sha256).hexdigest()[:16].encode()
#         left = bytes([_a ^ _b for _a, _b in zip(mac, left)])

#          # Round 3
#         iv = left

#         cipher_config = AES.new(keys[2][:16], AES.MODE_CTR, counter=Counter.new(128))
#         round_3 = cipher_config.encrypt(iv)

#         temp_right_2 = []

#         for i in range(len(right)):
#             if i == 0 and len(right) > len(round_3):
#                 temp = right[:len(round_3)] 
#                 begin_count = len(round_3)
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 end_count = len(round_3) + len(round_3) 
#             elif len(right) < end_count:
#                 temp = right[begin_count:]
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 break
#             else:
#                 temp = right[begin_count: end_count]
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 begin_count = end_count
#                 end_count += len(round_3)

        
        
#         right = "".encode()
#         for i in range(len(temp_right_2)):
#             right += temp_right_2[i]
        
#         # Round 2
#         mac = hmac.new(keys[1][:16], right, hashlib.sha256).hexdigest()[:16].encode()
#         left = bytes([_a ^ _b for _a, _b in zip(left, mac)])

#         # Round 1
#         iv = left
        
#         cipher_config = AES.new(keys[0][:16], AES.MODE_CTR, counter=Counter.new(128))
#         round_1 = cipher_config.encrypt(iv)


#         temp_right = []

#         for i in range(len(right)):
#             if i == 0 and len(right) > len(round_1):
#                 temp = right[:len(round_1)] 
#                 begin_count = len(round_1)
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 end_count = len(round_1) + len(round_1) 
#             elif len(right) < end_count:
#                 temp = right[begin_count:]
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 break
#             else:
#                 temp = right[begin_count: end_count]
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 begin_count = end_count
#                 end_count += len(round_1)
            
#         right = "".encode()
#         for i in range(len(temp_right)):
#             right += temp_right[i]
        
#         plain_text = left + right  

#         return plain_text
    
    
#     def Encrypt(self, plain_text, keys, Mac):
#         print(len(plain_text))

#         left = plain_text[:16]
#         right = plain_text[16:]

#         # Round 1
#         iv = left
        
#         cipher_config = AES.new(keys[0][:16], AES.MODE_CTR, counter=Counter.new(128))
#         round_1 = cipher_config.encrypt(iv)


#         temp_right = []

#         for i in range(len(right)):
#             if len(right) <= len(round_1):
#                 temp = right
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#             elif i == 0 and len(right) > len(round_1):
#                 temp = right[:len(round_1)] 
#                 begin_count = len(round_1)
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 end_count = len(round_1) + len(round_1) 
#             elif len(right) < end_count:
#                 temp = right[begin_count:]
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 break
#             else:
#                 temp = right[begin_count: end_count]
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#                 begin_count = end_count
#                 end_count += len(round_1)
            
#         right = "".encode()
#         for i in range(len(temp_right)):
#             right += temp_right[i]
        
       
#         # Round 2
#         mac = hmac.new(keys[1][:16], right, hashlib.sha256).hexdigest()[:16].encode()
#         left = bytes([_a ^ _b for _a, _b in zip(left, mac)])


#         # Round 3
#         iv = left

#         cipher_config = AES.new(keys[2][:16], AES.MODE_CTR, counter=Counter.new(128))
#         round_3 = cipher_config.encrypt(iv)

#         temp_right_2 = []

#         for i in range(len(right)):
#             if len(right) <= len(round_1):
#                 temp = right
#                 temp_right.append( bytes([_a ^ _b for _a, _b in zip(round_1, temp)]) )
#             elif i == 0 and len(right) > len(round_3):
#                 temp = right[:len(round_3)] 
#                 begin_count = len(round_3)
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 end_count = len(round_3) + len(round_3) 
#             elif len(right) < end_count:
#                 temp = right[begin_count:]
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 break
#             else:
#                 temp = right[begin_count: end_count]
#                 temp_right_2.append( bytes([_a ^ _b for _a, _b in zip(round_3, temp)]) )
#                 begin_count = end_count
#                 end_count += len(round_3)

        
        
#         right = "".encode()
#         for i in range(len(temp_right_2)):
#             right += temp_right_2[i]

#         # Round 4

#         mac = hmac.new(keys[3][:16], right, hashlib.sha256).hexdigest()[:16].encode()
#         left = bytes([_a ^ _b for _a, _b in zip(mac, left)])

#         cipher_text = left + right

#         Mac = hmac.new(Mac, cipher_text, hashlib.sha256).hexdigest()[:16].encode()
 
#         return cipher_text, Mac

        

        
    
    


