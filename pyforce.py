import os
import sys
import itertools
import hashlib

if sys.platform == "linux" or sys.platform == "linux2":
    os.system("clear")

elif sys.platform == "win32":
    os.system("cls")

strings = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'z', 'y',
'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Z', 'Y', '/', '\ ', '.',
 ';', '"', "'", ']', '[', '+', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ':', '|', ',', '=', '-', '_', '!', '@', '#', '$', '%', '^', '&', '*', '(' ,')'  '`', '~']

user_input_hash = input("\033[1;32m Hash: \033[1;m")
user_input_len = int(input("\033[1;32m Length: \033[1;m"))


print("\033[1;32m [+]Starting Script \033[1;m")

cracked = ""
for combo in itertools.product(''.join(strings), repeat=user_input_len):
    chars = ''.join(combo)
    sys.stdout.write("\r \033[1;32m [+]Trying: %s %s \033[1;m"%(chars, cracked))
    sys.stdout.flush()
    
    char_combo = chars.strip()

    hashingmd5 = hashlib.md5(char_combo.encode("utf-8")).hexdigest()
    hashing_uppermd5 = hashingmd5.upper()
    
    hashingsha1 = hashlib.sha1(char_combo.encode("utf-8")).hexdigest()
    hashing_uppersha1 = hashingsha1.upper()
    
    hashingsha224 = hashlib.sha224(char_combo.encode("utf-8")).hexdigest()
    hashing_uppersha224 = hashingsha224.upper()
    
    hashingsha256 = hashlib.sha256(char_combo.encode("utf-8")).hexdigest()
    hashing_uppersha256 = hashingsha256.upper()
    
    hashingsha384 = hashlib.sha384(char_combo.encode("utf-8")).hexdigest()
    hashing_uppersha384 = hashingsha384.upper()
    
    hashingsha512 = hashlib.sha512(char_combo.encode("utf-8")).hexdigest()
    hashing_uppersha512 = hashingsha512.upper()
    #print("\033[1;32m Trying: {0}".format(pwd))

    if hashingmd5 == user_input_hash or hashing_uppermd5 == user_input_hash:
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break
    if hashingsha1 == user_input_hash or hashing_uppersha1 == user_input_hash:
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break
    if hashingsha224 == user_input_hash or hashing_uppersha224 == user_input_hash:
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break
    if hashingsha256 == user_input_hash or hashing_uppersha256 == user_input_hash:
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break
    if hashingsha384 == user_input_hash or hashing_uppersha384 == user_input_hash:
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break
    if hashingsha512 == user_input_hash or hashing_uppersha512 == user_input_hash :
        print("\033[1;36m Hash Cracked: {0}".format(chars))
        break

