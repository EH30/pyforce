import os
import sys
import itertools
import hashlib
import threading
import concurrent.futures
import argparse


strings = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'z', 'y',
'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Z', 'Y', '/', '\ ', '.',
 ';', '"', "'", ']', '[', '+', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ':', '|', ',', '=', '-', '_', '!', '@', '#', '$', '%', '^', '&', '*', '(' ,')'  '`', '~', ' ']



def console_clear():
    if sys.platform == "linux" or sys.platform == "linux2":
        os.system("clear")
    elif sys.platform == "win32":
        os.system("cls")


def crypto(char_combo, algorithm):
    if algorithm == "md5":
        return hashlib.md5(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha224":
        return hashlib.sha224(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(char_combo.encode("utf-8")).hexdigest()


def combos(x):
    global Loop_Break
    
    for combo in itertools.product(''.join(strings), repeat=x):
        chars = ''.join(combo)

        if Loop_Break:
            exit()

        if crypto(chars.strip(), "md5") == args.Hash or crypto(chars.strip(), "md5").upper() == args.Hash:
            counts = 0
            print("\n\033[1;36m[+]Type: MD5 Hash Cracked: {0}\033[1;m".format(chars))
            Loop_Break = True
            while counts < 1:
                print("\n\033[1;36m[+]Type: MD5 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break
        elif crypto(chars.strip(), "sha1") == args.Hash or crypto(chars.strip(), "sha1").upper() == args.Hash:
            counts = 0
            Loop_Break = True
            print("\n\033[1;36m[+]Type: SHA1 Hash Cracked: {0}\033[1;m".format(chars))
            while counts < 1:
                print("\n\033[1;36m[+]Type: SHA1 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break
        elif crypto(chars.strip(), "sha256") == args.Hash or crypto(chars.strip(), "sha256").upper() == args.Hash:
            counts = 0
            Loop_Break = True
            print("\n\033[1;36m[+]Type:SHA256 Hash Cracked: {0}\033[1;m".format(chars))
            while counts < 1:
                print("\n\033[1;36m[+]Type: SHA256 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break
        elif crypto(chars.strip(), "sha224") == args.Hash or crypto(chars.strip(), "sha224").upper() == args.Hash:
            counts = 0
            Loop_Break = True
            print("\n\033[1;36m[+]Type:SHA224 Hash Cracked: {0}\033[1;m".format(chars))
            while counts < 1:
                print("\n\033[1;36m[+]Type: SHA224 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break
        elif crypto(chars.strip(), "sha384") == args.Hash or crypto(chars.strip(), "sha384").upper() == args.Hash:
            counts = 0
            Loop_Break = True
            print("\n\033[1;36m[+]Type:SHA384 Hash Cracked: {0}\033[1;m".format(chars))
            while counts < 1:
                print("\n\033[1;36m[+]Type: SHA384 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break
        elif crypto(chars.strip(), "sha512") == args.Hash or crypto(chars.strip(), "sha512").upper() == args.Hash:
            counts = 0
            Loop_Break = True
            print("\n\033[1;36m[+]Type:SHA512 Hash Cracked: {0}\033[1;m".format(chars))
            while counts < 1:
                print("\n\033[1;36m[+]Type: SHA512 Hash Cracked: {0}\033[1;m".format(chars))
                counts+=1
            exit()
            break


if __name__ == "__main__":
    Loop_Break = False

    try:
        if len(sys.argv[1]) < 1:
            print("Example: python pyforce.py -t [Threads] -l [First Length] -x [Second Length] -i [You're Hash]")
            print("Type: python pyforce.py -h For More Info")
            sys.exit()
    except IndexError as error:
        print("Example: python pyforce.py -l [Length of letters to try] -i [You're Hash]")
        print("Type: python pyforce.py -h For More Options")
        sys.exit()

    
    parse = argparse.ArgumentParser(description="Brute Force Options")
    parse.add_argument("-i", "--Hash", type=str, help="Enter The Hash")
    parse.add_argument("-t", "--threads", type=int, help="Enter The Number of Threads/max workers")
    parse.add_argument("-l", "--length0", type=int, help="Enter The First Length or single Length")
    parse.add_argument("-x", "--length1", type=int, help="Enter The Second Length")
    args = parse.parse_args()

    console_clear()
    print("\033[1;32m[+]Starting Script \033[1;m\n")

    if args.threads != None:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
        fs = [pool.submit(combos, x) for x in range(args.length0, args.length1+1)]
        threads_count = 0

        print("\r\033[1;32m[+]Trying Length: %d to %d Threads: %d Hash: %s \033[1;m"%(args.length0, args.length1, args.threads, args.Hash))
        for th in concurrent.futures.as_completed(fs):
            threads_count += 1
            sys.stdout.write("\r\033[1;32m[+]Finished Thread: %d \033[1;m"%(threads_count))
            sys.stdout.flush()
            if Loop_Break:
                pool.shutdown(wait=False)
                sys.exit()
    
    elif args.threads == None:
        try:
            if args.length1 != None:
                print("\r\033[1;32m[+]Trying Length: %d to %d Hash: %s \033[1;m"%(args.length0, args.length1, args.Hash))
                for x in range(args.length0, args.length1+1):
                    sys.stdout.write("\r\033[1;32m[+]Trying Characters Length: %d \033[1;m"%(x))
                    sys.stdout.flush()
                    if Loop_Break:
                        break
                    combos(x)
            elif args.length1 == None:
                print("\r\033[1;32m[+]Trying Length: %d Hash: %s \033[1;m"%(args.length0, args.Hash))
                combos(args.length0)
        except Exception as error:
            print("Example: python pyforce.py -l [Length of letters to try] -i [You're Hash]")
            print("Type: python pyforce.py -h For More Options")
            print(error)
        