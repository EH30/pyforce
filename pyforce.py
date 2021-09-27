import sys
import hashlib
import argparse
import itertools
import concurrent.futures

strings = [
 'a', 'b', 'c', 'd', 'e', 'f', 'g',
 'h', 'i', 'j', 'k', 'l', 'm', 'n',
 'o', 'p', 'q', 'r', 's', 't', 'u', 
 'v', 'w', 'x', 'z', 'y', 'A', 'B', 
 'C', 'D', 'E', 'F', 'G', 'H', 'I', 
 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 
 'X', 'Z', 'Y', '/','\ ', '.', ';', 
 '"', "'", ']', '[', '+', '1', '2', 
 '3', '4', '5', '6', '7', '8', '9', 
 '0', ':', '|', ',', '=', '-', '_', 
 '!', '@', '#', '$', '%', '^', '&', 
 '*', '(' ,')'  '`', '~', ' '
]


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
    elif algorithm == "blake2b":
        return hashlib.blake2b(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "blake2s":
        return hashlib.blake2s(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha3_224":
        return hashlib.sha3_224(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha3_256":
        return hashlib.sha3_256(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha3_384":
        return hashlib.sha3_384(char_combo.encode("utf-8")).hexdigest()
    elif algorithm == "sha3_512":
        return hashlib.sha3_512(char_combo.encode("utf-8")).hexdigest()

def combos(x):
    global Loop_Break, hashes, res
    
    for combo in itertools.product(''.join(strings), repeat=x):
        chars = ''.join(combo)

        if Loop_Break:
            exit()

        if crypto(chars, "md5") == args.i or crypto(chars, "md5").upper() == args.i:
            res = "\n\033[1;36m[+]Type: MD5 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha1") == args.i or crypto(chars, "sha1").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA1 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha256") == args.i or crypto(chars, "sha256").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA256 || Hash Cracked: [{0}]\033[1;m".format(chars)           
            Loop_Break = True
            exit()
        elif crypto(chars, "sha224") == args.i or crypto(chars, "sha224").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA224 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha384") == args.i or crypto(chars, "sha384").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA384 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha512") == args.i or crypto(chars, "sha512").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA512 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha3_224") == args.i or crypto(chars, "sha3_224").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA3_224 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha3_256") == args.i or crypto(chars, "sha3_256").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA3_256 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha3_384") == args.i or crypto(chars, "sha3_384").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA3_384 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "sha3_512") == args.i or crypto(chars, "sha3_512").upper() == args.i:
            res = "\n\033[1;36m[+]Type: SHA3_512 || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "blake2b") == args.i or crypto(chars, "blake2b").upper() == args.i:
            res = "\n\033[1;36m[+]Type: BLAKE2b || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()
        elif crypto(chars, "blake2s") == args.i or crypto(chars, "blake2s").upper() == args.i:
            res = "\n\033[1;36m[+]Type: BLAKE2s || Hash Cracked: [{0}]\033[1;m".format(chars)
            Loop_Break = True
            exit()

if __name__ == "__main__":
    Loop_Break = False
    res = ""

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
    parse.add_argument("-i", type=str, help="Enter The Hash")
    parse.add_argument("-t", type=int, help="Enter The Number of Threads/max workers")
    parse.add_argument("-l", type=int, help="Enter The First Length or single Length")
    parse.add_argument("-x", type=int, help="Enter The Second Length")
    args = parse.parse_args()

    print("\033[1;32m[+]Starting Script \033[1;m\n")

    if args.t != None:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.t)
        fs = [pool.submit(combos, x) for x in range(args.l, args.x+1)]
        threads_count = 0

        print("\r\033[1;32m[+]Trying Length: %d to %d || Threads: %d || Hash: %s \033[1;m"%(args.l, args.x, args.t, args.i))
        for th in concurrent.futures.as_completed(fs):
            threads_count += 1
            if Loop_Break:
                print(res)
                pool.shutdown(wait=False)
                sys.exit()
            print("\033[1;32m[+]Thread stopped trying next length\033[1;m")
    
    elif args.t == None:
        try:
            if args.x != None:
                print("\r\033[1;32m[+]Trying Length: %d to %d || Hash: %s \033[1;m"%(args.l, args.x, args.i))
                for x in range(args.l, args.x+1):
                    sys.stdout.write("\r\033[1;32m[+]Trying Characters Length: %d \033[1;m"%(x))
                    sys.stdout.flush()
                    if Loop_Break:
                        break
                    combos(x)
            elif args.x == None:
                print("\r\033[1;32m[+]Trying Length: %d Hash: %s \033[1;m"%(args.l, args.i))
                combos(args.l)
        except Exception as error:
            print("Example: python pyforce.py -l [Length of letters to try] -i [You're Hash]")
            print("Type: python pyforce.py -h For More Options")
            print(error)
