import os
import sys
import json
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

def load_data(filename):
    global jdata
    try:
        with open(filename, "r+") as opn:
            jdata = json.load(opn)
        opn.close()
    except Exception:
        print("[-]error with storing data")
        print("[-]deleting old data")
        opn.write("{}")
        opn.close()

def store_data(filename, hashed_value, h_type, val):
    global jdata
    try:
        with open(filename, "r+") as opn:
            jdata[hashed_value] = [h_type, val]
            opn.seek(0)
            json.dump(jdata, opn, indent=4)
            opn.truncate()
        opn.close()
    except Exception:
        print("[-]error with storing data")
        print("[-]deleting old data")
        opn.write("{}")
        opn.close()

def is_cracked(data, hashed):
    if hashed in data:
        return data[hashed]
    return [None]

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

def combos(x, hashed):
    global Loop_Break, hashes, res
    
    for combo in itertools.product(''.join(strings), repeat=x):
        chars = ''.join(combo)

        if Loop_Break:
            exit()

        if crypto(chars, "md5").lower() == hashed:
            res = ["MD5", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha1").lower() == hashed:
            res = ["SHA1", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha256").lower() == hashed:
            res = ["SHA256", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha224").lower() == hashed:
            res = ["SHA224", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha384").lower() == hashed:
            res = ["SHA384", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha512").lower() == hashed:
            res = ["SHA512", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha3_224").lower() == hashed:
            res = ["SHA3_224", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha3_256").lower() == hashed:
            res = ["SHA3_256", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha3_384").lower() == hashed:
            res = ["SHA3_384", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "sha3_512").lower() == hashed:
            res = ["SHA3_512", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "blake2b").lower() == hashed:
            res = ["BLAKE2b", chars]
            Loop_Break = True
            return 0
        elif crypto(chars, "blake2s").lower() == hashed:
            res = ["BLAKE2s", chars]
            Loop_Break = True
            return 0
    return 1


def launch_pad(hashed):
    global res, Loop_Break

    if args.t != None:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.t)
        fs = [pool.submit(combos, x,  hashed) for x in range(args.l, args.x+1)]
        threads_count = 0

        print("\r[*]Trying Length: %d to %d || Threads: %d || Hash: %s"%(args.l, args.x, args.t, hashed))
        for th in concurrent.futures.as_completed(fs):
            threads_count += 1
            if Loop_Break:
                print("[*]Type: {0} || Hash Cracked: [{1}]".format(res[0], res[1]))
                pool.shutdown(wait=False)
                return 0
            print("[*]Thread stopped trying next length")
    
    elif args.t == None:
        try:
            if args.x != None:
                print("\r[*]Trying Length: %d to %d || Hash: %s "%(args.l, args.x, hashed))
                for x in range(args.l, args.x+1):
                    sys.stdout.write("\r[*]Trying Characters Length: %d"%(x))
                    sys.stdout.flush()
                    if Loop_Break:
                        break
                    combos(x,hashed)
            elif args.x == None:
                print("\r[*]Trying Length: %d Hash: %s"%(args.l, hashed))
                combos(args.l, hashed)
            
            if res != None:
                print("\n[*]Type: {0} || Hash Cracked: [{1}]".format(res[0], res[1]))
            
        except Exception as error:
            print("Example: python pyforce.py -l [Length of letters to try] -i [You're Hash]")
            print("Type: python pyforce.py -h For More Options")
            print(error)
    
    return 0

if __name__ == "__main__":
    res = None
    data = None
    jdata = None
    temp = [None]
    Loop_Break = False
    file_data = "cracked_data.json"

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
    parse.add_argument("-f", type=str, help="Enter The File Name Which Contains List Of hashes")
    parse.add_argument("-t", type=int, help="Enter The Number of Threads/max workers")
    parse.add_argument("-l", type=int, help="Enter The First Length or single Length")
    parse.add_argument("-x", type=int, help="Enter The Second Length")
    parse.add_argument("-s", type=int, help="-s 1 will skip checking for already cracked hash")
    args = parse.parse_args()


    print("[*]Starting Script\n")
    if not os.path.isfile(file_data):
        print("[*]Creating File")
        opn = open("cracked_data.json", "w")
        opn.write("{}")
        opn.close()
    
    load_data(file_data)

    if args.i != None and args.f != None or args.i == None and args.f == None:
        print("use -i for a single hash typed in the terminal and -f for a file containing list of hashes")
    
    if args.f != None:
        if not os.path.isfile(args.f):
            print("[-]File does not exists")
            sys.exit()
        
        if os.stat(args.f).st_size == 0:
            print("[-]Empty File")
            sys.exit()

        with open(args.f, "r") as opn:
            for line in opn:
                data = line.strip()
                if len(data) == 0:
                    continue
                if args.s != None and args.s == 1:
                    pass
                else:
                    temp = is_cracked(jdata, data.lower())
                    if temp[0] != None:
                        print("[*]Found {0} || Cracked: [{1}] || hash: {2}".format(temp[0], temp[1], data))
                        continue

                launch_pad(data.lower())
                if res != None:
                    store_data(file_data, data, res[0], res[1])
                res = None
                Loop_Break = False
        opn.close()
    else:
        if args.s != None and args.s == 1:
            pass
        else:
            temp = is_cracked(jdata, args.i.lower())
            if temp[0] != None:
                print("[*]Found {0} || Cracked: [{1}] || hash: {2}".format(temp[0], temp[1], args.i.lower()))
                sys.exit()
        
        launch_pad(args.i.lower())
        if res != None:
            store_data(file_data, args.i.lower(), res[0], res[1])
