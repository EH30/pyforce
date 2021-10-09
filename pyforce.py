import os
import sys
import json
import argparse
import itertools
import libs.check_hash
import concurrent.futures

characters = [
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

sp_hash = []
hash_length = { 
    32: ["md4", "md5", "hmac-md4", "hmac-md5", "ntlm"], 40: ["sha1", "hmac-sha1"], 
    56: ["sha224", "sha3_224", "hmac-sha224", "hmac-sha3_224"], 
    64: ["sha256", "sha3_256", "blake2s", "hmac-sha256", "hmac-sha3_256", "hmac-blake2s"],
    96: ["sha384", "sha3_384", "hmac-sha384", "hmac-sha3_384"], 
    128: ["sha512", "sha3_512", "blake2b", "hmac-sha512", "hmac-sha3_512", "hmac-blake2b"]
}
hash_list = [
    "md4", "md5", "sha1", "sha224", "sha3_224", 
    "sha256", "sha3_256", "blake2s", "sha384", 
    "sha512", "sha3_512", "blake2b", "sha3_384",
    "hmac-md4", "hmac-md5", "hmac-sha1", "hmac-sha224", 
    "hmac-sha3_224", "hmac-sha256", "hmac-sha3_256", 
    "hmac-blake2s", "hmac-sha384", "hmac-sha512", 
    "hmac-sha3_512", "hmac-blake2b", "hmac-sha3_384",
    "ntlm"
]

def help_command():
    return """
    Example 1: python pyforce.py -i hash_here -t number_of_threads_here -l starting_length -x ending_length   
    Example 2: python pyforce.py -f list_of_hash.txt -t number_of_threads_here -l starting_length -x ending_length   
    Example 3: python pyforce.py -i hash_here -w wordlist_here
    """

def load_data(filename):
    global jdata
    
    try:
        with open(filename, "r+") as opn:
            jdata = json.load(opn)
        opn.close()
    except Exception:
        print("[-]error with storing data")
        print("[-]deleting old data")
        with open(filename, "w") as opn:
            opn.write("{}")
        opn.close()

def check_sp_hash(hashed, thash):
    if thash in sp_hash:
        return hashed
    
    return hashed.upper()

def store_data(filename, hashed, h_type, val):
    global jdata, salt

    try:
        with open(filename, "r+") as opn:
            jdata[hashed.upper()] = [h_type, val, salt if salt != None else None]
            opn.seek(0)
            json.dump(jdata, opn, indent=4)
            opn.truncate()
        opn.close()
    except Exception:
        print("[-]error with storing data")
        print("[-]deleting old data")
        opn.write("{}")
        opn.close()

def check_thash(hashed):
    global selected_thash

    try:
        if selected_thash != None:
            temp = selected_thash.strip().lower()
            if temp in hash_list:
                return [temp]
            print("[-]Unknown Hash Type: {0}".format(selected_thash))
            sys.exit()

        thash = hash_length[len(hashed)]
        return thash
    except KeyError:
        return None

def print_cracked(res):
    global salt

    if salt != None and res[0] in c_hash.hash_a:
        print("[*]salt: {0}".format(salt))
        print("\n[*]Type: {0} || Hash Cracked: [{1}]".format(res[0], res[1]))
        return 

    print("\n[*]Type: {0} || Hash Cracked: [{1}]".format(res[0], res[1]))

def is_cracked(data, hashed):
    if hashed in data:
        return data[hashed]
    return [None]

def find_cracked(hashed, jdata, skip):
    if skip != None and skip == 1:
        return -1
    else:
        temp = is_cracked(jdata, hashed.upper())
        if temp[0] != None:
            if temp[2] != None:
                return "[*]Found: {0} || Salt: {1} || Cracked: [{2}] || Hash: {3} ".format(temp[0], temp[2], temp[1], hashed)
            
            return "[*]Found: {0} || Cracked: [{1}] || Hash: {2}".format(temp[0], temp[1], hashed)
    
    return None

def combos(x, hashed, thash):
    global Loop_Break, res

    for combo in itertools.product(''.join(characters), repeat=x):
        chars = "".join(combo)
        
        if Loop_Break:
            exit()
        
        for item in thash:
            if c_hash.launch_check_hash(chars, check_sp_hash(hashed, item), item, salt):
                res = [item, chars]
                Loop_Break = True
                return 0
    return 1


def wlist_crack(hashed, wlist, thash):
    global Loop_Break, res, salt

    count = 0
    with open(wlist, "r", errors="ignore") as opn:
        for line in opn:
            sys.stdout.write("\r[*]Trying Line: %d"%(count))
            sys.stdout.flush()
            count += 1
            if Loop_Break:
                break

            line_strip = line.strip()
            for item in thash:
                if c_hash.launch_check_hash(line_strip, check_sp_hash(hashed, item), item, salt):
                    res = [item, line_strip]
                    Loop_Break = True
                    break
                elif c_hash.launch_check_hash(line, check_sp_hash(hashed, item), item, salt):
                    res = [item, line]
                    Loop_Break = True
                    break
        opn.close()


def launch_pad_wwlist(hashlist, wlist):
    global Loop_Break, res

    if not os.path.isfile(hashlist) or not os.path.isfile(wlist):
        print("[-]File does not exists")
        sys.exit()
    
    if os.stat(hashlist).st_size == 0 or os.stat(wlist).st_size == 0:
        print("[-]Empty File")
        sys.exit()
    
    temp = None
    thash = None
    with open(hashlist, "r") as opn:
        for line in opn:
            line = line.strip()
            thash = check_thash(line)
            if thash == None:
                print("[-]error: Unknown Hash length")
                continue
            
            
            temp = find_cracked(line, jdata, args.s)
            if temp != -1 and temp != None:
                print(temp)
                continue
            
            wlist_crack(line, args.w, thash)
            if res != None:
                print_cracked(res)
                store_data(file_data, line, res[0], res[1])
                Loop_Break = False
                res = None
    opn.close()

def launch_pad_wlist(hashed):
    global res

    thash = check_thash(hashed)
    if thash == None:
        print("[-]error: Unknown Hash length")
        sys.exit()
    
    temp = find_cracked(hashed, jdata, args.s)
    if temp != -1 and temp != None:
        print(temp)
        sys.exit()
    
    wlist_crack(hashed, args.w, thash)
    if res != None:
        print_cracked(res)
        store_data(file_data, hashed, res[0], res[1])

def launch_pad_force(hashed, thash):
    global res, Loop_Break

    if args.t != None:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.t)
        fs = [pool.submit(combos, x,  hashed, thash) for x in range(args.l, args.x+1)]
        threads_count = 0

        print("\r[*]Trying Length: %d to %d || Threads: %d || Hash: %s"%(args.l, args.x, args.t, hashed))
        for th in concurrent.futures.as_completed(fs):
            threads_count += 1
            if Loop_Break:
                print_cracked(res)
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
                    combos(x, hashed, thash)
            elif args.x == None:
                print("\r[*]Trying Length: %d Hash: %s"%(args.l, hashed))
                combos(args.l, hashed, thash)
            
            if res != None:
                print_cracked(res)
            
        except Exception as error:
            print("Example: python pyforce.py -i [You're Hash] -l [starting length] -x [ending length] ")
            print("Type: python pyforce.py -h For More Options")
            print(error)
    
    return 0

def laucnh_pad_hash_list(filename):
    global Loop_Break, res

    if not os.path.isfile(args.f):
        print("[-]File does not exists")
        sys.exit()
    
    if os.stat(args.f).st_size == 0:
        print("[-]Empty File")
        sys.exit()

    with open(filename, "r") as opn:
        for line in opn:
            line = line.strip()
            thash = check_thash(line)
            if thash == None:
                print("[-]error: Unknown Hash length")
                continue
            
            if len(line) == 0:
                continue
            
            temp = find_cracked(line, jdata, args.s)
            if temp != -1 and temp != None:
                print(temp)
                continue

            launch_pad_force(line, thash)
            if res != None:
                store_data(file_data, line, res[0], res[1])
            
            res = None
            Loop_Break = False
        
    opn.close()

if __name__ == "__main__":
    res = None
    salt = None
    temp = [None]
    jdata = None
    Loop_Break = False
    selected_thash = None
    file_data = "cracked_data.json"

    try:
        if len(sys.argv[1]) < 1:
            print("Example: python pyforce.py -t [Threads] -l [Starting Length] -x [Ending Length] -i [You're Hash]")
            print("Type: python pyforce.py -h For More Info")
            sys.exit()
    except IndexError as error:
        print("Example: python pyforce.py -i [You're Hash] -l [Starting length] -x [Ending Length]")
        print("Type: python pyforce.py -h For More Options")
        sys.exit()
    
    parse = argparse.ArgumentParser(description="Examples:\n{0}".format(help_command()), formatter_class=argparse.RawTextHelpFormatter)
    parse.add_argument("-i", type=str, help="Enter the hash")
    parse.add_argument("-f", type=str, help="Enter the file fame with list of hash (Example: list_of_hash.txt)")
    parse.add_argument("-w", type=str, help="Enter the wordlist ( If you use this then you can't use -t, -l and x )")
    parse.add_argument("-d", type=str, help="Enter the type of the hash you want to crack (md5, sha1 ...) ")
    parse.add_argument("-t", type=int, help="Enter the number of threads/max workers")
    parse.add_argument("-l", type=int, help="Enter the starting length")
    parse.add_argument("-x", type=int, help="Enter the ending length")
    parse.add_argument("-sl", type=str, help="Enter salt")
    parse.add_argument("-s", type=int, help="-s 1 will skip checking for already cracked hash")
    args = parse.parse_args()

    print("[*]Starting Script\n")
    if not os.path.isfile(file_data):
        print("[*]Creating File")
        opn = open("cracked_data.json", "w")
        opn.write("{}")
        opn.close()
    
    load_data(file_data)
    c_hash = libs.check_hash.CheckHash() 

    if args.i != None and args.f != None or args.i == None and args.f == None:
        print("use -i for a single hash typed in the terminal and -f for a file containing list of hashes")
        sys.exit()
    
    if args.w != None:
        if args.t != None or args.l != None or args.x != None:
            print("if you're going to use -w wordlist then you can't use -t, -l and -x")
            sys.exit()
    
    if args.sl != None:
        salt = args.sl
    
    if args.d != None:
        selected_thash = args.d

    if args.f != None and args.w == None:
        laucnh_pad_hash_list(args.f)
    elif args.w != None:
        if args.i != None:
            thash = check_thash(args.i)
            if thash == None:
                print("[-]error: Unknown Hash length")
                sys.exit()

            launch_pad_wlist(args.i)
        elif args.f != None:
            launch_pad_wwlist(args.f, args.w)
    else:
        thash = check_thash(args.i)
        if thash == None:
            print("[-]error: Unknown Hash length")
            sys.exit()
        
        hashed = args.i
        temp = find_cracked(hashed, jdata, args.s)
        if temp != -1 and temp != None:
            print(temp)
            sys.exit()
        
        launch_pad_force(hashed, thash)
        if res != None:
            store_data(file_data, hashed, res[0], res[1])
