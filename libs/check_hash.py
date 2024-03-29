import hmac
import bcrypt
import hashlib

class CheckHash:
    def __init__(self):
        self.hash_a =  [
            "md4", "md5", "sha1", "sha224", "sha3_224", 
            "sha256", "sha3_256", "blake2s", "sha384", 
            "sha512", "sha3_512", "blake2b", "sha3_384"
        ]
        self.hash_b = [
            "hmac-md4", "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha3_224", 
            "hmac-sha256", "hmac-sha3_256", "hmac-blake2s", "hmac-sha384", 
            "hmac-sha512", "hmac-sha3_512", "hmac-blake2b", "hmac-sha3_384"
        ]
        self.add_salt = ["bcrypt"]
    
    def check_hash(self, char_combo, hashed, algorithm, salt_key):
        if algorithm in self.hash_a:
            return hashlib.new(algorithm, char_combo.encode("utf-8")).hexdigest().upper() == hashed
        elif salt_key != None and algorithm in self.hash_b:
            return hmac.new(bytes(salt_key, "utf-8"), bytes(char_combo, "utf-8"), algorithm.split("-")[1]).hexdigest().upper() == hashed
        elif algorithm == "ntlm":
            return hashlib.new('md4', char_combo.encode('utf-16le')).hexdigest().upper() == hashed
        elif algorithm == "bcrypt":
            return bcrypt.checkpw(bytes(char_combo, "utf-8"), bytes(hashed, "utf-8"))
        
    def launch_check_hash(self, chars, hashed, algo, salt_key):
        if salt_key != None:
            if algo in self.hash_a or algo in self.add_salt:
                if self.check_hash(chars+salt_key, hashed, algo, None) or self.check_hash(salt_key+chars, hashed, algo, None) or self.check_hash(salt_key+chars+salt_key, hashed, algo, None):
                    return True
        
        return self.check_hash(chars, hashed, algo, salt_key)
