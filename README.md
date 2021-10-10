# Example
<img src="https://github.com/EH30/pyforce/blob/master/example.PNG" >

BruteForce / WordList
----------------------
Works on python3   

Example 1: python pyforce.py -i hash_here -t number_of_threads_here -l starting_length -x ending_length   
Example 2: python pyforce.py -f list_of_hash.txt -t number_of_threads_here -l starting_length -x ending_length   
Example 3: python pyforce.py -i hash_here -l starting_length -x ending_length -d hash_mode   
Example 4: python pyforce.py -i hash_here -w wordlist_here   
Example 5: python pyforce.py -i hash_here -l length   


# Usage
pip3 install requirements.txt   
python pyforce.py -h   

# pyforce
Simple Python script to crack Hash   
Works on python3   

---------------------   

Hash Types: md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, sha3_224, sha3_256, sha3_384, sha3_512, 
hmac-md4, hmac-md5, hmac-sha1, hmac-sha224, hmac-sha3_224, hmac-sha256, hmac-sha3_256, hmac-blake2s, hmac-sha384, 
hmac-sha512, hmac-sha3_512, hmac-blake2b, hmac-sha3_384 and bcrypt   
