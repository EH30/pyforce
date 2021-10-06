# Example
<img src="https://github.com/EH30/pyforce/blob/master/example.PNG" >


# Usage

python pyforce.py -l [The Lenght of Character combinations] -i [You're Hash]

usage: pyforce.py [-h] [-i HASH] [-t THREADS] [-l LENGTH0] [-x LENGTH1]

Options

optional arguments:   
  -h, --help             show this help message and exit   
  -i                     Enter The Hash   
  -t                     Enter The Number of Threads/max workers   
  -l                     Enter The First Length or single Length   
  -x                     Enter The Second Length   

# pyforce
Simple Python script to crack Hash 

BruteForce / WordList
----------------------

Example 1: python pyforce.py -i hash_here -t number_of_threads_here -l starting_length -x ending_length   
Example 2: python pyforce.py -f list_of_hash.txt -t number_of_threads_here -l starting_length -x ending_length   
Example 3: python pyforce.py -i hash_here -w wordlist_here   

Works on python3   
---------------------   

Hashing Algorithms: md5, sha1, sha224, sha256, sha384, sha512, blake2b, blake2s, sha3_224, sha3_256, sha3_384 and sha3_512
