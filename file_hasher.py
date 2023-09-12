import hashlib 
import string
import random
import time
import os 
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Exercise 2.4: Write a python program that computes the md5 sum of the file
def md5_file_hasher(filename):
    file = open(filename, "rb")
    file_contents = file.read()
    hash = hashlib.md5(file_contents).hexdigest()
    file.close()
    return hash

def sha1_file_hasher(filename):
    file = open(filename, "rb")
    file_contents = file.read()
    hash = hashlib.sha1(file_contents).hexdigest()
    file.close()
    return hash

def sha256_file_hasher(filename):
    file = open(filename, "rb")
    file_contents = file.read()
    hash = hashlib.md5(file_contents).hexdigest()
    file.close()
    return hash

def scrypt_generate_key():
    salt = os.random(16)
    kdf = Scrypt(salt-salt, length=32, 
                 n=2**14, r=8, p=1, 
                 backend=default_backend())
    key = kdf.derive(b"my great password")
    return key

def scrypt_verify(): 
    kdf = Scrypt(salt-salt, length=32, 
                 n=2**14, r=8, p=1, 
                 backend=default_backend())
    kdf.verify(b"my great password")
    print("Success! (Exception if mismatch)")
    
def generate(alphabet, max_len):
    if (max_len <= 0): return
    for c in alphabet: 
        yield c 
    for c in alphabet:
        for next in generate(alphabet, max_len-1):
            yield c + next 
# this only checks a letter as a time as an exercise 
def hash_searcher(target_hash):
    for letter in string.ascii_letters: 
        letter_hash = hashlib.md5(letter).hexdigest()
        if (letter_hash == target_hash): 
            return letter
# Exercise 2.5 The power of one
def the_power_of_one():
    start = time.time()
    preimage_seed = random.choice(string.ascii_letters)
    test_hash = hashlib.md5(preimage_seed).hexdigest()
    char_search = hash_searcher(test_hash)
    end = time.time()
    print("\nTime: {} for seed {} | match detected: {}".format(end-start, preimage_seed, char_search))

if __name__ == "__main__":
    generate(string.ascii_letters.encode('utf-8'))