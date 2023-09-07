import hashlib 
import string
import random
import time

def md5_file_hasher(filename):
    file = open(filename, "rb")
    file_contents = file.read()
    hash = hashlib.md5(file_contents).hexdigest()
    file.close()
    return hash

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

def the_power_of_one():
    start = time.time()
    preimage_seed = random.choice(string.ascii_letters)
    test_hash = hashlib.md5(preimage_seed).hexdigest()
    char_search = hash_searcher(test_hash)
    end = time.time()
    print("\nTime: {} for seed {} | match detected: {}".format(end-start, preimage_seed, char_search))

if __name__ == "__main__":
    generate(string.ascii_letters.encode('utf-8'))