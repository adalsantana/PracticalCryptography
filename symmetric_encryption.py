import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys 

class Oracle: 
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv 

    def accept(self, ciphertext):
        aesCipher = Cipher(algorithms.AES(self.key), 
                           modes.CBC(self.iv), 
                           backend = default_backend())
        decryptor = aesCipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        plaintext += decryptor.finalize()
        return plaintext[-1] == 15

# This function assumes that hte last ciphertext block is a full block off SSLV3 padding 
def lucky_get_one_byte(iv, ciphertext, block_number, oracle): 
    block_start = block_number * 16 
    block_end = block_start + 16 
    block = ciphertext[block_start: block_end]

    # Copy over the last block 
    mod_ciphertext = ciphertext[:-16] + block 
    if not oracle.accept(mod_ciphertext): 
        return False, None 
    
    # This is valid! Lets get the byte 
    # We first need the byte decrypted from the block 
    # It was XORed with the second to last block so, 
    # byte = 15 XOR (last byte of second to last block)
    second_to_last = ciphertext[-32:-16]
    intermediate = second_to_last[-1]^15

    # We still have to XOR it with its *real* 
    # preceding block in order to get the true value 
    if block_number == 0: 
        prev_block = iv
    else: 
        prev_block = ciphertext[block_start-16: block_start]
    
    # This function is counting in the penultimate block being lucky. 
    # We have to be lucky enough that the last byte of the penultimate will just happen to XOR with our intermediate byte to be 15 
    # This luck that we are counting on is dependent on the key and IV chosen
    return True, intermediate ^ prev_block[-1]

def generate_key():
    key = os.urandom(16)
    return key

# NEVER USE: ECB is not secure!
# KAT: Known Answer Test
#  Exercise 3.5 Write a program to read one of the NIST KAT
# Test and validate your AES library on all vectors on a couple of ECB test files
def ecb_example(offset, key, iv):
    ifile, ofile = sys.argv[1:3]
    aesCipher = Cipher(algorithms.AES(key), 
                           modes.CBC(iv), 
                           backend = default_backend())
    aesEncryptor = aesCipher.encryptor()
    with open (ifile, "rb") as reader:
        with open(ofile, "wb+") as writer:
            image_data = reader.read()
            header, body = image_data[:offset], image_data[offset:]
            body += b"\x00"*(16-(len(body))%16)
            writer.write(header + aesEncryptor.update(body))
    # NIST AES ECBFGSbox128.rsp ENCRYPT Kats