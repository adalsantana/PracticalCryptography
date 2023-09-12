import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys 
def generate_key():
    key = os.urandom(16)
    return key

# NEVER USE: ECB is not secure!
# KAT: Known Answer Test
#  Exercise 3.5 Write a program to read one of the NIST KAT
# Test and validate your AES library on all vectors on a couple of ECB test files
def ecb_example(offset):
    ifile, ofile = sys.argv[1:3]
    with open (ifile, "rb") as reader:
    with open(ofile, "wb+") as writer:
        image_data = reader.read()
        header, body = image_data[:offset], image_data[offset:]
        body += b"\x00"*(16-(len(body))%16)
        writer.write(header + aesEncryptor.update(body))
    # NIST AES ECBFGSbox128.rsp ENCRYPT Kats