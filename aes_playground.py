import os

def generate_key():
    key = os.urandom(16)
    return key