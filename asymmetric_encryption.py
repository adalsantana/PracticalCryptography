import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# generate a public/private key pair 
def key_gen(backend=default_backend(), password=None):
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size = 2048, 
        backend = backend
    )
    # extract the public key from the private key 
    public_key = private_key.public_key()

    # Convert the private key into bytes. We won't encrypt it this time
    private_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.noEncryption
    )

    # Convert the public key into bytes 
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convert the private key bytes back to a key 
    # Because there is no encyrption of the key, there is no password 
    private_key = serialization.load_pem_private_key(
        private_key_bytes, 
        backend=backend,
        password=password
    )

    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=backend
    )
    return private_key, public_key

######################################### RSA Done Wrong Part One ######################################### 
### DANGER ###
# The following RSA encryption and decyption is completely unsafe and terribly broken
# DO NOT USE for anything other than the practice exercise
############################
def simple_rsa_encrypt(m, publickey):
    # Public_numbers returns a data structure with 'e' and 'n' parameters 
    numbers = publickey.public_numbers()
    # Encryption is (m^e) % n
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    # private_mi,bers returns a data structure with the 'd' and 'n' parameters
    numbers = privatekey.private_numbers()
    # decryption is (c^d) % n
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

# RSA Operates on Integers not message bytes, so we now need to convert mesage into integers
def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python into to 
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def simple_rsa_crypto_main():
    public_key_file = None
    private_key_file = None
    public_key = None
    private_key = None 
    while True: 
        print("Simple RSA Crypto")
        print("------------------")
        print("\tprivate key file: {}".format(private_key_file))
        print("\tpublic_key_file: {}".format(public_key_file))
        print("\t1. Encrypt Message.")
        print("\t2. Decrypt Message.")
        print("\t3. Load public key File.")
        print("\t4. Load private key File.")
        print("\t5. Create and load new public and private key files.")
        print("\t6. Quit.\n")
        choice = input(" >> ")

        match choice: 
            case '1': 
                if not public_key:
                    print("\nNo public key loaded")
                else: 
                    message = input("\nPlaintext").encode()
                    message_as_int = bytes_to_int(message)
                    cipher_as_int = simple_rsa_encrypt(message_as_int, public_key)
                    cipher = int_to_bytes(cipher_as_int)
                    print("\nCiphertext (hexified): {}\n".format(binascii.hexlify(cipher)))
            case '2': 
                if not private_key:
                    print("\nNo private key loaded")
                else: 
                    cipher_hex = input("\nCiphertext (hexlified): ").encode()
                    cipher = binascii.unhexlify(cipher_hex)
                    cipher_as_int = bytes_to_int(cipher)
                    message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
                    message = int_to_bytes(message_as_int)
                    print("\nPlaintext: {}\n".format(message))
            case '3': 
                public_key_file_temp = input("\nEnter public key files: ")
                if not os.path.exists(public_key_file_temp):
                    print("File {} does not exist".format(public_key_file_temp))
                else: 
                    with open(public_key_file_temp, "rb") as public_key_file_object:
                        public_key = serialization.load_pem_public_key(
                            public_key_file_object.read(), 
                            backend = default_backend())
                        public_key_file = public_key_file_temp
                        print("\nPublic Key file loaded.\n")

                        #unload private key if any 
                        private_key = None
                        private_key_file = None
            case '4': 
                private_key_file_temp = input("\nEnter private key file: ")
                if not os.path.exists(private_key_file_temp): 
                    return print("File {} does not exist".format(private_key_file_temp))
                else: 
                    with open(private_key_file_temp, "rb") as private_key_file_object:
                        private_key = serialization.load_pem_private_key(
                            private_key_file_object.read(), 
                            backend = default_backend(), 
                            password = None)
            case '5': 
                private_key_file_temp = input("\nEnter a file name for new private key: ")
                public_key_file_temp = input("\nEnter a filename for a new public key: ")

                if os.path.exists(private_key_file_temp) or os.path.exists(public_key_file_temp):
                    print("File already exists")
                else: 
                    with open(private_key_file_temp, "wb+") as private_key_file_obj: 
                        with open(public_key_file_object, "wb+") as public_key_file_obj:
                            private_key = rsa.generate_private_key(
                                public_exponent = 65537, 
                                key_size = 2048, 
                                backend = default_backend())
                            public_key = private_key.public_key()
                            
                            private_key_bytes = private_key.private_bytes(
                                encoding=serialization.Encoding.PEM, 
                                format=serialization.PrivateFormat.TraditionalOpenSSL, 
                                encryption_algorithm=serialization.NoEncryption()
                            )
                            private_key_file_obj.write(private_key_bytes)

                            public_key_bytes = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM, 
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            public_key_file_obj.write(public_key_bytes)

                            public_key_file = None 
                            private_key_file = private_key_file_temp
            case '6':
                print("\n\nTerminating. This program will self destruct in 5 seconds. \n")
                pass
            case _: 
                print("Unknown option {}".format(choice))
            
### DANGER ###

##################
#
# To start asssume
# - all lowercase words
# - 4 characters or less 
# - This program should take a public key and rsa encrypted ciphertext as inputs
# - Use the RSA encryption to generate a few words of four or fewer letters and break the codes with a brute force program
#
##################

def brute_force_rsa(public_key, ciphertext):
    pass 

def test_brute_force_rsa():
    # get public/private key pair 
    private_key, public_key = key_gen()

# Get Alice to send a few encrypted messages to Bob for decryption
def simple_rsa_test_case():
    pass

def main():
    # Exercise 4.1 Use the simple rsa application to set up communication from Bob to Alice and then send a few encrypted messages from Alice to Bob for decryption
    simple_rsa_crypto_main()

if __name__ == '__main__': 
    main()