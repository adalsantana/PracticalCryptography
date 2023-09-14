from typing import Any
import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from collections import namedtuple

"""
    Notes about RSA: It is not typically used to encrypt messages how some of the below functions perform. 
                     It is typically used to encrypt a session key for a symmetric cipger, or for signatures 
                     Also a note for this demo of RSA vulnerability: When quantum computing arrives, most of our current assymetric algorithms will become breakable. 
                     RSA is already vulnerable to a number of contemprorary attacks, but when quantum computing becomes viable, it will be thoroughly broken
"""

# RSA Oracle Attack Component 
# Oracle only takes ciphertext and returns to if the ciphertext decrypts to a proper PKCS padded element
class FakeOracle: 
    def __init__(self, private_key):
        self.private_key = private_key
    
    def __call__(self, cipher_text):
        recovered_as_int = simple_rsa_decrypt(cipher_text, self.private_key)
        recovered = int_to_bytes(recovered_as_int, self.private_key.key_size//8)
        return recovered [0:2] == bytes([0, 2])
    
""" 
    Demo of ciphertext attacks against protocols based on RSA Encryption Standard 
"""
class RSAOracleAttacker:
    def __init__(self, public_key, oracle):
        self.public_key = public_key
        self.oracle = oracle
        
    def _step1_blinding(self, c):
        self.c0 = c
        self.B = 2**(self.public_key.key_size-16)
        self.s = [1]
        Interval = namedtuple('Interval', ['a', 'b'])
        self.M = [ [Interval(2*self.B), (3*self.B)-1] ]

        self.i = 1
        self.n = self.public_key.public_numbers().n

    def _find_s(self, start_s, s_max = None):
        si = start_s
        ci = simple_rsa_encrypt(si, self.public_key)
        while not self.oracle((self.c0 * ci) % self.n): 
            si += 1
            if s_max and (si > s_max):
                return None
            ci = simple_rsa_encrypt(si, self.public_key)
        return si 
    
    def _step2a_start_the_searching(self):
        # Notice starting s value is computed using c_div function from gmpy2. 
        # This is because we are working with large numbers, we cannot trust python's built-in floating point
        # Many of the values computerd are ranges and not guarunteed to be integers, so fractional values are possible
        si = self._find_s(start_s=gmpy2.c_div(self.n, 3*self.B))
        return si
    
    def _step2b_searching_with_more_than_one_interval(self):
        si = self._find_s(start_s = self.s[-1]+1)
        return si
    
    def _step2c_searching_with_one_interval_left(self): 
        a,b = self.M[-1][0]
        ri = gmpy2.c_div(2*(b*self.s[-1] - 2*self.B), self.n)
        si = None

        while si == None:
            si = gmpy2.c_div((2*self.B + ri*self.n), a)

            s_max = gmpy2.c_div((3*self.B+ri*self.n), a)

            si = self._find_s(start=si, s_max=s_max)
            ri += 1
        return si
    
    def _step3_narrowing_set_of_solutions(self, si): 
        new_intervals = set()
        Interval = namedtuple('Interval', ['a', 'b'])
        for a,b in self.M[-1]: 
            r_min = gmpy2.c_div((a*si - 3*self.B + 1), self.n)
            r_max = gmpy2.f_div((b*si - 2*self.B), self.n)

            for r in range(r_min, r_max+1):
                a_candidate = gmpy2.c_div((2*self.B+r*self.n), si)
                b_candidate = gmpy2.f_div((3*self.B-1+r*self.n), si)

                newInterval = Interval(max(a, a_candidate), min(b, b_candidate))
                new_intervals.add(newInterval)

        new_intervals = list(new_intervals)
        self.M.append(new_intervals)
        self.s.append(si)

        if(len(new_intervals) == 1 and new_intervals[0].a == new_intervals[0].b):
            return True
        return False 
    
    def _step4_computing_the_solution(self):
        interval = self.M[-1][0]
        return interval.a
    """
        Parameters: 
            c : ciphertext to perform the attack on. 
                Input must already be in integer form. Don't forget to call bytes_to_int() before calling this method
    """
    def attack(self, c): 
        self._step1_blinding()

        # do this until there is one interval left 
        finished = False 
        while not finished:
            if self.i == 1: 
                si = self._step2a_start_the_searching()
            elif len(self.M[-1] > 1): 
                si = self._step2b_searching_with_more_than_one_interval()
            elif len(self.M[-1]) == 1: 
                interval = self.M[-1][0]
                si = self._step2c_searching_with_one_interval_left()

            finished = self._step3_narrowing_set_of_solutions(si)
            self.i += 1
        m = self._step4_computing_the_solution()
        return m
# generate a private key 
def key_gen():
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size = 2048, 
        backend = default_backend()
    )

    # extract the public key from the private key 
    public_key = private_key.public_key()

    # Convert the private key into bytes. We won't encrypt it this time
    private_key_bytes  =public_key.public_bytes(
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
        backend=default_backend(),
        password=None
    )

    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return private_key, public_key

######################################### RSA Done Wrong Part One ######################################### 
### DANGER ###
# The following RSA encryption and decyption is completely unsafe and terribly broken
# DO NOT USE for anything other than the practice exercise
# Exercise: Rewrite the RSA encryption/decryption program to use the cryptography module instead of gmpy2 calculations
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
# operation updated with an optional min_size parameters
def int_to_bytes(i, min_size = None):
    # i might be a gmpy2 big integer; convert back to a Python into to 
    i = int(i)
    b = i.to_bytes((i.bit_length()+7)//8, byteorder='big')
    if min_size != None and len(b) < min_size: 
        b = b'\x00'*(min_size-len(b)) + b
    return b

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
        print("\t3. Load public =key File.")
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
                pass
            case '6':
                print("\n\nTerminating. This program will self destruct in 5 seconds. \n")
                pass
            case _: 
                print("Unknown option {}".format(choice))
            
### DANGER ###
"""
    Exercise 4.7 Multiply two RSA encrypted numbers together and decrypt the result to verify the modular exponentiation equation
"""
def homomorphic_rsa(msg_size = 32):
    # first generate the key pair to be used  
    private_key, public_key = key_gen()
    n = public_key.public_numbers().n
    # generate two numbers to encrypt
    m1 = os.urandom(msg_size)
    m2 = os.urandom(msg_size)
    print("\nGenerated numbers: {} {}".format(m1, m2))
    encryptedm1 = simple_rsa_encrypt(m1, public_key)
    encryptedm2 = simple_rsa_encrypt(m2, public_key)
    # FORGOT THE MODULUS WHEN I DID IT ON MY OWN
    product = (encryptedm1 * encryptedm2) % n
    print("\nEncrypted values {} {}\nProduct of encrypted values: {}".format(encryptedm1, encryptedm2, product))
    decrypted = simple_rsa_decrypt(product, private_key)
    print("\nDecrypted result: {}".format(decrypted))


def eves_protege(msg_size = 16):
    private_key, public_key = key_gen()
    n = public_key.public_numbers().n
    msg = 'Super Secret Message'
    r = os.urandom(msg_size)
    encrypted_msg = simple_rsa_encrypt(msg, public_key)
    encrypted_r = simple_rsa_encrypt(r, public_key)
    encrypted_product = (encrypted_msg * encrypted_r) % n
    decrypted_product = simple_rsa_decrypt(encrypted_product, private_key)
    print("\nDecrypted Product: {}".format(decrypted_product))


#####################################################
########   Common modulus RSA Attack Demo    ########
#####################################################
def common_modulus_keygen():
    private_key1 = rsa.generate_private_key(
        public_exponent = 65537, 
        key_size = 2048, 
        backend = default_backend()
    )

    public_key1 = private_key1.public_key()

    n = public_key1.public_numbers().n

    public_key2 = rsa.RSAPublicNumbers(3, n).public_key(default_backend())

    return public_key1, public_key2

def common_modulus_decrypt(c1, c2, key1, key2):
    key1_numbers = key1.public_numbers()
    key2_numbers = key2.public_numbers()

    if key1_numbers.n != key2_numbers.n:
        raise ValueError("Common modulus attack requires a common modulus")
    
    n = key1_numbers.n

    if key1_numbers.e == key2_numbers.e: 
        raise ValueError("Common modulus attack requires different public exponents")
    
    e1, e2 = key1_numbers.e, key2_numbers.e
    num1, num2 = min(e1, e2), max(e1, e2)

    while num2 != 0: 
        num1, num2 = num2, num1 % num2 
    gcd = num1

    a = gmpy2.invert(key1_numbers.e, key2_numbers.e)
    b = float(gcd - (a*e1))/float(e2)

    i = gmpy2.invert(key1_numbers.e, key2_numbers.e)

    mx = pow(c1, a, n)
    my = pow(i, int(-b), n)

    return mx * my % n

def common_modulus_attack_demo():
    pk1, pk2 = common_modulus_keygen()
    pt1 = "Alice's secret message"
    pt2 = "Eve's attack vector"
    c1 = simple_rsa_encrypt(pt1, pk1)
    c2 = simple_rsa_encrypt(pt2, pk2)
    result = common_modulus_decrypt(c1, c2, pk1, pk2)
    print("Demo Output: {}".format(result))

#####################################################
######## End Common modulus RSA Attack Demo  ########
#####################################################

# ----------------------------------------------------------------

#####################################################
########          RSA With Padding           ########
#####################################################
"""
    Padding helps to mitigate the chosen ciphertext attack and the common modulus attack. 
    An adversary is also unable to use the deterministic effects of RSA's encryption to analyze message patterns, frequency, and so forth. 
    Padding also solves the problem of losing leading zeros during encryption by ensuring the input is always a fixed size: the bit size of the modulus

    Do Note: Padding DOES NOT protect against man-in-the-middle or authentication problems. 
    Eve can still intercept and change the public key, enabling complete decryption of Alice's message. Bob still cannot tell who is sending him these messages. 
"""
def padding_main():
    message = b'test'
    private_key = rsa.generate_private_key(
        public_exponent = 65537, 
        key_size = 2048, 
        backend = default_backend()
    )

    public_key = private_key.public_key()

    # notice OAEP requires the use of a hashing algorithm
    ciphertext1 = public_key.encrypt(
        message, 
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()), 
            algorithm = hashes.SHA256(), 
            label = None # Rarely used. Could be because a label doesn't increase security.
        )
    )
    ###
    # WARNING: PKCS #1 v1.5 is obsolete and has vulnerabities that will be explored later. 
    # DO NOT USE EXCEPT WITH LEGACY PROTOCOLS
    ciphertext2 = public_key.encrypt(
        message, 
        padding.PKCS1v15()
        )
    
    recovered1 = private_key.decrypt(
        ciphertext1, 
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()), 
            algorithm = hashes.SHA256(), 
            label = None # Rarely used. Don't know why
        )
    )

    recovered2 = private_key.decrypt(
        ciphertext2, 
        padding.PKCS1v15()
    )

    print("Plaintext: {}".format(message))
    print("Ciphertext with PKCS #1 v1.5 padding (hexlified): {}".format(ciphertext1.hex()))
    print("Ciphertext with OAEP padding (hexlified): {}".format(ciphertext2.hex()))
    print("Recovered 1: {}".format(recovered1))
    print("Recovered 2: {}".format(recovered2))
#####################################################
########       End RSA With Padding          ########
#####################################################


#####################################################
#  Exploiting encryption with PKCS #1 v1.5 padding  #
#####################################################

def rsa_pkcs_exploit():
    Interval = namedtuple('Interval', ['a', 'b'])
    # Imports and dependencies for RS Oracle Attack 
    # Dependencies: simple_rsa_encrypt(), simple_rsa_decrypt(), bytes_to_int()
    private_key = rsa.generate_private_key(
        public_exponent = 65537, 
        key_size = 2048, 
        backend = default_backend()
    )

    public_key = private_key.public_key()

    message = b'test'
    ###
    # WARNING: PKCS #1 v1.5 is obsolete and has vulnerabities that will be explored later. 
    # DO NOT USE EXCEPT WITH LEGACY PROTOCOLS
    ciphertext = public_key.encrypt(
        message, 
        padding.PKCS1v15()
        )
    
    ciphertext_as_int = bytes_to_int(ciphertext)
    recovered_as_int = simple_rsa_decrypt(ciphertext_as_int, private_key)
    recovered = int_to_bytes(recovered_as_int)

    print("Plaintext: {}".format(message))
    print("Recovered: {}".format(recovered))

#####################################################
#                   End Section                     #
#####################################################

def main():
    # Exercise 4.1 Use the simple rsa application to set up communication from Bob to Alice and then send a few encrypted messages from Alice to Bob for decryption
    simple_rsa_crypto_main()

if __name__ == '__main__': 
    main()