# Listing 2-1 Intro to haslib 
import hashlib
md5hasher = hashlib.md5()
print("Empty hash: {}".format(md5hasher.hexdigest()))

#Listing 2-2: Hashing Names 
md5hasher = hashlib.md5(b'alice')
print("\nHash of alice: {}".format(md5hasher.hexdigest()))
md5hasher = hashlib.md5(b'bob')
print("\nHash of bob: {}".format(md5hasher.hexdigest()))

# Listing 2-3 Combining Operations
#md5hasher = hashlib.md5(b'alice')
print("\nOne Liner Hash of alice: {}".format(hashlib.md5(b'alice').hexdigest()))
print("\nOne Liner Hash of bob: {}".format(hashlib.md5(b'bob').hexdigest()))

""" Notes: Python differentiates between unicode and raw byte strings. For almost all cryptographic purposes you must use bytes
Otherwise you may end up with some nasty surprises when the interpreter attempst (or refuses) to convert Unicode string into bytes for you"""

# Exercies 2.1 Welcome to MD5 
# Computer the MD5 sum of the following inputs 
print("\nhash of alice: {}".format(hashlib.md5(b'alice').hexdigest()))
print("\nhash of bob: {}".format(hashlib.md5(b'bob').hexdigest()))
print("\nhash of balice: {}".format(hashlib.md5(b'balice').hexdigest()))
print("\nhash of cob: {}".format(hashlib.md5(b'cob').hexdigest()))
print("\nhash of a: {}".format(hashlib.md5(b'a').hexdigest()))
print("\nhash of aa: {}".format(hashlib.md5(b'aa').hexdigest()))
print("\nhash of aaaaaaaaaa: {}".format(hashlib.md5(b'aaaaaaaaaa').hexdigest()))
print("\nhash of a*100,000: {}".format(hashlib.md5(b'a'*100000).hexdigest()))

# Listing 2-4. Hash Update 
md5hasher = hashlib.md5()
md5hasher.update(b'a')
md5hasher.update(b'l')
md5hasher.update(b'i')
md5hasher.update(b'c')
md5hasher.update(b'e')
print("\nAlice of hash through update {}".format(md5hasher.hexdigest()))

# Exercises 2.2
#1. This hash produces a result stating the original input is "password"
#2. This hash produces a result stating it is an empty hash (e.g. the hash produced by lines 3 + 4 in this file)
#3. This hash produces a result stating the original input is "alice"