#!/usr/bin/env python2
import binascii
import hashlib

import sha3

def main():
    hash_funcs = [
        ('SHA-1', hashlib.sha1),
        ('SHA-224', hashlib.sha224),
        ('SHA-256', hashlib.sha256),
        ('SHA-384', hashlib.sha384),
        ('SHA-512', hashlib.sha512)]

    for (sha_type, sha_func) in hash_funcs:
        digest = sha_func('abc').digest()

        # Only loop 4 times since an iteration was done above
        for x in xrange(0, 4):
            digest = sha_func(digest).digest()
        print('{} with 5 Rounds: {}'.format(sha_type, digest.encode('hex')))

        # Loop another 5 times to get to 10
        for x in xrange(0, 5):
            digest = sha_func(digest).digest()
        print('{} with 10 Rounds: {}'.format(sha_type, digest.encode('hex')))

    # SHA3 is handled differently as it's not in hashlib.
    # Use the SHA3 creators' version
    hash3_funcs = [
        ('SHA3-224', sha3.SHA3_224),
        ('SHA3-256', sha3.SHA3_256),
        ('SHA3-384', sha3.SHA3_384),
        ('SHA3-512', sha3.SHA3_512)]

    for (sha_type, sha_func) in hash3_funcs:
        digest = sha_func([ord(c) for c in 'abc'])

        # Only loop 4 times since an iteration was done above
        for x in xrange(0, 4):
            digest = sha_func(digest)
        print('{} with 5 Rounds: {}'.format(sha_type, binascii.hexlify(digest)))

        # Loop another 5 times to get to 10
        for x in xrange(0, 5):
            digest = sha_func(digest)
        print('{} with 10 Rounds: {}'.format(sha_type, binascii.hexlify(digest)))

    hash3_funcs = [
        ('SHAKE128', sha3.SHAKE128),
        ('SHAKE256', sha3.SHAKE256)]

    for (sha_type, sha_func) in hash3_funcs:
        digest = sha_func([ord(c) for c in 'abc'], 31)

        # Only loop 4 times since an iteration was done above
        for x in xrange(0, 4):
            digest = sha_func(digest, 31)
        print('{} with 5 Rounds: {}'.format(sha_type, binascii.hexlify(digest)))

        # Loop another 5 times to get to 10
        for x in xrange(0, 5):
            digest = sha_func(digest, 31)
        print('{} with 10 Rounds: {}'.format(sha_type, binascii.hexlify(digest)))

if ('__main__' == __name__):
    main()
