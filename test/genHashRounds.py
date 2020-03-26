#!/usr/bin/env python3
import binascii
import hashlib


def main():
    hash_funcs = [
        ("SHA-1", hashlib.sha1),
        ("SHA-224", hashlib.sha224),
        ("SHA-256", hashlib.sha256),
        ("SHA-384", hashlib.sha384),
        ("SHA-512", hashlib.sha512),
    ]

    for (sha_type, sha_func) in hash_funcs:
        digest = sha_func("abc".encode()).digest()

        # Only loop 4 times since an iteration was done above
        for x in range(0, 4):
            digest = sha_func(digest).digest()
        print("{:>7} with  5 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))

        # Loop another 5 times to get to 10
        for x in range(0, 5):
            digest = sha_func(digest).digest()
        print("{:>7} with 10 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))


if "__main__" == __name__:
    main()
