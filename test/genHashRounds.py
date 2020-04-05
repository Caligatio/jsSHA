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
        ("SHA3-224", hashlib.sha3_224),
        ("SHA3-256", hashlib.sha3_256),
        ("SHA3-384", hashlib.sha3_384),
        ("SHA3-512", hashlib.sha3_512),
    ]

    for (sha_type, sha_func) in hash_funcs:
        digest = sha_func("abc".encode()).digest()

        # Only loop 4 times since an iteration was done above
        for _ in range(0, 4):
            digest = sha_func(digest).digest()
        print("{:>8} with  5 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))

        # Loop another 5 times to get to 10
        for _ in range(0, 5):
            digest = sha_func(digest).digest()
        print("{:>8} with 10 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))

    hash_funcs = [("SHAKE128", hashlib.shake_128), ("SHAKE256", hashlib.shake_128)]

    for (sha_type, sha_func) in hash_funcs:
        digest = sha_func("abc".encode()).digest(31)

        # Only loop 4 times since an iteration was done above
        for _ in range(0, 4):
            digest = sha_func(digest).digest(31)
        print("{:>8} with  5 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))

        # Loop another 5 times to get to 10
        for _ in range(0, 5):
            digest = sha_func(digest).digest(31)
        print("{:>8} with 10 Rounds: {}".format(sha_type, binascii.hexlify(digest).decode()))


if "__main__" == __name__:
    main()
