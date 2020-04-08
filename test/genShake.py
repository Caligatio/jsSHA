#!/usr/bin/env python3
import binascii
import hashlib


def main():
    test_vectors = {
        "Short": "abc",
        "Medium": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "Long": "a" * 1000000,
    }

    hash_funcs = {"SHAKE128": hashlib.shake_128, "SHAKE256": hashlib.shake_256}
    output_lens = [31, 63, 256]

    for hash_name, hash_func in hash_funcs.items():
        for vector_name, vector_value in test_vectors.items():
            for output_len in output_lens:
                print(
                    "{} with {:>6}    Input and {:>6} bit Output: {}".format(
                        hash_name,
                        vector_name,
                        output_len * 8,
                        binascii.hexlify(hash_func(vector_value.encode()).digest(output_len)).decode(),
                    )
                )


if "__main__" == __name__:
    main()
