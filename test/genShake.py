#!/usr/bin/env python3
import binascii

import sha3


def main():
    test_vectors = {
        "Short": "abc",
        "Medium": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "Long": "a" * 1000000,
    }

    hash_funcs = {"SHAKE128": sha3.SHAKE128, "SHAKE256": sha3.SHAKE256}
    output_lens = [31, 63]

    for hash_name, hash_func in hash_funcs.items():
        for vector_name, vector_value in test_vectors.items():
            for output_len in output_lens:
                print(
                    "{} with {:>6}    UTF-8 Input and {} bit Output: {}".format(
                        hash_name,
                        vector_name,
                        output_len * 8,
                        binascii.hexlify(hash_func(vector_value.encode(), output_len)).decode(),
                    )
                )
                print(
                    "{} with {:>6} UTF-16BE Input and {} bit Output: {}".format(
                        hash_name,
                        vector_name,
                        output_len * 8,
                        binascii.hexlify(
                            hash_func(vector_value.encode("UTF-16BE"), output_len)
                        ).decode(),
                    )
                )
                print(
                    "{} with {:>6} UTF-16LE Input and {} bit Output: {}".format(
                        hash_name,
                        vector_name,
                        output_len * 8,
                        binascii.hexlify(
                            hash_func(vector_value.encode("UTF-16LE"), output_len)
                        ).decode(),
                    )
                )


if "__main__" == __name__:
    main()
