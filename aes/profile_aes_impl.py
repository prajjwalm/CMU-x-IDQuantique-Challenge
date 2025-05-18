"""
The implementation of the AES was too slow to begin with. This module runs it
a reasonable number of times and is expected to be run with a profiler to
identify the time sinks.

The main method would take ~10s to execute.
"""

import numpy as np

from aes_impl import encrypt_message_aes_cbc


# We profile the same method as in our ipy notebook.
def aes_pseudo_rng(seed: bytes, num_bytes: int) -> list[bytes]:
    """
    Generates a sequence of pseudo-random bytes using the AES algorithm.

    :param seed: The seed to provide to the AES algorithm.
    :param num_bytes: The number of bytes to generate.

    :return: A list of length-1 byte strings. Each element of this list
             is a pseudo-random byte.
    """
    # One run of the AES generates 16 random bytes, assuming the input length is
    # less than 16 bytes. We will assume that the integers we provide it would
    # be shorter than 16 bytes, since its unlikely that our users will ask for
    # more than 16 * 2^128 bytes to be generated.
    num_iter = num_bytes // 16

    # The AES encryption itself provides the pseudo-randomness, so providing a
    # simple counter is sufficient. Note that this leads to the CTR mode of AES,
    # but we do not use that here.

    # 4 bytes should be enough to cover num_iter, the implementation will pad
    # this ot the needed 16 bytes.
    return [encrypt_message_aes_cbc(i.to_bytes(4), seed)
            for i in range(num_iter)]


def main():
    """
    Main method.
    """
    # We do some minor computations here as a reference to see how long our AES
    # takes. This usually takes ~0.4% of the total time (at this size, it is a
    # smaller chunk when more bytes are used and a larger when fewer are used,
    # as expected), so our implementation is worth ~250 of such operations. Not
    # too shabby, given the nature and complexity of AES.
    min(int.from_bytes(x) for x in aes_pseudo_rng(np.random.bytes(16), 10**6))


if __name__ == '__main__':
    main()