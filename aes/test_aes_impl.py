"""
Unit tests for the AES implementation. These make sure we are actually
implementing AES as documented and have not left any defects.
"""

from unittest import TestCase

from aes_impl import (encrypt_message_aes_cbc,
                      add_round_key,
                      transform_round_key,
                      mix_columns,
                      shift_rows,
                      sub_bytes_transformation_matrix)


class TestAesMethods(TestCase):
    """
    Unit tests covering the various methods used to implement the AES algorithm.

    The data in these tests are based on the example given in the AES Publication.
    (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
    """

    def test_sub_bytes_transformation_matrix(self):
        """
        This unit test ensures that the sub bytes transformation matrix works
        as expected.
        """
        matrix = [
            [0x19, 0xa0, 0x9a, 0xe9],
            [0x3d, 0xf4, 0xc6, 0xf8],
            [0xe3, 0xe2, 0x8d, 0x48],
            [0xbe, 0x2b, 0x2a, 0x08]
        ]
        sub_bytes_transformation_matrix(matrix)
        self.assertListEqual(
            [
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30]
            ],
            matrix
        )

    def test_shift_rows(self):
        """
        This unit test ensures that the shift rows operation works as expected.
        """
        matrix = [
            [0xd4, 0xe0, 0xb8, 0x1e],
            [0x27, 0xbf, 0xb4, 0x41],
            [0x11, 0x98, 0x5d, 0x52],
            [0xae, 0xf1, 0xe5, 0x30]
        ]
        shift_rows(matrix)
        self.assertListEqual(
            [
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]
            ],
            matrix
        )

    def test_mix_columns(self):
        """
        This unit test ensures that the mix columns operation works as expected.
        """
        self.assertListEqual(
            [
                [0x04, 0xe0, 0x48, 0x28],
                [0x66, 0xcb, 0xf8, 0x06],
                [0x81, 0x19, 0xd3, 0x26],
                [0xe5, 0x9a, 0x7a, 0x4c]
            ],
            mix_columns([
                [0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]
            ])
        )

    def test_generate_round_key(self):
        """
        This unit test ensures that the round key generation works as expected.
        """
        key = [
            [0x2b, 0x28, 0xab, 0x09],
            [0x7e, 0xae, 0xf7, 0xcf],
            [0x15, 0xd2, 0x15, 0x4f],
            [0x16, 0xa6, 0x88, 0x3c]
        ]
        transform_round_key(key, 0)
        self.assertListEqual(
            [
                [0xa0, 0x88, 0x23, 0x2a],
                [0xfa, 0x54, 0xa3, 0x6c],
                [0xfe, 0x2c, 0x39, 0x76],
                [0x17, 0xb1, 0x39, 0x05]
            ],
            key
        )
        transform_round_key(key, 1)
        self.assertListEqual(
            [
                [0xf2, 0x7a, 0x59, 0x73],
                [0xc2, 0x96, 0x35, 0x59],
                [0x95, 0xb9, 0x80, 0xf6],
                [0xf2, 0x43, 0x7a, 0x7f]
            ],
            key
        )

    def test_add_round_key(self):
        """
        This unit test ensures that the round key generation works as expected.
        """
        self.assertListEqual([
                [0xa4, 0x68, 0x6b, 0x02],
                [0x9c, 0x9f, 0x5b, 0x6a],
                [0x7f, 0x35, 0xea, 0x50],
                [0xf2, 0x2b, 0x43, 0x49]
            ],
            add_round_key([
                [0x04, 0xe0, 0x48, 0x28],
                [0x66, 0xcb, 0xf8, 0x06],
                [0x81, 0x19, 0xd3, 0x26],
                [0xe5, 0x9a, 0x7a, 0x4c]
            ], [
                [0xa0, 0x88, 0x23, 0x2a],
                [0xfa, 0x54, 0xa3, 0x6c],
                [0xfe, 0x2c, 0x39, 0x76],
                [0x17, 0xb1, 0x39, 0x05]
            ])
        )

    def test_full_aes(self):
        """
        This unit test ensures the full AES algorithm works as expected.
        """
        self.assertEqual(
            b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32',
            encrypt_message_aes_cbc(
                b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34',
                b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'))
