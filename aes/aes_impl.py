"""
An implementation of the AES-128 bit algorithm. Given the requirements of this
project, we only implement encryption and only in the CBC mode.

Adapted from: https://github.com/burakozpoyraz/Advanced-Encryption-Standard
"""

from functools import lru_cache


#           00   01   02   03   04   05   06   07   08   09   0a   0b   0c   0d   0e   0f
S_BOX = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],  # 00
         [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],  # 10
         [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],  # 20
         [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],  # 30
         [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],  # 40
         [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],  # 50
         [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],  # 60
         [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],  # 70
         [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],  # 80
         [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],  # 90
         [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],  # a0
         [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],  # b0
         [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],  # c0
         [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],  # d0
         [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],  # e0
         [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]  # f0


MIX_COLUMN_MATRIX = [[2, 3, 1, 1],
                     [1, 2, 3, 1],
                     [1, 1, 2, 3],
                     [3, 1, 1, 2]]


KEY_EXPANSION_ROUND_CONSTANT_R1 = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


@lru_cache(maxsize=0x100)
def sub_bytes_transformation(old_byte: int) -> int:
    """
    Applies the ``S_BOX`` on the given byte.
    """
    s_row = (old_byte & 0xF0) >> 4
    s_col =  old_byte & 0x0F
    return S_BOX[s_row][s_col]


def sub_bytes_transformation_matrix(state_matrix: list[list[int]]) -> None:
    """
    Performs the SubBytesTransformation step of the AES algorithm by applying
    the transformation on each element of the given matrix.

    :param state_matrix: The state matrix to transform. A 4x4 array of ints.
                         This array is modified.
    """
    for i in range(4):
        for j in range(4):
            state_matrix[i][j] = sub_bytes_transformation(state_matrix[i][j])


def shift_left(array: list[int], n: int) -> None:
    """
    Shifts the given ``array`` left by ``n`` steps.

    This operation is destructive.

    :param array: The array to shift. A 4 length array of ints. This array is
                  modified.

    :param n: The number of steps to shift.
    """
    array[:] = array[n:] + array[:n]


def shift_rows(matrix) -> None:
    """
    Performs the ShiftRows step of the AES algorithm.

    This operation is destructive.

    :param matrix: The matrix to shift. A 4x4 array of ints. This array is
                   modified.
    """
    for i in range(1, 4):
        shift_left(matrix[i], i)


@lru_cache(maxsize=0x300)
def galois_multiplication(mul: int, n: int) -> int:
    """
    Performs a Galois Multiplication of the given number with the given multiplier.
    We only cover the cases needed for encryption.
    """
    if mul == 0x01:
        return n
    elif mul == 0x02:
        num_shifted = (n << 1) & 0xFF
        if n & 0x80 == 0:
            return num_shifted
        else:
            return num_shifted ^ 0b00011011
    elif mul == 0x03:
        return galois_multiplication(0x02, n) ^ n

    raise ValueError(f"Unrecognized multiplier {mul} in Galois Multiplication.")


def mix_columns(matrix: list[list[int]]) -> list[list[int]]:
    """
    The MixColumns step of the AES algorithm.

    :param matrix: The matrix to transform. A 4x4 array of ints. This array is
                   not touched.
    """
    # This step is simply a matrix multiplication in the GF(256) space (so the
    # XOR is used in place of addition and galois_multiplication is used).
    #
    # The innermost loop is unravelled to make this implementation faster. This
    # method is easily the most time-hogging of the lot.
    return [[(
        galois_multiplication(MIX_COLUMN_MATRIX[row][0], matrix[0][col]) ^
        galois_multiplication(MIX_COLUMN_MATRIX[row][1], matrix[1][col]) ^
        galois_multiplication(MIX_COLUMN_MATRIX[row][2], matrix[2][col]) ^
        galois_multiplication(MIX_COLUMN_MATRIX[row][3], matrix[3][col])
    ) for col in range(4)] for row in range(4)]


def add_round_key(matrix: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """
    The Add Round Key step of the AES algorithm.

    :param matrix: The matrix to transform. A 4x4 array of ints. This array is
                   not touched.

    :param round_key: The key used in this round. Another 4x4 array of ints. We
                       XOR it with the matrix.
    """
    # Strongly creating afresh is more efficient than modifying in place here.
    return [[matrix[row][col] ^ round_key[row][col] for col in range(4)]
            for row in range(4)]


def transform_round_key(round_key: list[list[int]], round_index: int) -> None:
    """
    Generates the round key for the next round of the AES algorithm.

    This operation is destructive.

    :param round_key: The round key of the old round of the AES algorithm. A 4x4
                      array of ints. We modify this array.

    :param round_index: The index of the round we are operating for.

    :return: The next round key as a 4x4 array of ints.
    """
    prev_key_last_col = [round_key[row][3] for row in range(4)]
    shift_left(prev_key_last_col, 1)
    sub_rot_last_column = [sub_bytes_transformation(byte) for byte in prev_key_last_col]

    round_key[0][0] ^= (sub_rot_last_column[0] ^
                        KEY_EXPANSION_ROUND_CONSTANT_R1[round_index])

    for row in range(1, 4):
        round_key[row][0] ^= sub_rot_last_column[row]

    for col in range(1, 4):
        for row in range(4):
            round_key[row][col] ^= round_key[row][col - 1]


def aes_encrypt(state_matrix: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """
    Perform the AES encryption on the given state matrix using the given cipher
    key.

    :param state_matrix: The state matrix to encrypt. A 4x4 array of ints. This
                         array is not touched.

    :param round_key: The cipher key to use. A 4x4 array of ints. This array is
                      modified.

    :return: The encrypted state matrix as a 4x4 array of ints.
    """
    state_matrix = add_round_key(state_matrix, round_key)
    for i in range(10):
        transform_round_key(round_key, i)
        sub_bytes_transformation_matrix(state_matrix)
        shift_rows(state_matrix)
        if i != 9:
            state_matrix = mix_columns(state_matrix)
        state_matrix = add_round_key(state_matrix, round_key)

    return state_matrix


def encrypt_message_aes_cbc(message: bytes, cipher: bytes) -> bytes:
    """
    Encrypts the given bytes using the given cipher via the AES algorithm in CBC
    mode.

    This method is the only one exposed by this module, and should be the only
    one run outside of tests.

    :return: The encrypted bytes.
    """
    if not len(cipher) == 16:
        raise ValueError("The cipher must be exactly 16 bytes.")

    cipher_key = [[0] * 4 for _ in range(4)]
    for j in range(0, 16):
        cipher_key[j % 4][j // 4] = cipher[j]

    padding_needed = (16 - len(message) % 16) % 16
    message += b'\x00' * padding_needed

    encrypted_message = b""
    for i in range(len(message) // 16):
        buffer_matrix = [[0] * 4 for _ in range(4)]
        for j in range(0, 16):
            buffer_matrix[j % 4][j // 4] = message[16 * i + j]
        encrypted_buffer_matrix = aes_encrypt(buffer_matrix, cipher_key)

        for col in range(4):
            for row in range(4):
                encrypted_message += encrypted_buffer_matrix[row][col].to_bytes()

    return encrypted_message
