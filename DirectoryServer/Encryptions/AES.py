# Libraries
from hashlib import md5


# Import settings
__all__ = ['aes']


# Matrix Class
class _Matrix:
    """
    A class representing a 4x4 matrix of byte integers used in the AES algorithm.
    """

    # Maximum value of 1 byte
    MAX_ITEM_VALUE = 256

    # Count of rows in matrix
    ROW_COUNT = 4

    # Count of columns in matrix
    COL_COUNT = 4

    # Matrix size
    MATRIX_SIZE = ROW_COUNT * COL_COUNT

    # Constructor
    def __init__(self, data: str | int | list[list[int]]):
        """
        Initializes the matrix with data provided in different formats
        :param data: Either a string, integer, or list to initialize the matrix.
        If string - length must be a 16, if list - 4x4 matrix, if int - 16 bytes length
        """
        matrix = []

        if isinstance(data, str) and len(data) == self.MATRIX_SIZE:
            matrix = [[ord(data[i]) % self.MAX_ITEM_VALUE for i in range(j, j + self.COL_COUNT)]
                      for j in range(0, self.MATRIX_SIZE, self.COL_COUNT)]

        elif isinstance(data, int):
            for _ in range(self.ROW_COUNT):
                row = []
                for _ in range(self.COL_COUNT):
                    row.insert(0, data % self.MAX_ITEM_VALUE)
                    data >>= 8
                matrix.insert(0, row)

        elif isinstance(data, list) and len(data) == _Matrix.ROW_COUNT and len(data[0]) == _Matrix.COL_COUNT:
            matrix = data

        self.__matrix = matrix

    def __getitem__(self, coordinates: tuple[int, int]) -> int:
        """
        Retrieves the value at a specific position in the matrix
        :param coordinates: coordinates tuple
        :return: value at the specified position
        """
        row, col = coordinates
        if (0 <= row < self.ROW_COUNT) and (0 <= col < self.COL_COUNT):
            return self.__matrix[row][col]
        return -1

    def __setitem__(self, coordinates: tuple[int, int], value: int) -> None:
        """
        Sets a new value at a specific position in the matrix
        :param coordinates: coordinates tuple
        :param value: new value to set
        """
        row, col = coordinates
        if (0 <= row < self.ROW_COUNT) and (0 <= col < self.COL_COUNT) and (0 <= value <= self.MAX_ITEM_VALUE):
            self.__matrix[row][col] = value

    def get_row(self, row: int) -> list[int]:
        """
        Returns the row in matrix by its index
        :param row: row index
        :return: specific row in the matrix
        """
        if 0 <= row <= self.ROW_COUNT:
            return self.__matrix[row]

    def get_col(self, col: int) -> list[int]:
        """
        Returns the column in matrix by its index
        :param col: column index
        :return: specific column in the matrix
        """
        if 0 <= col <= self.COL_COUNT:
            return [self.__matrix[i][col] for i in range(self.ROW_COUNT)]

    def set_row(self, row: int, new_row: list) -> None:
        """
        Sets a new row value at a specific row index in the matrix
        :param row: row index
        :param new_row: new row to set
        """
        if (0 <= row <= self.ROW_COUNT) and (len(new_row) == self.ROW_COUNT):
            self.__matrix[row] = new_row

    def set_col(self, col: int, new_col: list) -> None:
        """
        Sets a new columns value at a specific column index in the matrix
        :param col: column index
        :param new_col: new column to set
        """
        if (0 <= col <= self.COL_COUNT) and (len(new_col) == self.COL_COUNT):
            for i in range(self.ROW_COUNT):
                self.__matrix[i][col] = new_col[i]

    def get_copy(self):
        """
        Function returns a copy of a matrix instance
        :rtype: _Matrix
        :return: a deep copy of an instance (self) matrix
        """
        return _Matrix([[self.__matrix[i][j] for j in range(self.COL_COUNT)] for i in range(self.ROW_COUNT)])

    def get_matrix(self) -> list[list[int]]:
        """
        Function returns instance matrix (list of lists)
        :return: list of 4 lists of ints, the initial matrix
        """
        return self.__matrix

    def get_string(self) -> str:
        """
        Method converts matrix to the string
        :return: str by 16 length, converted from the matrix. (ASCII used)
        """
        return ''.join(chr(ch) for row in self.__matrix for ch in row)


# Main AES class
class aes:
    """
    Advanced Encryption Standard (AES) implementation.

    Attributes:
    - rounds_count (int): The number of rounds in the AES algorithm. For the AES-128 default is 10.
    """

    # Static fields

    # Count of rounds in encryption (10 for 128 bit)
    __ROUNDS_COUNT = 10

    # Substitution box of AES algorithm
    __S_BOX = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    )

    # Inverse substitution box of AES algorithm
    __INVERSE_S_BOX = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    )

    # RCON table used for key expansion of AES algorithm
    __RCON_TABLE = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E,
        0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
    )

    # Constructor
    def __init__(self, dh_key: int) -> None:
        """
        Initializes the AES object with a session key (based on Diffie-Hellman key). Also initialize round keys
        :param dh_key: he Diffie-Hellman key used to derive the AES key.
        """
        dh_bytes = dh_key.to_bytes(256, byteorder='big')
        aes_key = int(md5(dh_bytes).hexdigest(), 16)

        self.__session_key = _Matrix(aes_key)
        self.__round_keys = aes.__key_expansion(self.__session_key)

    @staticmethod
    def __key_expansion(session_key: _Matrix) -> list[_Matrix]:
        """
        Expands the initial key into round keys.
        :return: List of round keys
        """
        key_columns = session_key.get_matrix().copy()
        iteration_size = 4

        i = 1
        while len(key_columns) < (aes.__ROUNDS_COUNT + 1) * 4:
            word = key_columns[-1].copy()

            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [aes.__S_BOX[b] for b in word]
                word[0] ^= aes.__RCON_TABLE[i]
                i += 1

            last = key_columns[-iteration_size].copy()
            key_columns.append([word[i] ^ last[i] for i in range(_Matrix.ROW_COUNT)])

        return [
            _Matrix(key_columns[4 * i:4 * (i + 1)])
            for i in range(len(key_columns) // iteration_size)
        ]

    def __add_round_key(self, data: _Matrix, round_index: int) -> None:
        """
        Adds round key to the data. Do xor byte by byte with round key and current state.
        :param data: [reference] The current state
        :param round_index: The index of the round key to be added
        """
        if round_index == -1:
            round_index = aes.__ROUNDS_COUNT

        if round_index < 0 or round_index > aes.__ROUNDS_COUNT:
            raise Exception("Round index is not valid")

        round_key = self.__round_keys[round_index]

        for i in range(_Matrix.ROW_COUNT):
            for j in range(_Matrix.COL_COUNT):
                data_value = data[i, j]
                key_value = round_key[i, j]
                data[i, j] = (data_value ^ key_value) % _Matrix.MAX_ITEM_VALUE

    @staticmethod
    def __sub_bytes(data: _Matrix) -> None:
        """
        Substitutes each byte of the matrix with its corresponding value in the S-Box.
        :param data: [reference] The current state matrix
        """
        for i in range(_Matrix.ROW_COUNT):
            for j in range(_Matrix.COL_COUNT):
                data[i, j] = aes.__S_BOX[data[i, j]]

    @staticmethod
    def __inverse_sub_bytes(data: _Matrix) -> None:
        """
        Substitutes each byte of the matrix with its corresponding value in the Inverse S-Box.
        :param data: [reference] The current state matrix
        """
        for i in range(_Matrix.ROW_COUNT):
            for j in range(_Matrix.COL_COUNT):
                data[i, j] = aes.__INVERSE_S_BOX[data[i, j]]

    @staticmethod
    def __shift_rows(data: _Matrix) -> None:
        """
        Shifts the rows of the matrix
        :param data: [reference] The current state matrix
        """
        for i in range(1, _Matrix.ROW_COUNT):
            data.set_row(i, data.get_row(i)[i:] + data.get_row(i)[:i])

    @staticmethod
    def __inverse_shift_rows(data: _Matrix) -> None:
        """
        Shifts the rows of the matrix in reverse order
        :param data: [reference] The current state matrix
        """
        for i in range(1, _Matrix.ROW_COUNT):
            shift = _Matrix.ROW_COUNT - i
            data.set_row(i, data.get_row(i)[shift:] + data.get_row(i)[:shift])

    @staticmethod
    def __xtime(val: int) -> int:
        if val & 0x80:
            return ((val << 1) ^ 0x1b) % _Matrix.MAX_ITEM_VALUE
        return val << 1

    @staticmethod
    def __xtimes_0e(val: int) -> int:
        return aes.__xtime(aes.__xtime(aes.__xtime(val) ^ val) ^ val)

    @staticmethod
    def __xtimes_0b(val: int) -> int:
        return aes.__xtime(aes.__xtime(aes.__xtime(val)) ^ val) ^ val

    @staticmethod
    def __xtimes_0d(val: int) -> int:
        return aes.__xtime(aes.__xtime(aes.__xtime(val) ^ val)) ^ val

    @staticmethod
    def __xtimes_09(val: int) -> int:
        return aes.__xtime(aes.__xtime(aes.__xtime(val))) ^ val

    @staticmethod
    def __mix_column(col: list[int]) -> None:
        c_0 = col[0]
        all_xor = col[0] ^ col[1] ^ col[2] ^ col[3]

        col[0] ^= all_xor ^ aes.__xtime(col[0] ^ col[1])
        col[1] ^= all_xor ^ aes.__xtime(col[1] ^ col[2])
        col[2] ^= all_xor ^ aes.__xtime(col[2] ^ col[3])
        col[3] ^= all_xor ^ aes.__xtime(c_0 ^ col[3])

    @staticmethod
    def __mix_columns(data: _Matrix) -> None:
        """
        Mixes the columns of the matrix by Rijndael algorithm
        :param data: [reference] The current state matrix
        """
        for i in range(_Matrix.COL_COUNT):
            col = data.get_col(i)
            aes.__mix_column(col)
            data.set_col(i, col)

    @staticmethod
    def __inverse_mix_column(col: list[int]) -> None:
        c_0, c_1, c_2, c_3 = col
        col[0] = aes.__xtimes_0e(c_0) ^ aes.__xtimes_0b(c_1) ^ aes.__xtimes_0d(c_2) ^ aes.__xtimes_09(c_3)
        col[1] = aes.__xtimes_09(c_0) ^ aes.__xtimes_0e(c_1) ^ aes.__xtimes_0b(c_2) ^ aes.__xtimes_0d(c_3)
        col[2] = aes.__xtimes_0d(c_0) ^ aes.__xtimes_09(c_1) ^ aes.__xtimes_0e(c_2) ^ aes.__xtimes_0b(c_3)
        col[3] = aes.__xtimes_0b(c_0) ^ aes.__xtimes_0d(c_1) ^ aes.__xtimes_09(c_2) ^ aes.__xtimes_0e(c_3)

    @staticmethod
    def __inverse_mix_columns(data: _Matrix) -> None:
        """
        Mixes the columns of the matrix in reverse order by Rijndael algorithm
        :param data: [reference] The current state matrix
        """
        for i in range(_Matrix.COL_COUNT):
            col = data.get_col(i)
            aes.__inverse_mix_column(col)
            data.set_col(i, col)

    @staticmethod
    def __divide_into_blocks(data: str) -> list[str]:
        """
        Divides the input data into blocks for encryption (by 16 bytes)
        :param data: The input data to be divided
        :return: List of data blocks by length of 16
        """
        block_size = _Matrix.MATRIX_SIZE
        num_blocks = (len(data) + block_size - 1) // block_size
        padded_data = data + (block_size - len(data) % block_size) * chr(0)

        blocks = [
            padded_data[i * block_size:(i + 1) * block_size]
            for i in range(num_blocks)
        ]

        return blocks

    def __encrypt_block(self, input_matrix: _Matrix) -> _Matrix:
        """
        Encrypts a single block of data
        :param input_matrix: The text block to be encrypted
        :return: The encrypted data block (Matrix)
        """
        state = _Matrix.get_copy(input_matrix)

        # Initial Round
        self.__add_round_key(state, 0)

        # Main Rounds
        for i in range(1, aes.__ROUNDS_COUNT):
            aes.__sub_bytes(state)
            aes.__shift_rows(state)
            aes.__mix_columns(state)
            self.__add_round_key(state, i)

        # Final Round
        aes.__sub_bytes(state)
        aes.__shift_rows(state)
        self.__add_round_key(state, -1)

        return state

    def __decrypt_block(self, encrypted_block: _Matrix) -> _Matrix:
        """
        Decrypts a single block of encrypted data
        :param encrypted_block: The block of encrypted data to be decrypted
        :return: The decrypted original text (in Matrix)
        """
        state = _Matrix.get_copy(encrypted_block)

        # Initial Round
        self.__add_round_key(state, -1)
        aes.__inverse_shift_rows(state)
        aes.__inverse_sub_bytes(state)

        # Main Rounds in reverse order
        for i in range(aes.__ROUNDS_COUNT - 1, 0, -1):
            self.__add_round_key(state, i)
            aes.__inverse_mix_columns(state)
            aes.__inverse_shift_rows(state)
            aes.__inverse_sub_bytes(state)

        # Final Round
        self.__add_round_key(state, 0)

        return state

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts the input text using AES-128
        :param plain_text: The text to be encrypted
        :return: List of encrypted data blocks
        """
        blocks = aes.__divide_into_blocks(plain_text)
        encrypted_list = []

        for block in blocks:
            encrypted_list.append(self.__encrypt_block(_Matrix(block)).get_string())

        return ''.join(encrypted_list)

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypts the cipher list into the original text using AES-128
        :param encrypted_text: encrypted data
        :return: The decrypted original text
        """
        blocks = aes.__divide_into_blocks(encrypted_text)
        decrypted_list = []

        for block in blocks:
            decrypted_list.append(self.__decrypt_block(_Matrix(block)).get_string())

        while decrypted_list[-1][-1] == chr(0):
            decrypted_list[-1] = decrypted_list[-1][:-1]

        decrypted_text = ''.join(decrypted_list)
        return decrypted_text
