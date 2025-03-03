import openfhe
from enum import Enum


PT = openfhe.Plaintext
CT = openfhe.Ciphertext
CC = openfhe.CryptoContext
KP = openfhe.KeyPair


class CodecType:
    ROW_WISE = "R"
    COL_WISE = "C"
    DIAG_WISE = "D"


class PackStyles:
    # pack matrix row-wise and vector column-wise, result is column-wise
    MM_CRC = 0
    # pack matrix column-wise and vector row-wise, result i row-wise
    MM_RCR = 1
    # pack matrix diagonal
    MM_DIAG = 2


PRECISION_DEFAULT = 1


# # Example matrix
# matrix = np.array([[1, 2, 3], [4, 5, 6]])
# # Convert the matrix to a vector using row-major (C-style) order
# vector_row_major = matrix.ravel(order='C')
# # Convert the matrix to a vector using column-major (Fortran-style) order
# vector_col_major = matrix.ravel(order='F')
# print("Row-major vector:", vector_row_major)
# print("Column-major vector:", vector_col_major)
