import openfhe
from enum import Enum

# CT = openfhe.Ciphertext
# CC = openfhe.CryptoContext

PT = openfhe.Plaintext
CT = openfhe.Ciphertext
CC = openfhe.CryptoContext
KP = openfhe.KeyPair


class EncodeStyles(Enum):
    ROW_WISE = 0
    COL_WISE = 1
    DIAG_WISE = 2


class PackStyles(Enum):
    # pack matrix row-wise and vector column-wise, result is column-wise
    MM_CRC = 0
    # pack matrix column-wise and vector row-wise, result i row-wise
    MM_RCR = 1
    # pack matrix diagonal
    MM_DIAG = 2
