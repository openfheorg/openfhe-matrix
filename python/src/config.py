import openfhe

CT = openfhe.Ciphertext
CC = openfhe.CryptoContext


class EncodeStyles:
    ROW_WISE = 0
    COL_WISE = 1
    DIAG_WISE = 2
