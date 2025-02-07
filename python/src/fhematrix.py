import os
import sys
import numpy as np
import copy
import math

# import openfhe related libraries
import openfhe
import openfhe_matrix

# import utils libraries
from config import *

# from config import EncodeStyles
# from utils_math import Math

PT = openfhe.Plaintext
CT = openfhe.Ciphertext
CC = openfhe.CryptoContext
KP = openfhe.KeyPair

ROW_WISE = 0
COL_WISE = 1
DIAG_WISE = 2


class CryptoInfo:
    def __init__(self, cc: CC, keys: KP, batch_size: int):
        self.cc = cc
        self.keys = keys
        self.pk = keys.publicKey
        self.sk = keys.secretKey
        self.batch_size = batch_size


class FHEMatrix:
    # ? Should we only use public key or both
    # ? Generate all possible rotation keys in advanced?

    def __init__(
        self,
        c_info: CryptoInfo,
        ctx: CT,
        shape: int,
        aut_rows: int,
        aut_cols: int,
        is_matrix: bool,
        nums_slots: int,
        row_size: int = 1,
        type: int = ROW_WISE,
    ):
        self.c_info = c_info
        self.ctx = ctx
        self.shape = shape
        self.aut_rows = aut_rows
        self.aut_cols = aut_cols
        self.is_matrix = is_matrix
        self.row_size = row_size
        self.nums_slots = nums_slots
        self.col_size = nums_slots // row_size
        self.encoding_styles = type

    def copy_info(self):
        return (
            self.c_info,
            self.ctx,
            self.shape,
            self.aut_rows,
            self.aut_cols,
            self.is_matrix,
            self.nums_slots,
            self.row_size,
            self.encoding_styles,
        )

    @classmethod
    def fhe_array(
        cls,
        c_info: CryptoInfo,
        data: list,
        nums_slots: int,
        row_size: int = 1,
        type: int = ROW_WISE,
    ):
        aut_rows, aut_cols, is_matrix = get_shape(data)
        print("data: \n", data)
        print("encoding style =  ", type)
        print("----> ", aut_rows, aut_cols, is_matrix)
        rows = next_power2(aut_rows)
        if is_matrix:
            cols = next_power2(aut_cols)
        else:
            cols = 1
        shape = (rows, cols)
        col_size = nums_slots // row_size

        if is_matrix:
            ptx = _encode_matrix(c_info.cc, data, nums_slots, row_size, type)
        else:
            ptx = _encode_vector(c_info.cc, data, nums_slots, row_size, type)

        ctx = c_info.cc.Encrypt(c_info.pk, ptx)

        # ? This function should be outside of this class as user don't have secretkey in general
        # TODO I will move outside of this function later. It should be received as an input.
        c_info.cc.EvalRotateKeyGen(
            c_info.sk,
            [row_size, -row_size, col_size, -row_size],
        )
        return cls(
            c_info,
            ctx,
            shape,
            aut_rows,
            aut_cols,
            is_matrix,
            nums_slots,
            row_size,
            type,
        )

    def decrypt(self):
        data = self.c_info.cc.Decrypt(self.ctx, self.c_info.sk)
        data.SetLength(self.nums_slots)
        if self.is_matrix == 1:
            data = to_matrix(data, self.row_size)
        return data


#########################################
# Public Methods
#########################################


def get_shape(data):
    """
    Get dimension of a matrix

    Parameters:
    ----------
    data : list or np.ndarray

    Returns
    -------
    rows, cols, is_matrix
    """
    if isinstance(data, list) or isinstance(data, tuple):
        rows = len(data)
        cols = len(data[0])
        is_matrix = 1 if cols > 1 else 0
        return rows, cols, is_matrix

    if isinstance(data, np.ndarray):
        if data.ndim == 1:
            return data.shape[0], 0, 0
        return data.shape[0], data.shape[1], 1

    print("ERRORS: Wrong parameters!!!")
    return None


def _encode_matrix(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = ROW_WISE,
) -> PT:
    """Encode a matrix or data without padding or replicate"""

    # col_size = num_slots // row_size

    if type == ROW_WISE:
        packed_data = pack_mat_row_wise(data, row_size, num_slots)
    elif type == COL_WISE:
        packed_data = pack_mat_col_wise(data, row_size, num_slots)
    else:
        packed_data = [0]

    return cc.MakeCKKSPackedPlaintext(packed_data)


def _encode_vector(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = ROW_WISE,
) -> PT:
    """Encode a vector with n replication"""

    if row_size < 1:
        sys.exit("ERROR: Number of repetitions should be larger than 0")

    if row_size == 1 and type == ROW_WISE:
        sys.exit("ERROR: Can't encode a vector row-wise with 0 repetitions")

    if not is_power2(row_size):
        sys.exit(
            "ERROR: The number of repetitions in vector packing should be a power of two"
        )

    # col_size = num_slots // row_size

    if type == ROW_WISE:
        packed_data = pack_vec_row_wise(data, row_size, num_slots)
    elif type == COL_WISE:
        packed_data = pack_vec_col_wise(data, row_size, num_slots)
    else:
        packed_data = [0]

    return cc.MakeCKKSPackedPlaintext(packed_data)


def matmul_square(ctm_A: FHEMatrix, ctm_B: FHEMatrix):
    """
    Matrix product of two array

    Parameters
    ----------
    ctm_A: FHEMatrix
    ctm_B: FHEMatrix

    Returns
    -------
    FHEMatrix
        Product of two square matrices
    """
    cc = ctm_A.c_info.cc
    keys = ctm_A.c_info.keys
    ct_prod = openfhe_matrix.EvalMatMulSquare(
        cc, keys, ctm_A.ctx, ctm_B.ctx, ctm_A.row_size
    )
    # TODO: fixed this
    a, b, c, d, e, f, g, h, i = ctm_A.copy_info()
    ctm_prod = FHEMatrix(a, b, c, d, e, f, g, h, i)
    ctm_prod.ctx = ct_prod

    return ctm_prod


def matvec(ctm_mat, ctv_vec):
    """Matrix-vector dot product of two arrays."""
    return None


def matrix_power(ctm_mat):
    """Raise a square matrix to the (integer) power n."""
    return None


def matrix_transpose(ctm_mat):
    """
    Transposes a matrix (or a stack of matrices) x.
    Encoding converting: row-wise becomes column-wise and vice versal
    """
    return None


def dot(context, keys, ct_a, ct_b):
    return None


# entries-wise multiply
def multiply(context, keys, ct_a, ct_b):
    # Multiply arguments element-wise.
    return None


def add(ct_a, ct_b):
    # Add arguments element-wise.
    return ct_a.context.EvalAdd(ct_a, ct_b)


def sub(context, keys, ct_a, ct_b):
    # Subtracts arguments element-wise.
    return ct_a.context.EvalSub(ct_a, ct_b)


def sum(data, axis=None):
    """Sum of array elements over a given axis"""
    # todo: should we let user uses secretKey or regenerate
    # cc = data.context
    # keys = data.keys

    # if axis == None:
    #     return cc.EvalSum(data.ctx)

    # if ct_a.is_matrix:
    #     if ct_a.encode_style == ROW_WISE:
    #         cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

    return None


def mean(ctx_a):
    """Compute the arithmetic mean along the specified axis."""
    # ssum = sum(ctx_a)

    # return ssum / ctx_a.nums_slots
    return None


#####################################################
# Helper functions
#####################################################


def pack_vec_row_wise(v, block_size, num_slots):
    """
    Clone a vector v to fill num_slots
    1 -> 1111 2222 3333
    2
    3
    """
    n = len(v)
    assert is_power2(block_size)
    assert is_power2(num_slots)
    if num_slots < n:
        sys.exit("ERROR ::: [row_wise_vector] vector is longer than total   slots")
    if num_slots == n:
        if num_slots // block_size > 1:
            sys.exit(
                "ERROR ::: [row_wise_vector] vector is too longer, can't duplicate"
            )
        return v

    # print info
    assert num_slots % block_size == 0
    total_blocks = num_slots // block_size
    free_slots = num_slots - n * block_size

    # compute padding
    packed = np.zeros(num_slots)
    k = 0
    for i in range(n):
        for j in range(block_size):
            packed[k] = v[i]
            k += 1
    return packed


def pack_vec_col_wise(v, block_size, num_slots):
    """
    Clone a vector v to fill num_slots
    1 -> 1230 1230 1230
    2
    3
    """
    n = len(v)
    assert is_power2(block_size)
    assert is_power2(num_slots)
    if block_size < n:
        sys.exit(
            f"ERROR ::: [col_wise_vector] vector of size ({n}) is longer than size of a slot ({block_size})"
        )
    if num_slots < n:
        sys.exit("ERROR ::: [col_wise_vector] vector is longer than total slots")
    if num_slots == n:
        return v

    packed = np.zeros(num_slots)

    # print info
    assert num_slots % block_size == 0
    total_blocks = num_slots // block_size
    free_slots = num_slots - n * total_blocks

    k = 0  # index into vector to write
    for i in range(total_blocks):
        for j in range(n):
            packed[k] = v[j]
            k += 1
        k += block_size - n

    return packed


# convert a vector of an packed_rw_mat to its original matrix
def to_matrix(vec, row_size):
    n_slots = len(vec)

    row = []
    mat = []
    for k in range(n_slots):
        row.append(vec[k])
        if (k + 1) % row_size == 0 and k > 1:
            mat.append(row)
            row = []
    return mat


def convert_cw_rw(v, block_size, num_slots):
    org_v = v[:block_size]
    vv = pack_vec_row_wise(org_v, block_size, num_slots)

    if 0:
        wnice_org = [round(x, 3) for x in v[: 2 * block_size]]
        vv_b = vv[: 2 * block_size]
        wnice = [round(x, 3) for x in vv_b]
        print(f"convert \n  {wnice_org}\n->{wnice}")
        print(f"{wnice}")
    return vv


def convert_rw_cw(v, block_size, num_slots):
    org_v = []
    # print(len(v), block_size, num_slots)
    for k in range(block_size):
        org_v.append(v[k * block_size])

    vv = pack_vec_col_wise(org_v, block_size, num_slots)

    if 0:
        wnice_org = [round(x, 3) for x in v[: 2 * block_size]]
        vv_b = vv[: 2 * block_size]
        wnice = [round(x, 3) for x in vv_b]
        print(f"convert {org_v} to {vv[:block_size]}")
        print(f"{wnice}")
    return vv


def print_mat(matrix, rows):
    for i in range(rows):
        print(matrix[i])
        # print('\n')


def pack_mat_row_wise(matrix, block_size, num_slots, debug=0):
    """
    Packing Matric M using row-wise
    [[1 2 3] -> [1 2 3 0 4 5 6 0 7 8 9 0]
    [4 5 6]
    [7 8 9]]
    """
    assert is_power2(block_size)
    assert is_power2(num_slots)
    assert num_slots % block_size == 0
    n = len(matrix)
    m = len(matrix[0])
    total_blocks = num_slots // block_size
    # freeslots w.r.t block_size (not all free slots)
    free_slots = num_slots - n * block_size

    if debug:
        print(
            "#\t [enc. matrix] n = %d, m = %d, #slots = %d, bs = %d, blks = %d, #freeslots = %d, used <= %.3f"
            % (
                n,
                m,
                num_slots,
                block_size,
                total_blocks,
                free_slots,
                (num_slots - free_slots) / num_slots,
            )
        )

    if num_slots < n * m:
        Exception("encrypt_matrix ::: Matrix is too big compared with num_slots")

    packed = np.zeros(num_slots)
    k = 0  # index into vector to write
    for i in range(n):
        for j in range(m):
            packed[k] = matrix[i][j]
            k += 1
        for j in range(m, block_size):
            packed[k] = 0
            k += 1
    return packed


def pack_mat_col_wise(matrix, block_size, num_slots, verbose=0):
    """
    Packing Matric M using row-wise
    [[1 2 3] -> [1 4 7 0 2 5 8 0 3 6 9 0]
     [4 5 6]
     [7 8 9]]
    """
    assert is_power2(block_size)
    assert is_power2(num_slots)
    assert num_slots % block_size == 0
    cols = len(matrix)
    rows = len(matrix[0])
    total_blocks = num_slots // block_size
    free_slots = num_slots - cols * block_size

    if verbose:
        print(
            "#\t [enc. matrix] n = %d, m = %d, #slots = %d, bs = %d, blks = %d, #freeslots = %d, used <= %.3f"
            % (
                cols,
                rows,
                num_slots,
                block_size,
                total_blocks,
                free_slots,
                (num_slots - free_slots) / num_slots,
            )
        )

    if num_slots < cols * rows:
        Exception("encrypt_matrix ::: Matrix is too big compared with num_slots")

    packed = np.zeros(num_slots)
    k = 0  # index into vector to write

    for col in range(cols):
        for row in range(block_size):
            if row < rows:
                packed[k] = matrix[row][col]
            k = k + 1

    return packed


def next_power2(x):
    return 2 ** math.ceil(math.log2(x))


def is_power2(x):
    return (x & (x - 1) == 0) and x != 0
