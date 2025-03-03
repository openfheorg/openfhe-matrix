import os
import sys
import numpy as np
import copy
import math
from typing import Tuple

# import openfhe related libraries
import openfhe
import openfhe_matrix

# import config and helpter
from fhepy.config import *


# TODO: Build class PTMatrix to work with raw np.array
class PTArray:
    def __init__():
        return


# NOTE: gen_rotation keys: serialize keys separate the function and let someone use that (us or user)
# Case 1. 1 matrix = 1 ct
class CTArray:
    def __init__(
        self,
        ctx: CT,
        shape: Tuple[
            int, int
        ],  # original dimensions. shape = (n_rows,n_cols) before padding
        is_matrix: bool,
        nums_slots: int,
        n_cols: int = 1,  # block_size
        type: int = EncodeStyles.ROW_WISE,
    ):
        self.ctx = ctx
        self.shape = shape
        self.is_matrix = is_matrix  # plaintext matrix
        self.n_cols = n_cols  # padded cols
        self.n_rows = nums_slots // n_cols
        self.encoding_styles = type

    def copy_info(self):
        return (
            self.ctx,
            self.shape,
            self.is_matrix,
            self.nums_slots,
            self.n_cols,
            self.encoding_styles,
        )

    @classmethod
    def array(
        cls,
        cc,
        pk,
        data: list,
        nums_slots: int,
        block_size: int = 1,
        type: int = EncodeStyles.ROW_WISE,
    ):
        """
        block_size = row_size, number of repetitions, number of columns
        block_size is important for packing vectors
        """
        org_rows, org_cols, is_matrix = get_shape(data)

        if is_matrix:
            n_cols = next_power2(org_cols)
        else:
            n_cols = block_size
        shape = (org_rows, org_cols)
        n_rows = nums_slots // n_cols

        if is_matrix:
            ptx = _encode_matrix(cc, data, nums_slots, n_cols, type)
        else:
            ptx = _encode_vector(cc, data, nums_slots, n_cols, type)

        ctx = cc.Encrypt(pk, ptx)

        return cls(
            ctx,
            shape,
            is_matrix,
            nums_slots,
            n_cols,
            type,
        )

    def decrypt(self, cc, sk, precision=3):
        result = cc.Decrypt(self.ctx, sk)
        result.SetLength(self.nums_slots)
        result.GetFormattedValues(precision)
        result = result.GetRealPackedValue()
        n_rows, n_cols = self.shape
        if self.is_matrix == 1:
            result = to_matrix(result, n_rows * n_cols, self.n_cols)
            print(result)
            result = [
                [round(result[i][j], precision) for j in range(n_rows)]
                for i in range(n_cols)
            ]
        return result


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
    # print("data: ", data)
    if isinstance(data, list) or isinstance(data, tuple):
        rows = len(data)
        if isinstance(data[0], list) or isinstance(data[0], tuple):
            cols = len(data[0])
        else:
            cols = 1
        is_matrix = 1 if cols > 1 else 0
        return rows, cols, is_matrix

    if isinstance(data, np.ndarray):
        if data.ndim == 1:
            return data.shape[0], 0, 0
        return data.shape[0], data.shape[1], 1

    print("ERRORS: Wrong parameters!!!")
    return None


# Check the name convention
def _encode_matrix(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = EncodeStyles.ROW_WISE,
) -> PT:
    """Encode a matrix or data without padding or replicate"""

    if type == EncodeStyles.ROW_WISE:
        packed_data = pack_mat_row_wise(data, row_size, num_slots)
    elif type == EncodeStyles.COL_WISE:
        packed_data = pack_mat_col_wise(data, row_size, num_slots)
    else:
        # TODO Encoded Diagonal Matrix
        packed_data = [0]

    print("DEBUG[_encode_matrix] ", packed_data)

    return cc.MakeCKKSPackedPlaintext(packed_data)


def _encode_vector(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = EncodeStyles.ROW_WISE,
) -> PT:
    """Encode a vector with n replication"""

    if row_size < 1:
        sys.exit("ERROR: Number of repetitions should be larger than 0")

    if row_size == 1 and type == EncodeStyles.ROW_WISE:
        sys.exit("ERROR: Can't encode a vector row-wise with 0 repetitions")

    if not is_power2(row_size):
        sys.exit(
            "ERROR: The number of repetitions in vector packing should be a power of two"
        )

    if type == EncodeStyles.ROW_WISE:
        packed_data = pack_vec_row_wise(data, row_size, num_slots)
    elif type == EncodeStyles.COL_WISE:
        packed_data = pack_vec_col_wise(data, row_size, num_slots)
    else:
        packed_data = [0]

    return cc.MakeCKKSPackedPlaintext(packed_data)


# Problem: Model
# Case 1. design in OOP (Hints: create methods and add a wrapper to compute)  (I don't know how I should do now)
# Case 2. folder organization: our_lib.matmul_square (<===========)


def decrypt(cc, sk, data, nums_slots, precision=3):
    result = cc.Decrypt(data, sk)
    result.SetLength(nums_slots)
    result.GetFormattedValues(precision)
    result = result.GetRealPackedValue()
    result = [round(result[i], precision) for i in range(nums_slots)]
    return result


def gen_sum_row_keys(cc, sk, block_size):
    return cc.EvalSumRowsKeyGen(sk, None, block_size)


def gen_sum_col_keys(cc, sk, block_size):
    return cc.EvalSumColsKeyGen(sk)


def gen_rotation_keys(cc, sk, rotation_indices):
    cc.EvalRotateKeyGen(sk, rotation_indices)


# def matmul


def mms_mult(cc, keys, ctm_A: CTArray, ctm_B: CTArray):
    """
    Matrix product of two array

    Parameters
    ----------
    ctm_A: CTArray
    ctm_B: CTArray

    Returns
    -------
    CTArray
        Product of two square matrices
    """
    ct_prod = openfhe_matrix.EvalMatMulSquare(
        cc, keys, ctm_A.ctx, ctm_B.ctx, ctm_A.n_cols
    )

    ctm_prod = CTArray(*ctm_A.copy_info())
    ctm_prod.ctx = ct_prod

    return ctm_prod


def matvec(cc, keys, sum_col_keys, type, block_size, ctm_v, ctm_mat):
    """Matrix-vector dot product of two arrays."""
    ct_prod = openfhe_matrix.EvalMultMatVec(
        cc, keys, sum_col_keys, type, block_size, ctm_v.ctx, ctm_mat.ctx
    )
    # parse an option to repack
    # 1. RM <-> CM
    # (4 x 2) (2x1)

    # org_vector : 12

    # 1 1 1 1
    # 2 2 2 2

    # RM: 11112222

    # 1111111122222222

    # CM: 12121212

    # Default: 12 - > 11 22 -> 1111 22222

    # ctm_prod = CTArray(*ctm_v.copy_info())
    # ctm_prod.ctx = ct_prod
    # TODO: construct a CTArray after receiving a product
    # TODO: ciphertext replications
    return ct_prod


def matrix_power(ctm_mat):
    """Raise a square matrix to the (integer) power n."""
    # (a^2) - (a^4) - (a^8)
    return None


def matrix_transpose(ctm_mat):
    """
    Transposes a matrix (or a stack of matrices) x.
    Encoding converting: row-wise becomes column-wise and vice versal
    """
    return None


# dot(A.B) = A@B
# dot (v,w) = <v,w>


def dot(cc, keys, ctv_A, ctv_B):
    if not ctv_A.is_matrix and not ctv_B.is_matrix:
        ct_product = cc.EvalMult(ctv_A.ctx, ctv_B.ctx)

    return None


# entries-wise multiply
def multiply(cc, keys, ctm_A, ctm_B):
    # Multiply arguments element-wise.
    return cc.EvalMult(ctm_A.ctx, ctm_B.ctx)


def add(cc, ctm_A, ctm_B):
    # Add arguments element-wise.
    return cc.EvalAdd(ctm_A.ctx, ctm_B.ctx)


def sub(cc, keys, ctm_A, ctm_B):
    # Subtracts arguments element-wise.
    return cc.EvalSub(ctm_A.ctx, ctm_B.ctx)


def sum(cc, data, axis=None):
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
def to_matrix(vec, total_slots, row_size):
    n_slots = len(vec)
    row = []
    mat = []
    for k in range(n_slots):
        row.append(vec[k])
        if (k + 1) % row_size == 0 and k >= 1:
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
