import os
import sys
import numpy as np
import copy
import math
from typing import Tuple

# import openfhe related libraries
import openfhe
import openfhe_matrix

# import config and auxilarries files
from fhepy.config import *
from fhepy.matlib import *
from fhepy.array import *


# Case 1. 1 matrix = 1 ct
class CTArray:
    def __init__(
        self,
        data: openfhe.Ciphertext,
        shape: Tuple[
            int, int
        ],  # original dimensions. shape = (n_rows,n_cols) before padding
        is_matrix: bool,
        nums_slots: int,
        n_cols: int = 1,  # block_size
        codec: int = CodecType.ROW_WISE,
    ):
        self.data = data
        self.shape = shape
        self.is_matrix = is_matrix  # plaintext matrix
        self.n_cols = n_cols  # padded cols
        self.n_rows = nums_slots // n_cols
        self.nums_slots = nums_slots
        self.codec = codec

    def get_info(self):
        print(self.is_matrix)
        return [
            None,
            self.shape,
            self.is_matrix,
            self.nums_slots,
            self.n_cols,
            self.codec,
        ]

    def copy(self, is_deep_copy: bool = 1):
        return CTArray(
            self.data,
            self.shape,
            self.is_matrix,
            self.nums_slots,
            self.n_cols,
            self.codec,
        )

    def decrypt(self, cc, sk, precision=PRECISION_DEFAULT):
        print("Hello ")
        info = self.get_info()
        print(type(info))
        print(info[0])
        result = cc.Decrypt(self.data, sk)
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
def array(
    cc,
    pk,
    data: list,
    nums_slots: int,
    block_size: int = 1,
    type: int = CodecType.ROW_WISE,
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
        ptx = encode_matrix(cc, data, nums_slots, n_cols, type)
    else:
        ptx = encode_vector(cc, data, nums_slots, n_cols, type)

    data = cc.Encrypt(pk, ptx)

    return CTArray(
        data,
        shape,
        is_matrix,
        nums_slots,
        n_cols,
        type,
    )


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
def encode_matrix(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = CodecType.ROW_WISE,
) -> PT:
    """Encode a matrix or data without padding or replicate"""

    if type == CodecType.ROW_WISE:
        packed_data = pack_mat_row_wise(data, row_size, num_slots)
    elif type == CodecType.COL_WISE:
        packed_data = pack_mat_col_wise(data, row_size, num_slots)
    else:
        # TODO Encoded Diagonal Matrix
        packed_data = [0]

    print("DEBUG[encode_matrix] ", packed_data)

    return cc.MakeCKKSPackedPlaintext(packed_data)


def encode_vector(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    type: int = CodecType.ROW_WISE,
) -> PT:
    """Encode a vector with n replication"""

    if row_size < 1:
        sys.exit("ERROR: Number of repetitions should be larger than 0")

    if row_size == 1 and type == CodecType.ROW_WISE:
        sys.exit("ERROR: Can't encode a vector row-wise with 0 repetitions")

    if not is_power2(row_size):
        sys.exit(
            "ERROR: The number of repetitions in vector packing should be a power of two"
        )

    if type == CodecType.ROW_WISE:
        packed_data = pack_vec_row_wise(data, row_size, num_slots)
    elif type == CodecType.COL_WISE:
        packed_data = pack_vec_col_wise(data, row_size, num_slots)
    else:
        packed_data = [0]

    return cc.MakeCKKSPackedPlaintext(packed_data)


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


def matmul_square(cc: CC, keys: KP, ctm_A: CTArray, ctm_B: CTArray):
    """P
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
        cc, keys, ctm_A.data, ctm_B.data, ctm_A.n_cols
    )

    # ctm_prod = array(*ctm_A.get())
    array_info = ctm_A.get_info
    array_info[0] = ct_prod
    ctm_prod = CTArray(*array_info)

    return ctm_prod


def matvec(cc, keys, sum_col_keys, type, block_size, ctm_v, ctm_mat):
    """Matrix-vector dot product of two arrays."""
    ct_prod = openfhe_matrix.EvalMultMatVec(
        cc, keys, sum_col_keys, type, block_size, ctm_v.data, ctm_mat.data
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

    # ctm_prod = CTArray(*ctm_v.copy_data())
    # ctm_prod.data = ct_prod
    # TODO: construct a CTArray after receiving a product
    # TODO: data replications
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


def dot(cc, keys, cta_A, cta_B):
    if not cta_A.is_matrix and not cta_B.is_matrix:
        return multiply(cc, keys, cta_A, cta_B)

    # TODO: add dot product for vectors

    return None


# Hadamard product: multiply arguments element-wise.
def multiply(cc, keys, cta_A, cta_B):
    cta_hadamard = cta_A.copy(0)
    cta_hadamard.data = cc.EvalMult(cta_A.data, cta_B.data)
    return cta_hadamard


def add(cc, cta_A, cta_B):
    # Add arguments element-wise.
    info = cta_A.get_info()
    info[0] = cc.EvalAdd(cta_A.data, cta_B.data)
    cta = CTArray(*info)
    return cta


def sub(cc, keys, ctm_A, ctm_B):
    # Subtracts arguments element-wise.
    return cc.EvalSub(ctm_A.data, ctm_B.data)


def sum(cc, data, axis=None):
    """Sum of array elements over a given axis"""
    # todo: should we let user uses secretKey or regenerate
    # cc = data.context
    # keys = data.keys

    # if axis == None:
    #     return cc.EvalSum(data.data)

    # if ct_a.is_matrix:
    #     if ct_a.encode_style == ROW_WISE:
    #         cc.EvalRotateKeyGen(keys.secretKey, [1, -2])

    return None


def mean(data_a):
    """Compute the arithmetic mean along the specified axis."""
    # ssum = sum(data_a)

    # return ssum / data_a.nums_slots
    return None


# #####################################################
# # Helper functions
# #####################################################
