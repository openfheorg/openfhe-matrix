import os
import numpy as np
import math
from typing import Tuple

# import openfhe related libraries
import openfhe
import openfhe_matrix

# import config and auxilarries files
from fhepy.config import *
from fhepy.matlib import *
import fhepy.utils as utils
from fhepy.ptarray import ravel_mat, ravel_vec


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
        info = self.get_info()
        result = cc.Decrypt(self.data, sk)
        result.SetLength(self.nums_slots)
        result.GetFormattedValues(precision)
        result = result.GetRealPackedValue()
        n_rows, n_cols = self.shape
        if self.is_matrix == 1:
            result = utils.reshape(result, n_rows * n_cols, self.n_cols)
            # result = [
            #     [round(result[i][j], precision) for j in range(n_rows)]
            #     for i in range(n_cols)
            # ]
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
    org_rows, org_cols, is_matrix = utils.get_shape(data)

    if is_matrix:
        n_cols = next_power2(org_cols)
    else:
        n_cols = block_size
    shape = (org_rows, org_cols)
    n_rows = nums_slots // n_cols

    if is_matrix:
        ptx = ravel_mat(cc, data, nums_slots, n_cols, type)
    else:
        ptx = ravel_vec(cc, data, nums_slots, n_cols, type)

    data = cc.Encrypt(pk, ptx)

    return CTArray(
        data,
        shape,
        is_matrix,
        nums_slots,
        n_cols,
        type,
    )


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


#########################################
# Matrix Operations
#########################################
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
    info = ctm_A.get_info()
    info[0] = ct_prod
    return CTArray(*info)


def matvec(cc, keys, sum_col_keys, ctm_mat, ctv_v, block_size):
    """Matrix-vector dot product of two arrays."""
    print(ctm_mat.codec, ctv_v.codec)
    if ctm_mat.codec == "R" and ctv_v.codec == "C":
        print("CRC")
        ct_prod = openfhe_matrix.EvalMultMatVec(
            cc,
            keys,
            sum_col_keys,
            PackStyles.MM_CRC,
            block_size,
            ctv_v.data,
            ctm_mat.data,
        )
        rows, cols = ctm_mat.shape
        info = [ct_prod, (rows, 1), False, ctm_mat.nums_slots, cols, "C"]
        return CTArray(*info)

    elif ctm_mat.codec == "C" and ctv_v.codec == "R":
        print("RCR")
        ct_prod = openfhe_matrix.EvalMultMatVec(
            cc,
            keys,
            sum_col_keys,
            PackStyles.MM_RCR,
            block_size,
            ctv_v.data,
            ctm_mat.data,
        )
        rows, cols = ctm_mat.shape
        info = [ct_prod, (rows, 1), False, ctm_mat.nums_slots, cols, "R"]
        return CTArray(*info)
    else:
        print("ERROR [matvec] encoding styles are not matching!!!")
        return None

    # info = ctv_v.get_info()
    # info[0] = ct_prod
    # return CTArray(*info)
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


def dot(cc, keys, sum_col_keys, ctm_A, ctm_B):
    # TODO: check if the dimension is matching
    if not ctm_A.is_matrix and not ctm_B.is_matrix:
        ct_mult = cc.EvalMult(ctm_A.data, ctm_B.data)
        ct_prod = cc.EvalSumCols(ct_mult, ctm_A.n_cols, sum_col_keys)
        rows, cols = ctm_A.shape
        info = ctm_A.get_info()
        info[0] = ct_prod
        return CTArray(*info)
    else:
        return multiply(cc, keys, ctm_A, ctm_B)


# Hadamard product: multiply arguments element-wise.
def multiply(cc, keys, ctm_A, ctm_B):
    ctm_hadamard = ctm_A.copy(0)
    ctm_hadamard.data = cc.EvalMult(ctm_A.data, ctm_B.data)
    return ctm_hadamard


def add(cc, ctm_A, ctm_B):
    # Add arguments element-wise.
    info = ctm_A.get_info()
    info[0] = cc.EvalAdd(ctm_A.data, ctm_B.data)
    return CTArray(*info)


def sub(cc, keys, ctm_A, ctm_B):
    # Subtracts arguments element-wise.
    info = ctm_A.get_info()
    info[0] = cc.EvalSub(ctm_A.data, ctm_B.data)
    return CTArray(*info)


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
