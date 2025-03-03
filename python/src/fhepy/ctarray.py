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
        order: int = CodecType.ROW_WISE,
    ):
        self.data = data
        self.shape = shape
        self.is_matrix = is_matrix  # plaintext matrix
        self.n_cols = n_cols  # padded cols
        self.n_rows = nums_slots // n_cols
        self.nums_slots = nums_slots
        self.order = order

    def get_info(self):
        return [
            None,
            self.shape,
            self.is_matrix,
            self.nums_slots,
            self.n_cols,
            self.order,
        ]

    def copy(self, is_deep_copy: bool = 1):
        return CTArray(
            self.data,
            self.shape,
            self.is_matrix,
            self.nums_slots,
            self.n_cols,
            self.order,
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

    def ravel(self, cc, keys, rot_keys, order):
        # todo this function use to perform linear transformation. I will do it later
        if self.order == "R":
            if order == "C":
                print("...change order from RW to CW")

        if self.order == "C":
            if order == "R":
                print("...change order from CW to RW")

        return


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
    print(ctm_mat.order, ctv_v.order)
    if ctm_mat.order == "R" and ctv_v.order == "C":
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

    elif ctm_mat.order == "C" and ctv_v.order == "R":
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


def matrix_power(cc: CC, keys: KP, k: int, ctm_A: CTArray):
    """Raise a square matrix to the (integer) power n."""
    # todo power and squaring
    for i in range(k):
        res = matmul_square(cc, keys, ctm_A, ctm_A)
    return res


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
    info = ctm_A.get_info()
    info[0] = cc.EvalMult(ctm_A.data, ctm_B.data)
    return CTArray(*info)


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


def sum(cc, sum_keys, cta, axis=None):
    """Sum of array elements over a given axis"""
    # axis = None: sum everything
    # axis = 0: sum all rows
    # axis = 1: sum all cols
    rows_key, cols_key = sum_keys
    info = cta.get_info()
    if cta.order == "R":
        if axis == 1:
            info[0] = cc.EvalSumCols(cta, cta.n_cols, cols_key)
            info.n_cols = 1
        elif axis == 0:
            info[0] = cc.EvalSumRows(cta, cta.n_cols, rows_key)
            info.n_rows = 1
        else:
            info[0] = cc.EvalSumCols(cta, cta.n_cols, cols_key)
            info[0] = cc.EvalSumRows(info[0], info[0].n_cols, rows_key)
            info.n_rows = 1
            info.n_cols = 1
        return CTArray(*info)
    else:
        # remark: for different encoding, need to repack it or find a better way to do the sum
        return None

    return None


def mean(cc, sum_keys, cta, axis=None):
    """Compute the arithmetic mean along the specified axis."""
    total = sum(cc, sum_keys, cta, axis)
    if axis == 0:
        n = cta.n_rows
    elif axis == 1:
        n = cta.n_cols
    total.data = cc.EvalMul(total.data, n)
    return total


# def cumsum(cc, sum_keys, cta, axis=None):
#     return


# def reduce(cc, sum_keys, cta, axis=None):
#     return


# #####################################################
# # Helper functions
# #####################################################
