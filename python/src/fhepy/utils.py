import sys
import numpy as np
from fhepy.matlib import *


def get_dims(data):
    if data.ndim == 1:
        return data.shape[0], 0
    return data.shape[0], data.shape[1]


def linear_transformation(cc, keys, U):

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


def rotate(vec, k):
    n = len(vec)
    rot = [0] * n
    for i in range(n):
        rot[i] = vec[(i + k) % n]
    return rot


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

    # print data
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

    # print data
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
def reshape(vec, total_slots, row_size):
    n_slots = len(vec)
    row = []
    mat = []
    for k in range(n_slots):
        row.append(vec[k])
        if (k + 1) % row_size == 0 and k >= 1:
            mat.append(row)
            row = []
    return mat

# convert a vector of an packed_rw_mat to its original matrix
def reshape(vec, total_slots, row_size):
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
