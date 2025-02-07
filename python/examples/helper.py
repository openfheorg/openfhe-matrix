import numpy as np


class Math:
    @staticmethod
    def next_power2(x):
        return 2 ** math.ceil(math.log2(x))


class SVec:
    @staticmethod
    def _pack_row_wise(v, block_size, num_slots):
        """
        Clone a vector v to fill num_slots
        1 -> 1111 2222 3333
        2
        3
        """
        n = len(v)
        if num_slots < n:
            sys.exit("ERROR ::: [row_wise_vector] vector is longer than total slots")
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

    @staticmethod
    def _pack_col_wise(v, block_size, num_slots):
        """
        Clone a vector v to fill num_slots
        1 -> 1230 1230 1230
        2
        3
        """
        n = len(v)
        if block_size < n:
            sys.exit(
                f"ERROR ::: [col_wise_vector] vector ({n}) is longer than size of a slot ({block_size})"
            )
        if num_slots < n:
            sys.exit(f"ERROR ::: [col_wise_vector] vector is longer than total slots")
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

    @staticmethod
    def _rotate(vec, k):
        n = len(vec)
        rot = [0] * n
        for i in range(n):
            rot[i] = vec[(i + k) % n]
        return rot

    @staticmethod
    def _convert_2_mat(vec, row_size):
        d = len(vec)
        row = []
        mat = []
        for k in range(d):
            row.append(vec[k])
            if (k + 1) % row_size == 0 and k > 1:
                mat.append(row)
                row = []
        return mat

    @staticmethod
    def convert_cw_rw(v, block_size, num_slots):
        org_v = v[:block_size]
        vv = row_wise_vector(org_v, block_size, num_slots)

        if 0:
            wnice_org = [round(x, 3) for x in v[: 2 * block_size]]
            vv_b = vv[: 2 * block_size]
            wnice = [round(x, 3) for x in vv_b]
            print(f"convert \n  {wnice_org}\n->{wnice}")
            print(f"{wnice}")
        return vv

    @staticmethod
    def convert_rw_cw(v, block_size, num_slots):
        org_v = []
        # print(len(v), block_size, num_slots)
        for k in range(block_size):
            org_v.append(v[k * block_size])

        vv = col_wise_vector(org_v, block_size, num_slots)

        if 0:
            wnice_org = [round(x, 3) for x in v[: 2 * block_size]]
            vv_b = vv[: 2 * block_size]
            wnice = [round(x, 3) for x in vv_b]
            print(f"convert {org_v} to {vv[:block_size]}")
            print(f"{wnice}")
        return vv


class SMat:
    @staticmethod
    def _print_mat(matrix, rows):
        for i in range(rows):
            print(matrix[i])
            # print('\n')

    @staticmethod
    def _pack_row_wise(matrix, block_size, num_slots, debug=0):
        """
        Packing Matric M using row-wise
        [[1 2 3] -> [1 2 3 0 4 5 6 0 7 8 9 0]
        [4 5 6]
        [7 8 9]]
        """
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

    @staticmethod
    def _pack_col_wise(matrix, block_size, num_slots, verbose=0):
        """
        Packing Matric M using row-wise
        [[1 2 3] -> [1 4 7 0 2 5 8 0 3 6 9 0]
         [4 5 6]
         [7 8 9]]
        """
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
