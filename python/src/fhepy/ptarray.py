from typing import Tuple

# import openfhe related libraries
import openfhe
import openfhe_matrix

# import config and auxilarries files
from fhepy.config import *
from fhepy.matlib import *
import fhepy.utils as utils


class PTArray:
    def __init__(
        self,
        data: openfhe.Plaintext,
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


# encode_matrix
def ravel_mat(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    order: int = CodecType.ROW_WISE,
) -> PT:
    """Encode a matrix or data without padding or replicate"""

    if type == CodecType.ROW_WISE:
        packed_data = utils.pack_mat_row_wise(data, row_size, num_slots)
    elif type == CodecType.COL_WISE:
        packed_data = utils.pack_mat_col_wise(data, row_size, num_slots)
    else:
        # TODO Encoded Diagonal Matrix
        packed_data = [0]

    print("DEBUG[encode_matrix] ", packed_data)

    return cc.MakeCKKSPackedPlaintext(packed_data)


def ravel_vec(
    cc: CC,
    data: list,
    num_slots: int,
    row_size: int = 1,
    order: int = CodecType.ROW_WISE,
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
        packed_data = utils.pack_vec_row_wise(data, row_size, num_slots)
    elif type == CodecType.COL_WISE:
        packed_data = utils.pack_vec_col_wise(data, row_size, num_slots)
    else:
        packed_data = [0]

    return cc.MakeCKKSPackedPlaintext(packed_data)
