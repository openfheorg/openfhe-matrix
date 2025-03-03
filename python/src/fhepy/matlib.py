import math


class Math:
    @staticmethod
    def next_power2(x):
        return 2 ** math.ceil(math.log2(x))

    def is_power2(x):
        return (x & (x - 1) == 0) and x != 0
