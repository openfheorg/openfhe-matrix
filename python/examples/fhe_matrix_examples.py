import csv, random, unittest, ast, sys, os

# import pytest
from openfhe import *
from openfhe_matrix import *


sys.path.append("../src")
from fhematrix import *
# from config import *


# Function to generate a random square matrix of size n x n
def generate_random_matrix(n):
    return [[random.randint(0, 9) for _ in range(n)] for _ in range(n)]


# Function to multiply two matrices A and B in Plain
def matrix_multiply(A, B, precision=2):
    n = len(A)
    result = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            for k in range(n):
                result[i][j] += A[i][k] * B[k][j]
    # return result
    return [[round(result[i][j], precision) for j in range(n)] for i in range(n)]


# Demo for FHEMatrix library
def gen_crypto_context(ringDimension, mult_depth, batch_size):
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(HEStd_NotSet)
    parameters.SetRingDim(ringDimension)
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(59)
    parameters.SetBatchSize(batch_size)
    parameters.SetScalingTechnique(FIXEDAUTO)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetFirstModSize(60)
    parameters.SetSecretKeyDist(UNIFORM_TERNARY)

    # Enable the features that you wish to use
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    print("The CKKS scheme is using ring dimension: " + str(cc.GetRingDimension()))

    # Generate encryption keys
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)
    return cc, keys


def fhematrix_demo():
    print("Demo for FHEMatrix library")
    ringDimension = 2**5
    batch_size = ringDimension // 2
    mult_depth = 9

    # Setup CryptoContext for CKKS
    cc, keys = gen_crypto_context(ringDimension, mult_depth, batch_size)
    crypto_info = CryptoInfo(cc, keys, batch_size)
    precision = 2

    a = np.array([[1, 2], [3, 4]])
    b = np.array([[5, 6], [7, 8]])
    col_size, row_size = a.shape[0], a.shape[1]
    nums_slots = col_size * row_size

    # c = np.array([1, 2, 3, 4])
    # d = np.array([5, 6, 7, 8])
    # v_cs, v_rs = 4, 1
    # v_ns = 4

    print(type(a))

    fm_a = FHEMatrix.fhe_array(crypto_info, a, nums_slots, row_size, 0)
    fm_b = FHEMatrix.fhe_array(crypto_info, b, nums_slots, row_size, 0)

    # fv_c = FHEMatrix.fhe_array(crypto_info, c, nums_slots, row_size, 1)
    # fv_d = FHEMatrix.fhe_array(crypto_info, d, nums_slots, row_size, 1)

    fm_product = matmul_square(fm_a, fm_b)
    result = cc.Decrypt(fm_product.ctx, keys.secretKey)
    result.SetLength(nums_slots)
    # matrix = to_matrix(result, row_size=2)
    print("a@b = ", result)


fhematrix_demo()

# # Generate 40 test cases and write them to a CSV file
# def generate_test_cases_csv(filename, num_tests=40):
#     with open(filename, mode="w", newline="") as file:
#         writer = csv.writer(file)
#         writer.writerow(["A", "B", "expected"])  # Header row

#         for _ in range(num_tests):
#             n = random.randint(2, 3)  # Randomly choose matrix size (2x2 or 3x3)
#             A = generate_random_matrix(n)
#             B = generate_random_matrix(n)
#             expected = matrix_multiply(A, B)

#             # Write the matrices and the expected result as strings
#             writer.writerow([str(A), str(B), str(expected)])


# # Test case class
# class TestMatrixMultiplication(unittest.TestCase):
#     # Dynamically load test cases from a CSV file
#     @classmethod
#     def load_test_cases_from_csv(cls, filename):
#         test_cases = []
#         with open(filename, mode="r") as file:
#             reader = csv.reader(file)
#             next(reader)  # Skip header row
#             for row in reader:
#                 # Parse matrices and expected result using ast.literal_eval
#                 A = ast.literal_eval(row[0])
#                 B = ast.literal_eval(row[1])
#                 expected = ast.literal_eval(row[2])
#                 test_cases.append((A, B, expected))
#         return test_cases

#     # Function to dynamically generate test methods
#     @classmethod
#     def generate_test_case(cls, A, B, expected):
#         def test(self):
#             # self.assertEqual(matrix_multiply(A, B, precision=4), expected)
#             self.assertEqual(fhe_matrix_multiply(A, B, precision=4), expected)

#         return test


# # Main function to generate CSV and run tests
# if __name__ == "__main__":
#     # Generate the test cases and write them to the CSV file
#     generate_test_cases_csv("tests/mulmat_tests.csv")

#     # Load the test cases from the CSV file
#     test_cases = TestMatrixMultiplication.load_test_cases_from_csv("mulmat_tests.csv")

#     # Dynamically add test methods to the TestMatrixMultiplication class
#     for i, (A, B, expected) in enumerate(test_cases):
#         test_name = f"test_case_{i + 1}"
#         test_method = TestMatrixMultiplication.generate_test_case(A, B, expected)
#         setattr(TestMatrixMultiplication, test_name, test_method)

#     # Run the unittest framework
#     unittest.main()
