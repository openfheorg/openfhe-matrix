import random
from openfhe import *
from openfhe_matrix import *
from helper import *

import csv
import random
import unittest
import ast

TEST_DIR = 'tests'
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


# Function to multiply two matrices A and B in FHE
def fhe_matrix_multiply(AA, BB, precision=2):

    # print("Simple Test for Matrix Multiplications")

    A = np.array(AA)
    B = np.array(BB)
    
    # print(A)
    # print(B)

    n_rows = len(A)
    n_cols = len(A[0])
    
    vA = SMat._pack_row_wise(A, n_rows, 16)
    vB = SMat._pack_row_wise(B, n_rows, 16)

   
    precision = 2

    # Setup CryptoContext for CKKS

    ringDimension = 2**5
    batchSize = 2**4
    row_size = 4
    mult_depth = 9

    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(HEStd_NotSet)
    parameters.SetRingDim(ringDimension)
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(59)
    parameters.SetBatchSize(batchSize)
    parameters.SetScalingTechnique(FIXEDAUTO)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetFirstModSize(60)
    parameters.SetSecretKeyDist(UNIFORM_TERNARY)

    # Enable the features that you wish to use
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    # print("The CKKS scheme is using ring dimension: " + str(cc.GetRingDimension()))

    # Generate encryption keys
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)

    pA = cc.MakeCKKSPackedPlaintext(vA)
    pB = cc.MakeCKKSPackedPlaintext(vB)

    cA = cc.Encrypt(keys.publicKey, pA)
    cB = cc.Encrypt(keys.publicKey, pB)

    # print("Plain square matrix product: \n")
    # SMat._print_mat(A @ B, 4)

    ct_AB = EvalMatMulSquare(cc, keys, cA, cB, row_size)
    result = cc.Decrypt(ct_AB, keys.secretKey)
    result.SetLength(n_cols * n_rows)
    result.GetFormattedValues(precision)
    result = result.GetRealPackedValue()
    # print(result, type(result))
    
    matrix = SVec._convert_2_mat(result, n_rows)
    # print("FHE square matrix product = ", matrix)

    return [[round(matrix[i][j], precision) for j in range(n_rows)] for i in range(n_rows)]


# Generate 40 test cases and write them to a CSV file
def generate_test_cases_csv(filename, num_tests=40):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["A", "B", "expected"])  # Header row

        for _ in range(num_tests):
            # n = random.randint(2, 3)  # Randomly choose matrix size (2x2 or 3x3)
            n = 4  # Randomly choose matrix size (2x2 or 3x3)
            A = generate_random_matrix(n)
            B = generate_random_matrix(n)
            expected = matrix_multiply(A, B)

            # Write the matrices and the expected result as strings
            writer.writerow([str(A), str(B), str(expected)])


# Test case class
class Test(unittest.TestCase):

    # Dynamically load test cases from a CSV file
    @classmethod
    def load_test_cases_from_csv(cls, filename):
        test_cases = []
        with open(filename, mode="r") as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                # Parse matrices and expected result using ast.literal_eval
                A = ast.literal_eval(row[0])
                B = ast.literal_eval(row[1])
                expected = ast.literal_eval(row[2])
                test_cases.append((A, B, expected))
        return test_cases

    # Function to dynamically generate test methods
    @classmethod
    def generate_test_case(cls, A, B, expected):
        def test(self):
            # print(A)
            # print(B)
            # print(expected)
            # self.assertEqual(matrix_multiply(A, B, precision=4), expected)
            
            self.assertEqual(fhe_matrix_multiply(A, B, precision=4), expected)

        return test


# Main function to generate CSV and run tests
if __name__ == "__main__":
    # Generate the test cases and write them to the CSV file
    generate_test_cases_csv(TEST_DIR+"/mulmat_tests.csv",40)

    # Load the test cases from the CSV file
    test_cases = Test.load_test_cases_from_csv(TEST_DIR+"/mulmat_tests.csv")

    # Dynamically add test methods to the TestMatrixMultiplication class
    for i, (A, B, expected) in enumerate(test_cases):
        test_name = f"test_case_{i+1}"
        test_method = Test.generate_test_case(A, B, expected)
        setattr(Test, test_name, test_method)

    # Run the unittest framework
    unittest.main()
