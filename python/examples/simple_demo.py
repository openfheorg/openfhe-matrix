# import openfhe related libraries
import numpy as np
from openfhe import *
from openfhe_matrix import *

# import fhepy library
import fhepy as fp


def gen_crypto_context(ringDimension, row_size, mult_depth):
    # Setup CryptoContext for CKKS
    parameters = CCParamsCKKSRNS()
    parameters.SetSecurityLevel(HEStd_NotSet)
    parameters.SetRingDim(ringDimension)
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(59)
    parameters.SetBatchSize(ringDimension // 2)
    parameters.SetScalingTechnique(FIXEDAUTO)
    parameters.SetKeySwitchTechnique(HYBRID)
    parameters.SetFirstModSize(60)
    parameters.SetSecretKeyDist(UNIFORM_TERNARY)

    # Enable the features that you wish to use
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    cc.Enable(PKESchemeFeature.ADVANCEDSHE)

    # Generate encryption keys
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalSumKeyGen(keys.secretKey)

    return cc, keys


def demo():
    # TODO check with different ringDimension, write test cases
    ringDimension = 2**5
    block_size = 4
    mult_depth = 9
    total_slots = block_size * block_size

    cc, keys = gen_crypto_context(ringDimension, block_size, mult_depth)

    a = np.array([[1, 1, 1, 0], [2, 2, 2, 0], [3, 3, 3, 0], [4, 4, 4, 0]])
    b = np.array([[1, 0, 1, 0], [1, 1, 0, 0], [3, 0, 3, 0], [3, 0, 2, 0]])
    c = [1, 2, 3, 4]
    d = [5, 6, 7, 8]

    print("a: \n", a)
    print("b: \n", b)
    print("c: ", c)
    print("d: ", d)

    ctm_a = fp.array(cc, keys.publicKey, a, total_slots)
    ctm_b = fp.array(cc, keys.publicKey, b, total_slots)

    ctv_c = fp.array(cc, keys.publicKey, c, total_slots, block_size, "C")
    ctv_d = fp.array(cc, keys.publicKey, d, total_slots, block_size, "C")

    print("\nMatrix addition:")
    ct_sum = fp.add(cc, ctm_a, ctm_b)
    result = ct_sum.decrypt(cc, keys.secretKey)
    result = np.round(result, decimals=1)
    print(f"Matching = [{np.array_equal(result, a + b)}] \n{result}")

    print("\nMatrix multiplication:")
    ct_prod = fp.matmul_square(cc, keys, ctm_a, ctm_b)
    result = ct_prod.decrypt(cc, keys.secretKey)
    result = np.round(result, decimals=1)
    print(f"Matching = [{np.array_equal(result, a @ b)}] \n{result}")

    print("\nMatrix Vector multiplication: A@c")
    print("Result = ", a @ c)
    sum_col_keys = fp.gen_sum_col_keys(cc, keys.secretKey, block_size)
    ct_prod = fp.matvec(cc, keys, sum_col_keys, ctm_a, ctv_c, block_size)
    result = ct_prod.decrypt(cc, keys.secretKey)
    result = np.round(result, decimals=1)
    print(f"Matching = [{np.array_equal(result, a @ c)}] \n{result}")

    # # %%
    # print("\nDot product c.d:")
    # print(np.dot(c, d))

    # %%
    print("\nHadamard Product: a.b:")
    print(np.multiply(a, b))

    # # %%
    # print("\nCreate matrix:")
    # m = np.matrix([[1, 2], [3, 4]])
    # print(m)

    # # %%
    # print("\nCreate array:")
    # arr = np.array([[1, 2], [3, 4]])
    # print(arr)

    # # %%
    # print("\nSum of array elements: sum(a)")
    # print(np.sum(a))

    # # %%
    # print("\nMean of array elements: mean(a)")
    # print(np.mean(a))

    # # %%
    # print("\nAddition: a+b")
    # print(np.add(a, b))

    # # %%
    # print("\nSubtraction: a - b")
    # print(np.subtract(a, b))

    # # %%
    # print("\nReduce by addition:")
    # print("Before addition: ", c)
    # print(np.add.reduce(c))

    # # %%
    # print("\nReduce by subtraction:")
    # print("Before subtraction: ", c)
    # print(np.subtract.reduce(c))

    # # %%
    # print("\nAccumulate by addition:")
    # print("Before accumulate by addition: ", c)
    # print(np.add.accumulate(c))

    # # %%
    # print("\nAccumulate by subtraction:")
    # print("Before accumulate by subtraction: ", c)
    # print(np.subtract.accumulate(c))


demo()
