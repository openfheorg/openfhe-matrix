import random
from openfhe import *
from openfhe_matrix import *
from helper import *

def matrix_square_mul(A, B, precision=2):
  
  print("Simple Test for Matrix Multiplications")
  
  # A = np.array([[1, 1, 1, 0], [2, 2, 2, 0], [3, 3, 3, 0], [4, 4, 4, 0]])
  # B = np.array([[1, 0, 1, 0], [1, 1, 0, 0], [3, 0, 3, 0], [3, 0, 2, 0]])
    
  vA = SMat._pack_row_wise(A,4,16)
  vB = SMat._pack_row_wise(B,4,16)
  
  n_rows, n_cols = 4, 4
  precision = 2
  
  # Setup CryptoContext for CKKS
  
  ringDimension = 2**5
  batchSize = 2**4
  row_size = 4
  mult_depth = 9
  
  parameters = CCParamsCKKSRNS()
  parameters.SetSecurityLevel(HEStd_NotSet)
  parameters.SetRingDim(ringDimension);
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
      

  print("The CKKS scheme is using ring dimension: " 
          + str(cc.GetRingDimension()))
  
  # Generate encryption keys
  keys = cc.KeyGen()   
  cc.EvalMultKeyGen(keys.secretKey);
  cc.EvalSumKeyGen(keys.secretKey);


  pA = cc.MakeCKKSPackedPlaintext(vA);
  pB = cc.MakeCKKSPackedPlaintext(vB);

  cA = cc.Encrypt(keys.publicKey, pA);
  cB = cc.Encrypt(keys.publicKey, pB);

  print('Plain square matrix product: \n')
  SMat._print_mat(A@B,4)

  ct_AB = EvalMatMulSquare(cc, keys, cA, cB, row_size);
  result = cc.Decrypt(ct_AB, keys.secretKey)
  result.SetLength(n_cols * n_rows)
  matrix = SVec._convert_2_mat(result, n_rows)
  print("FHE square matrix product = ", matrix)
  
  return [[round(matrix[i][j], precision) for j in range(n)] for i in range(n)]
  


if __name__ == "__main__":
    main()

