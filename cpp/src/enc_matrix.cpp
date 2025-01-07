#include "enc_matrix.h"

void test()
{
  std::cout << "Hello Boca Raton!!!\n";
}

/*
Compute ct_matrix * ct_vector
*/
CT EvalMultMatVec(const CC &context,
                  const KeyPair& keys,
                  const MatKeys& eval_keys,
                  int type,
                  int row_size,
                  const CT &ct_vec,
                  const CT &ct_mat)
{
  CT ct_prod;
  auto ct_mult = context->EvalMult(ct_mat, ct_vec);

#ifdef DEBUG
  std::cout << "Debugging enabled" << std::endl;
  PT pt_mult;
  context->Decrypt(keys.secretKey, ct_mult, &pt_mult);
  pt_mult->SetLength(row_size * 4);
  std::vector<double> vec = pt_mult->GetRealPackedValue();
  PrintVector(vec);
#endif

  if (type == encode_style::MM_CRC) {
    std::cout << "Using encode_style = " << encode_style::MM_CRC
      << " with row_size = " << row_size << std::endl;
    ct_prod = context->EvalSumCols(ct_mult, row_size, *eval_keys);

#ifdef DEBUG
    PT pt_tmp;
    context->Decrypt(keys.secretKey, ct_prod, &pt_tmp);
    pt_tmp->SetLength(row_size * 4);
    std::vector<double> vec = pt_tmp->GetRealPackedValue();
    PrintVector(vec);
#endif
  }
  else if (type == encode_style::MM_RCR) {
    std::cout << "Using encode_style = " << encode_style::MM_RCR
      << " with row_size = " << row_size << std::endl;

    ct_prod = context->EvalSumRows(ct_mult, row_size, *eval_keys);
  }
  else {
    printf("To be continue ... \n");
  }
  return ct_prod;
};

/*
Generate the diagonals for the W permutation
*/

CT EvalLinTransSigma(CC cc, KeyPair keys, const CT c_vec, const int row_size)
{
  int n = row_size * row_size;
  CT c_result, c_tmp;
  std::vector<double> result(n, 0.0);

  PT p_result = cc->MakeCKKSPackedPlaintext(result);
  c_result = cc->Encrypt(keys.publicKey, p_result);

  // std::cout << "Compute Sigma Permutation with row_size = "
  //           << row_size << std::endl;
  
  std::vector<int> index_list(2 * row_size, 0);

  for (int k = -row_size; k < row_size; k++) {
    index_list[k+row_size] = k;
  }

  cc->EvalRotateKeyGen(keys.secretKey, index_list);

  std::cout <<"Start\n";
  for (int k = -row_size; k < row_size; k++) {
    // std::cout << "k = " << k << std::endl;
    std::vector<double> diag = GenSigmaDiag(row_size, k);
    // PrintVector(diag);
    auto p_diag = cc->MakeCKKSPackedPlaintext(diag);
    auto c_rotated = cc->EvalRotate(c_vec, k);
    cc->EvalAddInPlace(c_result, cc->EvalMult(c_rotated, p_diag));
    //  Debug(cc, keys, c_result, "c_result",16);
  }

  return c_result;
};

CT EvalLinTransTau(CC cc, KeyPair keys, const CT c_vec, const int row_size)
{
  int n = row_size * row_size;
  CT c_result, c_tmp;
  std::vector<double> result(n, 0.0);
  PT p_result = cc->MakeCKKSPackedPlaintext(result);
  c_result = cc->Encrypt(keys.publicKey, p_result);

  for (int k = 0; k < row_size; k++) {
    auto diag = GenTauDiag(row_size, k);
    auto p_diag = cc->MakeCKKSPackedPlaintext(diag);

    cc->EvalRotateKeyGen(keys.secretKey, {k});
    auto c_rotated = cc->EvalRotate(c_vec, row_size * k);
    cc->EvalAddInPlace(c_result, cc->EvalMult(c_rotated, p_diag));
  }

  return c_result;
};

CT EvalLinTransPhi(CC cc,
  KeyPair keys,
  const CT c_vec,
  const int row_size,
  const int k)
{
  int n = row_size * row_size;
  CT c_result, c_tmp;
  std::vector<double> result(n, 0.0);
  PT p_result = cc->MakeCKKSPackedPlaintext(result);
  c_result = cc->Encrypt(keys.publicKey, p_result);
  for (int i = 0; i < 2; i++)
  {
    int idx = k - i * row_size;
    auto diag = GenPhiDiag(row_size, k, i);
    PT p_diag = cc->MakeCKKSPackedPlaintext(diag);
    cc->EvalRotateKeyGen(keys.secretKey, { idx });
    CT c_rotated = cc->EvalRotate(c_vec, idx);
    cc->EvalAddInPlace(c_result, cc->EvalMult(c_rotated, p_diag));
  }
  return c_result;
};


CT EvalLinTransPsi(CC cc,
  KeyPair keys,
  const CT c_vec,
  const int row_size,
  const int k)
{
  cc->EvalRotateKeyGen(keys.secretKey, { row_size * k });
  CT c_result = cc->EvalRotate(c_vec, row_size * k);
  return c_result;
}



CT EvalMatMulSquare(CC cc,
  KeyPair keys,
  const CT cmat_A,
  const CT cmat_B,
  const int32_t row_size)
{

  // Step 1 - 1
  CT cA = EvalLinTransSigma(cc, keys, cmat_A, row_size);
  // Debug(cc, keys, cA, "_Step 1 - 1: Compute cA");
  // Step 1 - 2
  CT cB = EvalLinTransTau(cc, keys, cmat_B, row_size);
  // Debug(cc, keys, cB, "_Step 1 - 2: Compute cB");
  CT cAB = cc->EvalMult(cA, cB);
  // Debug(cc, keys, cAB, "_Step 1 - 3: Compute cAB");
  // Step 2 and 3
  for (int32_t k = 1; k < row_size; k++) {
    // std::cout << "Loop: " << k << std::endl;
    cA = EvalLinTransPhi(cc, keys, cA, row_size, k);
    // Debug(cc, keys, cA, "cA");
    cB = EvalLinTransPsi(cc, keys, cB, row_size, k);
    // Debug(cc, keys, cB, "cB");
    CT tmp = cc->EvalMult(cA, cB);
    cAB = cc->EvalAdd(cAB, tmp);
    // Debug(cc, keys, cAB, "cAB");
  }
  // std::cout << "Finish MM " << std::endl;
  return cAB;
}