

#include "enc_matrix.h"
#include "openfhe.h"

/***********************************************************************/

// void demo_rand_test(int32_t n_rows, int32_t n_cols){
// srand((unsigned)time(0));
//   for (int i = 0; i < argc; ++i) {
//         std::cout << argv[i] << "\n";
//     }

//   std::cout << "nRows = " << n_rows<<std::endl;
//   std::cout << "nCols = " << n_cols<<std::endl;
//   int32_t padded_cols = NextPow2(n_cols);

//   std::vector<std::vector<double>> matA = sampleMatrix<double>(n_rows,
//   n_cols, 1, 5); std::vector<double> vecA = flatten<double>(matA);

//   std::vector<double> B = sampleVec<double>(n_cols);
//   std::vector<double> cloneB = clone<double>(B, n_rows);

// }

void DemoMatVec(bool verbose = true) {
  uint32_t n_rows = 2;
  uint32_t n_cols = 4;

  std::vector<std::vector<double>> omat = {
      {1, 1, 1, 0},
      {2, 2, 2, 0},
  };
  std::vector<double> ovec = {1, 2, 3, 0};

  std::vector<double> mat = {1, 1, 1, 0, 2, 2, 2, 0};
  std::vector<double> vec = {1, 2, 3, 0, 1, 2, 3, 0};
  usint row_size = NextPow2(n_cols);

  lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_NotSet;
  int ringDimension = 1 << 12;   // 12 bits
  int32_t batchSize = 1 << 11;  // full slots
  int32_t numLargeDigits = 0;
  int32_t maxRelinSkDeg = 1;
  int32_t firstModSize = 60;
  int32_t dcrtBits = 59;
  int32_t multDepth = 2;
  lbcrypto::ScalingTechnique rsTech = lbcrypto::FIXEDAUTO;
  lbcrypto::KeySwitchTechnique ksTech = lbcrypto::HYBRID;

  std::cout << "Running in 64-bit mode" << std::endl;
  std::cout << "CKKS:: Ring dimension " << ringDimension << std::endl;
  std::cout << "batchSize = " << batchSize << std::endl;

  // Set crypto params and create context
  CryptoParams parameters;
  std::vector<int32_t> levelBudget;
  std::vector<int32_t> bsgsDim = {0, 0};

  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(dcrtBits);

  parameters.SetSecurityLevel(securityLevel);
  parameters.SetRingDim(ringDimension);
  parameters.SetBatchSize(batchSize);
  parameters.SetScalingTechnique(rsTech);
  parameters.SetKeySwitchTechnique(ksTech);
  parameters.SetNumLargeDigits(numLargeDigits);
  parameters.SetFirstModSize(firstModSize);
  parameters.SetMaxRelinSkDeg(maxRelinSkDeg);

  CC cc = GenCryptoContext(parameters);

  // Enable the features that you wish to use.
  cc->Enable(lbcrypto::PKE);
  cc->Enable(lbcrypto::LEVELEDSHE);
  cc->Enable(lbcrypto::ADVANCEDSHE);

  std::cout << "Generating keys" << std::endl;
  KeyPair keys = cc->KeyGen();
  std::cout << "\tMult keys" << std::endl;
  cc->EvalMultKeyGen(keys.secretKey);
  std::cout << "\tEvalSum keys" << std::endl;
  cc->EvalSumKeyGen(keys.secretKey);
  MatKeys evalSumRowKeys =
      cc->EvalSumRowsKeyGen(keys.secretKey, nullptr, row_size);
  MatKeys evalSumColKeys = cc->EvalSumColsKeyGen(keys.secretKey);

  std::cout << "Finish generating\n";

  CT ct_prod;
  PT pt_prod;

  PT pMat = cc->MakeCKKSPackedPlaintext(mat);
  PT pVec = cc->MakeCKKSPackedPlaintext(vec);

  CT cMat = cc->Encrypt(keys.publicKey, pMat);
  CT cVec = cc->Encrypt(keys.publicKey, pVec);

  if (verbose) {
    std::cout << "--- Matrix A ---\n";
    PrintVector(mat);

    std::cout << "--- Clonned Vector B ---\n";
    PrintVector(vec);
    std::cout << std::endl;

    std::cout << "Plaintext ::: Matrix * vector\n";
    std::vector<double> result = MulMatVec(omat, ovec);
    PrintVector(result);
    std::cout << std::endl;
  }

  ct_prod = EvalMultMatVec(cc, keys, evalSumColKeys, encode_style::MM_CRC,
                           row_size, cVec, cMat);

  cc->Decrypt(keys.secretKey, ct_prod, &pt_prod);
  pt_prod->SetLength(n_cols * n_rows);
  std::vector<double> vec_prod = pt_prod->GetRealPackedValue();

  if (verbose) {
    std::cout << "\n\nFHE ::: Matrix * vector \n";
    PrintVector(vec_prod);
    std::cout << std::endl;
  }

  std::cout << "FINISH!" << std::endl;
}

void DemoMulMat(bool verbose = true) {
  uint32_t n_rows = 4;
  uint32_t n_cols = 4;

  std::vector<std::vector<double>> omat_1 = {
      {1, 1, 1, 0},
      {2, 2, 2, 0},
      {3, 3, 3, 0},
      {4, 4, 4, 0},
  };

  std::vector<std::vector<double>> omat_2 = {
      {1, 0, 1, 0},
      {1, 1, 0, 0},
      {3, 0, 3, 0},
      {3, 0, 2, 0},
  };

  std::vector<double> mat_1 = Flatten<double>(omat_1);
  std::vector<double> mat_2 = Flatten<double>(omat_2);
  printf("Vector A");
  PrintVector(mat_1);
  printf("Vector B");
  PrintVector(mat_2);

  usint row_size = NextPow2(n_cols);

  lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_NotSet;
  int ringDimension = 1 << 5;   // 12 bits
  int32_t batchSize = 1 << 4;  // full slots
  int32_t numLargeDigits = 0;
  int32_t maxRelinSkDeg = 1;
  int32_t firstModSize = 60;
  int32_t dcrtBits = 59;
  int32_t multDepth = 20;
  lbcrypto::ScalingTechnique rsTech = lbcrypto::FIXEDAUTO;
  lbcrypto::KeySwitchTechnique ksTech = lbcrypto::HYBRID;

  std::cout << "Running in 64-bit mode" << std::endl;
  std::cout << "CKKS:: Ring dimension " << ringDimension << std::endl;
  std::cout << "batchSize = " << batchSize << std::endl;

  // Set crypto params and create context
  CryptoParams parameters;
  std::vector<int32_t> levelBudget;
  std::vector<int32_t> bsgsDim = {0, 0};

  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(dcrtBits);

  parameters.SetSecurityLevel(securityLevel);
  parameters.SetRingDim(ringDimension);
  parameters.SetBatchSize(batchSize);
  parameters.SetScalingTechnique(rsTech);
  parameters.SetKeySwitchTechnique(ksTech);
  parameters.SetNumLargeDigits(numLargeDigits);
  parameters.SetFirstModSize(firstModSize);
  parameters.SetMaxRelinSkDeg(maxRelinSkDeg);

  CC cc = GenCryptoContext(parameters);

  // Enable the features that you wish to use.
  cc->Enable(lbcrypto::PKE);
  cc->Enable(lbcrypto::LEVELEDSHE);
  cc->Enable(lbcrypto::ADVANCEDSHE);

  std::cout << "Generating keys" << std::endl;
  KeyPair keys = cc->KeyGen();
  std::cout << "\tMult keys" << std::endl;
  cc->EvalMultKeyGen(keys.secretKey);
  std::cout << "\tEvalSum keys" << std::endl;
  cc->EvalSumKeyGen(keys.secretKey);
  MatKeys evalSumRowKeys =
      cc->EvalSumRowsKeyGen(keys.secretKey, nullptr, row_size);
  MatKeys evalSumColKeys = cc->EvalSumColsKeyGen(keys.secretKey);

  std::cout << "Finish generating\n";

  CT ct_prod;
  PT pt_prod;

  PT pMat_1 = cc->MakeCKKSPackedPlaintext(mat_1);
  PT pMat_2 = cc->MakeCKKSPackedPlaintext(mat_2);

  CT cMat_1 = cc->Encrypt(keys.publicKey, pMat_1);
  CT cMat_2 = cc->Encrypt(keys.publicKey, pMat_2);

  if (verbose) {
    std::cout << "Plaintext ::: Matrix * Matrix\n";
    std::vector<std::vector<double>> result = MulMats(omat_1, omat_2);
    PrintMatrix(result);
    std::cout << std::endl;
  }

  ct_prod = EvalMatMulSquare(cc, keys, cMat_1, cMat_2, row_size);
  std::cout <<"Hello 1\n";
  cc->Decrypt(keys.secretKey, ct_prod, &pt_prod);
  std::cout <<"Hello 2\n";
  pt_prod->SetLength(n_cols * n_rows);
  std::cout <<"Hello 3\n";
  std::vector<double> vec_prod = pt_prod->GetRealPackedValue();
  std::cout <<"Hello 4\n";

  if (verbose) {
    std::cout << "\n\nFHE ::: Matrix * Matrix \n";
    PrintVector(vec_prod);
    std::cout << std::endl;
  }

  std::cout << "FINISH!" << std::endl;
}

int main(int argc, char* argv[]) {
  DemoMulMat();
  // std::cout<<"Hello Saigon!!!"<<std::endl;
  // test();
}