#ifndef UTILS_H
#define UTILS_H

// load necessary library
#include "config.h"
#include "helper.h"

uint32_t NextPow2(uint32_t x);
void Debug(CC cc, KeyPair keys, CT ct, std::string msg, int length = 16);
std::vector<double> GenSigmaDiag(const int32_t row_size, const int32_t k);
std::vector<double> GenTauDiag(const int32_t row_size, const int32_t k);
std::vector<double> GenPhiDiag(const int32_t row_size, const int32_t k, const int type);
std::vector<double> GenPsiDiag(const int32_t row_size, const int32_t k);
#endif // UTILS_H