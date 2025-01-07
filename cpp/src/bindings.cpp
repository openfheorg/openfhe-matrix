#include <pybind11/pybind11.h>
#include "enc_matrix.h"

namespace py = pybind11;

PYBIND11_MODULE(openfhe_matrix, m) {
//   m.def("Hello", Hello, "Hello function");
  m.def("EvalMultMatVec",
        EvalMultMatVec,
        "Product of a matrix and a vector");
  m.def("EvalLinTransSigma",
        EvalLinTransSigma,
        "Compute Linear Transformation Sigma");
  m.def("EvalLinTransTau", 
        EvalLinTransTau, 
        "Compute Linear Transformation Tau");
  m.def("EvalLinTransPhi", 
        EvalLinTransPhi, 
        "Compute Linear Transformation Phi");
  m.def("EvalLinTransPsi", 
        EvalLinTransPsi, 
        "Compute Linear Transformation Psi");
  m.def("EvalMatMulSquare", 
        EvalMatMulSquare, 
        "Product of two square matrices");
}