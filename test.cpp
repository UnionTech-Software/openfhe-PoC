#include<iostream>
#include "openfhe.h"

using namespace lbcrypto;
using namespace std;

int main(int argc, char* argv[]) {
uint32_t multDepth = 5;
uint32_t scaleModSize = 58; 
CCParams<CryptoContextCKKSRNS> parameters;
parameters.SetMultiplicativeDepth(multDepth);
parameters.SetScalingModSize(scaleModSize);
parameters.SetScalingTechnique(FIXEDMANUAL); 
parameters.SetFirstModSize(60);
CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
cc->Enable(PKE);
cc->Enable(LEVELEDSHE);
auto keys = cc->KeyGen();
cc->EvalAtIndexKeyGen(keys.secretKey, {1, -2});
cc->EvalRotateKeyGen(keys.secretKey, {1, -2});
}