
#include <iostream>

#include "AESState.h"
#include "binfhecontext.h"
#include "utils.h"

using namespace AESTransciphering;

int main() {
  PrintHeader("AES Transciphering");

  // need to manually set n: (I: 512,II:600,III:448)
  uint32_t n = 448;
  uint32_t q = 1 << 10;
  std::cout << "n= " << n << std::endl;
  std::cout << "q= " << q << std::endl;

  AESTransciphering::BitTensor T;

  srand(time(nullptr));
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);

  for (uint32_t i = 0; i < 4; i++) {
    for (uint32_t j = 0; j < 4; j++) {
      for (uint32_t k = 0; k < 8; k++) {
        NativeVector v = dug.GenerateVector(n);
        v *= 0;
        uint32_t bit = rand() % 2;
        NativeInteger b = (q >> (bit)) % q;
        T[i][j][k] = std::make_shared<lbcrypto::LWECiphertextImpl>(v, b);
      }
      // std::cout << acc << " ";
    }
  }

  std::vector<AESTransciphering::BitTensor> schedule;
  uint32_t n_rounds = 10;
  std::cout << ">>> Rounds=" << n_rounds << std::endl;
  std::cout << ">>> n= " << n << ", q= " << q << std::endl;
  std::cout << ">>> Number of elemnets in T= " << (4 * 4 * 8) << std::endl;
  std::cout << ">>> Size of elemnet in T= " << sizeof(T[0][0][0]) * 8 << " bits"
            << std::endl;

  BENCHMARK("Key Sheduler", {
    for (uint32_t r = 0; r < n_rounds; r++) {
      AESTransciphering::BitTensor key_r;
      for (uint32_t i = 0; i < 4; i++) {
        for (uint32_t j = 0; j < 4; j++) {
          for (uint32_t k = 0; k < 8; k++) {
            NativeVector v = NativeVector(n, q);
            v *= 0;
            NativeInteger b = 0;
            key_r[i][j][k] =
                std::make_shared<lbcrypto::LWECiphertextImpl>(v, b);
          }
        }
      }
      schedule.push_back(key_r);
    }
  });

  // BENCHMARK("Initiate Transcipherer",
  //           { AESTransciphering::HAES transcipherer(schedule); });

  // // I need to do it twice since with the first one, it faces scope issues
  // // to benchmark the Transcipher itself comment the lines 64-65 and uncomment
  // // the lines 70-72
  AESTransciphering::HAES transcipherer(schedule);
  transcipherer.Transcipher(T);
  // BENCHMARK("HHE.Decomp()", { transcipherer.Transcipher(T); });
  std::cout << T[0][0][0]->GetB() << std::endl;
}