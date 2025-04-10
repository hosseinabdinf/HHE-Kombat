#include <cassert>
#include <iostream>

#include "bench_printer.h"
#include "bench_utils.h"
#include "filip.h"
#include "homomorphic_filip.h"
#include "utils.h"
// #include "vectorutils.hpp"

using namespace std;

// comment this for running the full benchmark
// uncomment for benchmarking SKE only
// #define SKE_BENCH_ONLY

void printVector(const std::vector<int>& vec) {
  std::cout << "[ ";
  for (const auto& val : vec) {
    std::cout << val << " ";
  }
  std::cout << "]" << endl;
}

int main() {
  int BENCHMARK_ITERATIONS = 100;
  Printer printer(true);
  printer.PrintHeader("Homomorphic Filip Test");

  srand(time(NULL));

  int N = 1 << 14;  // length of the secret key
  int n = 144;      // size of subset used to encrypt each bit
  int k = 63;       // number of bits added in the threshold function
  int d = 35;       // threshold limit
  FiLIP filip(N, n, k, d);

  printer.PrintMessage("Symmetric Filip parameters: ");
  cout << filip << endl;

  HomomorphicFiLIP homFilip(filip);
  // cout << "HomomorphicFiLIP homFilip(filip);" << endl;
  printer.PrintMessage("Homomorphic Filip parameters: ");
  cout << homFilip << endl;

  long int iv = 1234567;

  int N_TESTS = 1;
  int size_msg = 10;
  float avg_time = 0.0;
  for (int _i = 0; _i < N_TESTS; _i++) {
    // create a random message
    vector<int> m(size_msg);
    for (int i = 0; i < size_msg; i++) m[i] = rand() % 2;

    // encipher m with FiLIP
    // vector<int> c = filip.enc(iv, m);
    printer.PrintHeader("Symmetric Filip");
    printer.PrintMessages("#elements: ", m.size(),
                          ", size of element (bit): ", sizeof(m[0]) * 8);
    vector<int> c;
    BENCHMARK_ITER("SKE.Enc()", BENCHMARK_ITERATIONS,
                   { c = filip.enc(iv, m); });

    // run FiLIP::decryption homomorphically, thus c_lwe must encrypt m
    // auto start = clock();
    // vector<Ctxt_LWE> c_lwe = homFilip.transform(iv, c);

    printer.PrintHeader("Transciphering");
    vector<Ctxt_LWE> c_lwe;
    BENCHMARK_ITER("HHE.Decomp()", BENCHMARK_ITERATIONS,
                   { c_lwe = homFilip.transform(iv, c); });

    // avg_time += float(clock() - start) / CLOCKS_PER_SEC;

    // run LWE decryption. Thus, dec_m must be equal to m
    vector<int> dec_m = homFilip.dec(c_lwe);
    //
    //        cout << "    m  = " << m << endl;
    //        cout << "dec(c) = " << dec_m << endl;

    printer.PrintMessages("p:", 2, ", logp:", 1);
    printer.PrintMessage("Original Message:");
    printVector(m);
    printer.PrintMessage("Decrypted message:");
    printVector(dec_m);
    assert(m == dec_m);

    if (0 == _i % 10) cout << "Noise: " << homFilip.noise(c_lwe, m) << endl;
  }
  // cout << "Avg. time to decrypt homomorphically: " << avg_time / N_TESTS << "
  // s"
  //      << endl;
  // cout << "Avg. time to decrypt EACH BIT homomorphically: "
  //      << (avg_time / N_TESTS) / size_msg << " s" << endl;

  return 0;
}
