#include <cipher.h>
#include <test_data.h>
#include <benchmark_util.h>

// params
const int N = 2048, k = 1, Bg_bit = 23, l = 1;
  // const int N = 2048, k = 1, Bg_bit = 17, l = 2;
  // const int N = 2048, k = 1, Bg_bit = 13, l = 3;
  // const int N = 2048, k = 1, Bg_bit = 5, l = 9;
const double rlwe_std_dev = 2.2148688116005568e-16;

Torus torus_diff(Torus a, Torus b){
  uint64_t diff_abs = a < b ? b-a : a-b;
  return diff_abs > 1ULL<<63 ? -diff_abs : diff_abs;
}

extern TLWE_Key __debug_tlwe_exct_key;

void test_CMUX_ct(){
  // HE setup
  TRLWE_Key key2 = trlwe_new_binary_key(N, k, rlwe_std_dev);
  TRGSW_Key key2_gsw = trgsw_new_key(key2, l, Bg_bit);
  TLWE_Key extracted_key2 = tlwe_alloc_key(N*k, rlwe_std_dev);
  trlwe_extract_tlwe_key(extracted_key2, key2);
  __debug_tlwe_exct_key = extracted_key2;
  // cipher setup
  VPEval vp = new_vp_evaluator(N, k, LUT_SIZE);
  f2_setup_constants(k, N, l, Bg_bit);
  TRGSW_DFT * sk = encrypt_key(_test_data_key, key2_gsw);
  DFT_Polynomial * lut = vp_create_LUT2(_test_data_lut, OUT_PREC, vp, Bg_bit);
  TLWE * stream = tlwe_alloc_sample_array(OUT_SIZE, N);
  uint32_t * rnd_stream = gen_rnd_stream(_test_data_rnd);
  // run cipher
  MEASURE_TIME("", 10, "Cipher for 32 messages (single-threaded)", 
    stream_cipher2(stream, sk, lut, rnd_stream, OUT_SIZE, vp);
  );
  printf("Output stream: ");
  double var = 0;
  for (size_t i = 0; i < OUT_SIZE; i++){
    const Torus phase = tlwe_phase(stream[i], extracted_key2);
    const uint64_t res = torus2int(phase, OUT_PREC);
    const uint64_t expec = _test_data_result[i];
    var += pow(torus_diff(phase, int2torus(expec, OUT_PREC)), 2);
    if(res != expec){
      printf("Failed. Stream[%lu]: Expected %lu Was %lu\n", i, expec, res);
      // break;
    }
    printf("%lu, ", res);
  }
  printf("\n");
  var /= OUT_SIZE;
  printf("Torus Sigma: 2^%lf\n", log2(torus2double(sqrt(var))));
}

void test_CMUX_ct_mt(){
  // HE setup
  TRLWE_Key key2 = trlwe_new_binary_key(N, k, rlwe_std_dev);
  TRGSW_Key key2_gsw = trgsw_new_key(key2, l, Bg_bit);
  TLWE_Key extracted_key2 = tlwe_alloc_key(N*k, rlwe_std_dev);
  trlwe_extract_tlwe_key(extracted_key2, key2);
  __debug_tlwe_exct_key = extracted_key2;
  // cipher setup
  VPEval * vp = new_vp_evaluator_array(NUM_ROUNDS, N, k, LUT_SIZE);
  f2_setup_constants(k, N, l, Bg_bit);
  TRGSW_DFT * sk = encrypt_key(_test_data_key, key2_gsw);
  DFT_Polynomial * lut = vp_create_LUT2(_test_data_lut, OUT_PREC, vp[0], Bg_bit);
  TLWE * stream = tlwe_alloc_sample_array(OUT_SIZE, N);
  uint32_t * rnd_stream = gen_rnd_stream(_test_data_rnd);
  // run cipher
  MEASURE_TIME("", 10, "Cipher for 32 messages (multi-threaded)", 
    stream_cipher_mt(stream, sk, lut, rnd_stream, OUT_SIZE, vp);
  );
  printf("Output stream: ");
  double var = 0;
  for (size_t i = 0; i < OUT_SIZE; i++){
    const Torus phase = tlwe_phase(stream[i], extracted_key2);
    const uint64_t res = torus2int(phase, OUT_PREC);
    const uint64_t expec = _test_data_result[i];
    var += pow(torus_diff(phase, int2torus(expec, OUT_PREC)), 2);
    if(res != expec){
      printf("Failed. Stream[%lu]: Expected %lu Was %lu\n", i, expec, res);
      // break;
    }
    printf("%lu, ", res);
  }
  printf("\n");
  var /= OUT_SIZE;
  printf("Torus Sigma: 2^%lf\n", log2(torus2double(sqrt(var))));
}

int main(int argc, char const *argv[])
{
  printf("Testing multi-threaded cipher\n");
  test_CMUX_ct_mt();
  printf("\n\nTesting single-threaded cipher\n");
  test_CMUX_ct();
  return 0;
}
