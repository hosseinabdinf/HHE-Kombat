#include <cipher.h>
#include <test_data_mp.h>
#include <benchmark_util.h>

extern TLWE_Key __debug_tlwe_exct_key;

Torus torus_diff(Torus a, Torus b){
  uint64_t diff_abs = a < b ? b-a : a-b;
  return diff_abs > 1ULL<<63 ? -diff_abs : diff_abs;
}

void test_MP(){
  // params
  const int N = 2048, k = 1;
  const int Bg_bit_mix = 12, l_mix = 3;
  const int Bg_bit_cipher = 10, l_cipher = 2;
  const double rlwe_std_dev = 2.2148688116005568e-16;
  // HE setup
  TRLWE_Key key2 = trlwe_new_binary_key(N, k, rlwe_std_dev);
  TRGSW_Key key1_gsw = trgsw_new_key(key2, l_mix, Bg_bit_mix);
  TRGSW_Key key2_gsw = trgsw_new_key(key2, l_cipher, Bg_bit_cipher);
  TLWE_Key extracted_key2 = tlwe_alloc_key(N*k, rlwe_std_dev);
  trlwe_extract_tlwe_key(extracted_key2, key2);
  __debug_tlwe_exct_key = extracted_key2;
  // cipher setup
  VPEval vp = new_vp_evaluator(N, k, LUT_SIZE);
  f2_setup_constants(k, N, l_cipher, Bg_bit_cipher);
  TRGSW_DFT * server_key = encrypt_key(_test_data_server_key, key1_gsw);
  TRGSW_DFT * client_key = encrypt_key(_test_data_client_key, key2_gsw);
  TRGSW_DFT * sk = trgsw_alloc_new_DFT_sample_array(2048, l_cipher, Bg_bit_cipher, k, N);
  TRLWE * lut = vp_create_LUT(_test_data_lut, OUT_PREC, vp);
  TLWE * stream = tlwe_alloc_sample_array(OUT_SIZE, N);
  uint32_t * rnd_stream = gen_rnd_stream(_test_data_rnd);
  // key mixing
  MEASURE_TIME("", 10, "Key mixing (single-thread)", 
    key_mixing(sk, server_key, client_key);
  );
  // run cipher
  // "stream_cipher" is a unoptimized version of the cipher, just to check correctness
  // todo: replace this call with stream_cipher_mt or stream_cipher2 before benchmarking it (or use the other file to banchmark)
  stream_cipher(stream, sk, lut, rnd_stream, OUT_SIZE, vp);
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
  test_MP();
  return 0;
}

