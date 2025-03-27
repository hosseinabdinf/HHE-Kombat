#include <cipher.h>

extern uint64_t __glb_rnd_idx;
#define NUM_THREADS 14
// #define LUT_PER_THREAD 2

#define MAX_THREADS NUM_ROUNDS
typedef struct _cipher_args
{
  TLWE out;
  TRGSW_DFT * input, * tmp;
  DFT_Polynomial * lut;
  VPEval vp;
  uint32_t w[NUM_ROUNDS/NUM_THREADS + 1], size;
} cipher_args;

void __debug_decrypt_and_print_bits(char * mask, TRGSW_DFT * c, uint64_t size);
extern TLWE_Key __debug_tlwe_exct_key;
void * filter_thread(void * arg_p){
  cipher_args * arg = (cipher_args *) arg_p;
  trgsw_xor_cleartext_array(arg->tmp, arg->input, arg->w[0], F_SIZE);
  vp_eval_LUT2(arg->out, arg->tmp, arg->lut, arg->vp);
  trgsw_bits_to_Zq_lwe_addto(arg->out, &arg->tmp[LUT_SIZE], OUT_PREC,  ADD_SIZE, arg->vp);
   
  for (size_t i = 1; i < arg->size; i++){
    trgsw_xor_cleartext_array(arg->tmp, &arg->input[i*F_SIZE], arg->w[i], F_SIZE);
    vp_eval_LUT2_addto(arg->out, arg->tmp, arg->lut, arg->vp);
    trgsw_bits_to_Zq_lwe_addto(arg->out, &arg->tmp[LUT_SIZE], OUT_PREC,  ADD_SIZE, arg->vp);
  }
  return NULL;
}

void stream_cipher_mt(TLWE * stream, TRGSW_DFT sk[2048], DFT_Polynomial * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval * vp){
  const uint32_t luts_per_thread = (uint32_t) ceil(((double) NUM_ROUNDS) / ((double) NUM_THREADS));
  TRGSW_DFT s[2048], * s2 = trgsw_alloc_new_DFT_sample_array(F_SIZE*NUM_THREADS, sk[0]->l, sk[0]->Bg_bit, vp[0]->k, vp[0]->N);
  TLWE * tmp = tlwe_alloc_sample_array(NUM_THREADS, stream[0]->n);
  // threads
  pthread_t threads[NUM_THREADS];
  cipher_args args[NUM_THREADS];
  for (size_t i = 0; i < NUM_THREADS; i++){
    args[i].vp = vp[i];
    args[i].lut = lut;
    args[i].tmp = &s2[i*F_SIZE];
    args[i].out = tmp[i];
  }
  
  // reset
  memcpy(s, sk, sizeof(TRGSW_DFT)*2048);
  __glb_rnd_idx = 0;
  // stream
  for (size_t j = 0; j < output_size; j++){
    // sample
    for (size_t i = 0; i < NUM_ROUNDS*F_SIZE; i++){
      const uint32_t r = rand_int(i, 2048, rnd_stream);
      TRGSW_DFT tmp2 = s[i];
      s[i] = s[r];
      s[r] = tmp2;
    }
    tlwe_noiseless_trivial_sample(stream[j], 0);
    // whitening and filter
    for (size_t i = 0; i < NUM_THREADS; i++){
      args[i].input = &s[i*F_SIZE*luts_per_thread];
      args[i].size = luts_per_thread;
      if((i == NUM_THREADS - 1) && NUM_ROUNDS%NUM_THREADS) {
        args[i].size = NUM_ROUNDS%NUM_THREADS;
      }
      for (size_t k = 0; k < luts_per_thread && i*luts_per_thread + k < NUM_ROUNDS; k++){
        args[i].w[k] = rand_int2(F_SIZE, rnd_stream);
      }
      pthread_create(&threads[i], NULL, *filter_thread, (void *) &(args[i]));
    }
    for (size_t i = 0; i < NUM_THREADS; i++){
      pthread_join(threads[i], NULL);
      tlwe_addto(stream[j], tmp[i]);
    }
  }
  free_tlwe_array(tmp, NUM_THREADS);
}