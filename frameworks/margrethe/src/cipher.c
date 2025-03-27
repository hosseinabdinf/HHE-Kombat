#include <cipher.h>

uint64_t __glb_rnd_idx = 0;

void shake256(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);

uint32_t * gen_rnd_stream(const uint8_t * seed){
  uint32_t * res = (uint32_t *) safe_malloc(sizeof(uint32_t)*25000);
  shake256((uint8_t *) res, 100000, seed, 32);
  // printf("rnd:");
  // for (size_t i = 0; i < 20; i++){
  //   printf("%d, ", ((uint8_t *) res)[i]);
  // }
  // printf("\n");
  return res;
}

// returns an integer in [a, b)
uint32_t rand_int(uint32_t a, uint32_t b, uint32_t * rnd_stream){
  const uint64_t b_a = b - a, rnd = rnd_stream[__glb_rnd_idx];
  __glb_rnd_idx++;
  const uint32_t rnd32 = ((rnd*b_a)>>32);
  return a + rnd32;
}

// returns an integer in [0,2^b))
uint32_t rand_int2(uint32_t b, uint32_t * rnd_stream){
  const uint32_t rnd = rnd_stream[__glb_rnd_idx]>>(32-b);
  __glb_rnd_idx++;
  return rnd;
}

void key_mixing(TRGSW_DFT * out, TRGSW_DFT * client1_key, TRGSW_DFT * client2_key){
  for (size_t i = 0; i < 2048; i++){
    trgsw_xor(out[i], client1_key[i], client2_key[i]);
  }
  // mod red
  TRGSW tmp = trgsw_alloc_new_sample(out[0]->l, out[0]->Bg_bit, out[0]->samples[0]->k, out[0]->samples[0]->b->N);
  for (size_t i = 0; i < 2048; i++){
    trgsw_from_DFT(tmp, out[i]);
    trgsw_to_DFT(out[i], tmp);
  }
  free_trgsw(tmp);
}

TRGSW_DFT * encrypt_key(const uint8_t * s, TRGSW_Key key){
  TRGSW tmp = trgsw_alloc_new_sample(key->l, key->Bg_bit, 1, key->trlwe_key->s[0]->N);
  TRGSW_DFT * res = trgsw_alloc_new_DFT_sample_array(2048, key->l, key->Bg_bit, 1, key->trlwe_key->s[0]->N);
  for (size_t i = 0; i < 2048; i++){
    trgsw_monomial_sample(tmp, s[i], 0, key);
    trgsw_to_DFT(res[i], tmp);
  }
  free_trgsw(tmp);
  return res;
}

TLWE_Key __debug_tlwe_exct_key;
void __debug_decrypt_and_print_bits(char * mask, TRGSW_DFT * c, uint64_t size){
  TLWE tmp = tlwe_alloc_sample(__debug_tlwe_exct_key->n);
  TRLWE tmp2 = trlwe_alloc_new_sample(1, __debug_tlwe_exct_key->n);
  uint64_t res = 0;
  for (size_t i = 0; i < size; i++){
    trlwe_from_DFT(tmp2, c[i]->samples[c[i]->l]);
    trlwe_extract_tlwe(tmp, tmp2, 0);
    const uint64_t bit = torus2int(tlwe_phase(tmp, __debug_tlwe_exct_key), c[i]->Bg_bit);
    if(bit > 0) res |= (1<<i);
  }
  printf(mask, res);
  free_trlwe(tmp2);
  free_tlwe(tmp);
}

uint64_t __debug_decrypt_bits(TRGSW_DFT * c, uint64_t size){
  TLWE tmp = tlwe_alloc_sample(__debug_tlwe_exct_key->n);
  TRLWE tmp2 = trlwe_alloc_new_sample(1, __debug_tlwe_exct_key->n);
  uint64_t res = 0;
  for (size_t i = 0; i < size; i++){
    trlwe_from_DFT(tmp2, c[i]->samples[c[i]->l]);
    trlwe_extract_tlwe(tmp, tmp2, 0);
    const uint64_t bit = torus2int(tlwe_phase(tmp, __debug_tlwe_exct_key), c[i]->Bg_bit);
    if(bit > 0) res |= (1<<i);
  }
  free_trlwe(tmp2);
  free_tlwe(tmp);
  return res;
}

void stream_cipher(TLWE * stream, TRGSW_DFT sk[2048], TRLWE * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval vp){
  TRGSW_DFT s[2048], * s2 = trgsw_alloc_new_DFT_sample_array(F_SIZE, sk[0]->l, sk[0]->Bg_bit, vp->k, vp->N);
  TLWE tmp = tlwe_alloc_sample(stream[0]->n);
  // reset
  memcpy(s, sk, sizeof(TRGSW_DFT)*2048);
  __glb_rnd_idx = 0;
  // stream
  for (size_t j = 0; j < output_size; j++){
    // sample
    for (size_t i = 0; i < NUM_ROUNDS*F_SIZE; i++){
      const uint32_t r = rand_int(i, 2048, rnd_stream);
      TRGSW_DFT tmp = s[i];
      s[i] = s[r];
      s[r] = tmp;
    }
    tlwe_noiseless_trivial_sample(stream[j], 0);
    // whitening and filter
    for (size_t i = 0; i < NUM_ROUNDS; i++){
      const uint32_t w = rand_int2(F_SIZE, rnd_stream);
      trgsw_xor_cleartext_array(s2, &s[i*F_SIZE], w, F_SIZE);
      vp_eval_LUT(tmp, s2, lut, vp);
      tlwe_addto(stream[j], tmp);
      trgsw_bits_to_Zq_lwe(tmp, &s2[LUT_SIZE], OUT_PREC,  ADD_SIZE, vp);
      tlwe_addto(stream[j], tmp);
    }
  }
  free_tlwe(tmp);
}

void stream_cipher2(TLWE * stream, TRGSW_DFT sk[2048], DFT_Polynomial * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval vp){
  TRGSW_DFT s[2048], * s2 = trgsw_alloc_new_DFT_sample_array(F_SIZE, sk[0]->l, sk[0]->Bg_bit, vp->k, vp->N);
  TLWE tmp = tlwe_alloc_sample(stream[0]->n);
  // reset
  memcpy(s, sk, sizeof(TRGSW_DFT)*2048);
  __glb_rnd_idx = 0;
  // stream
  for (size_t j = 0; j < output_size; j++){
    // sample
    for (size_t i = 0; i < NUM_ROUNDS*F_SIZE; i++){
      const uint32_t r = rand_int(i, 2048, rnd_stream);
      TRGSW_DFT tmp = s[i];
      s[i] = s[r];
      s[r] = tmp;
    }
    tlwe_noiseless_trivial_sample(stream[j], 0);
    // whitening and filter
    for (size_t i = 0; i < NUM_ROUNDS; i++){
      const uint32_t w = rand_int2(F_SIZE, rnd_stream);
      trgsw_xor_cleartext_array(s2, &s[i*F_SIZE], w, F_SIZE);
      vp_eval_LUT2(tmp, s2, lut, vp);
      trgsw_bits_to_Zq_lwe_addto(tmp, &s2[LUT_SIZE], OUT_PREC,  ADD_SIZE, vp);
      tlwe_addto(stream[j], tmp);
    }
  }
  free_tlwe(tmp);
}
