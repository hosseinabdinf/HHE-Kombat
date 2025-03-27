#include <cipher.h>

static TRGSW_DFT one_trgsw_dft = NULL;
void f2_setup_constants(uint64_t k, uint64_t N, uint64_t l, uint64_t Bg_bit){
  TRGSW tmp = trgsw_new_noiseless_trivial_sample(1, l, Bg_bit, k, N);
  one_trgsw_dft = trgsw_alloc_new_DFT_sample(l, Bg_bit, k, N);
  trgsw_to_DFT(one_trgsw_dft, tmp);
  free_trgsw(tmp);
}


// void trgsw_xor(TRGSW_DFT out, TRGSW_DFT A, TRGSW_DFT B){
//   assert(out != A); assert(out != B);
//   // A (1 - B) + B (1 - A) --> A + B - 2AB
//   trgsw_mul_DFT2(out, A, B); // AB
//   trgsw_DFT_add(out, out, out); // 2AB
//   trgsw_DFT_sub(out, A, out); // A - 2AB
//   trgsw_DFT_add(out, B, out); // A + B - 2AB
// }

void trgsw_xor(TRGSW_DFT out, TRGSW_DFT A, TRGSW_DFT B){
  assert(out != A); assert(out != B);
  // A (1 - B) + B (1 - A) --> A + B - 2AB --> A(1 - 2B) + B
  trgsw_DFT_add(out, B, B); // 2B
  trgsw_DFT_sub(out, one_trgsw_dft, out); // 1 - 2B
  trgsw_mul_DFT2(out, out, A); // A(1 - 2B)
  trgsw_DFT_add(out, out, B); // A(1 - 2B) + B
}


void trgsw_xor2(TRGSW_DFT out, TRGSW_DFT A, TRGSW_DFT B, TRGSW_DFT AB){
  assert(out != A); assert(out != B);
  // A (1 - B) + B (1 - A) --> A + B - 2AB
  trgsw_DFT_add(out, AB, AB); // 2AB
  trgsw_DFT_sub(out, A, out); // A - 2AB
  trgsw_DFT_add(out, B, out); // A + B - 2AB
}


void trgsw_xor_cleartext(TRGSW_DFT out, TRGSW_DFT A, uint8_t B){
  if(B == 1){
    trgsw_DFT_sub(out, one_trgsw_dft, A);
  }else{
    trgsw_DFT_copy(out, A);
  }
}

uint64_t __debug_decrypt_bits(TRGSW_DFT * c, uint64_t size);

void trgsw_xor_cleartext_array(TRGSW_DFT * out, TRGSW_DFT * A, uint32_t b, uint64_t size){
  // const uint64_t a =  __debug_decrypt_bits(A, F_SIZE);
  for (size_t i = 0; i < size; i++){
    const uint64_t b_bit = (b>>i)&1;
    if(b_bit == 1){
      trgsw_DFT_sub(out[i], one_trgsw_dft, A[i]);
    }else{
      trgsw_DFT_copy(out[i], A[i]);
    }
  }
  // const uint64_t out_b =  __debug_decrypt_bits(out, F_SIZE);
  // printf("A: %lx b: %x = %lx \n", a, b, out_b);
  // assert(a^b == out_b);
}

void trgsw_bits_to_Zq_lwe(TLWE out, TRGSW_DFT * in, uint32_t prec,  uint32_t size, VPEval vp){
  trlwe_noiseless_trivial_sample(vp->lut_buffer[0], 0);
  for (size_t i = 0; i < 1ULL<<size; i++){
    vp->lut_buffer[0]->b->coeffs[i] = int2torus(i, prec);
  }
  blind_rotate_vp(vp->lut_buffer[0], in, size, vp);
  trlwe_extract_tlwe(out, vp->lut_buffer[0], 0);
}

void trgsw_bits_to_Zq_lwe_addto(TLWE out, TRGSW_DFT * in, uint32_t prec,  uint32_t size, VPEval vp){
  trlwe_noiseless_trivial_sample(vp->lut_buffer[0], 0);
  for (size_t i = 0; i < 1ULL<<size; i++){
    vp->lut_buffer[0]->b->coeffs[i] = int2torus(i, prec);
  }
  blind_rotate_vp(vp->lut_buffer[0], in, size, vp);
  trlwe_extract_tlwe_addto(out, vp->lut_buffer[0], 0);
}
