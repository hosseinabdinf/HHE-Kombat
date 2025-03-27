#include <vertical_packing.h>

VPEval new_vp_evaluator(uint64_t N, uint64_t k, uint64_t size){
  VPEval res = (VPEval) safe_malloc(sizeof(*res));
  res->N = N;
  res->k = k;
  res->log_N = (uint64_t) log2(N);
  res->n_luts = 1ULL << (size - res->log_N);
  res->size = size;
  res->lut_buffer = trlwe_alloc_new_sample_array(res->n_luts/2, 1, N);
  res->tmp_dft = trlwe_alloc_new_DFT_sample(k, N);
  res->tmp = trlwe_alloc_new_sample(k, N);
  res->tmp_poly = polynomial_new_torus_polynomial(N);
  res->tmp_poly_DFT = polynomial_new_DFT_polynomial(N);
  return res;
}

VPEval copy_vc_evaluator(VPEval vp){
  return new_vp_evaluator(vp->N, vp->k, vp->size);
}

VPEval * new_vp_evaluator_array(uint64_t count, uint64_t N, uint64_t k, uint64_t size){
  VPEval * res = (VPEval *) safe_malloc(count*sizeof(VPEval));
  res[0] = new_vp_evaluator(N, k, size);
  for (size_t i = 1; i < count; i++){
    res[i] = copy_vc_evaluator(res[0]);
  }
  return res;
}



TRLWE * vp_create_LUT(uint64_t * LUT, uint32_t precision, VPEval vp){
  const uint64_t n_luts = vp->n_luts;
  TRLWE * res = trlwe_alloc_new_sample_array(n_luts, vp->k, vp->N);
  for (size_t i = 0; i < n_luts; i++){
    trlwe_noiseless_trivial_sample(res[i], 0);
    for (size_t j = 0; j < vp->N; j++) res[i]->b->coeffs[j] += int2torus(LUT[i*vp->N + j], precision);
  }
  return res;
}

DFT_Polynomial * vp_create_LUT2(uint64_t * LUT, uint32_t precision, VPEval vp, uint64_t Bg_bit){
  const uint64_t n_luts = vp->n_luts;
  DFT_Polynomial * res = polynomial_new_array_of_polynomials_DFT(vp->N, n_luts);
  for (size_t i = 0; i < n_luts; i++){
    for (size_t j = 0; j < vp->N; j++) vp->tmp_poly->coeffs[j] = LUT[i*vp->N + j] << (Bg_bit - precision);
    polynomial_torus_to_DFT(res[i], vp->tmp_poly);
  }
  return res;
}

void CMUX(TRLWE out, TRLWE in1, TRLWE in2, TRGSW_DFT selector, VPEval vp){
  trlwe_sub(vp->tmp, in2, in1); // B - A
  trgsw_mul_trlwe_DFT(vp->tmp_dft, vp->tmp, selector);  // S(B - A)
  trlwe_from_DFT(vp->tmp, vp->tmp_dft); 
  trlwe_add(out, vp->tmp, in1); // S(B - A) + A 
}

void CMUX_ct(TRLWE out, DFT_Polynomial in1, DFT_Polynomial in2, TRGSW_DFT selector, VPEval vp){
  assert(selector->l == 1);
  polynomial_sub_DFT_polynomials(vp->tmp_poly_DFT, in2, in1); // B - A
  trlwe_DFT_mul_by_polynomial(vp->tmp_dft, selector->samples[selector->l], vp->tmp_poly_DFT); // S(B - A)
  polynomial_scale_and_add_DFT_polynomials(vp->tmp_dft->b, vp->tmp_dft->b, in1, 1ULL << (64 - selector->Bg_bit)); // S(B - A) + A 
  trlwe_from_DFT(out, vp->tmp_dft);
}

// blind rotate for the vertical packing
// rotates in powers of two
void blind_rotate_vp(TRLWE tv, TRGSW_DFT * s, uint64_t size, VPEval vp){
  const int N2 = vp->N<<1;
  for (size_t i = 0; i < size; i++){
    const int a_i = N2 - (1ULL << i);
    trlwe_mul_by_xai_minus_1(vp->tmp, tv, a_i);
    trgsw_mul_trlwe_DFT(vp->tmp_dft, vp->tmp, s[i]);
    trlwe_from_DFT(vp->tmp, vp->tmp_dft);
    trlwe_addto(tv, vp->tmp);
  }
}


void vp_eval_LUT2_wo_extract(TRGSW_DFT * input, DFT_Polynomial * LUT_in, VPEval vp){
  const uint32_t log_N = vp->log_N, size = vp->size;  
  // vertical packing
  if(size > log_N){
    for (size_t i = 0; i < size - log_N; i++){
      const uint64_t N_luts_half = 1<<(size - log_N - i - 1);
      for (size_t j = 0; j < N_luts_half; j++){
        if(i == 0){
          CMUX_ct(vp->lut_buffer[j], LUT_in[j], LUT_in[j + N_luts_half], input[size - i - 1], vp);
        }else{
          CMUX(vp->lut_buffer[j], vp->lut_buffer[j], vp->lut_buffer[j + N_luts_half], input[size - i - 1], vp);
        }
      }
    }
  }
  // evaluate last log_2(N) bits using a blind rotate.
  const uint64_t size_br = vp->size > vp->log_N ? vp->log_N : vp->size;
  blind_rotate_vp(vp->lut_buffer[0], input, size_br, vp);
}

void vp_eval_LUT2(TLWE output, TRGSW_DFT * input, DFT_Polynomial * LUT_in, VPEval vp){
  vp_eval_LUT2_wo_extract(input, LUT_in, vp);
  trlwe_extract_tlwe(output, vp->lut_buffer[0], 0);
}

void vp_eval_LUT2_addto(TLWE output, TRGSW_DFT * input, DFT_Polynomial * LUT_in, VPEval vp){
  vp_eval_LUT2_wo_extract(input, LUT_in, vp);
  trlwe_extract_tlwe_addto(output, vp->lut_buffer[0], 0);
}

void vp_eval_LUT(TLWE output, TRGSW_DFT * input, TRLWE * LUT_in, VPEval vp){
  const uint32_t log_N = vp->log_N, size = vp->size;  
  // vertical packing
  if(size > log_N){
    for (size_t i = 0; i < size - log_N; i++){
      const uint64_t N_luts_half = 1<<(size - log_N - i - 1);
      for (size_t j = 0; j < N_luts_half; j++){
        if(i == 0){
          CMUX(vp->lut_buffer[j], LUT_in[j], LUT_in[j + N_luts_half], input[size - i - 1], vp);
        }else{
          CMUX(vp->lut_buffer[j], vp->lut_buffer[j], vp->lut_buffer[j + N_luts_half], input[size - i - 1], vp);
        }
      }
    }
  }
  // evaluate last log_2(N) bits using a blind rotate.
  const uint64_t size_br = vp->size > vp->log_N ? vp->log_N : vp->size;
  blind_rotate_vp(vp->lut_buffer[0], input, size_br, vp);
  trlwe_extract_tlwe(output, vp->lut_buffer[0], 0);
}