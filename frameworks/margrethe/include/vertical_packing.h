#include <mosfhet.h>

typedef struct {
  uint64_t N, k, log_N, size, n_luts;
  TRLWE_DFT tmp_dft;
  TRLWE tmp, * lut_buffer;
  TorusPolynomial tmp_poly;
  DFT_Polynomial tmp_poly_DFT;
} * VPEval;

VPEval new_vp_evaluator(uint64_t N, uint64_t k, uint64_t size);
TRLWE * vp_create_LUT(uint64_t * LUT, uint32_t precision, VPEval vp);
DFT_Polynomial * vp_create_LUT2(uint64_t * LUT, uint32_t precision, VPEval vp, uint64_t Bg_bit);
void blind_rotate_vp(TRLWE tv, TRGSW_DFT * s, uint64_t size, VPEval vp);
void vp_eval_LUT(TLWE output, TRGSW_DFT * input, TRLWE * LUT_in, VPEval vp);
void vp_eval_LUT2(TLWE output, TRGSW_DFT * input, DFT_Polynomial * LUT_in, VPEval vp);
void vp_eval_LUT2_addto(TLWE output, TRGSW_DFT * input, DFT_Polynomial * LUT_in, VPEval vp);
VPEval * new_vp_evaluator_array(uint64_t count, uint64_t N, uint64_t k, uint64_t size);