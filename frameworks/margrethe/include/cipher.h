#include <mosfhet.h>
#include <vertical_packing.h>
#include <pthread.h>

#define LUT_SIZE 18
#define ADD_SIZE 4
#define F_SIZE (LUT_SIZE+ADD_SIZE)
#define NUM_ROUNDS 14
#define OUT_PREC 4
#define OUT_SIZE 32

uint32_t * gen_rnd_stream(const uint8_t * seed);
void f2_setup_constants(uint64_t k, uint64_t N, uint64_t l, uint64_t Bg_bit);
void trgsw_xor_cleartext_array(TRGSW_DFT * out, TRGSW_DFT * A, uint32_t b, uint64_t size);
void trgsw_bits_to_Zq_lwe(TLWE out, TRGSW_DFT * in, uint32_t prec,  uint32_t size, VPEval vp);
void trgsw_bits_to_Zq_lwe_addto(TLWE out, TRGSW_DFT * in, uint32_t prec,  uint32_t size, VPEval vp);
TRGSW_DFT * encrypt_key(const uint8_t * s, TRGSW_Key key);
void stream_cipher(TLWE * stream, TRGSW_DFT sk[2048], TRLWE * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval vp);
void stream_cipher2(TLWE * stream, TRGSW_DFT sk[2048], DFT_Polynomial * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval vp);

void stream_cipher_mt(TLWE * stream, TRGSW_DFT sk[2048], DFT_Polynomial * lut, uint32_t * rnd_stream, uint64_t output_size, VPEval * vp);
uint32_t rand_int(uint32_t a, uint32_t b, uint32_t * rnd_stream);
uint32_t rand_int2(uint32_t b, uint32_t * rnd_stream);

void trgsw_xor(TRGSW_DFT out, TRGSW_DFT A, TRGSW_DFT B);
void key_mixing(TRGSW_DFT * out, TRGSW_DFT * client1_key, TRGSW_DFT * client2_key);

