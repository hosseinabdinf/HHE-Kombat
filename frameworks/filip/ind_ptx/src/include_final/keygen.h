#ifndef KEYGEN
#define KEYGEN

#include <NTL/mat_ZZ.h>
#include <vector>
#include <fftw3.h>
#include <complex>
#include "params.h"
#include "sampler.h"

// secret key of the bootstrapping scheme
typedef struct {
    ModQPoly sk;
    ModQPoly sk_inv;
} SKey_boot;

// secret key of the NTRU base scheme
typedef struct {
    ModQMatrix sk;
    ModQMatrix sk_inv;
} SKey_base_NTRU;

// secret key of the LWE base scheme
typedef std::vector<int> SKey_base_LWE;

/** 
 * Bootstrapping key.
 * It consists of several sets of keys corresponding to different
 * decomposition bases of the bootstrapping key B_bsk.
 * The i-th set contains vectors with l_bsk[i] complex vectors.
 * These complex vectors are an encryption of some bit of the secret key
 * of the base scheme in the NGS form.
 */
typedef std::vector<std::vector<std::vector<NGSFFTctxt>>> BSKey_NTRU;

/** 
 * Bootstrapping key.
 * It consists of several sets of keys corresponding to different
 * decomposition bases of the bootstrapping key B_bsk.
 * The i-th set contains vectors with l_bsk[i] complex vectors.
 * These complex vectors are an encryption of some bit of the secret key
 * of the base scheme in the NGS form.
 */
typedef std::vector<std::vector<NGSFFTctxt>> BSKey_LWE;

// key-switching key from NTRU to NTRU
typedef ModQMatrix KSKey_NTRU;

// key-switching key from NTRU to LWE
typedef struct{
    ModQMatrix A;
    std::vector<int> b;
}  KSKey_LWE;


class KeyGen
{
    Param param;
    Sampler sampler;

    public:

        KeyGen(Param _param): param(_param), sampler(_param)
        {}

        /**
         * Generate a secret key of the bootstrapping scheme. 
         * @param[out] sk_boot secret key of the bootstrapping scheme.
         */
        void get_sk_boot(SKey_boot& sk_boot);

        /**
         * Generate a secret key of the base scheme. 
         * @param[out] sk_base secret key of the base scheme.
         */
        void get_sk_base(SKey_base_NTRU& sk_base);

        /**
         * Generate a secret key of the base scheme. 
         * @param[out] sk_base secret key of the base scheme.
         */
        void get_sk_base(SKey_base_LWE& sk_base);

        /**
         * Generate a key-switching key from the bootstrapping scheme to the base scheme. 
         * @param[out] ksk key-switching key.
         * @param[in] sk_base secret key of the base scheme.
         * @param[in] sk_boot secret key of the bootstrapping scheme.
         */
        void get_ksk(KSKey_NTRU& ksk, const SKey_base_NTRU& sk_base, const SKey_boot& sk_boot);

        /**
         * Generate a key-switching key from the bootstrapping scheme to the base scheme. 
         * @param[out] ksk key-switching key.
         * @param[in] sk_base secret key of the base scheme.
         * @param[in] sk_boot secret key of the bootstrapping scheme.
         */
        void get_ksk(KSKey_LWE& ksk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot);

        /**
         * Generate a bootstrapping key
         * @param[out] bsk bootstrapping key.
         * @param[in] sk_base secret key of the base scheme.
         * @param[in] sk_boot secret key of the bootstrapping scheme.
         */
        void get_bsk(BSKey_NTRU& bsk, const SKey_base_NTRU& sk_base, const SKey_boot& sk_boot);

        /**
         * Generate a bootstrapping key
         * @param[out] bsk bootstrapping key.
         * @param[in] sk_base secret key of the base scheme.
         * @param[in] sk_boot secret key of the bootstrapping scheme.
         */
        void get_bsk(BSKey_LWE& bsk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot);

        /**
         * Generate a bootstrapping key (EXPERIMENTAL)
         * @param[out] bsk bootstrapping key.
         * @param[in] sk_base secret key of the base scheme.
         * @param[in] sk_boot secret key of the bootstrapping scheme.
         */
        void get_bsk2(BSKey_LWE& bsk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot);
};

/**
* Encrypts a polynomial into a vector ciphertext under the NTRU problem.
* @param[out] ct ciphertext encrypting the input
* @param[in] m polynomial to encrypt
* @param[in] l dimension of the vector ciphertext
* @param[in] B base used in the gadget vector
* @param[in] sk_boot contains f and f^-1
**/ 
void enc_ngs(NGSFFTctxt& ct, const ModQPoly& m, int l, int B, const SKey_boot& sk_boot);

/**
* Encrypts an integer into a vector ciphertext under the NTRU problem.
* @param[out] ct ciphertext encrypting the input
* @param[in] m integer to encrypt (it is treated as a degree-0 polynomial)
* @param[in] l dimension of the vector ciphertext
* @param[in] B base used in the gadget vector
* @param[in] sk_boot contains f and f^-1
**/ 
void enc_ngs(NGSFFTctxt& ct, int m, int l, int B, const SKey_boot& sk_boot);



/**
* Encrypts an integer into a scalar NTRU ciphertext (a polynomial)
* @param[out] ct ciphertext encrypting the input
* @param[in] m integer to encrypt (it is treated as a degree-0 polynomial)
* @param[in] sk_boot contains f and f^-1
* @param[in] p plaintext space is Z_p (integers modulo p)
**/ 
void enc_scalar_ctxt(ModQPoly& ct, int m, const SKey_boot& sk_boot);

/**
* Encrypts a polynomial into a scalar NTRU ciphertext (a polynomial)
* @param[out] ct ciphertext encrypting the input
* @param[in] m polynomial to encrypt
* @param[in] sk_boot contains f and f^-1
* @param[in] p plaintext space is Z_p (integers modulo p)
**/ 
void enc_scalar_ctxt(ModQPoly& ct, const ModQPoly& m, const SKey_boot& sk_boot);


/**
* Decrypts a scalar NTRU ciphertext into a polynomial modulo Param::p
* @param[in] ct ciphertext encrypting the message
* @param[in] sk_boot contains f and f^-1
**/ 
void dec_scalar_ctxt(ModQPoly &msg, const ModQPoly& ct, const SKey_boot& sk_boot);


/**
* Decrypts a scalar NTRU ciphertext into a polynomial modulo Param::p
* @param[in] ct ciphertext encrypting the message in the constant term
* @param[in] sk_boot contains f and f^-1
**/
int dec_scalar_ctxt_int(const ModQPoly& ct, const SKey_boot& sk_boot);

/**
* Multiplies a scalar ciphertext ct by an integer u.
* @param[out] ct ciphertext encrypting a message m. At the end, it encrypts m*u mod p
* @param[in] u integer that is multiplied by the ciphertext
**/ 
void mult_ctxt_by_int(ModQPoly& ct, int u);

/**
* Multiplies a scalar ciphertext ct by a polynomial u.
* @param[out] ct ciphertext encrypting a message m. At the end, it encrypts m*u mod p
* @param[in] u polynomial that is multiplied by the ciphertext
**/ 
void mult_ctxt_by_poly(ModQPoly& ct, const ModQPoly& u);

/**
* Multiplies a vector ciphertext ct by a polynomial u.
* @param[out] ct ciphertext encrypting a message m. At the end, it encrypts m*u mod p
* @param[in] u polynomial that is multiplied by the ciphertext
**/ 
void mult_ctxt_by_poly(NGSFFTctxt& ct, const ModQPoly& u);


/**
* Computes ct0 += ct1
* @param[in,out] ct0 ciphertext encrypting a message m0. At the end, it encrypts m0+m1 mod p
* @param[in] ct1 ciphertext encrypting a message m1
**/ 
void add_scalar_ctxt(ModQPoly& ct0, const ModQPoly& ct1);

void sub_scalar_ctxt(ModQPoly& ct0, const ModQPoly& ct1);


/**
* Compute (NGS) vector encryption of 1 - m
* @param[out] c_not ciphertext encrypting 1 - m
* @param[in] c vector ciphertext encrypting a message m
**/ 
void negate_vector_ctxt(NGSFFTctxt& c_not, const NGSFFTctxt& c);

/**
* Decrypts a vector NTRU ciphertext into a polynomial modulo Param::p
* @param[in] ct ciphertext encrypting the message
* @param[in] sk_boot contains f and f^-1
**/ 
void dec_vector_ctxt(ModQPoly &msg, const NGSFFTctxt& ct, const SKey_boot& sk_boot);

/**
* Decrypts a scalar NTRU ciphertext into a polynomial modulo Param::p
* @param[in] ct ciphertext encrypting the message in the constant term
* @param[in] sk_boot contains f and f^-1
**/
int dec_vector_ctxt_int(const NGSFFTctxt& ct, const SKey_boot& sk_boot);


/**
* Homomorphically adds one to ct0
* @param[in,out] ct0 scalar ciphertext encrypting a message m0. At the end, it encrypts m0+1 mod p
**/ 
void add_one_to_scalar_ctxt(ModQPoly& ct0);

/**
* Homomorphically adds one to ct0
* @param[in,out] ct0 scalar ciphertext encrypting a message m0. At the end, 
* it encrypts m0+1 mod p
**/ 
void add_one_to_veector_ctxt(NGSFFTctxt& ct0);


/**
* Computes (homomorphically) the XOR of two bits considering that the message space is modulo p
* @param[in,out] ct0 scalar ciphertext encrypting a message m0 mod p. At the end, it encrypts XOR(m0, m1)
* @param[in] ct1 a NGS vector ciphertext encrypting a message m1.
**/ 
void xor_mod_p(ModQPoly& ct0, const NGSFFTctxt& ct1);

/**
* Computes (homomorphically) the XOR of two bits considering that the message space is modulo p.
* This function is more general that the other xor_mod_p because the messages can be scaled,
* that is, ct0 and ct2 can encrypt bits multiplied by some polynomial u.
* This is useful when we want to set u as the "test polynomial".
*
* @param[in,out] ct0 scalar ciphertext encrypting a message u*m0 mod p,
* where u is a polynomial and m0 is a bit. At the end, it encrypts u*XOR(m0, m1)
* @param[in] ct1 a NGS vector ciphertext encrypting a bit m1.
* @param[in] ct2 a scalar ciphertext encrypting u*m1, where m1 is the same bit 
* encrypted by ct1 and u is the same polynomial used by ct0.
**/ 
void xor_mod_p(ModQPoly& ct0, const NGSFFTctxt& ct1, const ModQPoly& ct2);

/**
* Returns a scalar ciphertext encrypting X^b where b is the bit encrypted by the input
* @param[in] ct scalar ciphertext encrypting a *bit* b (modulo mod p)
**/ 
ModQPoly lift_to_exponent(const ModQPoly& ct);

/**
* Returns a scalar ciphertext encrypting u*X^b mod p where b is the bit encrypted by the input
* @param[in] ct scalar ciphertext encrypting u*b mod p, where b is a bit
* @param[in] u a polynomial modulo mod p
**/ 
ModQPoly lift_to_exponent_scaled(const ModQPoly& c, const ModQPoly& u);

double noise_scalar_ctxt(const ModQPoly &msg, const ModQPoly& ct, const SKey_boot& sk_boot);

double noise_scalar_ctxt(int msg, const ModQPoly& ct, const SKey_boot& sk_boot);


/**
* Takes a vector encryption of a bit b and produces a vector encryption of
* X^(2*b) mod X^N + 1
* @param[in, out] at the end, ct_X_2b = vec encryption of X^(2*b)
* @param[in] vector encryption of b in {0, 1}
**/ 
void map_enc_b_to_enc_X_2b(NGSFFTctxt& ct_X_2b, const NGSFFTctxt& ct_bit);





#endif
