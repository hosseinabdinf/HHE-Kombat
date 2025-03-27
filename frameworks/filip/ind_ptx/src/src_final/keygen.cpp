#include "keygen.h"
#include "params.h"
#include "lwehe.h"
#include "fft.h"

#include<iostream>
#include<time.h>
#include<algorithm>

using namespace NTL;
using namespace std;

void KeyGen::get_sk_boot(SKey_boot& sk_boot)
{
    cout << "Started generating the secret key of the bootstrapping scheme" << endl;
    clock_t start = clock();
    sk_boot.sk = ModQPoly(Param::N,0);
    sk_boot.sk_inv = ModQPoly(Param::N,0);

    if (2 == Param::p)
        sampler.get_invertible_vector(sk_boot.sk, sk_boot.sk_inv, Param::t, 1L);
    else
        sampler.get_invertible_vector(sk_boot.sk, sk_boot.sk_inv, Param::p, 1L);
    cout << "Generation time of the secret key of the bootstrapping scheme: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_sk_base(SKey_base_NTRU& sk_base)
{
    cout << "Started generating the secret key of the base scheme" << endl;
    clock_t start = clock();
    sk_base.sk = ModQMatrix(param.n, vector<int>(param.n,0L));
    sk_base.sk_inv = ModQMatrix(param.n, vector<int>(param.n,0L));

    sampler.get_invertible_matrix(sk_base.sk, sk_base.sk_inv, 1L, 0L);
    cout << "Generation time of the secret key of the base scheme: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_sk_base(SKey_base_LWE& sk_base)
{
    cout << "Started generating the secret key of the base scheme" << endl;
    clock_t start = clock();
    sk_base.clear();
    sk_base = vector<int>(param.n,0L);

    sampler.get_binary_vector(sk_base);
    cout << "Generation time of the secret key of the base scheme: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_ksk(KSKey_NTRU& ksk, const SKey_base_NTRU& sk_base, const SKey_boot& sk_boot)
{
    //cout << "Started key-switching key generation" << endl;
    clock_t start = clock();
    // reset key-switching key
    ksk.clear();
    ksk = ModQMatrix(param.Nl, vector<int>(param.n,0));
    vector<vector<long>> ksk_long(param.Nl, vector<long>(param.n,0L));
    //cout << "Reset time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;

    // noise matrix G as in the paper
    ModQMatrix G(param.Nl, vector<int>(param.n,0L));
    sampler.get_ternary_matrix(G);
    //cout << "G gen time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
    
    // matrix G + P * Phi(f) * E as in the paper
    int coef_w_pwr = sk_boot.sk[0];
    for (int i = 0; i < param.l_ksk; i++)
    {
        G[i][0] += coef_w_pwr;
        coef_w_pwr *= Param::B_ksk;
    }
    for (int i = 1; i < Param::N; i++)
    {
        coef_w_pwr = -sk_boot.sk[Param::N-i];
        for (int j = 0; j < param.l_ksk; j++)
        {
            G[i*param.l_ksk+j][0] += coef_w_pwr;
            coef_w_pwr *= Param::B_ksk;
        }
    }
    //cout << "G+P time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;

    // parameters of the block optimization of matrix multiplication
    int block = 4;
    int blocks = (param.n/block)*block;
    int rem_block = param.n%block;
    // (G + P * Phi(f) * E) * F^(-1) as in the paper
    for (int i = 0; i < param.Nl; i++)
    {
        //cout << "i: " << i << endl;
        vector<long>& k_row = ksk_long[i];
        vector<int>& g_row = G[i];
        for (int k = 0; k < param.n; k++)
        {
            const vector<int>& f_row = sk_base.sk_inv[k];
            //cout << "j: " << j << endl;
            long coef = long(g_row[k]);
            for (int j = 0; j < blocks; j+=block)
            {
                k_row[j] += (coef * f_row[j]);
                k_row[j+1] += (coef * f_row[j+1]);
                k_row[j+2] += (coef * f_row[j+2]);
                k_row[j+3] += (coef * f_row[j+3]);
            }
            for (int j = 0; j < rem_block; j++)
                k_row[blocks+j] += (coef * f_row[blocks+j]);
        }
    }
    //cout << "After K time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;

    // reduce modulo q_base
    for (int i = 0; i < param.Nl; i++)
        param.mod_q_base(ksk[i], ksk_long[i]);
    cout << "KSKey-gen time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_ksk(KSKey_LWE& ksk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot)
{
    //cout << "Started key-switching key generation" << endl;
    clock_t start = clock();
    // reset key-switching key
    ksk.A.clear();
    ksk.b.clear();
    for (int i = 0; i < param.Nl; i++)
    {
        vector<int> row(param.n,0L);
        ksk.A.push_back(row);
    }
    ksk.b = vector<int>(param.Nl, 0L);
    //cout << "Reset time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;

    // noise matrix G as in the paper
    sampler.get_uniform_matrix(ksk.A);
    //cout << "A gen time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
    
    // matrix P * f_0 as in the paper
    vector<int> Pf0(param.Nl, 0L);
    int coef_w_pwr = sk_boot.sk[0];
    for (int i = 0; i < param.l_ksk; i++)
    {
        Pf0[i] += coef_w_pwr;
        coef_w_pwr *= Param::B_ksk;
    }
    for (int i = 1; i < Param::N; i++)
    {
        coef_w_pwr = -sk_boot.sk[Param::N-i];
        for (int j = 0; j < param.l_ksk; j++)
        {
            Pf0[i*param.l_ksk+j] += coef_w_pwr;
            coef_w_pwr *= Param::B_ksk;
        }
    }
    //cout << "Pf0 time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;

    // A*s_base + e + Pf0 as in the paper
    normal_distribution<double> gaussian_sampler(0.0, Param::e_st_dev);
    for (int i = 0; i < param.Nl; i++)
    {
        //cout << "i: " << i << endl;
        vector<int>& k_row = ksk.A[i];
        for (int k = 0; k < param.n; k++)
            ksk.b[i] -= k_row[k] * sk_base[k];
        ksk.b[i] += (Pf0[i] + static_cast<int>(round(gaussian_sampler(rand_engine))));
        param.mod_q_base(ksk.b[i]);
    }   
    cout << "KSKey-gen time: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_bsk(BSKey_NTRU& bsk, const SKey_base_NTRU& sk_base, const SKey_boot& sk_boot)
{
    clock_t start = clock();
    
    // index of a secret key coefficient of the base scheme
    int coef_counter = 0;

    // reset the input
    bsk.clear();

    // loop over different decomposition bases
    for (int iBase = 0; iBase < Param::B_bsk_size; iBase++)
    {
        vector<vector<NGSFFTctxt>> base_row;
        for (int iCoef = coef_counter; iCoef < coef_counter+param.bsk_partition[iBase]; iCoef++)
        {
            vector<NGSFFTctxt> coef_row;
            int sk_base_coef = sk_base.sk[iCoef][0];
            /** 
             * represent coefficient of the secret key 
             * of the base scheme using 2 bits.
             * The representation rule is as follows:
             * -1 => [0,1]
             * 0 => [0,0]
             * 1 => [1,0]
             * */
            int coef_bits[2] = {0,0};
            if (sk_base_coef == -1)
                coef_bits[1] = 1;
            else if (sk_base_coef == 1)
                coef_bits[0] = 1;
            // encrypt each bit using the NGS scheme
            for (int iBit = 0; iBit < 2; iBit++)
            {
                NGSFFTctxt bit_row;
                enc_ngs(bit_row, coef_bits[iBit], param.l_bsk[iBase], param.B_bsk[iBase], sk_boot);
                coef_row.push_back(bit_row);
            }
            base_row.push_back(coef_row);
        }
        bsk.push_back(base_row);
        coef_counter += param.bsk_partition[iBase];
    }    

    cout << "Bootstrapping key generation: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_bsk(BSKey_LWE& bsk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot)
{
    clock_t start = clock();
    
    // index of a secret key coefficient of the base scheme
    int coef_counter = 0;

    // reset the input
    bsk.clear();
    bsk = vector<vector<NGSFFTctxt>>(Param::B_bsk_size);
    for (int i = 0; i < Param::B_bsk_size; i++)
        bsk[i] = vector<NGSFFTctxt>(param.bsk_partition[i], NGSFFTctxt(param.l_bsk[i], FFTPoly(Param::N2p1)));
    
    // loop over different decomposition bases
    for (int iBase = 0; iBase < Param::B_bsk_size; iBase++)
    {
        vector<NGSFFTctxt> base_row(param.bsk_partition[iBase], NGSFFTctxt(param.l_bsk[iBase], FFTPoly(Param::N2p1)));
        for (int iCoef = coef_counter; iCoef < coef_counter+param.bsk_partition[iBase]; iCoef++)
        {
            NGSFFTctxt coef_row(param.l_bsk[iBase], FFTPoly(Param::N2p1));
            int sk_base_coef = sk_base[iCoef];
            
            // encrypt each bit using the NGS scheme
            enc_ngs(coef_row, sk_base_coef, param.l_bsk[iBase], param.B_bsk[iBase], sk_boot);
            base_row[iCoef-coef_counter] = coef_row;
        }
        bsk[iBase] = base_row;
        coef_counter += param.bsk_partition[iBase];
    }    

    cout << "Bootstrapping key generation: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void KeyGen::get_bsk2(BSKey_LWE& bsk, const SKey_base_LWE& sk_base, const SKey_boot& sk_boot)
{
    clock_t start = clock();
    
    // index of a secret key coefficient of the base scheme
    int coef_counter = 0;

    // reset the input
    bsk.clear();
    bsk = vector<vector<NGSFFTctxt>>(Param::B_bsk_size);
    for (int i = 0; i < Param::B_bsk_size; i++)
        bsk[i] = vector<NGSFFTctxt>(4 * (param.bsk_partition[i] >> 1), NGSFFTctxt(param.l_bsk[i], FFTPoly(Param::N2p1)));
    
    // loop over different decomposition bases
    int bits[4];
    for (int iBase = 0; iBase < Param::B_bsk_size; iBase++)
    {
        vector<NGSFFTctxt> base_row(4 * (param.bsk_partition[iBase] >> 1), NGSFFTctxt(param.l_bsk[iBase], FFTPoly(Param::N2p1)));
        for (int iCoef = coef_counter; iCoef < coef_counter+param.bsk_partition[iBase]; iCoef+=2)
        {
            NGSFFTctxt coef_row(param.l_bsk[iBase], FFTPoly(Param::N2p1));
            // bits to encrypt: s[coef]*s[coef+1], s[coef]*(1-s[coef+1]), (1-s[coef])*s[coef+1] 
            bits[0] = sk_base[iCoef]*sk_base[iCoef+1];
            bits[1] = sk_base[iCoef]*(1-sk_base[iCoef+1]);
            bits[2] = (1-sk_base[iCoef])*sk_base[iCoef+1];
            bits[3] = (1-sk_base[iCoef])*(1-sk_base[iCoef+1]);
            // encrypt each bit using the NGS scheme
            for (int iBit = 0; iBit < 4; iBit++)
            {
                enc_ngs(coef_row, bits[iBit], param.l_bsk[iBase], param.B_bsk[iBase], sk_boot);
                base_row[4*((iCoef-coef_counter) >> 1)+iBit] = coef_row;
            } 
        }
        bsk[iBase] = base_row;
        coef_counter += param.bsk_partition[iBase];
    }    

    cout << "Bootstrapping2 generation: " << float(clock()-start)/CLOCKS_PER_SEC << endl;
}

void enc_ngs(NGSFFTctxt& ct, int m, int l, int B, const SKey_boot& sk_boot)
{
    ModQPoly msg(Param::N,0L);
    msg[0] = m; // msg = m (degree-0 polynomial)
    enc_ngs(ct, msg, l, B, sk_boot);
}

void mult_poly_by_int(ModQPoly& a, const int b){
    for(int i = 0; i < a.size(); i++)
        a[i] *= b;
}

void enc_ngs(NGSFFTctxt& ct, const ModQPoly& m, int l, int B, const SKey_boot& sk_boot)
{
    if(ct.size() != l)
        ct = NGSFFTctxt(l);

    FFTPoly sk_boot_inv_fft(Param::N2p1); // f^-1 in FFT form
    fftN.to_fft(sk_boot_inv_fft, sk_boot.sk_inv);
    FFTPoly g_fft(Param::N2p1);
    ModQPoly msg(m); // at each iteration i, msg will be equal to m * B^i
    FFTPoly msg_fft(Param::N2p1);
    FFTPoly tmp_ct(Param::N2p1);
    vector<long> tmp_ct_long(Param::N);
    vector<int> tmp_ct_int(Param::N);

    int powerB = 1;

    for (int i = 0; i < l; i++)
    {
        // sample random ternary vector
        ModQPoly g(Param::N,0L);
        Sampler::get_ternary_vector(g);
        // FFT transform it
        fftN.to_fft(g_fft, g);
        // compute g * sk_boot^(-1)
        tmp_ct = g_fft * sk_boot_inv_fft;
        // compute g * sk_boot^(-1) + B^i * m
        fftN.to_fft(msg_fft, msg); // msg = m * B^i
        tmp_ct += msg_fft;
        // inverse FFT of the above result
        fftN.from_fft(tmp_ct_long, tmp_ct);
        // reduction modulo q_boot
        mod_q_boot(tmp_ct_int, tmp_ct_long);
        // FFT transform for further use
        fftN.to_fft(tmp_ct, tmp_ct_int);

        ct[i] = tmp_ct;

        mult_poly_by_int(msg, B);
    }
}


void enc_scalar_ctxt(ModQPoly& ct, const ModQPoly& m, const SKey_boot& sk_boot){
    int p = Param::p;
    FFTPoly sk_boot_inv_fft(Param::N2p1); // f^-1 in FFT form
    fftN.to_fft(sk_boot_inv_fft, sk_boot.sk_inv);
    FFTPoly g_fft(Param::N2p1);

    ModQPoly msg(Param::N);
    for(int i = 0; i < Param::N; i++)
        msg[i] = (q_boot / p) * m[i]; // msg = m * floor(Q / p) \in Z[X]

    FFTPoly msg_fft(Param::N2p1);
    FFTPoly tmp_ct(Param::N2p1);
    vector<long> tmp_ct_long(Param::N);
       
    // sample random ternary vector
    ModQPoly g(Param::N,0L);
    Sampler::get_ternary_vector(g);

    // FFT transform it
    fftN.to_fft(g_fft, g);
    
    // compute g * sk_boot^(-1)
    tmp_ct = g_fft * sk_boot_inv_fft;
    
    // compute g * sk_boot^(-1) + B^i * m
    fftN.to_fft(msg_fft, msg); // msg = m * (Q / p)
    
    tmp_ct += msg_fft;

    // inverse FFT of the above result
    fftN.from_fft(tmp_ct_long, tmp_ct);
    
    // reduction modulo q_boot
    mod_q_boot(ct, tmp_ct_long);
}


void enc_scalar_ctxt(ModQPoly& ct, int m, const SKey_boot& sk_boot)
{
    ModQPoly msg(Param::N, 0);
    msg[0] = lazy_mod(m, Param::p); // msg = m \in Z_p[X]

    enc_scalar_ctxt(ct, msg, sk_boot);
}



void dec_scalar_ctxt(ModQPoly &msg, const ModQPoly& ct, const SKey_boot& sk_boot){

    FFTPoly sk_boot_fft(Param::N2p1); // f in FFT form
    FFTPoly tmp_ct_fft(Param::N2p1);
    FFTPoly ct_fft(Param::N2p1);

    fftN.to_fft(sk_boot_fft, sk_boot.sk);
    fftN.to_fft(ct_fft, ct);

    tmp_ct_fft = ct_fft * sk_boot_fft;

    vector<long> tmp_ct_long(Param::N);
    fftN.from_fft(tmp_ct_long, tmp_ct_fft);

    mod_q_boot(msg, tmp_ct_long);

    for(int i = 0; i < Param::N; i++){
        msg[i] = int(round((double(msg[i])/double(q_boot))*Param::p));
    }

}


int dec_scalar_ctxt_int(const ModQPoly& ct, const SKey_boot& sk_boot){
    ModQPoly msg(Param::N);

    dec_scalar_ctxt(msg, ct, sk_boot);

    return msg[0];
}

void mult_ctxt_by_int(ModQPoly& ct, int u){
    for(int i = 0; i < Param::N; i++){
        ct[i] = (int) ((((long) ct[i]) * ((long) u)) % q_boot);
        ct[i] = lazy_mod(ct[i], q_boot);
    }
}

void mult_ctxt_by_poly(ModQPoly& ct, const ModQPoly& u){
    
    FFTPoly ct_fft(Param::N2p1); // ct in FFT form
    fftN.to_fft(ct_fft, ct);

    FFTPoly u_fft(Param::N2p1); // u in FFT form
    fftN.to_fft(u_fft, u);

    vector<long> tmp_ct_long(Param::N);
       
    // compute FFT(ct * sk_boot^(-1)
    ct_fft = ct_fft * u_fft;

    // inverse FFT of the above result
    fftN.from_fft(tmp_ct_long, ct_fft);
    
    // reduction modulo q_boot
    mod_q_boot(ct, tmp_ct_long);
}


void mult_ctxt_by_poly(NGSFFTctxt& ct, const ModQPoly& u){
    int l = ct.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    FFTPoly u_fft(Param::N2p1); // u in FFT form
    fftN.to_fft(u_fft, u);

    for(int i = 0; i < l; i++){
        ct[i] *= u_fft;
    }

}


void add_scalar_ctxt(ModQPoly& ct0, const ModQPoly& ct1){
    for(int i = 0; i < Param::N; i++){
        ct0[i] = (int) ((((long) ct0[i]) + ((long) ct1[i])) % q_boot);
        ct0[i] = lazy_mod(ct0[i], q_boot);
    }
}

void sub_scalar_ctxt(ModQPoly& ct0, const ModQPoly& ct1){
    for(int i = 0; i < Param::N; i++){
        ct0[i] = (int) ((((long) ct0[i]) - ((long) ct1[i])) % q_boot);
        ct0[i] = lazy_mod(ct0[i], q_boot);
    }
}

void add_one_to_scalar_ctxt(ModQPoly& ct0){
    ct0[0] = (int) (((long) ct0[0]) + ((long) (q_boot / Param::p) ) % q_boot);
    ct0[0] = lazy_mod(ct0[0], q_boot);
}




// ------------- general functions, but not present in original FINAL
//
//


void dec_vector_ctxt(ModQPoly &msg, const NGSFFTctxt& ct, const SKey_boot& sk_boot){
	if (0 == msg.size())
		msg = ModQPoly(Param::N, 0);

    int l = ct.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    ModQPoly enc_tmp(Param::N, 0);
    enc_tmp[0] = round(q_boot / (double) Param::p); // trivial noiseless encryption of 1
    vector<long> tmp_poly_long(Param::N);

	external_product(tmp_poly_long, enc_tmp, ct, B, logB, l); // mult ct by one
	mod_q_boot(enc_tmp, tmp_poly_long);

	dec_scalar_ctxt(msg, enc_tmp, sk_boot);
}


int dec_vector_ctxt_int(const NGSFFTctxt& ct, const SKey_boot& sk_boot){

    ModQPoly msg(Param::N);

    dec_vector_ctxt(msg, ct, sk_boot);

    return msg[0];
}




void add_one_to_vector_ctxt(NGSFFTctxt& ct0){
    int l = ct0.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    ModQPoly poly_powB(Param::N,0L);
    FFTPoly fft_powB(Param::N2p1);

    int powerB = 1;
    for (int i = 0; i < l; i++)
    {
        poly_powB[0] = powerB;
        // FFT transform it
        fftN.to_fft(fft_powB, poly_powB);

        ct0[i] += fft_powB;

        powerB *= B;
    }
}


void negate_vector_ctxt(NGSFFTctxt& c_not, const NGSFFTctxt& c){
    int l = c.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    if(c_not.size() != l)
        c_not = NGSFFTctxt(l);

    // XXX: we can speed up it by precomputing FFT(B**i)
    int powerB = 1;
    ModQPoly poly_powB(Param::N, 0L);
    FFTPoly fft_powB(Param::N2p1);

    for (int i = 0; i < l; i++)
    {
        poly_powB[0] = powerB;
        // FFT transform it
        fftN.to_fft(fft_powB, poly_powB);

        c_not[i] = fft_powB;
        c_not[i] -= c[i]; // c_not[i] = FFT(B^i) - c[i]

        powerB *= B;
    }
    // now c_not = (B^0, ..., B^(l-1)) - c in FFT domain
}




// --------------- functions related to FiLIP
// XXX: we should move them to another file to avoid changing FINAL

void xor_mod_p(ModQPoly& ct0, const NGSFFTctxt& ct1, const ModQPoly& ct2){
    int l = ct1.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;


    vector<long> tmp_poly_long(Param::N);
    ModQPoly tmp(ct0);

    mult_ctxt_by_int(tmp, -2); // -2*u*m0

    external_product(tmp_poly_long, tmp, ct1, B, logB, l);
    mod_q_boot(tmp, tmp_poly_long); // - 2*u*m0*m1
    
    add_scalar_ctxt(ct0, tmp); // m0*u + -2*u*m0*m1
    add_scalar_ctxt(ct0, ct2); // u*(m0 + m1 - 2*m0*m1)
}


void xor_mod_p(ModQPoly& ct0, const NGSFFTctxt& ct1){
    int l = ct1.size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    vector<long> tmp_poly_long(Param::N);
    ModQPoly tmp(ct0);

    mult_ctxt_by_int(tmp, -2); // -2*m0
    add_one_to_scalar_ctxt(tmp); // 1 - 2*m0

    external_product(tmp_poly_long, tmp, ct1, B, logB, l);
    mod_q_boot(tmp, tmp_poly_long); // (1 - 2*m0)*m1

    add_scalar_ctxt(ct0, tmp); // m0 + (1 - 2*m0)*m1 = m0 + m1 - 2*m0*m1
}


ModQPoly lift_to_exponent_scaled(const ModQPoly& c, const ModQPoly& u)
{
    int N = Param::N;
    int p = Param::p;

    // c encrypts u*m, where m is bit
    // notice that
    // u*m * (X - 1) + u =  u*X^m  (just set m = 0 and m = 1 and verify both sides of equation)

    ModQPoly res(N); 
    for (int i = 0; i < N - 1; i++)
        res[i+1] = c[i];
    res[0] = -c[N-1];
    // res = u * m * X

    sub_scalar_ctxt(res, c); // now res = u*m*(X - 1)

    ModQPoly tmp(Param::N);
    for(int i = 0; i < N; i++)
        tmp[i] = (q_boot / p) * u[i]; // tmp is noiseless encryption of u
    
    add_scalar_ctxt(res, tmp); // now res = u*m*(X - 1) + u

    return res;
}



ModQPoly lift_to_exponent(const ModQPoly& c)
{
    int N = Param::N;

    // c encrypts a bit m
    // notice that
    // m * (X - 1) + 1 =  X^m  (just set m = 0 and m = 1 and verify both sides of equation)

    ModQPoly res(N); 
    for (int i = 0; i < N - 1; i++)
        res[i+1] = c[i];
    res[0] = -c[N-1];
    // res = c * X

    sub_scalar_ctxt(res, c); // now res = c*(X - 1)

    add_one_to_scalar_ctxt(res); // res = c*(X - 1) + 1

    return res;
}


double noise_scalar_ctxt(const ModQPoly &msg, const ModQPoly& ct, const SKey_boot& sk_boot){

    int Q = q_boot;
    int p = Param::p;

    ModQPoly noise(Param::N);
    vector<long> tmp_noise_long(Param::N);
    for(int i = 0; i < Param::N; i++)
        tmp_noise_long[i] = ct[i] - (Q / p) * msg[i];
    mod_q_boot(noise, tmp_noise_long);  // noise = g / f

    FFTPoly sk_boot_fft(Param::N2p1); // f in FFT form
    fftN.to_fft(sk_boot_fft, sk_boot.sk);

    FFTPoly noise_fft(Param::N2p1);
    fftN.to_fft(noise_fft, noise); // noise_fft = FFT(g / f)

    noise_fft = noise_fft * sk_boot_fft; // noise_fft = FFT(g)
    fftN.from_fft(tmp_noise_long, noise_fft);
    mod_q_boot(noise, tmp_noise_long); // noise = g

    double max_log = 0;
    for (int i = 0; i < Param::N; i++){
        int coef = abs(noise[i]);
        if (coef != 0){
            double log_coef = log(coef) / log(2);
            if (log_coef > max_log)
                max_log = log_coef;
        }
    }

    return max_log;
}

double noise_scalar_ctxt(int msg, const ModQPoly& ct, const SKey_boot& sk_boot){
    ModQPoly _msg(Param::N, 0);
    _msg[0] = msg;
    return noise_scalar_ctxt(_msg, ct, sk_boot);
}


void map_enc_b_to_enc_X_2b(NGSFFTctxt& ct_X_2b, const NGSFFTctxt& ct_bit){

    ct_X_2b = ct_bit; // copy ct_bit


    ModQPoly x_square_minus_1(Param::N);
    x_square_minus_1[0] = -1;
    x_square_minus_1[2] = 1; // now we have X^2 - 1

    mult_ctxt_by_poly(ct_X_2b, x_square_minus_1);

    add_one_to_vector_ctxt(ct_X_2b);

}
