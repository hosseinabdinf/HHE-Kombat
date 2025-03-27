#include <iostream>
#include <cassert>
#include <time.h>
#include <cstdint>
#include <stdexcept>
#include <chrono>
#include <limits.h>

#include <NTL/ZZX.h>

#include "utils.h"

#include "FINAL.h"

using namespace std;
using namespace NTL;


ModQPoly random_poly(int bound){
    ModQPoly u(Param::N, 0);
    for(int i = 0; i < Param::N; i++){
        u[i] = rand() % bound;
        if (bound > 2){
            if (u[i] * 2 > bound)
                u[i] -= bound;
        }
    }
    return u;
}


void test_params()
{
    {
        Param param(LWE);
        cout << "Ciphertext modulus of the base scheme (LWE): " << param.q_base << endl;
        cout << "Dimension of the base scheme (LWE): " << param.n << endl;
        cout << "Ciphertext modulus for bootstrapping (LWE): " << q_boot << endl;
        cout << "Polynomial modulus (LWE): " << Param::get_def_poly() << endl;
        assert(param.l_ksk == int(ceil(log(double(param.q_base))/log(double(Param::B_ksk)))));
        cout << "Decomposition length for key-switching (LWE): " << param.l_ksk << endl;
        cout << "Decomposition bases for key-switching (LWE): " << Param::B_ksk << endl;
        cout << "Dimension for bootstrapping (LWE): " << Param::N << endl;
        cout << "Decomposition bases for bootstrapping (LWE): ";
        for (const auto &v: param.B_bsk) cout << v << ' ';
        cout << endl;
        cout << "Delta (LWE): " << param.delta_base << endl;
        cout << "Half Delta (LWE): " << param.half_delta_base << endl;
    }

    
    cout << "Plaintext modulus t: " << Param::t << endl;
    cout << "Plaintext modulus p: " << Param::p << endl;
    cout << endl;
    cout << "PARAMS ARE OK" << endl;
}


// ----- NGS tests

void test_enc_scalar_ciphertext(SchemeLWE& s_lwe){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct(Param::N);

    // test encryption of integers
    for(int i = 0; i < NTESTS; i++){
        int m = rand() % p;
        m = lazy_mod(m, p);

        enc_scalar_ctxt(ct, m, sk_boot);

        int _m = dec_scalar_ctxt_int(ct, sk_boot);

        assert((m - _m) % p == 0);
        
        double log_noise = noise_scalar_ctxt(m, ct, sk_boot);

        assert(abs(log_noise) < 0.0001); // log of noise is 0 (noise is ternary)
    }

    // test encryption of polynomials
    for(int i = 0; i < NTESTS; i++){
        ModQPoly m = random_poly(p);

        enc_scalar_ctxt(ct, m, sk_boot);

        ModQPoly _m(Param::N);

        dec_scalar_ctxt(_m, ct, sk_boot);

        for(int j = 0; j < Param::N; j++)
            assert((m[j] - _m[j]) % p == 0);
        
        double log_noise = noise_scalar_ctxt(m, ct, sk_boot);

        assert(abs(log_noise) < 0.0001); // log of noise is 0 (noise is ternary)
    }

}



void test_enc_dec_vector_ciphertext(SchemeLWE& s_lwe){

    int NTESTS = 100;
    int p = Param::p; 

//    int l = parLWE.l_bsk[0];
//    int B = parLWE.B_bsk[0];
//    int logB = parLWE.shift_bsk[0];

    int logB = 3;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));


    SKey_boot& sk_boot = s_lwe.sk_boot;
    
//    ModQPoly ct(Param::N);
    NGSFFTctxt ct;

    // test encryption of integers
    for(int i = 0; i < NTESTS; i++){
        int m = rand() % p;
        m = lazy_mod(m, p);

        enc_ngs(ct, m, l, B, sk_boot);

        int _m = dec_vector_ctxt_int(ct, sk_boot);

        assert((m - _m) % p == 0);
        
//        double log_noise = noise_vector_ctxt(m, ct, sk_boot);

//        assert(abs(log_noise) < log(l * B * sqrt(N)); 
    }

    // test encryption of polynomials
    for(int i = 0; i < NTESTS; i++){
        ModQPoly m = random_poly(p);

        enc_ngs(ct, m, l, B, sk_boot);

        ModQPoly _m(Param::N);

        dec_vector_ctxt(_m, ct, sk_boot);

        for(int j = 0; j < Param::N; j++)
            assert((m[j] - _m[j]) % p == 0);
        
//        double log_noise = noise_vector_ctxt(m, ct, sk_boot);
//
//        assert(abs(log_noise) < log(l * B * sqrt(N)); 
    }

}

void test_mult_scalar_ctxt_int(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m = rand() % p;
        m = lazy_mod(m, p);

        int u = rand() % p;
        u = lazy_mod(u, p);

        enc_scalar_ctxt(ct, m, sk_boot);
        mult_ctxt_by_int(ct, u);

        int _m = dec_scalar_ctxt_int(ct, sk_boot);

        if (verbose){
            cout << "m = " << m << endl;
            cout << "u = " << u << endl;
            cout << "dec(ctxt * u) = " << _m << endl;
        }

        assert((m*u - _m) % p == 0);
        
        if (verbose){
            double log_noise = noise_scalar_ctxt(_m, ct, sk_boot);
            cout << "noise = " << log_noise << endl;
        }
    }

}

void test_add_one_to_scalar_ctxt(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m0 = rand() % p;
        m0 = lazy_mod(m0, p);

        enc_scalar_ctxt(ct0, m0, sk_boot);
        add_one_to_scalar_ctxt(ct0);

        int _m = dec_scalar_ctxt_int(ct0, sk_boot);

        if (verbose){
            cout << "m0 = " << m0 << endl;
            cout << "dec(c0 + 1) = " << _m << endl;
        }

        assert((m0 + 1 - _m) % p == 0);
        
        if (verbose){
            double log_noise = noise_scalar_ctxt(_m, ct0, sk_boot);
            cout << "noise = " << log_noise << endl;
        }
    }
}

void test_add_scalar_ctxt(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);
    ModQPoly ct1(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m0 = rand() % p;
        int m1 = rand() % p;
        m0 = lazy_mod(m0, p);
        m1 = lazy_mod(m1, p);

        enc_scalar_ctxt(ct0, m0, sk_boot);
        enc_scalar_ctxt(ct1, m1, sk_boot);
        add_scalar_ctxt(ct0, ct1);

        int _m = dec_scalar_ctxt_int(ct0, sk_boot);

        if (verbose){
            cout << "m0 = " << m0 << endl;
            cout << "m1 = " << m1 << endl;
            cout << "dec(c0+c1) = " << _m << endl;
        }

        assert((m0 + m1 - _m) % p == 0);
        
        if (verbose){
            double log_noise = noise_scalar_ctxt(_m, ct0, sk_boot);
            cout << "noise = " << log_noise << endl;
        }
    }
}

void test_ext_prod_mod_p(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 50;
    int p = Param::p; 
    int l = parLWE.l_bsk[0];
    int B = parLWE.B_bsk[0];
    int logB = parLWE.shift_bsk[0];

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);
    NGSFFTctxt ct1;
    
    vector<long> tmp_poly_long(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m0 = rand() % p;
        m0 = lazy_mod(m0, p);

        int m1 = rand() % p;
        m1 = lazy_mod(m1, p);

        int m = (m0*m1) % p;


        enc_scalar_ctxt(ct0, m0, sk_boot);

        double noise = noise_scalar_ctxt(m0, ct0, sk_boot);
        if (verbose)
            cout << "noise c0 = " << noise << endl;

        enc_ngs(ct1, m1, l, B, sk_boot);

        external_product(tmp_poly_long, ct0, ct1, B, logB, l);
        mod_q_boot(ct0, tmp_poly_long);

        int _m = dec_scalar_ctxt_int(ct0, sk_boot);

        if (verbose){
            cout << "m0*m1 = " << m0 << "*" << m1 << " = " << (m0*m1 % p) << endl;
            cout << "dec(c0*c1) = " << _m << endl;
        }

        assert((m - _m) % p == 0);

        noise = noise_scalar_ctxt(m, ct0, sk_boot);

        if (verbose)
            cout << "noise c0*c1 = " << noise << endl;
    }

}



void test_even_hamming_weight_exponent(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 25;
    int NBITS = 100;
    int p = Param::p; 
    int l = parLWE.l_bsk[0];
    int B = parLWE.B_bsk[0];
    int logB = parLWE.shift_bsk[0];

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);

    vector<NGSFFTctxt> ct1(NBITS);
    
    ModQPoly Xsquare(Param::N, 0);
    Xsquare[2] = 1;

    vector<long> tmp_poly_long(Param::N);

    for(int _i = 0; _i < NTESTS; _i++){

        enc_scalar_ctxt(ct0, 1, sk_boot);

        vector<int> bits(NBITS);
        for(int i = 0; i < NBITS; i++){
            bits[i] = rand() % 2;
            if(0 == bits[i])
                enc_ngs(ct1[i], 1, l, B, sk_boot);
            else
                enc_ngs(ct1[i], Xsquare, l, B, sk_boot);
            
        }

        int exp_hw = 0;
        for(int i = 0; i < NBITS; i++){
            external_product(tmp_poly_long, ct0, ct1[i], B, logB, l);
            mod_q_boot(ct0, tmp_poly_long);

            exp_hw += bits[i];
    
            ModQPoly exp_msg(Param::N, 0);
            exp_msg[2*exp_hw] = 1;

            double noise = noise_scalar_ctxt(exp_msg, ct0, sk_boot);
            if (verbose)
                cout << "noise c0 = " << noise << endl;

            ModQPoly dec_msg(Param::N);
            dec_scalar_ctxt(dec_msg, ct0, sk_boot);

            for(int j = 0; j < Param::N; j++)
                assert(dec_msg[j] == exp_msg[j]);
 
            if (verbose){
                cout << "i = " << i << endl;
                cout << "exp_hw = " << exp_hw << endl;
                cout << "dec(c0)[2*exp_hw] = " << dec_msg[2*exp_hw] << endl;
            }

        }
    }
}

void test_scaled_xor_mod_p(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 2;
    int NXORS = 200;

    int p = Param::p; 
    int l = parLWE.l_bsk[0];
    int B = parLWE.B_bsk[0];
    int logB = parLWE.shift_bsk[0];

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);

    vector<NGSFFTctxt> ct1(NXORS);
    vector<ModQPoly> ct2(NXORS);

    for(int _i = 0; _i < NTESTS; _i++){
        enc_scalar_ctxt(ct0, 0, sk_boot);

        ModQPoly u = random_poly(p); // multiplied by XORs

        vector<int> msg(Param::N);
        for(int i = 0; i < NXORS; i++){
            msg[i] = rand() % 2;

            ct2[i] = ModQPoly(Param::N);

            enc_ngs(ct1[i], msg[i], l, B, sk_boot);

            if (0 == msg[i])
                enc_scalar_ctxt(ct2[i], 0, sk_boot);
            else
                enc_scalar_ctxt(ct2[i], u, sk_boot);
        }

        int exp_xor = 0;

        for(int i = 0; i < NXORS; i++){
            xor_mod_p(ct0, ct1[i], ct2[i]);
            exp_xor = (exp_xor + msg[i]) % 2;
        }

        ModQPoly _m(Param::N);
        dec_scalar_ctxt(_m, ct0, sk_boot);

        if (verbose){
            cout << "expected XOR: " << exp_xor << endl;
            cout << "u[0] = " << u[0] << endl;
            cout << "u[1] = " << u[1] << endl;
            cout << "dec(XOR(c0,c1,c2))[0] = " << _m[0] << endl;
            cout << "dec(XOR(c0,c1,c2))[1] = " << _m[1] << endl;
        }

        for(int i = 0; i < Param::N; i++)
            assert((exp_xor * u[i] - _m[i]) % p == 0);

        double noise;
        if(0 == exp_xor)
            noise = noise_scalar_ctxt(0, ct0, sk_boot);
        else
            noise = noise_scalar_ctxt(u, ct0, sk_boot);
        if (verbose){
            cout << "noise XOR(c0, c1, ct2) = " << noise << endl;
        }
    }
}


void test_xor_mod_p(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 10;
    int NXORS = 20;

    int p = Param::p; 
    int l = parLWE.l_bsk[0];
    int B = parLWE.B_bsk[0];
    int logB = parLWE.shift_bsk[0];
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;
    cout << "logB = " << logB << endl;


    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);

    vector<NGSFFTctxt> ct1(NXORS);
    
    for(int _i = 0; _i < NTESTS; _i++){
        enc_scalar_ctxt(ct0, 0, sk_boot);

        vector<int> msg(Param::N);
        for(int i = 0; i < NXORS; i++){
            msg[i] = rand() % 2;
            enc_ngs(ct1[i], msg[i], l, B, sk_boot);
        }

        int exp_xor = 0;

        for(int i = 0; i < NXORS; i++){
            xor_mod_p(ct0, ct1[i]);
            exp_xor = (exp_xor + msg[i]) % 2;
        }

        int _m = dec_scalar_ctxt_int(ct0, sk_boot);

        if (verbose){
            cout << "expected XOR: " << exp_xor << endl;
            cout << "dec(XOR(c0,c1)) = " << _m << endl;
        }

        assert((exp_xor - _m) % p == 0);

        double noise = noise_scalar_ctxt(exp_xor, ct0, sk_boot);
        if (verbose){
            cout << "noise XOR(c0,c1) = " << noise << endl;
        }
    }
}

void test_negate_vector_ctxt(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 50;
    int p = Param::p; 

    int logB = 3;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    NGSFFTctxt ct;
    NGSFFTctxt ct_out;

    ModQPoly enc_one(Param::N, 0);
    enc_one[0] = round(q_boot / p); // trivial noiseless encryption of 1
    vector<long> tmp_poly_long(Param::N);
        
    ModQPoly exp_msg(Param::N, 0);

    ModQPoly scalar_ct_out(Param::N, 0);
    
    for(int _i = 0; _i < NTESTS; _i++){

        int bit = rand() % 2;

        enc_ngs(ct, bit, l, B, sk_boot);

        negate_vector_ctxt(ct_out, ct);

        exp_msg[0] = (bit ? 0 : 1); // negate bit

        external_product(tmp_poly_long, enc_one, ct_out, B, logB, l);
        mod_q_boot(scalar_ct_out, tmp_poly_long);

        double noise = noise_scalar_ctxt(exp_msg, scalar_ct_out, sk_boot);
        if (verbose && 0 == _i % 5)
            cout << "noise after negate_vector_ctxt = " << noise << endl;

        ModQPoly dec_msg(Param::N);
        dec_scalar_ctxt(dec_msg, scalar_ct_out, sk_boot);

        for(int j = 0; j < Param::N; j++){
            assert(0 == (dec_msg[j] - exp_msg[j]) % p);
        }
    }
}


void test_map_enc_b_to_enc_X_2b(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 50;
    int p = Param::p; 

    int logB = 2;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    NGSFFTctxt ct;
    NGSFFTctxt ct_out;

    ModQPoly enc_one(Param::N, 0);
    enc_one[0] = round(q_boot / p); // trivial noiseless encryption of 1
    vector<long> tmp_poly_long(Param::N);

    ModQPoly scalar_ct_out(Param::N, 0);
    
    for(int _i = 0; _i < NTESTS; _i++){

        int bit = rand() % 2;

        enc_ngs(ct, bit, l, B, sk_boot);

        ModQPoly exp_msg(Param::N, 0);
        if (bit)
            exp_msg[2] = 1; // X^2
        else
            exp_msg[0] = 1; // X^0

        map_enc_b_to_enc_X_2b(ct_out, ct);


        external_product(tmp_poly_long, enc_one, ct_out, B, logB, l);
        mod_q_boot(scalar_ct_out, tmp_poly_long);

        double noise = noise_scalar_ctxt(exp_msg, scalar_ct_out, sk_boot);
        if (verbose && 0 == _i % 5)
            cout << "noise after map_enc_b_to_enc_X_2b = " << noise << endl;

        ModQPoly dec_msg(Param::N);
        dec_scalar_ctxt(dec_msg, scalar_ct_out, sk_boot);

        for(int j = 0; j < Param::N; j++)
            assert(dec_msg[j] == exp_msg[j]);
    }
}

void test_lift_to_exponent(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct(Param::N);
    ModQPoly dec_msg(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m = rand() % 2;

        enc_scalar_ctxt(ct, m, sk_boot);

        ModQPoly ct_lifted = lift_to_exponent(ct);

        dec_scalar_ctxt(dec_msg, ct_lifted, sk_boot);

        if (verbose){
            cout << "dec_msg[0] = " << dec_msg[0] << endl;
            cout << "dec_msg[1] = " << dec_msg[1] << endl;
        }

        if (0 == m){
            assert(dec_msg[0] == 1);
            assert(dec_msg[1] == 0);
        }else{
            assert(dec_msg[0] == 0);
            assert(dec_msg[1] == 1);
        }

        for(int i = 2; i < Param::N; i++)
            assert(dec_msg[i] == 0);

        double log_noise = noise_scalar_ctxt(dec_msg, ct_lifted, sk_boot);
        if (verbose){
            cout << "noise = " << log_noise << endl;
        }

        assert(abs(log_noise) < 2);
    }
}


void test_lift_to_exponent_scaled(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 100;
    int p = Param::p; 

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct(Param::N);
    ModQPoly dec_msg(Param::N);

    for(int i = 0; i < NTESTS; i++){

        int m = rand() % 2;

        ModQPoly u = random_poly(3); // ternary polynomial

        if (0 == m)
            enc_scalar_ctxt(ct, 0, sk_boot);
        else
            enc_scalar_ctxt(ct, u, sk_boot);
        // now ct encrypts u * m

        ModQPoly ct_lifted = lift_to_exponent_scaled(ct, u); // ct_lifted encrypts u*X^m

        dec_scalar_ctxt(dec_msg, ct_lifted, sk_boot);

        if (verbose){
            cout << "m = " << m << endl;
            cout << "u[0] = " << u[0] << endl;
            cout << "u[1] = " << u[1] << endl;
            cout << "u[N-1] = " << u[Param::N-1] << endl;
            cout << "dec_msg[0] = " << dec_msg[0] << endl;
            cout << "dec_msg[1] = " << dec_msg[1] << endl;
            cout << "dec_msg[2] = " << dec_msg[2] << endl;
        }

        ModQPoly exp_msg(u);
        if (1 == m){
            ModQPoly X(Param::N, 0); X[1] = 1;
            mult_ctxt_by_poly(exp_msg, X); // now exp_msg = u * X
        }
        assert(dec_msg == exp_msg);

        double log_noise = noise_scalar_ctxt(dec_msg, ct_lifted, sk_boot);
        if (verbose){
            cout << "noise = " << log_noise << endl;
        }

        assert(abs(log_noise) < 2);
    }
}


void test_even_hamming_weight_plus_bit_test_vector_on_the_left(SchemeLWE& s_lwe, bool verbose = false){

    int NTESTS = 1;
    int NBITS = 800; // large values of NBITS introduce decryption errors because of final noise
    int p = Param::p; 
//    int l = parLWE.l_bsk[0];
//    int B = parLWE.B_bsk[0];
//    int logB = parLWE.shift_bsk[0];

    int logB = 2;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;

    int d = NBITS / 2;

    int pow_two = 2; // use this variable to obtain the final bit (from threshold_xor) times a power of two

    ModQPoly t = get_test_vector_for_threshold_xor(Param::N, d);
    mult_ctxt_by_int(t, pow_two);

    SKey_boot& sk_boot = s_lwe.sk_boot;
    
    ModQPoly ct0(Param::N);

    vector<NGSFFTctxt> ct1(NBITS);
    vector<ModQPoly> ct2(NBITS);
    
    ModQPoly Xsquare(Param::N, 0);
    Xsquare[2] = 1;

    vector<long> tmp_poly_long(Param::N);

    for(int _i = 0; _i < NTESTS; _i++){

        cout << endl;
        cout << "TEST " << _i << endl;
            
        enc_scalar_ctxt(ct0, t, sk_boot); // enc 2^k * t(X)

        int first_bit = rand() % 2;
        NGSFFTctxt ct_first_bit;
        ModQPoly X_to_first_bit(Param::N, 0);
        X_to_first_bit[first_bit] = 1;
        enc_ngs(ct_first_bit, X_to_first_bit, l, B, sk_boot);
        external_product(tmp_poly_long, ct0, ct_first_bit, B, logB, l);
        mod_q_boot(ct0, tmp_poly_long); // now ct0 encrypts 2^k * t(X)*X^first_bit 

        ModQPoly exp_msg(t);
        mult_ctxt_by_poly(exp_msg, X_to_first_bit); // 2^k * t(X) * X^first_bit

        double noise = noise_scalar_ctxt(exp_msg, ct0, sk_boot);
        if (verbose)
            cout << "noise c0 = " << noise << endl;

        ModQPoly dec_msg(Param::N);
        dec_scalar_ctxt(dec_msg, ct0, sk_boot);

        assert(dec_msg == exp_msg);

        vector<int> bits(NBITS);
        for(int i = 0; i < NBITS; i++){
            bits[i] = rand() % 2;
            if(0 == bits[i])
                enc_ngs(ct1[i], 1, l, B, sk_boot);
            else
                enc_ngs(ct1[i], Xsquare, l, B, sk_boot);
        }
        // now ct1[i] encrypts X^(2*bits[i])

        assert(dec_msg == exp_msg);

        int exp_hw = 0;
        for(int i = 0; i < NBITS; i++){
            external_product(tmp_poly_long, ct0, ct1[i], B, logB, l);
            mod_q_boot(ct0, tmp_poly_long); // ct0 encrypts t(X)*X^(first_bit + 2*(bits[0]+...+bits[i]))

            exp_hw += bits[i];
    
            ModQPoly powX(Param::N, 0);
            powX[2*bits[i]] = 1;

            mult_ctxt_by_poly(exp_msg, powX); // t(X) * X^(2*exp_hw + first_bit)

            noise = noise_scalar_ctxt(exp_msg, ct0, sk_boot);
            if (verbose)
                cout << "(i = " << i << ") noise c0 = " << noise << endl;

            dec_scalar_ctxt(dec_msg, ct0, sk_boot);

            assert(dec_msg == exp_msg);

//            if (verbose){
//                cout << "i = " << i << endl;
//                cout << "first_bit = " << first_bit << endl;
//                cout << "exp_hw = " << exp_hw << endl;
//                cout << "threshold_xor(2*exp_hw + first_bit, d) = " << threshold_xor(2*exp_hw + first_bit, d) << endl;
//                cout << "dec(c0)[0] = " << dec_msg[0] << endl;
//            }

            assert(dec_msg[0] == pow_two * threshold_xor(2*exp_hw + first_bit, d));
        }
    }
}


/**
 *  Receives 
 *      a vector of vector ciphertexts encrypting the bits to be xored
 *      a vector of scalar ciphertexts encrypting 2^k * t(X) * b for every bit b be xored
 *      a vector of vector ciphertexts encrypting X^(2*b) for every bit b to be added for the hamming weight
 *      a polynomial u equal to 2^k * t(X), where t(X) is the "test vector"
 *
 *   Returns a scalar NTRU ciphertext encrypting a polynomial whose constant term
 * is equal to 2^k * threshold_xor(bits to xor, bits for hamming weight, d)
 */
ModQPoly simulate_homomorphic_filip_dec(const vector<NGSFFTctxt>& vec_ctxt_xor,
                                        const vector<ModQPoly>& ctxt_xor,
                                        const vector<NGSFFTctxt>& ctxt_hw,
                                        const ModQPoly& u){
    int nxor_bits = ctxt_xor.size();
    int nbits_hw = ctxt_hw.size();

    int l = ctxt_hw[0].size();
    int logB = ceil((log(q_boot)/log(2)) / l);
    int B = 1 << logB;

    ModQPoly ct_xors(ctxt_xor[0]); // copy enc of 2^k * t(X) * b for the first bit b to be xored

    for(int i = 1; i < nxor_bits; i++){
        xor_mod_p(ct_xors, vec_ctxt_xor[i], ctxt_xor[i]);
    }
    // now ct_xors encrypts 2^k * XOR(b0, ..., bn) for each bi to be xored

    
    ModQPoly ct_res = lift_to_exponent_scaled(ct_xors, u); // ct_res encrypts 2^k * t(X) * X^XOR(b0,...,bn)

    // now add the bits for the hamming weight
    vector<long> tmp_poly_long(Param::N);
    for(int i = 0; i < nbits_hw; i++){
        external_product(tmp_poly_long, ct_res, ctxt_hw[i], B, logB, l);
        mod_q_boot(ct_res, tmp_poly_long); // ct_res encrypts 2^k*t(X)*X^(XOR + 2*(bits[0]+...+bits[i]))
    }


    return ct_res;
}


void test_simulate_homomorphic_filip_dec(SchemeLWE& s_lwe, bool verbose = false){

    // ------- Init FHE params  ---------------- //
    int NTESTS = 1;
    int p = Param::p; 
    int logB = 2;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;


    // ------- Init Filip params  ---------------- //
    int nxor_bits = 81;
    int d = 32;
    int nbits_hw = 63;

    // ------- Init param to specify what bit we are decrypting
    int index_decrypted_bit = 1;
    // has to be between 0 and ceil(log_2(p))
    assert(0 <= index_decrypted_bit && index_decrypted_bit < ceil(log(p)/log(2)));

    // ----------------------------------------------------------------------------
    // ----------------------------------------------------------------------------
    // All the rest is automatic


    SKey_boot& sk_boot = s_lwe.sk_boot;

    // creates 2^k * t(X), i.e., test vector times power of two corresponding to the bit to be decrypted
    int pow_two = 1 << index_decrypted_bit; 
    ModQPoly t_2k = get_test_vector_for_threshold_xor(Param::N, d);
    mult_ctxt_by_int(t_2k, pow_two); 


    vector<int> bits_xor(nxor_bits); // bits to be xored
    vector<int> bits_hw(nbits_hw);  // bits for the hamming weight

    for(int i = 0; i < nxor_bits; i++)
        bits_xor[i] = rand() % 2;
    for(int i = 0; i < nbits_hw; i++)
        bits_hw[i] = rand() % 2;

    // Encrypt bits for the xor part
    vector<NGSFFTctxt> vec_ct_xors(nxor_bits);
    vector<ModQPoly> sca_ct_xors(nxor_bits);
    for(int i = 0; i < nxor_bits; i++){
        int bi = bits_xor[i];

        enc_ngs(vec_ct_xors[i], bi, l, B, sk_boot); // enc bi

        sca_ct_xors[i] = ModQPoly(Param::N);
        if (0 == bi)
            enc_scalar_ctxt(sca_ct_xors[i], 0, sk_boot); // enc bi * 2^k * t(X)
        else
            enc_scalar_ctxt(sca_ct_xors[i], t_2k, sk_boot); // enc bi * 2^k * t(X)
    }

    // Encrypt bits for the hamming weight part
    ModQPoly Xsquare(Param::N, 0);
    Xsquare[2] = 1;
    vector<NGSFFTctxt> vec_ct_hw(nbits_hw);
    for(int i = 0; i < nbits_hw; i++){
        if(0 == bits_hw[i])
            enc_ngs(vec_ct_hw[i], 1, l, B, sk_boot);
        else
            enc_ngs(vec_ct_hw[i], Xsquare, l, B, sk_boot);
        // now vec_ct_hw[i] encrypts X^(2*bits_hw[i])
    }
    // -------------- Setup finished

    
    // ---------- Now run FiLIP decryption homomorphically
    auto start = clock();
    ModQPoly ct_ith_bit = simulate_homomorphic_filip_dec(vec_ct_xors, sca_ct_xors, vec_ct_hw, t_2k);
    float time_dec = float(clock()-start)/CLOCKS_PER_SEC;
    cout << "Time to homomorphically decrypt one bit: " << time_dec << " s" << endl;

   
    // --------- Check the result
    ModQPoly dec_msg(Param::N);
    dec_scalar_ctxt(dec_msg, ct_ith_bit, sk_boot);

    int exp_hw = 0;
    int xor_bit = 0;
    for (int i = 0; i < nxor_bits; i++)
        xor_bit = (xor_bit + bits_xor[i]) % 2;
    for (int i = 0; i < nbits_hw; i++)
        exp_hw += bits_hw[i];

    assert(dec_msg[0] == pow_two * threshold_xor(2*exp_hw + xor_bit, d));
    cout << "dec_msg[0] = " << dec_msg[0] << endl;
    double noise = noise_scalar_ctxt(dec_msg, ct_ith_bit, sk_boot);
    if (verbose)
        cout << "noise ct_ith_bit = " << noise << endl;

    // ------- Simulate FiLIP encryption
    int ptxt = rand() % 2;
    int filip_ctxt = (ptxt + threshold_xor(2*exp_hw + xor_bit, d)) % 2;

    // ------- Now decrypt it homomorphically
    //     For this, we have an FHE ciphertext encrypting 2^k*F(s), where s is FiLIP's secret key
    // and we want to output an FHE ciphertext encrypting 2^k * (F(s) xor filip_ctxt),
    // but this is equivalent to outputting an FHE encryption of 
    //          2^k * F(s)  if filip_ctxt == 0 
    //      and
    //          2^k * neg(F(s))  if filip_ctxt == 1
    int delta_2k = (q_boot / Param::p) * pow_two;
    if (1 == filip_ctxt){
        // compute ct_ith_bit = enc(delta_2k) - ct_ith_bit
        ct_ith_bit[0] = delta_2k - ct_ith_bit[0]; // negate the constant term, where the bit is encrypted
        for(int i = 1; i < Param::N; i++)
            ct_ith_bit[i] *= -1;
        mod_q_boot(ct_ith_bit);
    }

    // ----- Now check the final result: the FHE ciphertext must encrypt 2^k * ptxt mod p
    dec_scalar_ctxt(dec_msg, ct_ith_bit, sk_boot);
    assert(dec_msg[0] == pow_two * ptxt);

}



int main()
{
    srand(time(NULL));

    test_params();

    cout << endl;
    cout << "-------------------------" << endl;
    cout << "NGS tests" << endl;

    SchemeLWE s_lwe;
    
    cout << "p = " << Param::p << endl;
//
    cout << "test_enc_scalar_ciphertext(s_lwe);" << endl;
    test_enc_scalar_ciphertext(s_lwe);

    cout << "test_enc_dec_vector_ciphertext(s_lwe);" << endl;
    test_enc_dec_vector_ciphertext(s_lwe);
    cout << "OK" << endl;

    cout << "test_ext_prod_mod_p(s_lwe);" << endl;
    test_ext_prod_mod_p(s_lwe);
    cout << "test_mult_scalar_ctxt_int(s_lwe);" << endl;
    test_mult_scalar_ctxt_int(s_lwe);
    cout << "test_add_scalar_ctxt(s_lwe);" << endl;
    test_add_scalar_ctxt(s_lwe);
    cout << "test_add_one_to_scalar_ctxt(s_lwe);" << endl;
    test_add_one_to_scalar_ctxt(s_lwe);
    cout << "test_xor_mod_p(s_lwe);" << endl;
    test_xor_mod_p(s_lwe);
    cout << "test_scaled_xor_mod_p(s_lwe);" << endl;
    test_scaled_xor_mod_p(s_lwe);
    cout << "test_lift_to_exponent(s_lwe);" << endl;
    test_lift_to_exponent(s_lwe);
    cout << "test_lift_to_exponent_scaled(s_lwe);" << endl;
    test_lift_to_exponent_scaled(s_lwe);

    cout << "test_even_hamming_weight_exponent(s_lwe, true);" << endl;
    test_even_hamming_weight_exponent(s_lwe);

    cout << "test_even_hamming_weight_plus_bit_test_vector_on_the_left(s_lwe)" << endl;
    test_even_hamming_weight_plus_bit_test_vector_on_the_left(s_lwe);
//

    cout << "test_negate_vector_ctxt";
    test_negate_vector_ctxt(s_lwe, true);
    cout << "OK" << endl;
//
//
//
//
    cout << "test_map_enc_b_to_enc_X_2b";
    test_map_enc_b_to_enc_X_2b(s_lwe, true);
    cout << "OK" << endl;

//
    cout << "test_simulate_homomorphic_filip_dec(s_lwe) ... ";
    test_simulate_homomorphic_filip_dec(s_lwe, true);
    cout << "OK" << endl;
//
    return 0;
}
