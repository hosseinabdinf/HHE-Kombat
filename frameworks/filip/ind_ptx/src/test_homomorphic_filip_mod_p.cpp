#include <iostream>
#include <cassert>
#include <time.h>
#include <cstdint>
#include <stdexcept>
#include <chrono>
#include <limits.h>

#include <NTL/ZZX.h>

#include "utils.h"

#include "filip.h"

#include "homomorphic_filip_mod_p.h"

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


// ----- NGS tests

void test_global_setup(SchemeLWE& s_lwe, bool verbose = false){

    // ------- Init FHE params  ---------------- //
    int NTESTS = 1;
    int p = Param::p; 
    int logp = ceil(log(p) / log(2));
    int logB = 3;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;


    // ------- Init Filip params  ---------------- //
    int len_sk = 1 << 14;
    int size_subset = 144;
    int nxor_bits = 81;
    int threshold_limit = 32;
    int nbits_hw = size_subset - nxor_bits;
    // XXX: In a secure implementation, aes_key must be random
    int8_t aes_key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    // ----------------------------------------------------------------------------
    // ----------------------------------------------------------------------------
    // All the rest is automatic

    int iv = random() % (1 << 20);

    FiLIP filip(len_sk, size_subset, nbits_hw, threshold_limit, aes_key);
 
    HomomorphicFiLIPModP homFilip(filip, s_lwe);
    homFilip.run_global_setup(filip.sk); // uses FiLIP's secret key to run global setup

    auto start_p_setup = clock();
    homFilip.run_p_dependent_setup(p);
    float time_p_setup = float(clock()-start_p_setup)/CLOCKS_PER_SEC;
    cout << "Time to run p-dependent setup: " << time_p_setup << " s" << endl;

    // Now test if 
    //  enc_sk[i] == enc(sk[i])
    //  enc_not_sk[i] == enc(NOT(sk[i]))
    //  enc_X_to_2_sk[i] == enc(X^(2*sk[i]))
    //  enc_X_to_not_2_sk[i] == enc(X^(2*NOT(sk[i])))
    SKey_boot& sk_ngs = homFilip.fhe.sk_boot;

    ModQPoly dec_msg(Param::N, 0);
    for(int i = 0; i < len_sk; i++){
	    dec_vector_ctxt(dec_msg, homFilip.enc_sk[i], sk_ngs);
        assert(dec_msg[0] == filip.sk[i]);
        for(int j = 1; j < Param::N; j++)
            assert(0 == dec_msg[j]);

        dec_vector_ctxt(dec_msg, homFilip.enc_not_sk[i], sk_ngs);
        assert(dec_msg[0] == !filip.sk[i]);
        for(int j = 1; j < Param::N; j++)
            assert(0 == dec_msg[j]);

        dec_vector_ctxt(dec_msg, homFilip.enc_X_to_2_sk[i], sk_ngs);
        ModQPoly exp_msg(Param::N, 0);
        exp_msg[2*filip.sk[i]] = 1;
        assert(dec_msg == exp_msg);

        dec_vector_ctxt(dec_msg, homFilip.enc_X_to_not_2_sk[i], sk_ngs);
        ModQPoly exp_msg_not(Param::N, 0);
        exp_msg_not[2*(filip.sk[i] ? 0 : 1)] = 1;
        assert(dec_msg == exp_msg_not);
    }
}


void test_p_dependent_setup(SchemeLWE& s_lwe, bool verbose = false){

    // ------- Init FHE params  ---------------- //
    int NTESTS = 1;
    int p = Param::p; 
    int logp = ceil(log(p) / log(2));
    int logB = 2;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;


    // ------- Init Filip params  ---------------- //
    int len_sk = 1 << 11;
    int size_subset = 144;
    int nxor_bits = 81;
    int threshold_limit = 32;
    int nbits_hw = size_subset - nxor_bits;
    // XXX: In a secure implementation, aes_key must be random
    int8_t aes_key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    // ----------------------------------------------------------------------------
    // ----------------------------------------------------------------------------
    // All the rest is automatic

    int iv = random() % (1 << 20);

    FiLIP filip(len_sk, size_subset, nbits_hw, threshold_limit, aes_key);
 
    HomomorphicFiLIPModP homFilip(filip, s_lwe);
    homFilip.run_global_setup(filip.sk); // uses FiLIP's secret key to run global setup

    auto start_p_setup = clock();
    homFilip.run_p_dependent_setup(p);
    float time_p_setup = float(clock()-start_p_setup)/CLOCKS_PER_SEC;
    cout << "Time to run p-dependent setup: " << time_p_setup << " s" << endl;


    // Now test if ciphertexts initialized on p-setup are encrypting the expected values
    SKey_boot& sk_ngs = homFilip.fhe.sk_boot;
    ModQPoly dec_msg(Param::N, 0);

    ModQPoly t = get_test_vector_for_threshold_xor(Param::N, threshold_limit);
    ModQPoly zero_poly(Param::N, 0);
    ModQPoly exp_msg(Param::N, 0);

    for(int i = 0; i < logp; i++){

        t *= (1 << i);

        for(int j = 0; j < len_sk; j++){
			dec_scalar_ctxt(dec_msg, homFilip.sca_enc_b_t[i][j], s_lwe.sk_boot);
			//assert
            if (filip.sk[j]){
                exp_msg = t;
                exp_msg -= dec_msg;
                exp_msg %= p;
                assert(zero_poly == exp_msg); // check dec_msg == 2^i * t * sk[j]
            }else
                assert(zero_poly == dec_msg);
            
			
			dec_scalar_ctxt(dec_msg, homFilip.sca_enc_not_b_t[i][j], s_lwe.sk_boot);
			//assert
            if (! filip.sk[j]){
                exp_msg = t;
                exp_msg -= dec_msg;
                exp_msg %= p;
                assert(zero_poly == exp_msg); // check dec_msg == 2^i * t * NOT(sk[j])
            }else
                assert(zero_poly == dec_msg);

        }
    }
}

void test_simulate_homomorphic_filip_dec(SchemeLWE& s_lwe, bool verbose = false){
    
	int NTESTS = 10; // number of times we run the same test with random inputs

    // ------- Init FHE params  ---------------- //
    int p = Param::p; 
    int logp = ceil(log(p) / log(2));
    int logB = 4;
    int B = 1 << logB;
    int l = ceil(log(q_boot) / log(B));
    cout << "l = " << l << endl;
    cout << "B = " << B << endl;


    // ------- Init Filip params  ---------------- //
    int len_sk = 1 << 8;
    int size_subset = 144;
    int nxor_bits = 81;
    int threshold_limit = 32;
    int nbits_hw = size_subset - nxor_bits;
    // XXX: In a secure implementation, aes_key must be random
    int8_t aes_key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    // ----------------------------------------------------------------------------
    // ----------------------------------------------------------------------------
    // All the rest is automatic

    int iv = random() % (1 << 20);

    FiLIP filip(len_sk, size_subset, nbits_hw, threshold_limit, aes_key);

    cout << "HomomorphicFiLIPModP homFilip(filip);" << endl;
    HomomorphicFiLIPModP homFilip(filip, s_lwe, logB);

    auto start_p_setup = clock();
    homFilip.run_p_dependent_setup(p);
    float time_p_setup = float(clock()-start_p_setup)/CLOCKS_PER_SEC;
    cout << "Time to run p-dependent setup: " << time_p_setup << " s" << endl;


    for (int _i = 0; _i < NTESTS; _i++){

        int msg_mod_p = random() % p;

        vector<int> msg_bin = binary_decomp(msg_mod_p, logp);

        std::vector<int> ctxt_filip = filip.enc(iv, msg_bin);

        SKey_boot& sk_boot = s_lwe.sk_boot;

        // ---------- Now run FiLIP decryption homomorphically
        cout << "Ctxt_LWE ctxt_fhe = homFilip.transform(iv, ctxt_filip);" << endl;
        auto start = clock();
        Ctxt_LWE ctxt_fhe = homFilip.transform(iv, ctxt_filip);
        float time_dec = float(clock()-start)/CLOCKS_PER_SEC;
        cout << "Time to homomorphically decrypt " << logp << " bits: " << time_dec << " s" << endl;
        cout << "Amortized time per bit: " << (time_dec / logp) << " s" << endl;

        iv++; // update IV for next iteration

        // --------- Check the result
        SKey_boot& sk_ngs = homFilip.fhe.sk_boot;

        int dec_msg = homFilip.fhe.decrypt_mod_p(ctxt_fhe);
        if (verbose){
            cout << "dec_msg = " << dec_msg << endl;
            cout << "msg = " << msg_mod_p << endl;
            cout << "p = " << p << endl;
            double noise = homFilip.fhe.noise_mod_p(ctxt_fhe, dec_msg);
            cout << "noise = " << noise << endl;
            cout << "noise budget: log(q_base) - log(p) - noise = "
                    << log(parLWE.q_base) / log(2) << " - " 
                    << log(p) / log(2) << " - " 
                    << noise           << " = " 
                    << log(parLWE.q_base)/log(2) - log(p)/log(2) - noise 
                    << endl;
        }

        // ----- Now check the final result: the FHE ciphertext must encrypt 2^k * ptxt mod p
        assert(0 == (dec_msg - msg_mod_p) % p);
        cout << endl;
    }

    cout << homFilip << endl << endl;
}



int main()
{
    srand(time(NULL));

    cout << endl;
    cout << "-------------------------" << endl;
    cout << "p = " << Param::p << endl;
    
    SchemeLWE s_lwe;

//    cout << "test_global_setup(s_lwe) ... ";
//	test_global_setup(s_lwe, true);
//    cout << "     test_global_setup(s_lwe) ...   OK" << endl;
//    cout << endl;
//
//    cout << "test_p_dependent_setup(s_lwe) ... ";
//	test_p_dependent_setup(s_lwe, true);
//    cout << "     test_p_dependent_setup(s_lwe) ...   OK" << endl;;
//    cout << endl;
//
    cout << "-------------------------" << endl;
    cout << "test_homomorphic_filip_dec(s_lwe) ... ";
    test_simulate_homomorphic_filip_dec(s_lwe, true);
    cout << "     test_homomorphic_filip_dec(s_lwe) ... OK" << endl;
//
    return 0;
}
