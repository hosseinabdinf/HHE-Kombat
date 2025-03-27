
#include "homomorphic_filip_mod_p.h"

#include "utils.h"

using namespace std::chrono; // to measure execution times


//#define DEBUG true
#define DEBUG true

HomomorphicFiLIPModP::HomomorphicFiLIPModP(const FiLIP& f, SchemeLWE& s_lwe, int _log_B_ngs)
    : len_sk(f.len_sk), size_subset(f.size_subset), size_domain_thr(f.size_domain_thr),
        threshold_limit(f.threshold_limit), 
        num_bits_xored(f.size_subset - f.size_domain_thr),
        csprng(f.csprng),
        fhe(s_lwe)
{
    this->log_B_ngs = _log_B_ngs; 
    this->B_ngs = 1 << log_B_ngs;
    this->l_ngs = ceil(log(q_boot) / log(B_ngs));


	high_resolution_clock::time_point t_before = high_resolution_clock::now();
    run_global_setup(f.sk);
    high_resolution_clock::time_point t_after = high_resolution_clock::now();

	double t_duration = duration_cast<milliseconds>(t_after - t_before).count();

    cout << "Time to run global setup: " << t_duration << " ms" << endl;

    // initialize vectors that will store the permuted and masked subsets used 
    // during homomorphic evaluation of FiLIP::decryption
    vec_ctxt_xor = vector<NGSFFTctxt*>(num_bits_xored);
    ctxt_xor = std::vector<ModQPoly*>(num_bits_xored);
    ctxt_hw = std::vector<NGSFFTctxt*>(size_domain_thr);

    whitening = vector<int>(size_subset);
}



void HomomorphicFiLIPModP::run_global_setup(const vector<int>& sk){

    enc_sk = std::vector<NGSFFTctxt>(len_sk);  // enc(sk[i])
    enc_not_sk = std::vector<NGSFFTctxt>(len_sk);  // enc(NOT(sk[i]))
    enc_X_to_2_sk = std::vector<NGSFFTctxt>(len_sk); // enc(X^(2*sk[i]))
    enc_X_to_not_2_sk = std::vector<NGSFFTctxt>(len_sk); // enc(X^(2*NOT(sk[i])))


    SKey_boot& sk_ngs = fhe.sk_boot;

    // In a real implementation, these encryptions are run by the client
    // and the vector enc_sk is sent to the cloud

	high_resolution_clock::time_point t_before = high_resolution_clock::now();
 	for(int i = 0; i < len_sk; i++){
        enc_ngs(enc_sk[i], sk[i], l_ngs, B_ngs, sk_ngs);
    }
	high_resolution_clock::time_point t_after = high_resolution_clock::now();
	double t_duration = duration_cast<milliseconds>(t_after - t_before).count();
    cout << "  Time to run client's global setup: " << t_duration << " ms" << endl;


    // Now transform enc_sk (sent by client) into the other vectors
	t_before = high_resolution_clock::now();
    for(int i = 0; i < len_sk; i++){
        negate_vector_ctxt(enc_not_sk[i], enc_sk[i]);
        
        map_enc_b_to_enc_X_2b(enc_X_to_2_sk[i], enc_sk[i]);
        map_enc_b_to_enc_X_2b(enc_X_to_not_2_sk[i], enc_not_sk[i]);
    }
	t_after = high_resolution_clock::now();
	t_duration = duration_cast<milliseconds>(t_after - t_before).count();
    cout << "  Time to run server's global setup: " << t_duration << " ms" << endl;
}


void HomomorphicFiLIPModP::run_p_dependent_setup(int p){
    this->p = p;
    logp = ceil(log(p)/log(2));
    int Delta = round(q_boot / p);


    // XXX: can raise error if norm Delta_t*Delta > 2^32
    ModQPoly Delta_t = get_test_vector_for_threshold_xor(Param::N, threshold_limit);
    Delta_t *= Delta;
    Delta_t %= q_boot; // Delta * t(X)

    std::vector<long> long_poly(Param::N);

    sca_enc_b_t = std::vector<std::vector<ModQPoly>>(logp); // [i][j] --> enc(2^i*sk[j]*t(X) mod p)
    sca_enc_not_b_t = std::vector<std::vector<ModQPoly>>(logp); // [i][j] --> enc(2^i*NOT(sk[j])*t(X) mod p)
    for(int i = 0; i < logp; i++){
        sca_enc_b_t[i] = std::vector<ModQPoly>(len_sk);
        sca_enc_not_b_t[i] = std::vector<ModQPoly>(len_sk);
        ModQPoly pow2Delta_t(Delta_t);
        pow2Delta_t *= (1<<i);
        pow2Delta_t %= q_boot; // Delta * 2^i * t(X)

        cout << "i = " << i << endl;
        for(int j = 0; j < len_sk; j++){
            sca_enc_b_t[i][j] = ModQPoly(Param::N);
            external_product(long_poly, pow2Delta_t, enc_sk[j], B_ngs, log_B_ngs, l_ngs); // Delta*2^i*t(X) * enc(sk[j])
            sca_enc_b_t[i][j] = ModQPoly(Param::N);
            mod_q_boot(sca_enc_b_t[i][j], long_poly);

            sca_enc_not_b_t[i][j] = ModQPoly(Param::N);
            external_product(long_poly, pow2Delta_t, enc_not_sk[j], B_ngs, log_B_ngs, l_ngs); // Delta*2^i*t(X) * enc(NOT(sk[j]))
            sca_enc_not_b_t[i][j] = ModQPoly(Param::N);
            mod_q_boot(sca_enc_not_b_t[i][j], long_poly);

        }
    }

}


// This function set the vectors  
// std::vector<NGSFFTctxt*> vec_ctxt_xor; // ciphertexts encrypting the bits to be xored
// std::vector<ModQPoly*> ctxt_xor; //  scalar ciphertexts encrypting 2^pow_2 * t(X) * b for every bit b be xored
// std::vector<NGSFFTctxt*> ctxt_hw; // encryptions of X^(2*b) for every bit b to be added for the hamming weight
void HomomorphicFiLIPModP::subset_permut_whiten(int pow_2){
    
    // set indexes as [0, 1, ..., len_sk - 1]
    vector<int> indexes(len_sk);
    for(int i = 0; i < len_sk; i++)
        indexes[i] = i;


    int vec_size = len_sk / 2;
    int modulus = len_sk;

    vector<int> rand_ints(vec_size);
	csprng.get_random_vector(rand_ints, vec_size, modulus);
    shuffle(indexes, rand_ints);

    csprng.get_random_binary_vector(this->whitening, size_subset);

    for(int i = 0; i < num_bits_xored; i++){
        int j = indexes[i];
        int wi = whitening[i];
        if (0 == wi){
            // takes index j, thus, we are applying permutation and subset
            vec_ctxt_xor[i] = &(enc_sk[j]);
            ctxt_xor[i] = &( sca_enc_b_t[pow_2][j] );
        }else{
        // wi is one --> b XOR wi = NOT(b), thus, copy from negated sk
            vec_ctxt_xor[i] = &(enc_not_sk[j]);
            ctxt_xor[i] = &( sca_enc_not_b_t[pow_2][j] );
        }
    }

    for(int i = num_bits_xored; i < size_subset; i++){
        int j = indexes[i];
        int wi = whitening[i];
        if (0 == wi){
            // takes index j, thus, we are applying permutation and subset
            ctxt_hw[i - num_bits_xored] = &(enc_X_to_2_sk[j]);
        }else{
        // wi is one --> b XOR wi = NOT(b), thus, copy from negated sk
            ctxt_hw[i - num_bits_xored] = &(enc_X_to_not_2_sk[j]);
        } 
    }
}


        
Ctxt_LWE HomomorphicFiLIPModP::transform(long int iv, const std::vector<int>& c){

    assert(c.size() == logp);

    int n_ints = c.size() * (len_sk / 2); // for each c[i], we need len_sk/2 random integers for permutation
    int modulus = len_sk;
    int n_bits = c.size() * size_subset; // for each c[i], we need size_subset random bits for whitening


	high_resolution_clock::time_point t_before;
    high_resolution_clock::time_point t_after;

    // generate enough random bytes for c.size() iterations of FiLIP
	t_before = high_resolution_clock::now();
    this->csprng.generate_random_bytes(iv, n_ints, modulus, n_bits);
	t_after = high_resolution_clock::now();

//	double t_duration = duration_cast<milliseconds>(t_after - t_before).count();
	double t_duration = duration_cast<microseconds>(t_after - t_before).count();

    cout << "(HomomorphicFiLIPModP) Time to generate random bytes: " << t_duration << " microseconds" << endl;


    ModQPoly scalar_ctxt(Param::N, 0);

    for(int i = 0; i < logp; i++){
        scalar_ctxt += enc_bit(c[i], i);
    }

    #if DEBUG
        ModQPoly msg(Param::N, 0);
        
        dec_scalar_ctxt(msg, scalar_ctxt, fhe.sk_boot);

        double noise = noise_scalar_ctxt(msg, scalar_ctxt, fhe.sk_boot);
        
        cout << "*** DEBUG mode on (turn it off to measure time more accurately)" << endl;
        cout << "Before NTRU->LWE keySwt: " << endl;
        cout << "   decypted msg: " << msg[0] << endl;
        cout << "   noise: " << noise << endl;
        cout << "   noise budget: log(q_boot) - log(p) - noise = "
                    << log(q_boot) / log(2) << " - " 
                    << log(Param::p) / log(2) << " - " 
                    << noise           << " = " 
                    << log(q_boot)/log(2) - log(Param::p)/log(2) - noise 
                    << endl;
    #endif

    //   At this point, scalar_ctxt encrypts a polynomial whose constant term is
    // equal to  m = sum m_i * 2^i   where m_i is the bit encrypted by the
    // FiLIP ciphertext c[i].
    //   Now, we convert scalar_ctxt to an LWE ciphertext encrypting m

    //mod q_boot
    mod_q_boot(scalar_ctxt);

    Ctxt_LWE ctxt;
    // mod switch from q_boot to q_base
    modulo_switch_to_base_lwe(scalar_ctxt);
    // extract constant term and key switch from sk_boot to sk_base

    #if DEBUG
		// debug mode, measure time of key switching
		t_before = high_resolution_clock::now();
		fhe.key_switch(ctxt, scalar_ctxt);
		t_after = high_resolution_clock::now();
		t_duration = duration_cast<microseconds>(t_after - t_before).count();
		cout << "   (HomomorphicFiLIPModP) Time to key switch at the end: " << t_duration * 0.001 << " ms" << endl;
	#else
		fhe.key_switch(ctxt, scalar_ctxt);
    #endif

    return ctxt;
}


ModQPoly HomomorphicFiLIPModP::enc_bit(int ci, int pow_2){
     assert(0 == ci || 1 == ci);

    // compute encryption of f(x, y) = 2^pow_2 * (XOR(x) + THR(y) % 2) mod p
    ModQPoly f_x_y = compute_xor_thr(pow_2);

    // ------- Now we xor f_x_y with the FiLIP ciphertext
    //     For this, we have an FHE ciphertext encrypting 2^k*F(s), where s is FiLIP's secret key
    // and we want to output an FHE ciphertext encrypting 2^k * (F(s) xor filip_ctxt),
    // but this is equivalent to outputting an FHE encryption of 
    //          2^k * F(s)  if filip_ctxt == 0 
    //      and
    //          2^k * neg(F(s))  if filip_ctxt == 1
    int delta_2k = (q_boot / Param::p) * (1 << pow_2);
    if (1 == ci){
        // compute ct_ith_bit = enc(delta_2k) - ct_ith_bit
        f_x_y[0] = delta_2k - f_x_y[0]; // negate the constant term, where the bit is encrypted
        for(int i = 1; i < Param::N; i++)
            f_x_y[i] *= -1;
        mod_q_boot(f_x_y);
    }
    // now f_x_y encrypts 2^pow_2 * mi

    return f_x_y;
}

ModQPoly HomomorphicFiLIPModP::compute_xor_thr(int pow_2){

    this->subset_permut_whiten(pow_2);// init vectors vec_ctxt_xor, ctxt_xor, and ctxt_hw

    // u = 2^pow_2 * t(X), i.e., power of two times test vector
    ModQPoly u = get_test_vector_for_threshold_xor(Param::N, threshold_limit);
    u *= (1 << pow_2);
    u %= q_boot;

    ModQPoly ct_xors(*(ctxt_xor[0])); // copy enc of 2^k * t(X) * b for the first bit b to be xored

    for(int i = 1; i < num_bits_xored; i++){
        xor_mod_p(ct_xors, *(vec_ctxt_xor[i]), *(ctxt_xor[i]));
    }

    // now ct_xors encrypts 2^k * XOR(b0, ..., bn) for each bi to be xored
    ModQPoly ct_res = lift_to_exponent_scaled(ct_xors, u); // ct_res encrypts 2^k * t(X) * X^XOR(b0,...,bn)

    // now add the bits for the hamming weight
    vector<long> tmp_poly_long(Param::N);
    for(int i = 0; i < size_domain_thr; i++){
        external_product(tmp_poly_long, ct_res, *(ctxt_hw[i]), B_ngs, log_B_ngs, l_ngs);
        mod_q_boot(ct_res, tmp_poly_long); // ct_res encrypts 2^k*t(X)*X^(XOR + 2*(bits[0]+...+bits[i]))
    }

    return ct_res;
}

std::vector<int> HomomorphicFiLIPModP::dec(std::vector<Ctxt_LWE> c){
    return std::vector<int>(1);
}

double HomomorphicFiLIPModP::noise(const std::vector<Ctxt_LWE>& c, const std::vector<int>& m){
    return 0.0;
}


std::ostream& operator<<(std::ostream& os, const HomomorphicFiLIPModP& u){
	double final_keyswt_key_MB = parLWE.Nl * (parLWE.n + 1) * (log(parLWE.q_base) / log(2)) / (8.0 * 1000000);
    double client_up_MB = u.len_sk * u.l_ngs * Param::N * (log(q_boot) / log(2)) / (8.0 * 1000000);
    os << "HomomorphicFiLIP: {" 
        << "p: " << u.p
        << ", ceil(log p): " << u.logp
        << ", N: " << Param::N
        << ", B_ngs: 2**" << u.log_B_ngs
        << ", l_ngs: " << u.l_ngs
        << ", len(Filip.sk): " << u.len_sk
        << ", size_subset: " << u.size_subset
        << ", size_domain_threshold: " << u.size_domain_thr
        << ", threshold_limit: " << u.threshold_limit 
        << ", FINAL's key-switching key in MB: " << final_keyswt_key_MB
        << ", client's upload in MB: " << client_up_MB + final_keyswt_key_MB
        << "}";
        return os;
}
