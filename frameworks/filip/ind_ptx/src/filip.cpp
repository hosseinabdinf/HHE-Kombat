#include "filip.h"
#include "utils.h"
//#include "final/FINAL.h"
#include "FINAL.h"

#include <chrono>

using namespace std;

FiLIP::FiLIP(int len_sk, int size_subset, int size_domain_thr, int threshold_limit, int8_t aes_key[16])
    : len_sk(len_sk), size_subset(size_subset), size_domain_thr(size_domain_thr),
        threshold_limit(threshold_limit), 
        num_bits_xored(size_subset - size_domain_thr),
        csprng(aes_key)
{

    sk = vector<int>(len_sk);
    Sampler::get_binary_vector(sk);

    whitening = vector<int>(size_subset);
}

void FiLIP::subset_permut_whiten(vector<int>& res)
{
    vector<int> v(sk); // copy secret key
	if (res.size() != (unsigned int)size_subset)
	    res = vector<int>(size_subset);

    int vec_size = sk.size() / 2;
    int modulus = sk.size();

    vector<int> indexes = vector<int>(vec_size);
	csprng.get_random_vector(indexes, vec_size, modulus);
    csprng.get_random_binary_vector(this->whitening, size_subset);

    // permute
    for(int i = 0; i < v.size() / 2; i++){
        int j = indexes[i];
        swap(v, i, j);
    }

    // take subset and apply whitening
    for(int i = 0; i < res.size(); i++){
        res[i] = v[i] ^ whitening[i];
    }
}

int FiLIP::compute_xor_thr(vector<int> perm_subset_sk)
{
    int _xor = 0;
    int i;
    // xor the first bits of perm_subset_sk
    for(i = 0; i < num_bits_xored; i++)
        _xor = (_xor + perm_subset_sk[i]) % 2;

    // sum the last bits of perm_subset_sk
    int sum = 0;
    for(; i < size_subset; i++)
        sum += perm_subset_sk[i];
    int T_d_n = (sum < threshold_limit ? 0 : 1);
    return _xor ^ T_d_n; // XOR(x_1, ..., x_k) xor T_{d,n}(y_1, ..., y_n) 
}

int FiLIP::enc_bit(int b)
{

    assert(0 == b || 1 == b);

    vector<int> permuted_subset;
	subset_permut_whiten(permuted_subset);

    int f_x_y = compute_xor_thr(permuted_subset);

    return (b + f_x_y) % 2;
}

/**
*  Uses the initialization vector iv to encrypt each entry of msg, 
* which is supposed to be a binary vector.
*/
std::vector<int> FiLIP::enc(int iv, std::vector<int> msg) {

    int n_ints = msg.size() * (len_sk / 2); // for each msg[i], we need len_sk/2 random integers for permutation
    int modulus = len_sk;
    int n_bits = msg.size() * size_subset; // for each msg[i], we need size_subset random bits for whitening


//    auto start = clock();
    this->csprng.generate_random_bytes(iv, n_ints, modulus, n_bits);
//    float time_rb = float(clock()-start)/CLOCKS_PER_SEC;
//    cout << "Time to generate random bytes: " << time_rb * 1000 << " ms" << endl;

    vector<int> ctxt(msg.size());

    for(int i = 0; i < msg.size(); i++){
        ctxt[i] = enc_bit(msg[i]);
    }
    return ctxt;
}

std::vector<int> FiLIP::dec(int iv, std::vector<int> c)
{
    return enc(iv, c); // decryption and encryption are actually the same
}

std::ostream& operator<<(std::ostream& os, const FiLIP& u){
    os << "FiLIP: {" 
        << "len_sk: " << u.len_sk
        << ", size_subset: " << u.size_subset
        << ", size_domain_threshold: " << u.size_domain_thr
        << ", threshold_limit: " << u.threshold_limit 
        << "}";
        return os;
}

