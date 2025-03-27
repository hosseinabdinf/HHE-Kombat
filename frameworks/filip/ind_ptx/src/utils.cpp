#include "utils.h"

using namespace std;


void swap(vector<int>& v, int i, int j)
{
    int tmp = v[i];
    v[i] = v[j];
    v[j] = tmp;
}

void shuffle(std::vector<int>& v,
              std::default_random_engine& rand_engine,
              std::uniform_int_distribution<int>& uni_sampler)
{
    for(int i = 0; i < v.size() / 2; i++){
        int j = uni_sampler(rand_engine) % v.size();
        swap(v, i, j);
    }
}

void shuffle(std::vector<int>& v, const std::vector<int>& rand_indexes){
    for(int i = 0; i < v.size() / 2; i++){
        int j = rand_indexes[i];
        swap(v, i, j);
    }
}



int threshold_xor(int i, int d){
    int b = i % 2;
    int k = (i - b) / 2;
    return (b + ( (i - b)/2 >= d)) % 2;
}

std::vector<int> get_test_vector_for_threshold_xor(int N, int d) {
    // Threshold: if HW < d, then output 0
    // Thus, if 2*HW + XOR < d, then output XOR
    // Otherwise, output not XOR

    std::vector<int> t(N);
    // t(X) = sum_{i=0}^{N-1} f(i) * X^(2N - i) 
    //      = -sum_{i=0}^{N-1} f(i) * X^(N - i) 
    //
    //      Let i = 2*k + b, then
    //      f(i) = [ b  if k < d
    //             [ ~b if k >= d
    // 

    for(int i = 0; i < N; i++){
        t[N - i] = - threshold_xor(i, d);
    }

    return t;
}


vector<int> binary_decomp(int x, int nbits){
    vector<int> bits(nbits);
    for(int i = 0; i < nbits; i++){
        bits[i] = x % 2;
        x /= 2;
    }
    return bits;
}

