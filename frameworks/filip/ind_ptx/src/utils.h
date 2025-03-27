#ifndef __MY_UTILS_FUNCS__
#define __MY_UTILS_FUNCS__

#include <vector>
#include <iostream> 
#include <random>

void swap(std::vector<int>& v, int i, int j);

void shuffle(std::vector<int>& v,
              std::default_random_engine& rand_engine,
              std::uniform_int_distribution<int>& uni_sampler);

void shuffle(std::vector<int>& v, const std::vector<int>& rand_indexes);

int threshold_xor(int i, int d);

std::vector<int> get_test_vector_for_threshold_xor(int N, int d);


template <typename T>
void operator *=(std::vector<T>& u, const T& scalar) {
    for(int i = 0; i < u.size(); i++)
        u[i] *= scalar;
}

template <typename T>
void operator +=(std::vector<T>& u, const std::vector<T>& v) {
    for(int i = 0; i < u.size(); i++)
        u[i] += v[i];
}


template <typename T>
void operator -=(std::vector<T>& u, const std::vector<T>& v) {
    for(int i = 0; i < u.size(); i++)
        u[i] -= v[i];
}

template <typename T>
void operator %=(std::vector<T>& u, const T& scalar) {
    for(int i = 0; i < u.size(); i++)
        u[i] %= scalar;
}



template <typename T>
std::ostream& operator<< (std::ostream &out, const std::vector<T> & u) {
    if (0 == u.size())
        return out << "[ ]";
        
    std::cout << "[";
    for (long i = 0; i < u.size()-1; i++)
        out << u[i] << ", ";
    out << u[u.size()-1] << "]";
    return out;
}

std::vector<int> binary_decomp(int x, int nbits);

#endif
