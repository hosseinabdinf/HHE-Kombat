/**
 *  Implements the random number generator used by FiLIP stream cipher with f = XOR-THR
 */

#ifndef __CSPRNG_for_FiLIP__
#define __CSPRNG_for_FiLIP__

#include <vector>
#include <random>

#include "tiny-aes/aes.hpp" // from https://github.com/kokke/tiny-AES-c 


class CSPRNG
{
    public:

        int nbytes; // number of random bytes that were generated
        uint8_t* random_bytes; // randomness pool

        int used_bytes; // number of bytes from the randomness pol that were already used

        uint8_t aes_key[16]; // key for AES-128

        int iv;  // initialization vector


        struct AES_ctx ctx; // stores keys for each round of AES

        CSPRNG(int8_t* _aes_key);

        void generate_random_bytes(int iv, int nbytes);


        //      Generate random bytes sufficient to generate n integers mod
        // modulus and m bits.
        void generate_random_bytes(int iv, int n, int modulus, int m);


        /**
         *      Use the pool of random bytes (specifically, from random_bytes[used_bytes]
         *  to random_bytes[nbytes-1]) to generate a random vector with vec_size entries and each
         *  entry in the set {0, 1, ..., modulus-1}.
         *      Before using this function, use generate_random_bytes
         */
		void get_random_vector(std::vector<int> vec, int vec_size, int modulus);

        /**
         *      Use the pool of random bytes (specifically, from random_bytes[used_bytes]
         *  to random_bytes[nbytes-1]) to generate a random vector with vec_size entries and each
         *  entry in {0, 1}.
         *      Before using this function, use generate_random_bytes
         */
		void get_random_binary_vector(std::vector<int>& vec, int vec_size);


        /**
         *  Return the number of random bytes still available in the randomness pool.
         *  If it returns zero, run generate_random_bytes again with new iv.
         */
        int available_bytes() const;
};


std::ostream& operator<<(std::ostream& os, const CSPRNG& u);

#endif
