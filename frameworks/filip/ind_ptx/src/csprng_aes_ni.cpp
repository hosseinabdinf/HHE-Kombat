#include "csprng.h"

#include <iostream>
#include <cassert>
#include <cmath>

#include "aes-ni.h"

using namespace std;


// Returns a array with 16*nblocks bytes (each AES-128 block has 16 bytes)
int8_t* allocate_vec_msgs(int nblocks){
    int8_t* vec = (int8_t*) malloc( (nblocks * 16) * sizeof(uint8_t) );
    return vec;
}

void set_vec_iv_msg(int8_t* vec, int nblocks, int iv){

    int positions_per_block = 16;

    // assuming len(vec) > nblocks * 16
    for (int i = 0; i < nblocks; i++){
        int k = i;
        int base = (1 << 8); // size of one byte
        // First 4 bytes of each block store the counter
        for (int j = 0; j < 5; j++){
            vec[i*positions_per_block + j] = k % base;
            k >>= 8; // same as k /= base;          
        }
        k = iv;
        // Bytes from 5th to 8th used to store the iv
        for (int j = 5; j < 9; j++){
            vec[i*positions_per_block + j] = k % base;
            k >>= 8; // same as k /= base;          
        }
        // Remaining 8 bytes are not used
        for (int j = 9; j < positions_per_block; j++){
            vec[i*positions_per_block + j] = 0;
        }
    }
}


/**
 *  Assumes that msg has 16*nblocks entries
 *  At the end, each consecutive 16 entries of ctxt correspond to
 *  the encryption of the block defined by the 16 corresponding entries
 *  of msg. That is
 *  	ctxt[i*16, ..., (i+1)*16 - 1] = enc(msg[i*16, ..., (i+1)*16 - 1])
 */
void enc_blocks(int8_t* ctxt, int8_t* msg, int nblocks){
    for (int i = 0; i < nblocks; ++i) {
      aes128_enc(msg + (i * 16), ctxt + (i * 16)); // encrypts i-th block (16 bytes = 128 bits)
    }
}


CSPRNG::CSPRNG(int8_t* _aes_key) {
    for(int i = 0; i < 16; i++)
        this->aes_key[i] = _aes_key[i];

    aes128_load_key(aes_key);

    this->nbytes = 0;
    this->used_bytes = 0;
    this->iv = 0;
}

        
void CSPRNG::generate_random_bytes(int iv, int _nbytes){

    int nblocks = ceil(_nbytes / 16.0); // each AES-128 block has 16 bytes


	std::cout << "# AES blocks: " << nblocks << std::endl;

    _nbytes = nblocks * 16; // always generate multiple of 16 to be compatible with AES

    if (_nbytes == this->nbytes && iv == this->iv){
        this->used_bytes = 0;
        return;    // avoid generating the same random bytes
    }

    this->iv = iv;

    if (this->nbytes != _nbytes){
        if (this->nbytes > 0)
            free(this->random_bytes);
        this->nbytes = _nbytes;
        this->random_bytes = allocate_vec_msgs(nblocks);
        this->iv_counter = allocate_vec_msgs(nblocks);
    }

    set_vec_iv_msg(this->iv_counter, nblocks, iv); // populate iv_counter with plaintext
    this->used_bytes = 0;
    
    // finally use AES-128 to generate 16*nblocks random bytes
    enc_blocks(this->random_bytes, this->iv_counter, nblocks);
}

        
void CSPRNG::generate_random_bytes(int iv, int n_ints, int modulus, int n_bits){
 
    int log_mod = ceil(log(modulus) / log(2));
    int bytes_per_int = ceil(log_mod / 8.0);
    int needed_bytes_for_ints = n_ints * bytes_per_int;

    int needed_bytes_for_bits = ceil(n_bits / 8.0);

    int total_bytes = needed_bytes_for_ints + needed_bytes_for_bits;

    generate_random_bytes(iv, total_bytes);
}


        
void CSPRNG::get_random_vector(vector<int> vec, int vec_size, int modulus){
    
	if (vec.size() != (unsigned int)vec_size)
	    vec = vector<int>(vec_size);

    int log_mod = ceil(log(modulus) / log(2));

    int bytes_per_element = ceil(log_mod / 8.0);

    // assert there are enough bytes in the ramdomness pool to generate the vector
    assert(nbytes - used_bytes >= bytes_per_element * vec_size);

    int j = used_bytes; // index of first byte used to generate this vector

    for(int i = 0; i < vec_size; i++){
        // transform next bytes into an integer in {0, 1, ..., mod_perm - 1}
        vec[i] = random_bytes[j];
        for (int k = 1; k < bytes_per_element; k++){
            vec[i] <<= 8;
            vec[i] += random_bytes[j + k];
        }
        // now per[i] = sum b_k * 256**k where b_k are random bytes, so it can by slightly larger than modulus-1
        vec[i] %= modulus;
        j += bytes_per_element; // we have consumed `bytes_per_element` bytes
    }

    this->used_bytes = j;
}


void CSPRNG::get_random_binary_vector(vector<int>& vec, int vec_size){

	if (vec.size() != (unsigned int)vec_size)
	    vec = vector<int>(vec_size);

    int needed_bytes = ceil(vec_size / 8.0);

    // assert there are enough bytes in the ramdomness pool to generate the vector
    assert(nbytes - used_bytes >= needed_bytes);

    int i = 0;

    for(int j = used_bytes; j < used_bytes + needed_bytes; j++){
        uint8_t bytej = random_bytes[j];
        int k = 0;
        while(k < 8 && i < vec_size){
            vec[i] = bytej % 2;
            bytej >>= 1;
            k++;
            i++;
        }
    }
    this->used_bytes += needed_bytes;
}

        
int CSPRNG::available_bytes() const{
    return nbytes - used_bytes;
}



std::ostream& operator<<(std::ostream& os, const CSPRNG& u){
    os << "CSPRNG: {" 
        << "nbytes: " << u.nbytes
        << ", used_bytes: " << u.used_bytes
        << ", unused_bytes: " << u.available_bytes()
        << ", AES key: ";
    for(int i = 0; i < 15; i++){
        os << (int)u.aes_key[i] << " ";
    }
    os << (int)u.aes_key[15] << "}";
    return os;
}

