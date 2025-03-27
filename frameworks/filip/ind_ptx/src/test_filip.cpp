#include "filip.h"
#include <cassert>
#include <iostream>


using namespace std;


template <typename ELEMENT>
std::ostream& operator<<(std::ostream& os, const vector<ELEMENT>& u){
	unsigned int lastPosition = u.size() - 1;
	for (unsigned int i = 0; i < lastPosition; i++){
		os << u[i] << ", ";
	}
	os << u[lastPosition];
	return os;
}

int main()
{

    int N = 1 << 10; // length of the secret key
    int n = 144;    // size of subset used to encrypt each bit
    int k = 63;     // number of bits added in the threshold function
    int d = 35;          // threshold limit
    uint8_t aes_key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    FiLIP filip(N, n, k, d, aes_key);

    cout << filip << endl;

    long int iv = 1234567;

    // create a random message
    srand(time(NULL));
    int size_msg = 1 << 10;
    vector<int> m(size_msg);
    for(int i = 0; i < size_msg; i++)
        m[i] = rand() % 2; 

    cout << "vector<int> c = filip.enc(iv, m);" << endl;
    vector<int> c = filip.enc(iv, m);

    cout << "vector<int> dec_m = filip.dec(iv, c);" << endl;
    vector<int> dec_m = filip.dec(iv, c);

    cout << "    m  = " << m << endl;
    cout << "    c  = " << c << endl;
    cout << "dec(c) = " << dec_m << endl;

    assert(m == dec_m);

    return 0;
}
