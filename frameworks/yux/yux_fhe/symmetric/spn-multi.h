#pragma once
#ifndef SPN_MULTI_H
#define SPN_MULTI_H
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdint.h>

using namespace std;
void decryption(unsigned char out[], unsigned char in[],
                unsigned char RoundKey[], int Nr);
void encryption(unsigned char out[], unsigned char in[],
                unsigned char RoundKey[], int Nr);
long KeyExpansion(unsigned char RoundKey[], long ROUND, long blockByte,
                  unsigned char Key[]);
void decRoundKey(unsigned char RoundKey_invert[], unsigned char RoundKey[],
                 long ROUND, long BlockByte);
#endif
