#pragma once
#ifndef SPN_MULTI_H
#define SPN_MULTI_H
#include <cstdlib>
#include <cstdio>
#include <stdint.h>
#include <iostream>

using namespace std;
void decryption(unsigned char out[], unsigned char in[], unsigned char RoundKey[], int Nr);
void encryption(unsigned char out[], unsigned char in[], unsigned char RoundKey[], int Nr);
long KeyExpansion(unsigned char RoundKey[], long ROUND, long blockByte,  unsigned char Key[]);
void decRoundKey(unsigned char RoundKey_invert[], unsigned char RoundKey[], long ROUND,long BlockByte);
#endif
