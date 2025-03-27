#pragma once
#ifndef SPN_MULTI_H16
#define SPN_MULTI_H16
#include <cstring>
#include<cstdlib>
#include<cstdio>
#include <stdint.h>
#include <iostream>

namespace std {} using namespace std;
// The round number is ROUND =10
#include <NTL/GF2X.h>
#include <NTL/SmartPtr.h>
#include <NTL/ZZX.h>
#include <NTL/GF2E.h>

namespace NTL {} using namespace NTL;

static const unsigned char roundConstant_char = 0xCD;


void Yu2x_16_decRoundKey(Vec<GF2E>& RoundKey_invert, Vec<GF2E>& RoundKey, long Nr,long blockByte);
void Yu2x_16_encryption(unsigned char outCh[], unsigned char inCh[], Vec<GF2E>& RoundKey, int Nr);
void Yu2x_16_decryption(unsigned char outCh[], unsigned char inCh[], Vec<GF2E>& RoundKey, int Nr);
long Yu2x_16_KeyExpansion(unsigned char RoundKey[], long round, long blockByte,  unsigned char Key[]);
long Yu2x_16_KeyExpansion1(Vec<GF2E>& RoundKey, long round, long blockByte, unsigned char KeyCh[]);

#endif