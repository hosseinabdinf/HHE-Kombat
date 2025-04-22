// AES.h
#ifndef AES_H
#define AES_H

#include <cstdio>

#define Nb 4

int getSBoxValue(int num);
long AESKeyExpansion(unsigned char RoundKey[240], unsigned char Key[], int NN);
void AddRoundKey(unsigned char state[4][4], unsigned char RoundKey[240], int round);
void SubBytes(unsigned char state[4][4]);
void ShiftRows(unsigned char state[4][4]);
void MixColumns(unsigned char state[4][4]);
void Cipher(unsigned char out[16], unsigned char in[16], unsigned char RoundKey[240], int Nr);

#endif // AES_H