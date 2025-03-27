/* File for creating, deleting and doing operations on bitVectors */
#include <assert.h>
#include <math.h>
#include <stdlib.h>

typedef unsigned int u32;
typedef unsigned char u8;

extern u8 weight[256];

struct BitVector {
  u32 *values;
  int length, wordLenght;
  u8 con;
};

struct BitVector *NewBitVector(int len);
void DeleteBitVector(struct BitVector *bv);
void SetBit(struct BitVector *bv, int index);
void UnSetBit(struct BitVector *bv, int index);
u8 IsSet(struct BitVector *bv, int index);
struct BitVector *RandomBitVector(int len);
void FlipBit(struct BitVector *bv, int index);
void Wipe(struct BitVector *bv);
void Embed(struct BitVector *bv, struct BitVector *ebv);
int HighestSetBit(struct BitVector *bv);
int LowestSetBit(struct BitVector *bv);
void CopyV1toV2(struct BitVector *v1, struct BitVector *v2);
u8 Equal(struct BitVector *v1, struct BitVector *v2);
struct BitVector *v1ANDv2(struct BitVector *v1, struct BitVector *v2);
void ORv1toV2(struct BitVector *v1, struct BitVector *v2);
void AddV1toV2(struct BitVector *v1, struct BitVector *v2);
void RotateLeft(struct BitVector *bv, int rr);

int HammingWeight(struct BitVector *bv);
int HammingDistance(struct BitVector *bv1, struct BitVector *bv2);

void PrintVectorHEX(struct BitVector *bv);
void PrintVectorBits(struct BitVector *bv);