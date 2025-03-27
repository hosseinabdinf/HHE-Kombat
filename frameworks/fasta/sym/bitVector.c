/* File for creating, deleting and doing operations on bitVectors */
#include "bitVector.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned int u32;
typedef unsigned char u8;

u8 weight[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

struct BitVector *NewBitVector(int len) {
  /* Returns a pointer to a bitVector of length len, initialized to 0-vector. */
  struct BitVector *bv;

  bv = (struct BitVector *)malloc(sizeof(struct BitVector));
  bv->length = len;
  bv->wordLenght = (bv->length + 31) >> 5;
  bv->values = (u32 *)calloc(bv->wordLenght, sizeof(u32));
  bv->con = 0;
  return bv;
}

void DeleteBitVector(struct BitVector *bv) {
  /* Frees all memory allocated to bv. */
  free(bv->values);
  free(bv);
}

void SetBit(struct BitVector *bv, int index) {
  /* Sets bit index in bv to 1. */
  if (index > bv->length - 1 || index < 0) {
    printf("(bitVector->setBit)Can't set bit %d in vector of length %d\n",
           index, bv->length);
    exit(0);
  }
  bv->values[index >> 5] |= 1 << (index & 0x1f);
}

void UnSetBit(struct BitVector *bv, int index) {
  /* Sets bit index in bv to 0. */
  if (index > bv->length - 1 || index < 0) {
    printf("(bitVector->unSetBit)Can't un-set bit %d in vector of length %d\n",
           index, bv->length);
    exit(0);
  }
  if (IsSet(bv, index)) // ensures the bit really is set
    bv->values[index >> 5] ^= 1 << (index & 0x1f);
}

u8 IsSet(struct BitVector *bv, int index) {
  /* Returns 1 if bit index in bv is set, 0 otherwise. */
  if (bv->length < index) {
    printf("(bitVector->isSet)Trying to check bit %d in vector of length %d\n",
           index, bv->length);
    return 0;
  }
  if (bv->values[index >> 5] & (1 << (index & 0x1f)))
    return 1;
  else
    return 0;
}

struct BitVector *RandomBitVector(int len) {
  /* Returns a random bitVector of length len. */
  struct BitVector *bv;
  int i;
  u32 mask, rr;

  bv = NewBitVector(len);
  for (i = 0; i < bv->wordLenght; ++i) {
    bv->values[i] = (u32)random();
    if (32 * i + 31 < len) {
      rr = (u32)random();
      if (rr & 1)
        SetBit(bv, 32 * i +
                       31); // because highest set bit from random() is always 0
    }
  }
  mask = (1 << (len & 0x1f)) - 1;
  if (mask)
    bv->values[bv->wordLenght - 1] &= mask; // setting bits higher than len to 0

  return bv;
}

void FlipBit(struct BitVector *bv, int index) {
  /* Flips bit index in bv. */
  if (index > bv->length - 1) {
    printf("(bitVector->flipBit)Can't flip bit %d in vector of length %d\n",
           index, bv->length);
    exit(0);
  }
  if (IsSet(bv, index))
    UnSetBit(bv, index);
  else
    SetBit(bv, index);
}

void Wipe(struct BitVector *bv) {
  /* Sets all bits in bv to 0. */
  int i;

  for (i = 0; i < bv->wordLenght; ++i)
    bv->values[i] = 0;
  bv->con = 0;
}

void Embed(struct BitVector *bv, struct BitVector *ebv) {
  /* Copies bv of shorter or equal length than ebv, into ebv. */
  int i;

  if (bv->length > ebv->length) {
    printf("(Embed)Can't Embed vector of length %d into vector of length %d.\n",
           bv->length, ebv->length);
    exit(0);
  }
  Wipe(ebv);
  for (i = 0; i < bv->wordLenght; ++i)
    ebv->values[i] = bv->values[i];
}

int HighestSetBit(struct BitVector *bv) {
  /* Returns the index of the highest set bit in bv.  Returns -1 if bv=0. */
  int i, j;
  u32 m1, m2;

  i = bv->wordLenght - 1;
  while (i >= 0 && bv->values[i] == 0)
    i--;
  if (i < 0)
    return -1;

  j = 0;
  m1 = bv->values[i] & 0xffff0000;
  if (m1) {
    j += 16;
    m1 >>= 16;
  } else
    m1 = bv->values[i] & 0xffff;

  m2 = m1 & 0xff00;
  if (m2) {
    j += 8;
    m2 >>= 8;
  } else
    m2 = m1 & 0xff;

  m1 = m2 & 0xf0;
  if (m1) {
    j += 4;
    m1 >>= 4;
  } else
    m1 = m2 & 0xf;

  m2 = m1 & 0xc;
  if (m2) {
    j += 2;
    m2 >>= 2;
  } else
    m2 = m1 & 0x3;

  if (m2 > 1)
    j++;

  return 32 * i + j;
}

int LowestSetBit(struct BitVector *bv) {
  /* Returns index of lowest set bit in bv.  Returns -1 if bv=0. */
  int i = 0, j;
  u32 m1, m2;

  while (i < bv->wordLenght && bv->values[i] == 0)
    ++i;
  if (i == bv->wordLenght)
    return -1;

  m1 = bv->values[i] & 0xffff;
  j = 0;
  if (m1 == 0) {
    j += 16;
    m1 = (bv->values[i] & 0xffff0000) >> 16;
  }

  m2 = m1 & 0xff;
  if (m2 == 0) {
    j += 8;
    m2 = (m1 & 0xff00) >> 8;
  }

  m1 = m2 & 0xf;
  if (m1 == 0) {
    j += 4;
    m1 = (m2 & 0xf0) >> 4;
  }

  m2 = m1 & 0x3;
  if (m2 == 0) {
    j += 2;
    m2 = (m1 & 0xc) >> 2;
  }

  if (m2 == 2)
    j++;

  return 32 * i + j;
}

void CopyV1toV2(struct BitVector *v1, struct BitVector *v2) {
  /* Makes v2 a copy of v1. */
  int i;

  if (v1->length != v2->length) {
    printf("(copyV1toV2)Trying to copy vector of length %d into vector of "
           "legth %d\n",
           v1->length, v2->length);
    exit(0);
  }
  for (i = 0; i < v1->wordLenght; ++i)
    v2->values[i] = v1->values[i];
  v2->con = v1->con;
}

u8 Equal(struct BitVector *v1, struct BitVector *v2) {
  /* Returns 1 if v1 and v2 are equal, and 0 otherwise. */
  int i;

  if (v1->length != v2->length)
    return 0;
  if (v1->con != v2->con)
    return 0;
  for (i = 0; i < v1->wordLenght; ++i) {
    if (v1->values[i] ^ v2->values[i])
      return 0;
  }
  return 1;
}

int HammingWeight(struct BitVector *bv) {
  /* Returns the Hamming weight of bv. */
  int i, w = 0;

  for (i = 0; i < bv->wordLenght; ++i) {
    w += weight[bv->values[i] & 0xff];
    w += weight[(bv->values[i] >> 8) & 0xff];
    w += weight[(bv->values[i] >> 16) & 0xff];
    w += weight[bv->values[i] >> 24];
  }
  return w;
}

struct BitVector *v1ANDv2(struct BitVector *v1, struct BitVector *v2) {
  /* Returns the bitwise AND of v1 and v2. */
  struct BitVector *ret;
  int i;

  if (v1->length != v2->length) {
    printf("(bitVector->v1ANDv2)Vectors have different lengths (%d and %d)\n",
           v1->length, v2->length);
    exit(0);
  }
  ret = NewBitVector(v1->length);
  for (i = 0; i < ret->wordLenght; ++i)
    ret->values[i] = v1->values[i] & v2->values[i];
  ret->con = v1->con & v2->con;

  return ret;
}

void ORv1toV2(struct BitVector *v1, struct BitVector *v2) {
  /* ORs v1 onto v2. */
  int i;

  if (v1->length != v2->length) {
    printf("(bitVector->ORv1toV2)Vectors not of same lengths (%d and %d)\n",
           v1->length, v2->length);
    exit(0);
  }
  for (i = 0; i < v1->wordLenght; ++i)
    v2->values[i] |= v1->values[i];
  v2->con |= v1->con;
}

void AddV1toV2(struct BitVector *v1, struct BitVector *v2) {
  /* Adds v1 to v2 using XOR. */
  int i;

  if (v1->length != v2->length) {
    printf("(bitVector->addV1toV2)Vectors not of same lengths (%d and %d)\n",
           v1->length, v2->length);
    exit(0);
  }
  for (i = 0; i < v1->wordLenght; ++i)
    v2->values[i] ^= v1->values[i];
  v2->con ^= v1->con;
}

void RotateLeft(struct BitVector *bv, int rr) {
  /* Rotates bv rr positions to the left, cyclically */
  int i, j;
  struct BitVector *topBits;

  if (rr == 0)
    return;

  topBits = NewBitVector(rr);
  j = 0;
  for (i = bv->length - rr; i < bv->length; ++i) {
    if (IsSet(bv, i))
      SetBit(topBits, j);
    j++;
  }
  for (i = bv->length - 1; i >= rr; --i) {
    if (IsSet(bv, i - rr))
      SetBit(bv, i);
    else
      UnSetBit(bv, i);
  }
  for (i = 0; i < rr; ++i) {
    if (IsSet(topBits, i))
      SetBit(bv, i);
    else
      UnSetBit(bv, i);
  }
  DeleteBitVector(topBits);
}

int HammingDistance(struct BitVector *bv1, struct BitVector *bv2) {
  /* Returns the Hamming distance between bv1 and bv2. */
  struct BitVector *s;
  int retd;

  if (bv1->length != bv2->length) {
    printf("(bitVector->hammingDistance)Trying to compute distance between "
           "vectors of length %d and %d\n",
           bv1->length, bv2->length);
    exit(0);
  }

  s = NewBitVector(bv1->length);
  CopyV1toV2(bv1, s);
  AddV1toV2(bv2, s);
  retd = HammingWeight(s);
  DeleteBitVector(s);

  return retd;
}

void PrintVectorHEX(struct BitVector *bv) {
  int i;

  for (i = bv->wordLenght - 1; i >= 0; --i)
    printf("%08x ", bv->values[i]);
}

void PrintVectorBits(struct BitVector *bv) {
  int i;

  printf("[");
  for (i = bv->length - 1; i >= 0; --i) {
    if (IsSet(bv, i))
      printf("1");
    else
      printf(".");
  }
  printf("]");
}
