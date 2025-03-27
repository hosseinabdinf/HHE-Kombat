#ifndef FASTA_H
#define FASTA_H

#include "bitVector.h"
#include <gmp.h>
#include <stdlib.h>

typedef struct plaintext {
  struct BitVector **block;
  int numBlocks;
} plaintext;

typedef struct ciphertext {
  struct BitVector **block;
  int numBlocks;
} ciphertext;

void fillRotationAmounts(mpz_t N);
void printRotationAmounts();
void printState(struct BitVector **input);
void deleteState(struct BitVector **state);
struct BitVector **ThetaIteration(struct BitVector **input, int r1, int r2,
                                  int r3);
struct BitVector **LinearTransformation(struct BitVector **input);
struct BitVector **Chi(struct BitVector **input);
void bitVectorToGMP(mpz_t ret, struct BitVector *bv);
struct BitVector *generateKeyStreamBlock(struct BitVector *key);
struct ciphertext *encrypt(struct plaintext *PT, struct BitVector *key);
struct plaintext *decrypt(struct ciphertext *CT, struct BitVector *key);

#endif