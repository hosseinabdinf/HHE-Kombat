/* Reference implementation for generating key stream for the Fasta stream
cipher.  Note that the code makes use of the GMP library, licensed under the GNU
LGPLv3 and GNU GPLv2 licenses.

Copyright (c) 2022 Simula UiB

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// #include "bitVector.h"
#include "Fasta.h"
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

int R1[4], R2[4], R3[4], ii[4], jj[4],
    ll[4]; // arrays for the rotation amounts.  Updated for every linear
           // transformation.

mpz_t T; // T will be set to the constant 7896437765612010000 = 62^4 * 19^4 *
         // 5^4 * 9^4, the number of different linear transformations in Fasta.

void fillRotationAmounts(mpz_t N) {
  /* Generates the 24 rotation amounts given by N, and fills them in the arrays
   * R1, R2, R3, ii, jj and ll. */
  int i;
  mpz_t r, q;

  mpz_init(r);
  mpz_init(q);
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 3);
    R1[i] = 1 + (int)mpz_get_ui(r);
    N = q;
  } // set r1 rotation amounts for the four Theta-applications
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 3);
    R2[i] = 4 + (int)mpz_get_ui(r);
    R3[i] = 7 + ((2 * R1[i] + R2[i] + 1) % 3);
    N = q;
  } // set r2 and r3 rotation amonuts
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 5);
    ii[i] = (int)mpz_get_ui(r);
    N = q;
  } // set rotation amounts between first two Theta applications
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 19);
    jj[i] = (int)mpz_get_ui(r);
    N = q;
  } // set rotation amounts used after second Theta application
  for (i = 0; i < 4; ++i) {
    mpz_fdiv_qr_ui(q, r, N, 62);
    ll[i] = (int)mpz_get_ui(r);
    N = q;
  } // set rotation amounts after third Theta application
}

void printRotationAmounts() {
  /* Prints the current rotation amounts. */
  int i;

  for (i = 0; i < 4; ++i)
    printf("%d ", R1[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", R2[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", R3[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%d ", ii[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%2d ", jj[i]);
  printf("|");
  for (i = 0; i < 4; ++i)
    printf("%2d ", ll[i]);
  printf("|\n");
}

void printState(struct BitVector **input) {
  /* Prints out the five words in input as hexadecimal strings on five lines. */
  int i;

  for (i = 0; i < 5; ++i) {
    PrintVectorHEX(input[i]);
    printf("\n");
  }
  printf("\n");
}

void deleteState(struct BitVector **state) {
  /* Frees memory allocated by state. */
  int i;

  for (i = 0; i < 5; ++i)
    DeleteBitVector(state[i]);
  free(state);
}

struct BitVector **ThetaIteration(struct BitVector **input, int r1, int r2,
                                  int r3) {
  /* Returns Theta(input) with the variable rotations 1=r1<=3 and 4<=r2<=6 and
   * 7<=r3<=9. */
  struct BitVector *sum, *w1, *w2, *w3;
  struct BitVector **out;
  int i;

  sum = NewBitVector(329);
  w1 = NewBitVector(329);
  w2 = NewBitVector(329);
  w3 = NewBitVector(329);

  for (i = 0; i < 5; ++i)
    AddV1toV2(input[i], sum);
  // sum=i0+i1+i2+i3+i4

  CopyV1toV2(sum, w1);
  RotateLeft(w1, r1);

  CopyV1toV2(sum, w2);
  RotateLeft(w2, r2);

  CopyV1toV2(sum, w3);
  RotateLeft(w3, r3);

  AddV1toV2(w1, sum);
  AddV1toV2(w2, sum);
  AddV1toV2(w3, sum);
  // here sum is the output of Theta

  out = (struct BitVector **)malloc(5 * sizeof(struct BitVector *));
  for (i = 0; i < 5; ++i) {
    out[i] = NewBitVector(329);
    CopyV1toV2(input[i], out[i]);
    AddV1toV2(sum, out[i]);
  }
  // output from Theta added back onto the input words
  DeleteBitVector(sum);
  DeleteBitVector(w1);
  DeleteBitVector(w2);
  DeleteBitVector(w3);

  return out;
}

struct BitVector **LinearTransformation(struct BitVector **input) {
  /* Returns the linear transformation of the input, using the current rotation
   * amounts. */
  struct BitVector **out, **tmp;
  int i;

  out = ThetaIteration(input, R1[0], R2[0], R3[0]);
  // first Theta done

  for (i = 0; i < 4; ++i)
    RotateLeft(out[i + 1], 5 * (i + 1) + ii[i]);
  // first rotations done

  tmp = ThetaIteration(out, R1[1], R2[1], R3[1]);
  deleteState(out); // clean up old memory
  out = tmp;

  for (i = 0; i < 4; ++i)
    RotateLeft(out[i + 1], 19 * (i + 1) + jj[i]);

  tmp = ThetaIteration(out, R1[2], R2[2], R3[2]);
  deleteState(out);
  out = tmp;

  for (i = 0; i < 4; ++i)
    RotateLeft(out[i + 1], 62 * (i + 1) + ll[i]);

  tmp = ThetaIteration(out, R1[3], R2[3], R3[3]);
  deleteState(out);
  out = tmp;

  return out;
}

struct BitVector **Chi(struct BitVector **input) {
  /* Returns Chi(input), where Chi is 5 applications of Keccak's Chi-function on
   * a 329-bit block. */
  struct BitVector **out, *w1, *w2;
  int i;

  out = (struct BitVector **)malloc(5 * sizeof(struct BitVector *));
  w1 = NewBitVector(329);
  w2 = NewBitVector(329);
  for (i = 0; i < 5; ++i) {
    CopyV1toV2(input[i], w1);
    CopyV1toV2(input[i], w2);
    RotateLeft(w1, 1);
    RotateLeft(w2, 2);
    out[i] = v1ANDv2(w1, w2);
    AddV1toV2(input[i], out[i]);
    AddV1toV2(w2, out[i]);
  }
  DeleteBitVector(w1);
  DeleteBitVector(w2);

  return out;
}

void bitVectorToGMP(mpz_t ret, struct BitVector *bv) {
  /* Returns the GMP-number represented by bv in ret. */
  mpz_t pow2;
  int i;

  mpz_set_ui(ret, 0);
  mpz_init(pow2);
  for (i = 0; i < bv->length; ++i) {
    if (IsSet(bv, i)) {
      mpz_ui_pow_ui(pow2, 2, i);
      mpz_add(ret, ret, pow2);
    }
  }
}

struct BitVector *generateKeyStreamBlock(struct BitVector *key) {
  /* Returns a 1645-bit string of Fasta key stream from the given key and the
   * given state of the random generator. */
  struct BitVector **input, **tmp, **out, *keyStream, *eks, *alpha_r, **alpha_c;
  mpz_t N;
  int i, j;

  mpz_init(N);
  input = (struct BitVector **)malloc(5 * sizeof(struct BitVector *));
  alpha_c = (struct BitVector **)malloc(5 * sizeof(struct BitVector *));
  for (i = 0; i < 5; ++i) {
    input[i] = NewBitVector(329);
    CopyV1toV2(key, input[i]);
    RotateLeft(input[i], i);
  }
  // cipher state initialized with key

  alpha_r = RandomBitVector(63);
  bitVectorToGMP(N, alpha_r);
  mpz_mod(N, N, T);
  DeleteBitVector(alpha_r);
  fillRotationAmounts(N);
  out = LinearTransformation(input);
  deleteState(input);
  for (i = 0; i < 5; ++i) {
    alpha_c[i] = RandomBitVector(329);
    AddV1toV2(alpha_c[i], out[i]);
    DeleteBitVector(alpha_c[i]);
  }
  // Initial affine transformation done

  for (i = 0; i < 6; ++i) { // Fasta has six rounds
    tmp = Chi(out);
    // tmp is state after Chi-transformation
    deleteState(out);

    alpha_r = RandomBitVector(63);
    bitVectorToGMP(N, alpha_r);
    mpz_mod(N, N, T);
    DeleteBitVector(alpha_r);
    fillRotationAmounts(N);
    out = LinearTransformation(tmp);
    deleteState(tmp);
    for (j = 0; j < 5; ++j) {
      alpha_c[j] = RandomBitVector(329);
      AddV1toV2(alpha_c[j], out[j]);
      DeleteBitVector(alpha_c[j]);
    }
    // out is now state after affine transformation
  }
  free(alpha_c);

  for (i = 0; i < 5; ++i)
    AddV1toV2(key, out[i]); // feed-forward of key

  keyStream = NewBitVector(1645);
  eks = NewBitVector(1645);
  Embed(out[0], keyStream);
  for (i = 1; i < 5; ++i) {
    Embed(out[i], eks);
    RotateLeft(keyStream, 329);
    AddV1toV2(eks, keyStream);
  }
  // final cipher state of 5 x 329-bit vectors converted to one 1645-bit vector

  return keyStream;
}

struct ciphertext *encrypt(struct plaintext *PT, struct BitVector *key) {
  /* Encrypts the plaintext stored in PT with the given key, and returns it in a
   * ciphertext object. */
  int i;
  struct ciphertext *CT;

  srandom(1); // The seed for the randomness can be set arbitrary, but must be
              // the same in the encryption and decryption procedures
  mpz_init_set_str(T, "7896437765612010000", 10);

  CT = (struct ciphertext *)malloc(sizeof(struct ciphertext));
  CT->block =
      (struct BitVector **)malloc(PT->numBlocks * sizeof(struct BitVector *));
  CT->numBlocks = 0;
  for (i = 0; i < PT->numBlocks; ++i) {
    CT->block[i] = generateKeyStreamBlock(key);
    AddV1toV2(PT->block[i], CT->block[i]);
    CT->numBlocks++;
  }

  return CT;
}

struct plaintext *decrypt(struct ciphertext *CT, struct BitVector *key) {
  /* Decrypts the ciphertext stored in CT with the given key, and returns it in
   * a plaintext object. */
  int i;
  struct plaintext *PT;

  srandom(1); // The seed for the randomness can be set arbitrary, but must be
              // the same in the encryption and decryption procedures
  mpz_init_set_str(T, "7896437765612010000", 10);

  PT = (struct plaintext *)malloc(sizeof(struct plaintext));
  PT->block =
      (struct BitVector **)malloc(CT->numBlocks * sizeof(struct BitVector *));
  PT->numBlocks = 0;
  for (i = 0; i < CT->numBlocks; ++i) {
    PT->block[i] = generateKeyStreamBlock(key);
    AddV1toV2(CT->block[i], PT->block[i]);
    PT->numBlocks++;
  }

  return PT;
}
