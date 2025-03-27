/*
  Example program that encrypts a plaintext file using Fasta and writes the
  ciphertext to file. Then it reads in the ciphertext file and decrypts it to
  verify that we get back the same plaintext. Key is generated at random on every
  run.
*/

#include "Fasta.h"
#include "utils.h"
#include <bits/time.h>
// #include <cstddef>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <x86intrin.h>

struct plaintext *readPlaintextFile(const char *filename) {
  /* Reads in plaintext from the given file and returns it in a plaintext
   * object. */
  FILE *fp;
  struct plaintext *PT;
  int i, j;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("Could not open the file %s\n", filename);
    exit(0);
  }

  PT = (struct plaintext *)malloc(sizeof(struct plaintext *));
  fscanf(fp, "%d\n", &PT->numBlocks);
  PT->block =
      (struct BitVector **)malloc(PT->numBlocks * sizeof(struct BitVector *));
  for (i = 0; i < PT->numBlocks; ++i) {
    PT->block[i] = NewBitVector(1645);
    for (j = 51; j >= 0; --j)
      fscanf(fp, "%8x ", PT->block[i]->values + j);
    fscanf(fp, "\n");
  }
  fclose(fp);

  return PT;
}

struct ciphertext *readCiphertextFile(const char *filename) {
  /* Reads in ciphertext from the given file and returns it in a ciphertext
   * object. */
  FILE *fp;
  struct ciphertext *CT;
  int i, j;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("Could not open the file %s\n", filename);
    exit(0);
  }

  CT = (struct ciphertext *)malloc(sizeof(struct ciphertext *));
  fscanf(fp, "%d\n", &CT->numBlocks);
  CT->block =
      (struct BitVector **)malloc(CT->numBlocks * sizeof(struct BitVector *));
  for (i = 0; i < CT->numBlocks; ++i) {
    CT->block[i] = NewBitVector(1645);
    for (j = 51; j >= 0; --j)
      fscanf(fp, "%8x ", CT->block[i]->values + j);
    fscanf(fp, "\n");
  }
  fclose(fp);

  return CT;
}

void printPlaintextFile(struct plaintext *PT, const char *filename) {
  /* Prints the plaintext PT to a file with the given name. */
  FILE *fp;
  int i, j;

  fp = fopen(filename, "w");
  fprintf(fp, "%d\n", PT->numBlocks);
  for (i = 0; i < PT->numBlocks; ++i) {
    for (j = 51; j >= 0; --j)
      fprintf(fp, "%08x ", PT->block[i]->values[j]);
    fprintf(fp, "\n");
  }
  fclose(fp);
}

void printCiphertextFile(struct ciphertext *CT, const char *filename) {
  /* Prints the ciphertext CT to a file with the given name. */
  FILE *fp;
  int i, j;

  fp = fopen(filename, "w");
  fprintf(fp, "%d\n", CT->numBlocks);
  for (i = 0; i < CT->numBlocks; ++i) {
    for (j = 51; j >= 0; --j)
      fprintf(fp, "%08x ", CT->block[i]->values[j]);
    fprintf(fp, "\n");
  }
  fclose(fp);
}

int main(int argc, char *argv[]) {
  // benchmarking variables
  long start_mem, end_mem;
  uint32_t aux;
  uint64_t start_cycle, end_cycle;
  struct timespec start_time, end_time;

  struct plaintext *ptxt, *decrypted;
  struct ciphertext *ctxt;
  struct BitVector *K;

  K = RandomBitVector(329);
  ptxt = readPlaintextFile("originalPlaintext.txt");
  printf("> Reading Plaintext (numblock: %d, lenght: %d)\n", ptxt->numBlocks,
         ptxt->block[0]->length);

  printf("-=== SYM Encryption ===-\n");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_cycle = __rdtscp(&aux);
  start_mem = GetMemoryUsage();

  ctxt = encrypt(ptxt, K);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);

  // print the benchmarks
  printf("-> done! \n");
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  printf("-=== SYM Decryption ===-\n");
  clock_gettime(CLOCK_MONOTONIC, &start_time);
  start_cycle = __rdtscp(&aux);
  start_mem = GetMemoryUsage();

  decrypted = decrypt(ctxt, K);

  end_cycle = __rdtscp(&aux);
  end_mem = GetMemoryUsage();
  clock_gettime(CLOCK_MONOTONIC, &end_time);

  // print the benchmarks
  printf("-> done! \n");
  PrintTimeNS(start_time, end_time);
  PrintCycles(start_cycle, end_cycle);
  PrintMemory(start_mem, end_mem);

  // printCiphertextFile(ctxt, "ciphertext.txt");
  // printf("> Encryption of plaintext written to ciphertext.txt\n");
  // printPlaintextFile(decrypted, "decryptedPlaintext.txt");
  // printf("Ciphertext decrypted and written to decryptedPlaintext.txt\n");
}

void printTimeNS() {}