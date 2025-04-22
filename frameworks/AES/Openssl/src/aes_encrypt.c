#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/utils.h"

// Error handling
void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

// AES-128-CBC encryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int main(void) {
  PrintHeader("OpenSSL AES - Pure SKE");

  // 16 bytes (128-bit) key and IV
  unsigned char key[16] = "0123456789abcdef";
  unsigned char iv[16] = "abcdef9876543210";

  // 16 bytes plaintext (128-bit)
  unsigned char plaintext[16] = "Hello1234567890";

  // Buffer for ciphertext
  unsigned char ciphertext[128];
  int ciphertext_len;

  // Encrypt the plaintext
  BENCHMARK_ITER("AES-128-CBC Encryption", 1000, {
    ciphertext_len =
        encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
  });
  // ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv,
  // ciphertext);

  // Print ciphertext in hex
  printf("Ciphertext is:\n");
  for (int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
  printf("\n");

  return 0;
}
