#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tiny/aes.h"
#include "utils/utils.h"

int main() {
  PrintHeader("TinyAES - Pure SKE");
  // 16 bytes key and IV (AES-128)
  uint8_t key[16] = "0123456789abcdef";
  uint8_t iv[16] = "abcdef9876543210";

  // Input: 16 bytes
  uint8_t input[16] = "Hello1234567890";
  uint8_t buffer[16];
  memcpy(buffer, input, 16);  // Copy to buffer since CBC encrypts in-place

  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, key, iv);

  BENCHMARK_ITER("AES-128-CBC Encryption", 1000, {
    AES_CBC_encrypt_buffer(&ctx, buffer, 16);  // Length must be multiple of 16
  });

  // Print ciphertext
  printf("Encrypted data:\n");
  for (int i = 0; i < 16; i++) printf("%02x", buffer[i]);
  printf("\n");

  return 0;
}
