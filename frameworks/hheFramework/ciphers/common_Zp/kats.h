#pragma once

#include <x86intrin.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iterator>
#include <vector>

#include "../common/utils.h"
#include "Cipher.h"
#include "matrix.h"

template <class T>
class KnownAnswerTestZp {
 public:
  enum Testcase { MAT, DEC, USE_CASE, PREP };

 private:
  static constexpr bool PRESET_SEED = true;
  static constexpr size_t NUM_MATMULS_SQUARES = 3;
  static constexpr bool LAST_SQUARE = false;
  utils::SeededRandom rand;
  std::vector<uint64_t> key;
  std::vector<uint64_t> plaintext;
  std::vector<uint64_t> ciphertext_expected;
  size_t modulus;
  Testcase tc;
  size_t N;

 public:
  KnownAnswerTestZp(std::vector<uint64_t> key, std::vector<uint64_t> plaintext,
                    std::vector<uint64_t> ciphertext_expected, size_t modulus,
                    Testcase tc = DEC, size_t N = 4)
      : rand(PRESET_SEED),
        key(key),
        plaintext(plaintext),
        ciphertext_expected(ciphertext_expected),
        modulus(modulus),
        tc(tc),
        N(N) {}

  KnownAnswerTestZp(const uint64_t *key, size_t key_size,
                    const uint64_t *plaintext, size_t plaintext_size,
                    const uint64_t *ciphertext_expected, size_t ciphertext_size,
                    size_t modulus, Testcase tc = DEC, size_t N = 4)
      : rand(PRESET_SEED),
        key(key, key + key_size),
        plaintext(plaintext, plaintext + plaintext_size),
        ciphertext_expected(ciphertext_expected,
                            ciphertext_expected + ciphertext_size),
        modulus(modulus),
        tc(tc),
        N(N) {}

  bool mat_test() {
    long startMem, endMem;
    std::cout << "> Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            modulus);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() % modulus);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % modulus);  // not cryptosecure ;)
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-=== Computing in plain ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    matrix::vector vo;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi, b[r], modulus);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi, vo, modulus);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    return true;
  }

  bool dec_test() {
    long startMem, endMem;
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    T cipher(key, modulus);
    std::cout << "-=== Final decrypt ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> plain = cipher.decrypt(ciphertext_expected);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    if (plain != plaintext) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("key:      ", key, std::cerr);
      utils::print_vector("ciphertext", ciphertext_expected, std::cerr);
      utils::print_vector("plain:    ", plaintext, std::cerr);
      utils::print_vector("got:      ", plain, std::cerr);
      return false;
    }
    return true;
  }

  bool test() {
    long startMem, endMem;
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    std::cout << "> Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            modulus);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() % modulus);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % modulus);  // not cryptosecure ;)
    }

    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-=== Computing in plain ===-" << std::endl;

    matrix::vector vo, vo_p(N), vi_tmp;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi_tmp, b[r], modulus);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, modulus);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Encrypting input ===-" << std::endl;
    T cipher(key, modulus);
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> ciph = cipher.encrypt(vi);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Decrypting ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> plain = cipher.decrypt(ciph);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Computing ===-" << std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo_p, m[r], plain, b[r], modulus);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(plain, vo_p, modulus);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool prep_test() {
    long startMem, endMem;
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff;

    T cipher(key, modulus);
    std::cout << "-=== Preprocessing constants for 1 block ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.prep_one_block();
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::microseconds>(
        time_end - time_start);
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Time: " << time_diff.count() << " µs" << std::endl;
    std::cout << "-> Cycles: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    return true;
  }

  virtual bool run_test() {
    switch (tc) {
      case MAT:
        return mat_test();
      case DEC:
        return dec_test();
      case USE_CASE:
        return test();
      case PREP:
        return prep_test();
      default: {
        std::cout << "Testcase not found... " << std::endl;
        return false;
      }
    }
  }
};
