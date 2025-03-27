#pragma once

#include <helib/timing.h>

#include "../common/utils.h"
#include "helib/helib.h"
#include "matrix.h"

#include <x86intrin.h>

template <class T>
class HElibKnownAnswerTestZp {
 public:
  enum Testcase { MAT, DEC, USE_CASE, PACKED_MAT, PACKED_USE_CASE };

 private:
  static constexpr bool PRESET_SEED = true;
  static constexpr size_t NUM_MATMULS_SQUARES = 3;
  static constexpr bool LAST_SQUARE = false;
  static constexpr bool MOD_SWITCH = false;
  utils::SeededRandom rand;
  std::vector<uint64_t> key;
  std::vector<uint64_t> plaintext;
  std::vector<uint64_t> ciphertext_expected;
  long m;          // m-th cyclotomic polynomial
  long plain_mod;  // plaintext prime
  long r;          // Lifting [defualt = 1]
  long L;          // bits in the ciphertext modulus chain
  long c;          // columns in the key-switching matrix [default=2]
  long d;          // Degree of the field extension [default=1]
  long k;          // Security parameter [default=80]
  long s;          // Minimum number of slots [default=0]
  Testcase tc;
  size_t N;
  bool use_bsgs;
  uint64_t bsgs_n1;
  uint64_t bsgs_n2;

 public:
  HElibKnownAnswerTestZp(std::vector<uint64_t> key,
                         std::vector<uint64_t> plaintext,
                         std::vector<uint64_t> ciphertext_expected, long m,
                         long plain_mod, long r, long L, long c, long d = 1,
                         long k = 128, long s = 1, Testcase tc = DEC,
                         size_t N = 4, bool use_bsgs = false,
                         uint64_t bsgs_n1 = 0, uint64_t bsgs_n2 = 0)
      : rand(PRESET_SEED),
        key(key),
        plaintext(plaintext),
        ciphertext_expected(ciphertext_expected),
        m(m),
        plain_mod(plain_mod),
        r(r),
        L(L),
        c(c),
        d(d),
        k(k),
        s(s),
        tc(tc),
        N(N),
        use_bsgs(use_bsgs),
        bsgs_n1(bsgs_n1),
        bsgs_n2(bsgs_n2) {}

  HElibKnownAnswerTestZp(const uint64_t *key, size_t key_size,
                         const uint64_t *plaintext, size_t plaintext_size,
                         const uint64_t *ciphertext_expected,
                         size_t ciphertext_size, long m, long plain_mod, long r,
                         long L, long c, long d = 1, long k = 128, long s = 1,
                         Testcase tc = DEC, size_t N = 4, bool use_bsgs = false,
                         uint64_t bsgs_n1 = 0, uint64_t bsgs_n2 = 0)
      : rand(PRESET_SEED),
        key(key, key + key_size),
        plaintext(plaintext, plaintext + plaintext_size),
        ciphertext_expected(ciphertext_expected,
                            ciphertext_expected + ciphertext_size),
        m(m),
        plain_mod(plain_mod),
        r(r),
        L(L),
        c(c),
        d(d),
        k(k),
        s(s),
        tc(tc),
        N(N),
        use_bsgs(use_bsgs),
        bsgs_n1(bsgs_n1),
        bsgs_n2(bsgs_n2) {}

  bool mat_test() {
    long startMem, endMem;
    auto context = T::create_context(m, plain_mod, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.create_pk();
    cipher.print_parameters();
    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> mat(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      mat[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        mat[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          mat[r][i].push_back(rand.random_uint64() %
                              plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }
    endMem = utils::getMemoryUsage();
    std::cout << "...done" << std::endl;
    std::cout << "-=== Computing in plain ===- " << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;

    startMem = utils::getMemoryUsage();
    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, mat[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    // HE:
    std::cout << "-=== Computing in HE ===-" << std::endl;
    startMem = utils::getMemoryUsage();
    std::vector<helib::Ctxt> vi_e;
    std::vector<helib::Ctxt> vo_e;
    for (size_t i = 0; i < N; i++) {
      cipher.encrypt(vi_e[i], vi[i]);
    }
    std::cout << "-> Initial noise:" << std::endl;
    cipher.print_noise(vi_e[0]);

    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.affine(vo_e, mat[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.square(vi_e, vo_e);
    }

    std::cout << "-> Final noise:" << std::endl;
    cipher.print_noise(vo_e[0]);

    for (size_t i = 0; i < N; i++) {
      cipher.decrypt(vo_e[i], vo_p[i]);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool dec_test() {
    long startMem, endMem;
    
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    auto context = T::create_context(m, plain_mod, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    cipher.activate_bsgs(use_bsgs);
    cipher.add_gk_indices();
    cipher.create_pk(true);

    std::cout << "-=== HE encrypting key ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.encrypt_key();
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "-=== HE decrypting ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<helib::Ctxt> ciph = cipher.HE_decrypt(ciphertext_expected);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Final noise:" << std::endl;
    cipher.print_noise(ciph);

    std::cout << "-=== Final decrypt ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> plain = cipher.decrypt_result(ciph);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
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
    std::chrono::milliseconds time_diff;

    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> mat(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      mat[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        mat[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          mat[r][i].push_back(rand.random_uint64() %
                              plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    endMem = utils::getMemoryUsage();

    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Computing in plain ===- " << std::endl;
    startMem = utils::getMemoryUsage();
    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, mat[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "...done" << std::endl;

    std::cout << " -=== Encrypting input ===- " << std::endl;
    typename T::Plain plain_cipher(key, plain_mod);
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> ciph = plain_cipher.encrypt(vi);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    auto context = T::create_context(m, plain_mod, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    cipher.create_pk();
    std::cout << "-=== HE encrypting key ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.encrypt_key();
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "-=== HE decrypting ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<helib::Ctxt> vi_e = cipher.HE_decrypt(ciph);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e);

    std::vector<helib::Ctxt> vo_e;
    std::cout << "-=== Computing in HE ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.affine(vo_e, mat[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.square(vi_e, vo_e);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Final noise:" << std::endl;
    cipher.print_noise(vo_e[0]);

    std::cout << "-=== Final decrypt ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    for (size_t i = 0; i < N; i++) {
      cipher.decrypt(vo_e[i], vo_p[i]);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "... done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << end - start << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool packed_mat_test() {
    long startMem, endMem;
    
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    auto context = T::create_context(m, plain_mod, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;
    cipher.activate_bsgs(use_bsgs);
    if (use_bsgs)
      cipher.add_bsgs_indices(bsgs_n1, bsgs_n2);
    else
      cipher.add_diagonal_indices(N);
    cipher.create_pk(true);

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> mat(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      mat[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        mat[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          mat[r][i].push_back(rand.random_uint64() %
                              plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Computing in plain ===- " << std::endl;
    startMem = utils::getMemoryUsage();
    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, mat[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    // HE:
    std::cout << "-=== Computing in HE ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    helib::Ctxt vi_e = cipher.packed_encrypt(vi);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Encryption time: " << time_diff.count() << " milliseconds"
              << std::endl;
    std::cout << "Cycles: " << end - start << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    auto size = cipher.get_cipher_size(vi_e);
    std::cout << "Ciphertext size = " << size << " Bytes" << std::endl;

    std::cout << "-> Initial noise:" << std::endl;
    cipher.print_noise(vi_e);

    std::cout << "[packed] affine and square" << std::endl;
    if (use_bsgs) cipher.set_bsgs_params(bsgs_n1, bsgs_n2);
    helib::Ctxt vo_e(helib::ZeroCtxtLike, vi_e);
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      vo_e = cipher.packed_affine(mat[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        vi_e = cipher.packed_square(vo_e);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Computation time: " << time_diff.count() << " milliseconds"
              << std::endl;
    std::cout << "Cycles: " << end - start << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Final noise:" << std::endl;
    cipher.print_noise(vo_e);

    size = cipher.get_cipher_size(vi_e, MOD_SWITCH);
    std::cout << "Final ciphertext size = " << size << " Bytes" << std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.packed_decrypt(vo_e, vo_p, N);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Decryption time: " << time_diff.count() << " milliseconds"
              << std::endl;
    std::cout << "Cycles: " << end - start << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "...done" << std::endl;
    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool packed_test() {
    long startMem, endMem;
    
    uint32_t aux;
    uint64_t start, end;
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "> N = " << N << std::endl;
    std::cout << "-=== Getting random elements ===-" << std::endl;

    startMem = utils::getMemoryUsage();
    // random matrices
    std::vector<matrix::matrix> mat(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      mat[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        mat[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          mat[r][i].push_back(rand.random_uint64() %
                              plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== Computing in plain ===- " << std::endl;
    startMem = utils::getMemoryUsage();
    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, mat[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }
    endMem = utils::getMemoryUsage();
    std::cout << "-> done!" << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << " -=== Encrypting input ===- " << std::endl;
    typename T::Plain plain_cipher(key, plain_mod);
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<uint64_t> ciph = plain_cipher.encrypt(vi);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "Generating Galois Keys" << std::endl;
    startMem = utils::getMemoryUsage();
    auto context = T::create_context(m, plain_mod, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    size_t rem = N % cipher.get_plain_size();
    size_t num_block = N / cipher.get_plain_size();
    if (rem) num_block++;
    std::set<long> flatten_gks;
    for (long i = 1; i < num_block; i++)
      flatten_gks.emplace(-(long)(i * cipher.get_plain_size()));

    cipher.activate_bsgs(use_bsgs);
    cipher.add_gk_indices();
    cipher.add_some_gk_indices(flatten_gks);
    if (use_bsgs)
      cipher.add_bsgs_indices(bsgs_n1, bsgs_n2);
    else
      cipher.add_diagonal_indices(N);
    cipher.create_pk(true);
    endMem = utils::getMemoryUsage();
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;

    std::cout << "-=== HE encrypting key ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.encrypt_key();
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "-=== HE decrypting ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    std::vector<helib::Ctxt> vi_e_vec = cipher.HE_decrypt(ciph);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e_vec);

    std::cout << "HE postprocessing..." << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    if (rem != 0) {
      std::vector<long> mask(rem, 1);
      cipher.mask(vi_e_vec.back(), mask);
    }
    helib::Ctxt vi_e = cipher.flatten(vi_e_vec);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e);

    std::cout << "-=== Computing in HE ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    if (use_bsgs) cipher.set_bsgs_params(bsgs_n1, bsgs_n2);
    helib::Ctxt vo_e(helib::ZeroCtxtLike, vi_e);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      vo_e = cipher.packed_affine(mat[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        vi_e = cipher.packed_square(vo_e);
    }
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "-> done! \n";
    std::cout << "-> Time: " << time_diff.count() << " ms" << std::endl;
    std::cout << "-> Cycle: " << end - start << std::endl;
    std::cout << "-> Memory: " << endMem - startMem << " KB" << std::endl;
    std::cout << "-> Final noise:" << std::endl;
    cipher.print_noise(vo_e);

    auto size = cipher.get_cipher_size(vi_e, MOD_SWITCH);
    std::cout << "Final ciphertext size = " << size << " Bytes" << std::endl;

    std::cout << "-=== Final decrypt ===-" << std::endl;
    time_start = std::chrono::high_resolution_clock::now();
    start = __rdtscp(&aux);
    startMem = utils::getMemoryUsage();
    cipher.packed_decrypt(vo_e, vo_p, N);
    endMem = utils::getMemoryUsage();
    end = __rdtscp(&aux);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "... done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << end - start << std::endl;
    std::cout << "Memory: " << endMem - startMem << " KB" << std::endl;
    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
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
      case PACKED_MAT:
        return packed_mat_test();
      case PACKED_USE_CASE:
        return packed_test();
      default: {
        std::cout << "Testcase not found... " << std::endl;
        return false;
      }
    }
  }
};
