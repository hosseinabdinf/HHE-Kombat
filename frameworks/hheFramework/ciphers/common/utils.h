#pragma once

#include <malloc.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <ostream>
#include <random>
#include <string>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#endif

extern "C" {
#include "KeccakHash.h"
}

namespace utils {

static long getMemoryUsage() {
  std::ifstream statm("/proc/self/statm");
  long size, resident;
  statm >> size >> resident;
  statm.close();

// Handle both _SC_PAGESIZE and _SC_PAGE_SIZE
#ifdef _SC_PAGESIZE
  long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
#elif defined(_SC_PAGE_SIZE)
  long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;
#else
#error "Neither _SC_PAGESIZE nor _SC_PAGE_SIZE is defined"
#endif

  long camem = resident * page_size_kb;

  long resmem = 0;
  std::ifstream file("/proc/self/status");
  std::string line;
  while (std::getline(file, line)) {
    if (line.rfind("VmRSS:", 0) == 0) {           // Search for "VmRSS"
      resmem = std::stol(line.substr(6)) / 1024;  // Convert from B to KB
    }
  }

  // Heap memory
  struct mallinfo2 mi = mallinfo2();
  long heapmem = mi.uordblks / 1024;  // Bytes to KB

  struct rusage usage;
  getrusage(RUSAGE_SELF, &usage);
  long physmem = usage.ru_maxrss;
  // std::cout << "\n -============= Memory status =============- \n";
  // std::cout << "\t\t Current-Allocated-Memory: " << camem << " KB \n";
  // std::cout << "\t\t Resident-Memory: " << resmem << " KB \n";
  // std::cout << "\t\t Heap-Memory: " << heapmem << " KB \n";
  // std::cout << "\t\t Physical-Memory: " << physmem << " KB \n";
  // std::cout << "-=============  =============- \n";
  std::cout << "> Memory Status (";
  std::cout << "Allocated: " << camem << " KB,";
  std::cout << " Resident: " << resmem << " KB,";
  std::cout << " Heap: " << heapmem << " KB,";
  std::cout << " Physical: " << physmem << " KB";
  std::cout << ")\n";
  return camem;
}
// return the current allocated memory usage (in kilobytes)
// static long getMemoryUsage() {
//   std::ifstream statm("/proc/self/statm");
//   long size, resident;
//   statm >> size >> resident;
//   statm.close();
//
// // Handle both _SC_PAGESIZE and _SC_PAGE_SIZE
// #ifdef _SC_PAGESIZE
//   long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
// #elif defined(_SC_PAGE_SIZE)
//   long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;
// #else
// #error "Neither _SC_PAGESIZE nor _SC_PAGE_SIZE is defined"
// #endif
//
//   long mem = resident * page_size_kb;
//   std::cout << "Current-Allocated-Memory: " << mem << " KB \n";
//   return mem;
// }

// reports only Resident memory (RAM)
// static long getMemoryUsage() {
//   std::ifstream file("/proc/self/status");
//   std::string line;
//   while (std::getline(file, line)) {
//     if (line.rfind("VmRSS:", 0) == 0) {  // Search for "VmRSS"
//       return std::stol(line.substr(6)) / 1024;  // Convert from B to KB
//     }
//   }
//   return 0;  // Failed to read
// }

// static long getMemoryUsage() {
//   std::ifstream file("/proc/self/status");
//   std::string line;
//   while (std::getline(file, line)) {
//     if (line.rfind("VmRSS:", 0) == 0) {                   // Search for
//     "VmRSS"
//       long memory_kb = std::stol(line.substr(6)) / 1024;  // Bytes to KB
//       std::cout << "VmRSS (in KB): " << memory_kb << std::endl;  // Print
//       result return memory_kb;
//     }
//   }
//   return 0;
// }

// static long getMemoryUsage() {
//   struct mallinfo2 mi = mallinfo2();
//   long mem = mi.uordblks / 1024;  // Bytes to KB
//   std::cout << "\n Heap:" << mem << "KB" << std::endl;
//   return mem;
// }

// reports the physical memory usage (KB)
// static long getMemoryUsage() {
//   struct rusage usage;
//   getrusage(RUSAGE_SELF, &usage);
//   std::cout << "physical mem (kb):" << usage.ru_maxrss << std::endl;
//   return usage.ru_maxrss;  // KB
// }

static void print_vector(std::string info, std::vector<uint8_t> vec,
                         std::ostream& out) {
  std::ios_base::fmtflags f(out.flags());  // get flags
  if (!info.empty()) {
    out << info << " ";
  }
  out << "{";
  const auto delim = ", ";
  for (auto a : vec) {
    out << std::hex << std::setw(2) << std::setfill('0');
    out << int(a) << delim;
  }
  out << "}\n";

  out.flags(f);  // reset flags
}

static void print_vector(std::string info, std::vector<uint64_t> vec,
                         std::ostream& out) {
  std::ios_base::fmtflags f(out.flags());  // get flags
  if (!info.empty()) {
    out << info << " ";
  }
  out << "{";
  const auto delim = ", ";
  for (auto a : vec) {
    out << std::hex << std::setw(16) << std::setfill('0');
    out << a << delim;
  }
  out << "}\n";

  out.flags(f);  // reset flags
}

static void encode(std::vector<uint8_t>& encoded, std::vector<uint64_t> in,
                   size_t bitsize) {
  size_t size = in.size() * bitsize;
  size = ceil((double)size / 8.0);

  encoded.clear();
  encoded.reserve(size);

  uint8_t tmp = 0;
  uint8_t cnt = 0;
  for (size_t i = 0; i < in.size(); i++) {
    for (size_t k = 0; k < bitsize; k++) {
      uint8_t bit = (in[i] >> k) & 1;
      tmp |= (bit << (7 - cnt));
      cnt++;
      if (cnt == 8) {
        encoded.push_back(tmp);
        cnt = 0;
        tmp = 0;
      }
    }
  }
  if (cnt) encoded.push_back(tmp);
}

static void decode(std::vector<uint64_t>& out, std::vector<uint8_t> encoded,
                   size_t bitsize) {
  size_t size = encoded.size() * 8;
  size /= bitsize;
  out.clear();
  out.reserve(size);

  uint64_t tmp = 0;
  uint8_t cnt = 0;
  for (size_t i = 0; i < encoded.size(); i++) {
    for (size_t k = 0; k < 8; k++) {
      uint8_t bit = (encoded[i] >> (7 - k)) & 1;
      tmp |= (bit << cnt);
      cnt++;
      if (cnt == bitsize) {
        out.push_back(tmp);
        tmp = 0;
        cnt = 0;
      }
    }
  }
}

// random_uint64() taken from the SEAL library
// (https://github.com/microsoft/SEAL)
static uint64_t random_uint64() {
  uint64_t result;
#ifdef __linux__
  std::random_device rd("/dev/urandom");
  result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#elif _WIN32
  if (!BCRYPT_SUCCESS(
          BCryptGenRandom(NULL, reinterpret_cast<unsigned char*>(&result),
                          sizeof(result), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
    throw runtime_error("BCryptGenRandom failed");
  }
#else
#warning \
    "SECURITY WARNING: System detection failed; falling back to a potentially insecure randomness source!"
  random_device rd;
  result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#endif
  return result;
}

class SeededRandom {
 private:
  Keccak_HashInstance shake128_;

  void init_shake(std::array<uint8_t, 16>& seed) {
    if (SUCCESS != Keccak_HashInitialize_SHAKE128(&shake128_))
      throw std::runtime_error("failed to init shake");
    if (SUCCESS != Keccak_HashUpdate(&shake128_, seed.data(), seed.size() * 8))
      throw std::runtime_error("SHAKE128 update failed");
    if (SUCCESS != Keccak_HashFinal(&shake128_, NULL))
      throw std::runtime_error("SHAKE128 final failed");
  }

  void init_shake(uint64_t seed1, uint64_t seed2) {
    std::array<uint8_t, 16> seed;
    uint8_t* seed_data = seed.data();
    *((uint64_t*)seed_data) = htobe64(seed1);
    *((uint64_t*)(seed_data + 8)) = htobe64(seed2);
    init_shake(seed);
  }

 public:
  static constexpr uint64_t PRESET_SEED1 = 5414582108744027571ULL;
  static constexpr uint64_t PRESET_SEED2 = 3580691526476218256ULL;

  SeededRandom(bool preset_seed = false) {
    if (preset_seed)
      init_shake(PRESET_SEED1, PRESET_SEED2);
    else
      init_shake(utils::random_uint64(), utils::random_uint64());
  }

  SeededRandom(uint64_t seed1, uint64_t seed2) { init_shake(seed1, seed2); }

  SeededRandom(std::array<uint8_t, 16>& seed) { init_shake(seed); }

  ~SeededRandom() = default;
  SeededRandom(const SeededRandom&) = delete;
  SeededRandom& operator=(const SeededRandom&) = delete;
  SeededRandom(const SeededRandom&&) = delete;

  uint64_t random_uint64() {
    uint8_t random_bytes[sizeof(uint64_t)];
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    return be64toh(*((uint64_t*)random_bytes));
  };
};

}  // namespace utils
