#ifndef UTILS_H
#define UTILS_H

#include <malloc.h>
#include <stdint.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

long GetMemoryUsage();
void PrintTimeNS(struct timespec start, struct timespec end);
void PrintCycles(uint64_t start, uint64_t end);
void PrintMemory(long start, long end);
void PrintHeader(const char* header);

#ifdef __cplusplus
}
#endif

// Benchmark Macro
#define BENCHMARK(name, code)                    \
  do {                                           \
    PrintHeader(name);                           \
    struct timespec start_time, end_time;        \
    clock_gettime(CLOCK_MONOTONIC, &start_time); \
    long start_mem = GetMemoryUsage();           \
    uint64_t start_cycle = __rdtsc();            \
                                                 \
    code;                                        \
                                                 \
    uint64_t end_cycle = __rdtsc();              \
    long end_mem = GetMemoryUsage();             \
    clock_gettime(CLOCK_MONOTONIC, &end_time);   \
                                                 \
    PrintTimeNS(start_time, end_time);           \
    PrintCycles(start_cycle, end_cycle);         \
    PrintMemory(start_mem, end_mem);             \
    printf("-> done! \n\n");                     \
  } while (0)

#endif
