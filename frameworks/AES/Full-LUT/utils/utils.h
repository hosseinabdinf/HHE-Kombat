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

// long GetMemoryUsage();
void GetMemoryUsage(long* camem, long* heapmem, long* physmem);
void PrintTimeNS(struct timespec start, struct timespec end);
void PrintCycles(uint64_t start, uint64_t end);
// void PrintMemory(long start, long end);
void PrintMemory(const char* name, long start, long end);
void PrintHeader(const char* header);

#ifdef __cplusplus
}
#endif

// benchmarking macro
#define BENCHMARK(name, ...)                                      \
  do {                                                            \
    PrintHeader(name);                                            \
    struct timespec start_time, end_time;                         \
    long start_camem, start_heapmem, start_physmem;               \
    clock_gettime(CLOCK_MONOTONIC, &start_time);                  \
    GetMemoryUsage(&start_camem, &start_heapmem, &start_physmem); \
    uint64_t start_cycle = __rdtsc();                             \
                                                                  \
    do {                                                          \
      __VA_ARGS__;                                                \
    } while (0);                                                  \
                                                                  \
    uint64_t end_cycle = __rdtsc();                               \
    long end_camem, end_heapmem, end_physmem;                     \
    GetMemoryUsage(&end_camem, &end_heapmem, &end_physmem);       \
    clock_gettime(CLOCK_MONOTONIC, &end_time);                    \
                                                                  \
    PrintTimeNS(start_time, end_time);                            \
    PrintCycles(start_cycle, end_cycle);                          \
    PrintMemory("Allocated ", start_camem, end_camem);            \
    PrintMemory("Heap ", start_heapmem, end_heapmem);             \
    PrintMemory("Physical ", start_physmem, end_physmem);         \
    printf("-> done! \n\n");                                      \
  } while (0)

#endif
