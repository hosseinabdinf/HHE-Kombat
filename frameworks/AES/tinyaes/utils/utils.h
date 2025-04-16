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

void PrintHeader(const char* header);
void GetMemoryUsage(long* camem, long* heapmem, long* physmem);
void PrintTimeNS(struct timespec start, struct timespec end);
void PrintTimeNSAvg(struct timespec start, struct timespec end, int iter);
void PrintCycles(uint64_t start, uint64_t end);
void PrintCyclesAvg(uint64_t start, uint64_t end, int iter);
void PrintMemory(const char* name, long start, long end);
void PrintMemoryAvg(const char* label, long start, long end, int iter);

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

#define BENCHMARK_ITER(name, iterations, ...)                                 \
  do {                                                                        \
    PrintHeader(name);                                                        \
    struct timespec start_time, end_time;                                     \
    long start_camem, start_heapmem, start_physmem;                           \
    long end_camem, end_heapmem, end_physmem;                                 \
    uint64_t start_cycle, end_cycle;                                          \
                                                                              \
    clock_gettime(CLOCK_MONOTONIC, &start_time);                              \
    GetMemoryUsage(&start_camem, &start_heapmem, &start_physmem);             \
    start_cycle = __rdtsc();                                                  \
                                                                              \
    for (int _i = 0; _i < (iterations); ++_i) {                               \
      __VA_ARGS__;                                                            \
    }                                                                         \
                                                                              \
    end_cycle = __rdtsc();                                                    \
    GetMemoryUsage(&end_camem, &end_heapmem, &end_physmem);                   \
    clock_gettime(CLOCK_MONOTONIC, &end_time);                                \
                                                                              \
    PrintTimeNSAvg(start_time, end_time, iterations);                         \
    PrintCyclesAvg(start_cycle, end_cycle, iterations);                       \
    PrintMemory("Allocated ", start_camem, end_camem);                        \
    PrintMemory("Heap ", start_heapmem, end_heapmem);                         \
    PrintMemory("Physical ", start_physmem, end_physmem);                     \
    PrintMemoryAvg("Allocated (avg)", start_camem, end_camem, iterations);    \
    PrintMemoryAvg("Heap (avg)", start_heapmem, end_heapmem, iterations);     \
    PrintMemoryAvg("Physical (avg)", start_physmem, end_physmem, iterations); \
    printf("-> done!\n\n");                                                   \
  } while (0)

#endif
