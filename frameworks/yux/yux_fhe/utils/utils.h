#ifndef UTILS_H
#define UTILS_H

#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

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

#endif
