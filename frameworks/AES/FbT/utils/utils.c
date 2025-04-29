#include "utils.h"

#include <stdio.h>

void PrintHeader(const char* header) {
  printf("\n ------------------===|\t %s \t|===------------------\n", header);
}

void GetMemoryUsage(long* camem, long* heapmem, long* physmem) {
  long resident_set = 0;
  FILE* fp = fopen("/proc/self/statm", "r");

  if (fp) {
    if (fscanf(fp, "%*s %ld", &resident_set) != 1) {
      fprintf(stderr,
              "Warning: Failed to read memory usage from /proc/self/statm\n");
    }
    fclose(fp);
  }

  *camem = resident_set * (sysconf(_SC_PAGESIZE) / 1024);  // KB

  // Heap memory
  struct mallinfo2 mi = mallinfo2();
  *heapmem = mi.uordblks / 1024;  // Bytes to KB

  // Maximum resident set size (RSS)
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    perror(" >>> getrusage failed!");
    *physmem = -1;
  } else {
    *physmem = usage.ru_maxrss;
  }

  printf(
      "> Memory Status (Allocated: %ld KB, Physical: %ld KB, Heap: %ld KB)\n",
      *camem, *physmem, *heapmem);
}

void PrintTimeNS(struct timespec start, struct timespec end) {
  // Calculate the elapsed time
  long seconds = end.tv_sec - start.tv_sec;
  long nanoseconds = end.tv_nsec - start.tv_nsec;
  long diff_ns = seconds * 1000000000L + nanoseconds;
  double diff_ms = diff_ns / 1.0e6;
  printf("-> Time: %.4f (ms), %ld (ns)\n", diff_ms, diff_ns);
}

void PrintTimeNSAvg(struct timespec start, struct timespec end, int iter) {
  long seconds = end.tv_sec - start.tv_sec;
  long nanoseconds = end.tv_nsec - start.tv_nsec;
  long diff_ns = seconds * 1000000000L + nanoseconds;
  double diff_ms = diff_ns / 1.0e6;
  printf("-> Average Time: %.4f (ms), %.4f (ns)\n", (diff_ms / iter),
         ((double)diff_ns / iter));
}

void PrintCycles(uint64_t start, uint64_t end) {
  printf("-> Cycles: %ld\n", (end - start));
}

void PrintCyclesAvg(uint64_t start, uint64_t end, int iter) {
  printf("-> Average cycles: %.4f\n", (double)(end - start) / iter);
}

void PrintMemory(const char* name, long start, long end) {
  printf("-> %s Memory: %ld KB\n", name, end - start);
}

void PrintMemoryAvg(const char* name, long start, long end, int iter) {
  printf("-> Average %s memory: %.2f KB\n", name,
         (double)(end - start) / (iter));
}