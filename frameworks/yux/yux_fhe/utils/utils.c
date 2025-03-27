#include "utils.h"
#include <stdio.h>

long GetMemoryUsage() {
  // currently allocated memory
  long resident_set;
  FILE *fp = fopen("/proc/self/statm", "r");
  // if (fp) {
  //   fscanf(fp, "%*s %ld", &resident_set);
  //   fclose(fp);
  // }

  if (fp) {
    if (fscanf(fp, "%*s %ld", &resident_set) != 1) {
        fprintf(stderr, "Warning: Failed to read memory usage from /proc/self/statm\n");
    }
    fclose(fp);
  }

  long camem = resident_set * (sysconf(_SC_PAGESIZE) / 1024); // KB

  // Heap memory
  struct mallinfo2 mi = mallinfo2();
  long heapmem = mi.uordblks / 1024; // Bytes to KB

  // maximum resident set size (RSS)
  long physmem = -1;
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    perror(" >>> getrusage failed!");
  } else {
    physmem = usage.ru_maxrss;
  }

  printf("> Memory Status (Allocated: %ld, Physical: %ld KB, Heap: %ld KB)\n",
         camem, physmem, heapmem);
  return camem;
}

void PrintTimeNS(struct timespec start, struct timespec end) {
  // Calculate the elapsed time
  long seconds = end.tv_sec - start.tv_sec;
  long nanoseconds = end.tv_nsec - start.tv_nsec;
  long diff_ns = seconds * 1000000000L + nanoseconds;
  double diff_ms = diff_ns / 1.0e6;
  printf("-> Time: %.4f (ms), %ld (ns)\n", diff_ms, diff_ns);
}

void PrintCycles(uint64_t start, uint64_t end) {
  printf("-> Cycles: %ld\n", (end - start));
}

void PrintMemory(long start, long end) {
  printf("-> Memory: %ld KB\n", end - start);
}

void PrintHeader(const char* header) {
  printf("-=== %s ===-\n", header);
}