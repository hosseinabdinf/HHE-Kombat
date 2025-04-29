import time
import os
import psutil
import resource
import statistics
from hwcounter import Timer

def get_memory_usage():
    process = psutil.Process(os.getpid())
    camem = process.memory_info().rss // 1024  # Resident Set Size in KB
    heapmem = process.memory_info().vms // 1024  # Virtual Memory Size in KB (approximate heap)
    physmem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # Max RSS in KB
    return camem, heapmem, physmem

def print_header(header):
    print(f"\n ------------------===|\t {header} \t|===------------------")

def print_status(message):
    print(f"--> {message}", end='', flush=True)

def print_message(message):
    print(f"--> {message}")

def benchmark(name, iterations, func):
    print_header(name)

    time_durations = []
    cycle_counts = []
    allocated_mem = []
    heap_mem = []
    physical_mem = []

    for _ in range(iterations):
        start_camem, start_heapmem, start_physmem = get_memory_usage()
        start_time_ns = time.perf_counter_ns()

        with Timer() as t:
            func()

        end_time_ns = time.perf_counter_ns()
        end_camem, end_heapmem, end_physmem = get_memory_usage()

        time_durations.append(end_time_ns - start_time_ns)
        cycle_counts.append(t.cycles)
        allocated_mem.append(end_camem - start_camem)
        heap_mem.append(end_heapmem - start_heapmem)
        physical_mem.append(end_physmem - start_physmem)

    avg_time_ms = statistics.mean(time_durations) / 1_000_000  # Convert ns to ms
    avg_cycles = statistics.mean(cycle_counts)
    avg_allocated_mem = statistics.mean(allocated_mem)
    avg_heap_mem = statistics.mean(heap_mem)
    avg_physical_mem = statistics.mean(physical_mem)

    print(f"-> Average Time: {avg_time_ms:.4f} ms")
    print(f"-> Average Cycles: {avg_cycles:.0f}")
    print(f"-> Average Allocated Memory: {avg_allocated_mem:.2f} KB")
    print(f"-> Allocated Memory: {allocated_mem[0]} KB")
    print(f"-> Average Heap Memory: {avg_heap_mem:.2f} KB")
    print(f"-> Heap Memory: {heap_mem[0]} KB")
    print(f"-> Average Physical Memory: {avg_physical_mem:.2f} KB")
    print(f"-> Physical Memory: {physical_mem[0]} KB")
    print("-> done!\n\n")


