package benchmark

import (
	"fmt"
	"os"
	"time"
	"syscall"
	"bufio"
	"strconv"
	"strings"
	"runtime"
)

func PrintHeader(header string) {
	fmt.Printf("\n ------------------===|\t %s \t|===------------------\n", header)
}

func GetMemoryUsage() (camem, heapmem, physmem int64) {
	// Get camem (allocated memory) from /proc/self/statm
	file, err := os.Open("/proc/self/statm")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) > 1 {
				if rssPages, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					pageSize := int64(os.Getpagesize())
					camem = (rssPages * pageSize) / 1024
				}
			}
		}
	}

	// Heap memory from runtime
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	heapmem = int64(memStats.Alloc / 1024) // bytes to KB

	// Physical memory from rusage
	var rusage syscall.Rusage
	err = syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	if err == nil {
		physmem = rusage.Maxrss
	}

	fmt.Printf("> Memory Status (Allocated: %d KB, Physical: %d KB, Heap: %d KB)\n", camem, physmem, heapmem)
	return
}

func PrintTimeNS(start, end time.Time) {
	diff := end.Sub(start)
	fmt.Printf("-> Time: %.4f (ms), %d (ns)\n", float64(diff.Nanoseconds())/1e6, diff.Nanoseconds())
}

func PrintTimeNSAvg(start, end time.Time, iter int) {
	diff := end.Sub(start)
	fmt.Printf("-> Average Time: %.4f (ms), %.4f (ns)\n",
		float64(diff.Nanoseconds())/1e6/float64(iter),
		float64(diff.Nanoseconds())/float64(iter))
}

func PrintCycles(start, end uint64) {
	fmt.Printf("-> Cycles: %d\n", end-start)
}

func PrintCyclesAvg(start, end uint64, iter int) {
	fmt.Printf("-> Average cycles: %.4f\n", float64(end-start)/float64(iter))
}

func PrintMemory(name string, start, end int64) {
	fmt.Printf("-> %s Memory: %d KB\n", name, end-start)
}

func PrintMemoryAvg(name string, start, end int64, iter int) {
	fmt.Printf("-> Average %s memory: %.2f KB\n", name, float64(end-start)/float64(iter))
}


func Benchmark(name string, targetFunc func()) {
	PrintHeader(name)

	startTime := time.Now()
	startCamem, startHeap, startPhys := GetMemoryUsage()
	startCycle := Rdtsc()

	targetFunc()

	endCycle := Rdtsc()
	endCamem, endHeap, endPhys := GetMemoryUsage()
	endTime := time.Now()

	PrintTimeNS(startTime, endTime)
	PrintCycles(startCycle, endCycle)
	PrintMemory("Allocated ", startCamem, endCamem)
	PrintMemory("Heap ", startHeap, endHeap)
	PrintMemory("Physical ", startPhys, endPhys)
	fmt.Println("-> done!\n")
}

func BenchmarkIter(name string, iterations int, targetFunc func()) {
	PrintHeader(name)

	startTime := time.Now()
	startCamem, startHeap, startPhys := GetMemoryUsage()
	startCycle := Rdtsc()

	for i := 0; i < iterations; i++ {
		targetFunc()
	}

	endCycle := Rdtsc()
	endCamem, endHeap, endPhys := GetMemoryUsage()
	endTime := time.Now()

	PrintTimeNSAvg(startTime, endTime, iterations)
	PrintCyclesAvg(startCycle, endCycle, iterations)
	PrintMemory("Allocated ", startCamem, endCamem)
	PrintMemory("Heap ", startHeap, endHeap)
	PrintMemory("Physical ", startPhys, endPhys)
	PrintMemoryAvg("Allocated (avg)", startCamem, endCamem, iterations)
	PrintMemoryAvg("Heap (avg)", startHeap, endHeap, iterations)
	PrintMemoryAvg("Physical (avg)", startPhys, endPhys, iterations)
	fmt.Println("-> done!\n")
}