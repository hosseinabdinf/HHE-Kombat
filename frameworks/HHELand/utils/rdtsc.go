package utils

// #cgo CFLAGS: -O2
// #include <x86intrin.h>
//
// //export read_tsc
// unsigned long long read_tsc() {
//     return __rdtsc();
// }
import "C"

func Rdtsc() uint64 {
	return uint64(C.read_tsc())
}
