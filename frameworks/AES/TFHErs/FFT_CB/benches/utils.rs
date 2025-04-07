use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::_rdtsc;

#[cfg(target_arch = "x86")]
use std::arch::x86::_rdtsc;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn _rdtsc() -> u64 {
    panic!("rdtsc is only supported on x86/x86_64");
}

fn calibrate_rdtsc() -> f64 {
    let calibration_duration = Duration::from_millis(100); // Calibration time
    let start_time = Instant::now();
    let start_cycles = unsafe { _rdtsc() };

    while start_time.elapsed() < calibration_duration {}

    let end_cycles = unsafe { _rdtsc() };
    let elapsed_cycles = end_cycles - start_cycles;

    (elapsed_cycles as f64) / (calibration_duration.as_secs_f64())
}

fn rdtsc_to_ms(cycles: u64, frequency: f64) -> f64 {
    (cycles as f64 / frequency) * 1000.0
}

#[cfg(target_os = "linux")]
fn get_memory_usage() -> (i64, i64, i64) {
    let mut camem = 0;
    let mut heapmem = 0;
    let mut physmem = 0;

    // Get the current memory usage
    let mut file = File::open("/proc/self/statm").unwrap();
    let mut statm = String::new();
    file.read_to_string(&mut statm).unwrap();

    // Parse the memory info from /proc/self/statm
    let parts: Vec<&str> = statm.split_whitespace().collect();
    if let Some(resident_set) = parts.get(1) {
        camem = resident_set.parse::<i64>().unwrap() * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } / 1024; // KB
    }

    // Heap memory (using malloc and mmap for heap memory)
    unsafe {
        heapmem = libc::mallinfo2().uordblks / 1024; // KB
    }

    // Get the maximum resident set size (RSS)
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
    }
    physmem = usage.ru_maxrss;

    (camem, heapmem, physmem)
}

#[cfg(target_os = "linux")]
pub fn print_time_ns(start: Instant, end: Instant) {
    let duration = end.duration_since(start);
    let diff_ns = duration.as_nanos();
    let diff_ms = diff_ns as f64 / 1_000_000.0;
    println!("-> Time: {:.4} (ms), {} (ns)", diff_ms, diff_ns);
}

#[cfg(target_os = "linux")]
pub fn print_cycles(start: u64, end: u64) {
    println!("-> Cycles: {}", end - start);
}

#[cfg(target_os = "linux")]
pub fn print_memory(name: &str, start: i64, end: i64) {
    println!("-> {} Memory: {} KB", name, end - start);
}

#[cfg(target_os = "linux")]
pub fn print_header(header: &str) {
    println!("\n ------------------===|\t {} \t|===------------------", header);
}

#[cfg(target_os = "linux")]
pub fn benchmark<F>(name: &str, f: F)
where
    F: FnOnce(),
{
    print_header(name);

    let start_time = Instant::now();
    let (start_camem, start_heapmem, start_physmem) = get_memory_usage();

    let frequency = calibrate_rdtsc(); // Get the frequency
    let start_cycles = unsafe { _rdtsc() };

    f(); // The function you want to benchmark

    let end_cycles = unsafe { _rdtsc() };
    let (end_camem, end_heapmem, end_physmem) = get_memory_usage();
    let end_time = Instant::now();

    print_time_ns(start_time, end_time);
    print_cycles(start_cycles, end_cycles);
    print_memory("Allocated", start_camem, end_camem);
    print_memory("Heap", start_heapmem, end_heapmem);
    print_memory("Physical", start_physmem, end_physmem);

    // Convert the cycle counts to milliseconds
    let elapsed_cycles = end_cycles - start_cycles;
    let elapsed_ms = rdtsc_to_ms(elapsed_cycles, frequency);

    println!("-> Elapsed Time (from cycles): {:.4} ms", elapsed_ms);
    println!("-> done! \n\n");
}
