#![allow(warnings)]
// use std::ffi::CString;
// use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::{cursor, QueueableCommand};
use std::{
    env,
    io::{stdout, Write},
};

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

use libc;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::io::Read;

fn get_memory_usage() -> (i64, i64, i64) {
    let mut camem = 0;
    let mut heapmem = 0;
    let mut physmem = 0;

    // Get the current memory usage from /proc/self/statm
    let mut file = File::open("/proc/self/statm").unwrap();
    let mut statm = String::new();
    file.read_to_string(&mut statm).unwrap();

    // Parse the memory info from /proc/self/statm
    let parts: Vec<&str> = statm.split_whitespace().collect();
    if let Some(resident_set) = parts.get(1) {
        // Calculate allocated memory (in KB)
        camem = resident_set.parse::<i64>().unwrap()
            * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as i64
            / 1024;
    }

    // Get heap memory using mallinfo2 (unsafe operation)
    unsafe {
        let mallinfo = libc::mallinfo2();
        heapmem = mallinfo.uordblks as i64 / 1024; // Convert from usize to i64 and then to KB
    }

    // Get the maximum resident set size (RSS) using getrusage (in KB)
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe {
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
    }
    // Convert RSS to KB
    physmem = usage.ru_maxrss as i64;

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
    println!(
        "\n ------------------===|\t {} \t|===------------------",
        header
    );
}

#[cfg(target_os = "linux")]
pub fn benchmark<F>(name: &str, iterations: usize, mut f: F)
where
    F: FnMut(),
{
    print_header(name);

    let frequency = calibrate_rdtsc(); // Get the CPU frequency

    let mut cycle_counts = Vec::with_capacity(iterations);
    let mut time_durations = Vec::with_capacity(iterations);
    let mut allocated_mem = Vec::with_capacity(iterations);
    let mut heap_mem = Vec::with_capacity(iterations);
    let mut physical_mem = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let (start_camem, start_heapmem, start_physmem) = get_memory_usage(); // Get initial memory
        let start_time = Instant::now();
        let start_cycles = unsafe { _rdtsc() };

        f(); // Execute the function

        let end_cycles = unsafe { _rdtsc() };
        let end_time = Instant::now();
        let (end_camem, end_heapmem, end_physmem) = get_memory_usage(); // Get final memory

        // Store cycle count and execution time
        cycle_counts.push(end_cycles - start_cycles);
        time_durations.push(end_time.duration_since(start_time));

        // Store memory usage per iteration
        allocated_mem.push(end_camem - start_camem);
        heap_mem.push(end_heapmem - start_heapmem);
        physical_mem.push(end_physmem - start_physmem);
    }

    // Compute averages
    let avg_cycles = cycle_counts.iter().sum::<u64>() as f64 / iterations as f64;
    let avg_time =
        time_durations.iter().sum::<Duration>().as_secs_f64() * 1000.0 / iterations as f64;
    let avg_time_from_cycles = rdtsc_to_ms(avg_cycles as u64, frequency);

    let avg_allocated_mem = allocated_mem.iter().sum::<i64>() as f64 / iterations as f64;
    let avg_heap_mem = heap_mem.iter().sum::<i64>() as f64 / iterations as f64;
    let avg_physical_mem = physical_mem.iter().sum::<i64>() as f64 / iterations as f64;

    // Print results
    print_cycles(0, avg_cycles as u64); // Display as if start was 0
    println!("-> Average Time: {:.4} ms", avg_time);
    println!(
        "-> Average Time (from cycles): {:.4} ms",
        avg_time_from_cycles
    );
    println!("-> Average Allocated Memory: {:.2} KB", avg_allocated_mem);
    println!("-> Allocated Memory: {} KB", allocated_mem[0]);
    println!("-> Average Heap Memory: {:.2} KB", avg_heap_mem);
    println!("-> Heap Memory: {} KB", heap_mem[0]);
    println!("-> Average Physical Memory: {:.2} KB", avg_physical_mem);
    println!("-> Physical Memory: {} KB", physical_mem[0]);
    println!("-> done! \n\n");
}

pub fn print_status(message: &str) {
    let mut stdout = stdout();
    stdout.queue(cursor::SavePosition).unwrap();
    stdout.write({ format!("--> ") }.as_bytes()).unwrap();
    stdout.write(message.as_bytes()).unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    stdout.flush().unwrap();
}

pub fn print_message(message: &str) {
    println!("--> {}", message);
}
