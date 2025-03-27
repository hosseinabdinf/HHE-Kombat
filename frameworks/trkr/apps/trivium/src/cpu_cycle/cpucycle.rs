#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::_rdtsc;

#[cfg(target_arch = "x86")]
use std::arch::x86::_rdtsc;
use std::sync::{Arc, Mutex};

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn _rdtsc() -> u64 {
    panic!("rdtsc is only supported on x86/x86_64");
}

use memory_stats::MemoryStats;
use std::time::{Duration, Instant};

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

pub fn print_cpu_and_mem(
    cpu_cycles_clone: Arc<Mutex<Vec<u64>>>,
    initial_mem: MemoryStats,
    final_mem: MemoryStats,
) {
    // ================ Print Average CPU Cycles ================
    let frequency = calibrate_rdtsc();
    // Use the original clone to access data after the benchmark
    let cycles = cpu_cycles_clone.lock().unwrap();
    if !cycles.is_empty() {
        let avg_cycles: u64 = cycles.iter().sum::<u64>() / cycles.len() as u64;
        let elapsed_ms = rdtsc_to_ms(avg_cycles, frequency);
        println!("Average elapsed time: {} ms", elapsed_ms);
        println!("Average CPU cycles: {}", avg_cycles);
    } else {
        println!("No CPU cycles recorded.");
    }
    // ================ Print the memory usage (KB) ================
    let p_memory_used_kb = (final_mem.physical_mem - initial_mem.physical_mem) / 1024;
    let v_memory_used_kb = (final_mem.virtual_mem - initial_mem.virtual_mem) / 1024;
    println!("Physical Memory used (KB): {}", p_memory_used_kb);
    println!("Virtual Memory used (KB): {}", v_memory_used_kb);
}
