use concrete_core::math::random::RandomGenerator;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use elisabeth::{u4, Encrypter, SystemParameters, LWE};
use memory_stats::memory_stats;
use pprof::criterion::{Output, PProfProfiler};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::_rdtsc;

#[cfg(target_arch = "x86")]
use std::arch::x86::_rdtsc;
use std::sync::{Arc, Mutex};

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn _rdtsc() -> u64 {
    panic!("rdtsc is only supported on x86/x86_64");
}

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

fn bench_encryption(c: &mut Criterion) {
    let id = if cfg!(not(feature = "multithread")) {
        "Elisabeth 60 - Encryption - Monothreaded"
    } else {
        "Elisabeth 60 - Encryption"
    };

    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    // this is Elisabeth symmetric cipher
    let (mut enc, _dec) = Encrypter::<u4>::new::<u4>(&SystemParameters::n60, None, None, None);

    let mut generator = RandomGenerator::new(None);

    // this is a vector of a single 4-bit integer
    let message = vec![u4(generator.random_uniform_n_lsb(4))];

    let mut ciphertext = vec![u4(0)];

    enc.encrypt(&mut ciphertext, &message);

    let final_mem = memory_stats().expect("Failed to get initial memory stats");

    // ================ Print the memory usage (KB) ================
    let p_memory_used_kb = (final_mem.physical_mem - initial_mem.physical_mem) / 1024;
    let v_memory_used_kb = (final_mem.virtual_mem - initial_mem.virtual_mem) / 1024;
    println!("Physical Memory used (KB): {}", p_memory_used_kb);
    println!("Virtual Memory used (KB): {}", v_memory_used_kb);

    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function(id, move |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter_batched(
            || message.clone(),
            |message1216| {
                let start_cpuc: u64;
                let end_cpuc: u64;

                unsafe {
                    start_cpuc = _rdtsc();
                }

                enc.encrypt(black_box(&mut ciphertext), black_box(&message1216));

                unsafe {
                    end_cpuc = _rdtsc();
                }

                let cycle_count = end_cpuc - start_cpuc;
                cpu_cycles.lock().unwrap().push(cycle_count);
            },
            BatchSize::SmallInput,
        )
    });

    // ================ Print Average CPU Cycles ================
    let frequency = calibrate_rdtsc();
    // Use the original clone to access data after the benchmark
    let cycles = cpu_cycles_clone.lock().unwrap();
    if !cycles.is_empty() {
        let avg_cycles: u64 = cycles.iter().sum::<u64>() / cycles.len() as u64;
        println!("Average CPU cycles: {}", avg_cycles);
        let elapsed_ms = rdtsc_to_ms(avg_cycles, frequency);
        println!("Average elapsed time: {} ms", elapsed_ms);
    } else {
        println!("No CPU cycles recorded.");
    }
}

fn bench_transcryption(c: &mut Criterion) {
    let mut id = if cfg!(feature = "single_key") {
        "Elisabeth 60 - Transciphering - Single Keyswitching Key"
    } else {
        "Elisabeth 60 - Transciphering - Two Keyswitching Key"
    }
    .to_string();
    if cfg!(not(feature = "multithread")) {
        id += " - Monothreaded";
    }

    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    #[cfg(not(feature = "single_key"))]
    let ((sk, std_dev_lwe), _sk_out, pk) = SystemParameters::n60.generate_fhe_keys();
    #[cfg(feature = "single_key")]
    let ((sk, std_dev_lwe), pk) = SystemParameters::n60.generate_fhe_keys();

    let (mut encrypter, mut decrypter) = Encrypter::<u4>::new::<LWE>(
        &SystemParameters::n60,
        Some(&sk),
        Some(std_dev_lwe.0),
        Some(pk),
    );

    // message
    let mut generator = RandomGenerator::new(None);
    let message = vec![u4(generator.random_uniform_n_lsb::<u8>(4))];

    let mut ciphertext = vec![u4(0)];
    let mut transciphered = vec![LWE::allocate(sk.key_size().to_lwe_size())];

    encrypter.encrypt(&mut ciphertext, &message);

    decrypter.decrypt(&mut transciphered, &ciphertext);

    let final_mem = memory_stats().expect("Failed to get initial memory stats");

    // ================ Print the memory usage (KB) ================
    let p_memory_used_kb = (final_mem.physical_mem - initial_mem.physical_mem) / 1024;
    let v_memory_used_kb = (final_mem.virtual_mem - initial_mem.virtual_mem) / 1024;
    println!("Physical Memory used (KB): {}", p_memory_used_kb);
    println!("Virtual Memory used (KB): {}", v_memory_used_kb);

    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function(id.as_str(), move |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter_batched(
            || ciphertext.clone(),
            |ctx| {
                let start_cpuc: u64;
                let end_cpuc: u64;

                unsafe {
                    start_cpuc = _rdtsc();
                }

                decrypter.decrypt(black_box(&mut transciphered), black_box(&ctx));

                unsafe {
                    end_cpuc = _rdtsc();
                }

                let cycle_count = end_cpuc - start_cpuc;
                cpu_cycles.lock().unwrap().push(cycle_count);
            },
            BatchSize::SmallInput,
        )
    });

    // ================ Print Average CPU Cycles ================
    let frequency = calibrate_rdtsc();
    // Use the original clone to access data after the benchmark
    let cycles = cpu_cycles_clone.lock().unwrap();
    if !cycles.is_empty() {
        let avg_cycles: u64 = cycles.iter().sum::<u64>() / cycles.len() as u64;
        println!("Average CPU cycles: {}", avg_cycles);
        let elapsed_ms = rdtsc_to_ms(avg_cycles, frequency);
        println!("Average elapsed time: {} ms", elapsed_ms);
    } else {
        println!("No CPU cycles recorded.");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_encryption, bench_transcryption
}
criterion_main!(benches);
