use criterion::Criterion;
use memory_stats::memory_stats;
use std::arch::x86_64::_rdtsc;
use std::sync::{Arc, Mutex};
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool, FheUint8};
use tfhe_trivium::{print_cpu_and_mem, KreyviumStream, KreyviumStreamByte};

pub fn kreyvium_bool_gen(c: &mut Criterion) {
    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [false; 128];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [false; 128];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));

    let mut kreyvium = KreyviumStream::<FheBool>::new(cipher_key, iv, &server_key);

    // once for memory benchmarking
    kreyvium.next_64();
    let final_mem = memory_stats().expect("Failed to get initial memory stats");
    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function("kreyvium bool generate 64 bits", |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter(|| {
            let start_cpuc: u64;
            let end_cpuc: u64;

            unsafe {
                start_cpuc = _rdtsc();
            }
            kreyvium.next_64();
            unsafe {
                end_cpuc = _rdtsc();
            }

            let cycle_count = end_cpuc - start_cpuc;
            cpu_cycles.lock().unwrap().push(cycle_count);
        })
    });

    print_cpu_and_mem(cpu_cycles_clone, initial_mem, final_mem);
}

pub fn kreyvium_bool_warmup(c: &mut Criterion) {
    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB000000000000".to_string();
    let mut key = [false; 128];

    for i in (0..key_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            key[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    let iv_string = "0D74DB42A91077DE45AC000000000000".to_string();
    let mut iv = [false; 128];

    for i in (0..iv_string.len()).step_by(2) {
        let mut val: u8 = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
        for j in 0..8 {
            iv[8 * (i >> 1) + j] = val % 2 == 1;
            val >>= 1;
        }
    }

    // once for memory benchmarking
    let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));
    let _kreyvium = KreyviumStream::<FheBool>::new(cipher_key, iv, &server_key);
    let final_mem = memory_stats().expect("Failed to get initial memory stats");
    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function("kreyvium bool warmup", |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter(|| {
            let start_cpuc: u64;
            let end_cpuc: u64;

            unsafe {
                start_cpuc = _rdtsc();
            }

            let cipher_key = key.map(|x| FheBool::encrypt(x, &client_key));
            let _kreyvium = KreyviumStream::<FheBool>::new(cipher_key, iv, &server_key);

            unsafe {
                end_cpuc = _rdtsc();
            }

            let cycle_count = end_cpuc - start_cpuc;
            cpu_cycles.lock().unwrap().push(cycle_count);
        })
    });

    print_cpu_and_mem(cpu_cycles_clone, initial_mem, final_mem);
}
