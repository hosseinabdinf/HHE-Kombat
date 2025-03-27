use std::arch::x86_64::_rdtsc;
use criterion::Criterion;
use memory_stats::memory_stats;
use std::sync::{Arc, Mutex};
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheBool, FheUint64, FheUint8};
use tfhe_trivium::{print_cpu_and_mem, TransCiphering, TriviumStream, TriviumStreamByte};

pub fn trivium_byte_gen(c: &mut Criterion) {
    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    // once for memory benchmarking
    trivium.next_64();
    let final_mem = memory_stats().expect("Failed to get initial memory stats");
    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function("trivium byte generate 64 bits", |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter(|| {
            let start_cpuc: u64;
            let end_cpuc: u64;

            unsafe {
                start_cpuc = _rdtsc();
            }
            trivium.next_64();

            unsafe {
                end_cpuc = _rdtsc();
            }

            let cycle_count = end_cpuc - start_cpuc;
            cpu_cycles.lock().unwrap().push(cycle_count);
        })
    });

    print_cpu_and_mem(cpu_cycles_clone, initial_mem, final_mem);
}

pub fn trivium_byte_trans(c: &mut Criterion) {
    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));

    let ciphered_message = FheUint64::try_encrypt(0u64, &client_key).unwrap();
    let mut trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

    // once for memory benchmarking
    trivium.trans_encrypt_64(ciphered_message.clone());
    let final_mem = memory_stats().expect("Failed to get initial memory stats");
    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function("trivium byte transencrypt 64 bits", |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter(|| {
            let start_cpuc: u64;
            let end_cpuc: u64;

            unsafe {
                start_cpuc = _rdtsc();
            }

            trivium.trans_encrypt_64(ciphered_message.clone());

            unsafe {
                end_cpuc = _rdtsc();
            }

            let cycle_count = end_cpuc - start_cpuc;
            cpu_cycles.lock().unwrap().push(cycle_count);
        })
    });

    print_cpu_and_mem(cpu_cycles_clone, initial_mem, final_mem);
}

pub fn trivium_byte_warmup(c: &mut Criterion) {
    let initial_mem = memory_stats().expect("Failed to get initial memory stats");

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    let key_string = "0053A6F94C9FF24598EB".to_string();
    let mut key = [0u8; 10];

    for i in (0..key_string.len()).step_by(2) {
        key[i >> 1] = u8::from_str_radix(&key_string[i..i + 2], 16).unwrap();
    }

    let iv_string = "0D74DB42A91077DE45AC".to_string();
    let mut iv = [0u8; 10];

    for i in (0..iv_string.len()).step_by(2) {
        iv[i >> 1] = u8::from_str_radix(&iv_string[i..i + 2], 16).unwrap();
    }

    // once for memory benchmarking
    let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));
    let _trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);
    let final_mem = memory_stats().expect("Failed to get initial memory stats");
    let cpu_cycles: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let cpu_cycles_clone = Arc::clone(&cpu_cycles);

    c.bench_function("trivium byte warmup", |b| {
        let cpu_cycles = Arc::clone(&cpu_cycles);
        b.iter(|| {
            let start_cpuc: u64;
            let end_cpuc: u64;

            unsafe {
                start_cpuc = _rdtsc();
            }

            let cipher_key = key.map(|x| FheUint8::encrypt(x, &client_key));
            let _trivium = TriviumStreamByte::<FheUint8>::new(cipher_key, iv, &server_key);

            unsafe {
                end_cpuc = _rdtsc();
            }

            let cycle_count = end_cpuc - start_cpuc;
            cpu_cycles.lock().unwrap().push(cycle_count);
        })
    });

    print_cpu_and_mem(cpu_cycles_clone, initial_mem, final_mem);
}
