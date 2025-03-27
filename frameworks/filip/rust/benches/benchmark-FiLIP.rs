#![allow(non_snake_case)]
use concrete_core::math::random::RandomGenerator;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};
use strum::IntoEnumIterator;
use FiLIP::{EncryptedBit, EncryptedKeyBit, Encrypter, SystemParameters};

fn bench(c: &mut Criterion) {
    let mut generator = RandomGenerator::new(None);

    for sys in SystemParameters::iter() {
        let (glwe_dimension, poly_size, base_log, level, std_dev) = sys.fhe_parameters();
        let mut group = c.benchmark_group(sys.name());

        let sk = sys.generate_fhe_key();

        let (mut encrypter, mut decrypter) = Encrypter::<bool>::new::<EncryptedKeyBit>(
            &sys,
            Some(&sk),
            Some(level),
            Some(base_log),
            Some(std_dev),
        );

        let message = vec![generator.random_uniform_binary::<u8>() == 1];
        let ciphertext = vec![false];

        group.bench_with_input(
            BenchmarkId::new("Encryption", poly_size.0),
            &ciphertext,
            move |b, ctx| {
                b.iter(|| encrypter.encrypt(black_box(&mut ctx.clone()), black_box(&message)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("Transcryption", poly_size.0),
            &ciphertext,
            move |b, ctx| {
                let mut transciphered = vec![EncryptedBit::allocate(
                    poly_size,
                    glwe_dimension.to_glwe_size(),
                )];
                b.iter(|| decrypter.decrypt(black_box(&mut transciphered), black_box(ctx)));
            },
        );
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);
