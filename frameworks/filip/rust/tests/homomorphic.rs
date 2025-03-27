use concrete_commons::parameters::PlaintextCount;
use concrete_core::{
    crypto::encoding::PlaintextList,
    math::{
        random::RandomGenerator,
        tensor::{AsRefSlice, AsRefTensor},
    },
};
use crossterm::{cursor, QueueableCommand};
use std::{
    env,
    io::{stdout, Write},
    time::Instant,
};
use FiLIP::{EncryptedBit, EncryptedKeyBit, Encrypter, SystemParameters, Torus};

fn main() {
    let args: Vec<String> = env::args().collect();
    let n_iter = args[1].parse().unwrap();
    let mut ran_test = false;
    if args[2..].contains(&"FiLIP_1280".to_string()) {
        println!("FiLIP 1280:");
        homomorphic(&SystemParameters::n1280, n_iter);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_1216".to_string()) {
        println!("FiLIP 1216:");
        homomorphic(&SystemParameters::n1216, n_iter);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_144".to_string()) {
        println!("FiLIP 144:");
        homomorphic(&SystemParameters::n144, n_iter);
        println!("");
        ran_test = true;
    }
    if !ran_test {
        panic!("Specify one or more version: FiLIP_144, FiLIP_1216 and/or FiLIP_1280.");
    }
}

fn homomorphic(parameters: &SystemParameters, n_iter: usize) {
    let (glwe_dimension, poly_size, base_log, level, std_dev) = parameters.fhe_parameters();

    let sk = parameters.generate_fhe_key();

    let mut stdout = stdout();
    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Building the transcrypter...").as_bytes())
        .unwrap();
    stdout.flush().unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    let now = Instant::now();
    let (mut encryptor, mut decryptor) = Encrypter::<bool>::new::<EncryptedKeyBit>(
        parameters,
        Some(&sk),
        Some(level),
        Some(base_log),
        Some(std_dev),
    );
    println!("Trancrypter built in {} s.", now.elapsed().as_secs());

    let mut generator = RandomGenerator::new(None);
    let message = generator
        .random_uniform_binary_tensor::<Torus>(n_iter)
        .as_slice()
        .iter()
        .map(|i| if *i == 1 { true } else { false })
        .collect::<Vec<_>>();

    let mut ciphertext = vec![Default::default(); n_iter];
    let mut transciphered =
        vec![EncryptedBit::allocate(poly_size, glwe_dimension.to_glwe_size()); n_iter];

    encryptor.encrypt(&mut ciphertext, &message);
    let now = Instant::now();
    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Transciphering...").as_bytes())
        .unwrap();
    stdout.flush().unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    decryptor.decrypt(&mut transciphered, &ciphertext);
    println!(
        "{} bits transcrypted in {} s. ({} s/b)",
        n_iter,
        now.elapsed().as_secs(),
        now.elapsed().as_secs_f64() / (n_iter as f64),
    );

    let errors: usize = transciphered
        .iter()
        .zip(message.iter())
        .map(|(lwe, message)| {
            let mut decrypted = PlaintextList::allocate(0, PlaintextCount(poly_size.0));
            sk.decrypt_glwe(&mut decrypted, lwe.as_glwe());

            let mut decoded = decrypted.as_tensor().as_slice()[0] >> (Torus::BITS as usize - 2);
            if decoded % 2 == 1 {
                decoded += 2;
            }
            decoded >>= 1;
            decoded %= 2;

            if *message ^ (decoded == 1) {
                1
            } else {
                0
            }
        })
        .sum();

    if errors > 0 {
        panic!(
            "{} error{} over {} bits.",
            errors,
            if errors > 1 { "s" } else { "" },
            n_iter
        );
    }
}
