use concrete_commons::{
    numeric::Numeric,
    parameters::{CiphertextCount, LweDimension, PlaintextCount},
};
use concrete_core::{
    crypto::{
        bootstrap::{Bootstrap, FourierBootstrapKey, StandardBootstrapKey},
        encoding::PlaintextList,
        glwe::GlweCiphertext,
        lwe::{LweCiphertext, LweList},
        secret::generators::EncryptionRandomGenerator,
    },
    math::{
        fft::Complex64, polynomial::MonomialDegree, random::RandomGenerator, tensor::AsMutTensor,
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
    let nb_bits = args[2].parse().unwrap();
    let mut ran_test = false;
    if args[3..].contains(&"FiLIP_1280".to_string()) {
        println!("FiLIP 1280:");
        multibit(&SystemParameters::n1280, n_iter, nb_bits);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_1216".to_string()) {
        println!("FiLIP 1216:");
        multibit(&SystemParameters::n1216, n_iter, nb_bits);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_144".to_string()) {
        println!("FiLIP 144:");
        multibit(&SystemParameters::n144, n_iter, nb_bits);
        println!("");
        ran_test = true;
    }
    if !ran_test {
        panic!("Specify one or more version: FiLIP_144, FiLIP_1216 and/or FiLIP_1280.");
    }
}

fn multibit(parameters: &SystemParameters, n_iter: usize, nb_bits: usize) {
    let (glwe_dimension, poly_size, base_log, level, std_dev) = parameters.fhe_parameters();
    let lwe_dimension = LweDimension(glwe_dimension.0 * poly_size.0);

    let sk = parameters.generate_fhe_key();

    // bootstrapping key
    let mut secret_generator = EncryptionRandomGenerator::new(None);
    let mut coef_bsk = StandardBootstrapKey::allocate(
        <Torus as Numeric>::ZERO,
        glwe_dimension.to_glwe_size(),
        poly_size,
        level,
        base_log,
        lwe_dimension,
    );
    coef_bsk.fill_with_new_trivial_key(
        &sk.clone().into_lwe_secret_key(),
        &sk,
        std_dev,
        &mut secret_generator,
    );
    let mut bsk = FourierBootstrapKey::allocate(
        Complex64::new(0., 0.),
        glwe_dimension.to_glwe_size(),
        poly_size,
        level,
        base_log,
        lwe_dimension,
    );
    bsk.fill_with_forward_fourier(&coef_bsk);

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
        .random_uniform_n_lsb_tensor::<u8>(n_iter, nb_bits)
        .as_container()
        .clone();
    let message_decomp = message
        .iter()
        .flat_map(|u| {
            (0..nb_bits)
                .rev()
                .into_iter()
                .map(|i| (u >> i) & 1 == 1)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut ciphertext = vec![Default::default(); n_iter * nb_bits];
    let mut transciphered =
        vec![EncryptedBit::allocate(poly_size, glwe_dimension.to_glwe_size()); n_iter * nb_bits];

    encryptor.encrypt(&mut ciphertext, &message_decomp);
    let now = Instant::now();
    stdout.queue(cursor::SavePosition).unwrap();
    stdout
        .write(format!("Transciphering...").as_bytes())
        .unwrap();
    stdout.flush().unwrap();
    stdout.queue(cursor::RestorePosition).unwrap();
    decryptor.decrypt(&mut transciphered, &ciphertext);

    let mut encrypted_messages =
        LweList::allocate(0, lwe_dimension.to_lwe_size(), CiphertextCount(n_iter));
    for (mut encrypted_message, encrypted_bits) in encrypted_messages
        .ciphertext_iter_mut()
        .zip(transciphered.chunks(nb_bits))
    {
        for (p, encrypted_bit) in encrypted_bits.iter().enumerate() {
            let mut lwe_in = LweCiphertext::allocate(0, lwe_dimension.to_lwe_size());
            lwe_in.fill_with_glwe_sample_extraction(encrypted_bit.as_glwe(), MonomialDegree(0));

            let mut lwe_out = LweCiphertext::allocate(0, lwe_dimension.to_lwe_size());

            let mut accumulator =
                GlweCiphertext::allocate(0, poly_size, glwe_dimension.to_glwe_size());
            accumulator
                .get_mut_body()
                .as_mut_tensor()
                .iter_mut()
                .enumerate()
                .for_each(|(i, a)| {
                    let val = (1 as Torus) << (Torus::BITS - (p + 3) as u32);
                    *a = if i < poly_size.0 / 2 {
                        val.wrapping_neg()
                    } else {
                        val
                    };
                });
            bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator);

            lwe_out.get_mut_body().0 += (1 as Torus) << (Torus::BITS - (p + 3) as u32);

            encrypted_message.update_with_add(&lwe_out);
        }
    }

    println!(
        "{} messages transcrypted in {} s. ({} s/message, {} s/b)",
        n_iter,
        now.elapsed().as_secs(),
        now.elapsed().as_secs_f64() / n_iter as f64,
        now.elapsed().as_secs_f64() / (n_iter * nb_bits) as f64,
    );

    let mut decrypted = PlaintextList::allocate(0, PlaintextCount(n_iter));
    sk.into_lwe_secret_key()
        .decrypt_lwe_list(&mut decrypted, &encrypted_messages);

    let errors: usize = decrypted
        .plaintext_iter()
        .zip(message.iter())
        .map(|(d, m)| {
            let mut decoded = d.0 >> (Torus::BITS - (nb_bits + 2) as u32);
            if decoded % 2 == 1 {
                decoded += 1;
            }
            decoded >>= 1;
            decoded %= 1 << nb_bits;
            if decoded != *m as Torus {
                1
            } else {
                0
            }
        })
        .sum();

    if errors > 0 {
        panic!(
            "{} error{} over {} message.",
            errors,
            if errors > 1 { "s" } else { "" },
            n_iter
        );
    }
}
