use concrete_core::math::{random::RandomGenerator, tensor::AsRefSlice};
use std::env;
use FiLIP::{Encrypter, SystemParameters, Torus};

fn main() {
    let args: Vec<String> = env::args().collect();
    let n_iter = args[1].parse().unwrap();
    let mut ran_test = false;
    if args[2..].contains(&"FiLIP_1280".to_string()) {
        println!("FiLIP 1280:");
        clear(&SystemParameters::n1280, n_iter);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_1216".to_string()) {
        println!("FiLIP 1216:");
        clear(&SystemParameters::n1216, n_iter);
        println!("");
        ran_test = true;
    }
    if args[2..].contains(&"FiLIP_144".to_string()) {
        println!("FiLIP 144:");
        clear(&SystemParameters::n144, n_iter);
        println!("");
        ran_test = true;
    }
    if !ran_test {
        panic!("Specify one or more version: FiLIP_144, FiLIP_1216 and/or FiLIP_1280.");
    }
}

pub fn clear(parameters: &SystemParameters, n_iter: usize) {
    let (mut encryptor, mut decryptor) =
        Encrypter::<bool>::new::<bool>(parameters, None, None, None, None);

    let mut generator = RandomGenerator::new(None);
    let message = generator
        .random_uniform_binary_tensor::<Torus>(n_iter)
        .as_slice()
        .iter()
        .map(|i| if *i == 1 { true } else { false })
        .collect::<Vec<_>>();

    let mut ciphertext = vec![Default::default(); n_iter];
    let mut decryption = vec![Default::default(); n_iter];

    encryptor.encrypt(&mut ciphertext, &message);
    decryptor.decrypt(&mut decryption, &ciphertext);

    assert_eq!(message, decryption);
}
