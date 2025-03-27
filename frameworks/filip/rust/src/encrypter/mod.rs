mod parameters;

use std::{
    env, fs,
    io::{stdout, Write},
    path::Path,
    time::Instant,
};

use crate::{filter::Filter, multiplexer::Multiplexer, symmetric_key::SymmetricKey, Bit, Torus};
use concrete_commons::{
    dispersion::StandardDev,
    key_kinds::BinaryKeyKind,
    parameters::{DecompositionBaseLog, DecompositionLevelCount},
};
use concrete_core::{crypto::secret::GlweSecretKey, math::random::RandomGenerator};

use crossterm::{cursor, QueueableCommand};
pub use parameters::*;

pub struct Encrypter<M: Multiplexer> {
    key: SymmetricKey<M>,
    filter: Filter,
}

impl<M: Multiplexer> Encrypter<M> {
    pub fn new<U: Multiplexer>(
        params: &SystemParameters,
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
    ) -> (Self, Encrypter<U>) {
        let mut generator = RandomGenerator::new(None);
        let seed = generator.random_uniform();

        let Parameters {
            n,
            key_size,
            filter,
        } = params.parameters();

        let mut key1 = vec![
            M::zero_with_fhe_parameters(
                sk.map(|s| s.polynomial_size()),
                sk.map(|s| s.key_size().to_glwe_size()),
                decomp_level,
                decomp_base_log
            );
            key_size
        ];
        let mut key2 = vec![
            U::zero_with_fhe_parameters(
                sk.map(|s| s.polynomial_size()),
                sk.map(|s| s.key_size().to_glwe_size()),
                decomp_level,
                decomp_base_log
            );
            key_size
        ];

        Self::key_gen(
            &mut key1,
            &mut key2,
            sk,
            decomp_level,
            decomp_base_log,
            noise_parameters,
            &mut generator,
            params,
        );
        (
            Self {
                key: SymmetricKey::new(key1, n, seed),
                filter: filter.clone(),
            },
            Encrypter::<U> {
                key: SymmetricKey::new(key2, n, seed),
                filter,
            },
        )
    }

    fn key_gen<U: Multiplexer>(
        sk1: &mut [M],
        sk2: &mut [U],
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
        generator: &mut RandomGenerator,
        params: &SystemParameters,
    ) {
        let env_var = env::var("KEY_DIRECTORY").ok();
        let path = env_var.as_ref().map(|s| &**s);
        let key_1_stored = path
            .map(|p| {
                Path::new(
                    format!(
                        "{}/keys/{}/symmetric/key_{}",
                        p,
                        params.name(),
                        M::descriptor()
                    )
                    .as_str(),
                )
                .exists()
            })
            .unwrap_or(false);
        let key_2_stored = path
            .map(|p| {
                Path::new(
                    format!(
                        "{}/keys/{}/symmetric/key_{}",
                        p,
                        params.name(),
                        U::descriptor()
                    )
                    .as_str(),
                )
                .exists()
            })
            .unwrap_or(false);
        let keys_stored = key_1_stored & key_2_stored;

        let mut stdout = stdout();
        if keys_stored {
            stdout.queue(cursor::SavePosition).unwrap();
            stdout
                .write(
                    format!(
                        "                                                                        "
                    )
                    .as_bytes(),
                )
                .unwrap();
            stdout.flush().unwrap();
            stdout.queue(cursor::RestorePosition).unwrap();
            stdout
                .write(format!("Loading keys from {}/keys", path.unwrap()).as_bytes())
                .unwrap();
            stdout.flush().unwrap();
            stdout.queue(cursor::RestorePosition).unwrap();
            let sk1_serialized = fs::read(format!(
                "{}/keys/{}/symmetric/key_{}",
                path.unwrap(),
                params.name(),
                M::descriptor()
            ))
            .unwrap();
            let sk2_serialized = fs::read(format!(
                "{}/keys/{}/symmetric/key_{}",
                path.unwrap(),
                params.name(),
                U::descriptor()
            ))
            .unwrap();
            sk1.clone_from_slice(
                bincode::deserialize::<Vec<M>>(&sk1_serialized)
                    .unwrap()
                    .as_slice(),
            );
            sk2.clone_from_slice(
                bincode::deserialize::<Vec<U>>(&sk2_serialized)
                    .unwrap()
                    .as_slice(),
            );
        } else {
            let len = sk1.len();
            let now = Instant::now();
            for (i, (key_bit_1, key_bit_2)) in sk1.iter_mut().zip(sk2.iter_mut()).enumerate() {
                stdout.queue(cursor::SavePosition).unwrap();
                stdout
                    .write(
                        format!(
                            "Generating key bit {}/{}. ({} seconds elapsed.)",
                            i + 1,
                            len,
                            now.elapsed().as_secs()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stdout.flush().unwrap();
                stdout.queue(cursor::RestorePosition).unwrap();
                if generator.random_uniform_binary::<u8>() == 1 {
                    *key_bit_1 = M::one(sk, decomp_level, decomp_base_log, noise_parameters);
                    *key_bit_2 = U::one(sk, decomp_level, decomp_base_log, noise_parameters);
                } else {
                    *key_bit_1 = M::zero(sk, decomp_level, decomp_base_log, noise_parameters);
                    *key_bit_2 = U::zero(sk, decomp_level, decomp_base_log, noise_parameters);
                }
            }
            if path.is_some() {
                fs::create_dir_all(format!(
                    "{}/keys/{}/symmetric",
                    path.unwrap(),
                    params.name()
                ))
                .unwrap();
                fs::write(
                    format!(
                        "{}/keys/{}/symmetric/key_{}",
                        path.unwrap(),
                        params.name(),
                        M::descriptor()
                    ),
                    &bincode::serialize(&sk1.to_vec()).unwrap(),
                )
                .unwrap();
                fs::write(
                    format!(
                        "{}/keys/{}/symmetric/key_{}",
                        path.unwrap(),
                        params.name(),
                        U::descriptor()
                    ),
                    bincode::serialize(&sk2.to_vec()).unwrap(),
                )
                .unwrap();
            }
        }
    }

    fn stream(&mut self) -> M::Bit {
        let key_round = self.key.random_whitened_subset();
        self.filter.call(&key_round)
    }

    pub fn encrypt(&mut self, res: &mut [M::Bit], message: &[bool]) {
        for (c, m) in res.iter_mut().zip(message.iter()) {
            *c = self.stream();
            if *m {
                c.not_inplace();
            }
        }
    }

    pub fn decrypt(&mut self, res: &mut [M::Bit], ciphertext: &[bool]) {
        for (d, c) in res.iter_mut().zip(ciphertext.iter()) {
            *d = self.stream();
            if *c {
                d.not_inplace();
            }
        }
    }
}
