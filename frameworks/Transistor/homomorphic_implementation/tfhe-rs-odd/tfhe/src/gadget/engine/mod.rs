//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::CiphertextModulus;
use crate::core_crypto::prelude::Container;
use crate::core_crypto::prelude::ContiguousEntityContainer;
use crate::core_crypto::prelude::EncryptionKeyChoice;
use crate::core_crypto::prelude::LweSize;
use crate::core_crypto::prelude::MonomialDegree;
use crate::core_crypto::prelude::PBSOrder;
use crate::core_crypto::prelude::PlaintextCount;
use crate::gadget::prelude::*;
use std::cell::RefCell;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
pub mod bootstrapping;
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::gadget::engine::bootstrapping::{Bootstrapper, ServerKey};
//use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::seeders::new_seeder;

use super::ciphertext::Encoding;
use super::server_key;



/// Trait to be able to acces thread_local
/// engines in a generic way
pub(crate) trait WithThreadLocalEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R;
}

// All our thread local engines
// that our exposed types will use internally to implement their methods
thread_local! {
    static GADGET_ENGINE: RefCell<GadgetEngine> = RefCell::new(GadgetEngine::new());
}

pub struct GadgetEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    bootstrapper: Bootstrapper,
}

impl WithThreadLocalEngine for GadgetEngine {
    fn with_thread_local_mut<R, F>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        GADGET_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }
}

impl GadgetEngine {
    pub fn create_client_key(&mut self, parameters: GadgetParameters) -> ClientKey {
        // generate the lwe secret key
        let lwe_secret_key = allocate_and_generate_new_binary_lwe_secret_key(
            parameters.lwe_dimension,
            &mut self.secret_generator,
        );

        // generate the glwe secret key
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            parameters.glwe_dimension,
            parameters.polynomial_size,
            &mut self.secret_generator,
        );

        ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters,
        }
    }

    pub fn create_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let server_key = self.bootstrapper.new_server_key(cks);

        server_key
    }

    pub fn trivial_encrypt(&mut self, message: u64) -> Ciphertext {
        Ciphertext::Trivial(message)
    }

    fn encryption_from_plaintext(
        &mut self,
        cks: &ClientKey,
        plaintext: Plaintext<u64>,
    ) -> LweCiphertext<Vec<u64>> {
        let (lwe_sk, encryption_noise) = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => (
                cks.glwe_secret_key.as_lwe_secret_key(),
                cks.parameters.glwe_modular_std_dev,
            ),
            EncryptionKeyChoice::Small => {
                let view = LweSecretKey::from_container(cks.lwe_secret_key.as_ref());
                (view, cks.parameters.lwe_modular_std_dev)
            }
        };

        allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            plaintext,
            encryption_noise,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        )
    }

    pub fn encode_message_into_plaintext(
        &mut self,
        message: u64,
        encoding: &Encoding,
    ) -> Plaintext<u64> {
        let zpelem = encoding.get_part_single_value_if_canonical(message);
        let buffer: u128 = (1 << 64) / encoding.get_modulus() as u128 * zpelem as u128;
        Plaintext(buffer as u64)
    }

    pub fn encrypt_arithmetic(
        &mut self,
        message: u64,
        encoding: &Encoding,
        cks: &ClientKey,
    ) -> Ciphertext {
        assert!(message < encoding.get_origin_modulus());

        //  Encode the arithmetic message over Zp
        let plaintext = self.encode_message_into_plaintext(message, encoding);

        let ct = self.encryption_from_plaintext(cks, plaintext);
        Ciphertext::EncodingEncrypted(ct, encoding.clone())
    }

    pub fn decrypt(&mut self, ct: &Ciphertext, cks: &ClientKey) -> u64 {
        let lwe_sk = match cks.parameters.encryption_key_choice {
            EncryptionKeyChoice::Big => cks.glwe_secret_key.as_lwe_secret_key(),
            EncryptionKeyChoice::Small => LweSecretKey::from_container(cks.lwe_secret_key.as_ref()),
        };

        match ct {
            Ciphertext::Trivial(b) => *b,
            Ciphertext::EncodingEncrypted(ciphertext, encoding) => {
                Self::decrypt_arithmetic(&lwe_sk, ciphertext, encoding)
            }
        }
    }

    fn decrypt_arithmetic(
        lwe_sk: &LweSecretKey<&[u64]>,
        ciphertext: &LweCiphertext<Vec<u64>>,
        encoding: &Encoding,
    ) -> u64 {
        // decryption
        let decrypted = decrypt_lwe_ciphertext(&lwe_sk, ciphertext);

        // cast as a u64
        let decrypted_u64 = decrypted.0 as u64;
        // println!("Debug : decrypted : {}", decrypted_u64);

        let divisor: u128 = 1 << 64;
        let divisor_float = divisor as f64;
        let slice: f64 = encoding.get_modulus() as f64 / divisor_float;
        // println!("Debug : decrypted : {}, on Zp : {}", decrypted_u64, decrypted_u64 as f64 / divisor_float * encoding.get_modulus() as f64);

        let floating_result = decrypted_u64 as f64 * slice;

        let closest_integer = floating_result.round() as u64 % encoding.get_modulus();

        for i in 0..encoding.get_origin_modulus() {
            if encoding.is_partition_containing(i, closest_integer) {
                return i;
            }
        }
        panic!("No value in Zo has been found for : {}.", floating_result);
    }
}

    
impl GadgetEngine {

    pub fn apply_lut(
        &mut self,
        input: &Ciphertext,
        output_encoding: &Encoding,
        f: &dyn Fn(u64) -> u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match input {
            Ciphertext::EncodingEncrypted(c, enc_in) => {
                let bootstrapper = &mut self.bootstrapper;
                let enc_inter = enc_in.apply_lut_to_encoding(f);
                bootstrapper.apply_bootstrapping_pattern(
                    c.clone(),
                    &enc_inter,
                    output_encoding,
                    server_key,
                )
            }
            _ => panic!(),
        }
    }


    pub fn encoding_switching_mul_constant(
        &mut self,
        input: &Ciphertext,
        coefficient: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };
        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        // compute the product with the coefficient
        let c = Cleartext(coefficient);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_cleartext_mul(&mut result, &x_ct, c);
                let new_encoding = encoding.multiply_encoding_by_constant(coefficient);
                Ciphertext::EncodingEncrypted(result, new_encoding)
            }
            Ciphertext::Trivial(_) => {
                panic!("Error : casting a trivial ciphertext ! ");
            }
        }
    }

    // Warning : To use only  with similar encodings!
    pub fn simple_sum(&mut self, input: &Vec<Ciphertext>, server_key: &ServerKey) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        input.iter().for_each(|x| match x {
            Ciphertext::EncodingEncrypted(x_ct, _) => {
                lwe_ciphertext_add_assign(&mut result, x_ct);
            }
            Ciphertext::Trivial(_) => {
                panic!("simple_sum not yet implemented with plaintexts")
            }
        });
        let same_encoding = match &input[0] {
            Ciphertext::EncodingEncrypted(_, enc) => enc,
            _ => panic!(),
        };
        Ciphertext::EncodingEncrypted(result, same_encoding.to_owned())
    }

    pub fn simple_plaintext_sum(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let buffer_value: u128 = (1 << 64) / modulus as u128 * constant as u128;
        let value = Plaintext(buffer_value as u64);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::EncodingEncrypted(result, encoding.clone())
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }

    pub fn simple_mul_constant(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let coeff = Cleartext(constant % modulus);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_cleartext_mul(&mut result, x_ct, coeff);
                Ciphertext::EncodingEncrypted(result, encoding.clone())
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }

    pub fn encoding_switching_sum_constant(
        &mut self,
        input: &Ciphertext,
        constant: u64,
        modulus: u64,
        server_key: &ServerKey,
    ) -> Ciphertext {
        let size = match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => server_key
                .key_switching_key
                .input_key_lwe_dimension()
                .to_lwe_size(),
            PBSOrder::BootstrapKeyswitch => server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };

        let mut result = LweCiphertext::new(0u64, size, CiphertextModulus::new_native());
        let buffer_value: u128 = (1 << 64) / modulus as u128 * constant as u128;
        let value = Plaintext(buffer_value as u64);
        match input {
            Ciphertext::EncodingEncrypted(x_ct, encoding) => {
                lwe_ciphertext_plaintext_add_assign(&mut result, value);
                lwe_ciphertext_add_assign(&mut result, x_ct);
                Ciphertext::EncodingEncrypted(result, encoding.add_constant(constant))
            }
            Ciphertext::Trivial(_) => {
                panic!("don't use trivial encryption in this context")
            }
        }
    }
}



//////////

impl Default for GadgetEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GadgetEngine {
    pub fn new() -> Self {
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::<_>::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::<_>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            bootstrapper: Bootstrapper::new(&mut deterministic_seeder),
        }
    }
}
