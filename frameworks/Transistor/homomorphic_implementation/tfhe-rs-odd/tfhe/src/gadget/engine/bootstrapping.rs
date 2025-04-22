#![allow(non_snake_case)] 


use crate::core_crypto::prelude::{CiphertextModulus, Container, ContiguousEntityContainer, ContiguousEntityContainerMut, Fft, MonomialDegree, PBSOrder, PlaintextCount};
use crate::gadget::engine::polynomial_algorithms::polynomial_wrapping_monic_monomial_mul_assign;
use crate::gadget::engine::slice_algorithms::slice_wrapping_add_assign;
use crate::gadget::prelude::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{DeterministicSeeder, EncryptionRandomGenerator};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::entities::*;

use self::polynomial_algorithms::polynomial_karatsuba_wrapping_mul;


/////Accumulator used in the BlindRotate part of the bootstrapping
type Accumulator = Vec<u64>;


/// Memory used as buffer for the bootstrap
///
/// It contains contiguous chunk which is then sliced and converted
/// into core's View types.
#[derive(Default)]
pub struct Memory {
    buffer: Vec<u64>,
}

pub struct BuffersRef<'a> {
    pub(crate) lookup_table: GlweCiphertextMutView<'a, u64>,
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u64>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u64>,
}


impl Memory {
    //generate the vector of values to fill in each window gor given input and output encodings in simple bootstrapping
    pub fn create_accumulator(encoding_in : &Encoding, encoding_out : &Encoding) -> Accumulator{
        assert!(encoding_in.is_valid());
        assert!(encoding_out.is_canonical());
        let p = encoding_in.get_modulus();
        assert!(p % 2 == 1);
        let mut accu : Accumulator = vec![0;p.try_into().unwrap()];
        for k  in 0..p{ //k is a ZpElem
            if k % 2 == 0{
                //finding the ZoElem i corresponding to this encoding in
                let i = encoding_in.inverse_encoding(k / 2);
                //Finding the new ZpElem corresponding to i in encoding out
                accu[k as usize] = match i{
                    Some(i) => encoding_out.get_part_single_value_if_canonical(i),
                    None => 0
                };
            }
            else{
                //finding the ZoElem i corresponding to this encoding in
                let i = encoding_in.inverse_encoding((p + 1)/2 + (k - 1) / 2);
                //Finding the new ZpElem corresponing to i in encoging out
                accu[k as usize] = match i{
                    Some(i) => encoding_out.negative_on_p_ring(encoding_out.get_part_single_value_if_canonical(i)),
                    None => 0
                };
            }
        }
        // accu.iter().enumerate().for_each(|(i, x)| print!("{} : {} |", i, x));
        // println!();
        accu
    }



    //common part of memory allocation for bootstrappings
    fn allocate_ciphertexts_for_bootstrapping(&mut self, server_key: &ServerKey)->(GlweCiphertext<&mut[u64]>, LweCiphertext<&mut[u64]>, LweCiphertext<&mut[u64]>){
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_elem_in_lwe_after_ks = server_key.key_switching_key.output_lwe_size().0;
        let num_elem_in_lwe_after_pbs = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;
        let total_elem_needed = num_elem_in_accumulator + num_elem_in_lwe_after_ks + num_elem_in_lwe_after_pbs;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u64);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (accumulator_elements, other_elements) =
            all_elements.split_at_mut(num_elem_in_accumulator);

        let accumulator = GlweCiphertext::from_container(
            accumulator_elements,
            server_key.bootstrapping_key.polynomial_size(),
            CiphertextModulus::new_native(),
        );
        let (after_ks_elements, after_pbs_elements) =
        other_elements.split_at_mut(num_elem_in_lwe_after_ks);

        let buffer_lwe_after_ks = LweCiphertextMutView::from_container(
            after_ks_elements,
            CiphertextModulus::new_native(),
        );
        let buffer_lwe_after_pbs = LweCiphertextMutView::from_container(
            after_pbs_elements,
            CiphertextModulus::new_native(),
        );

        (accumulator, buffer_lwe_after_ks, buffer_lwe_after_pbs)
    }




    /// Return a tuple with buffers that matches the server key.
    ///
    /// - The first element is the accumulator for bootstrap step.
    /// - The second element is a lwe buffer where the result of the of the bootstrap should be
    ///   written
    fn as_buffers(
        &mut self,
        server_key: &ServerKey,
        enc_in : &Encoding,
        enc_out : &Encoding
    ) -> BuffersRef<'_>{
        let (mut accumulator, buffer_lwe_after_ks, buffer_lwe_after_pbs) = self.allocate_ciphertexts_for_bootstrapping(server_key);

        ////accumulator filling
        let p = enc_in.get_modulus();
        let new_p = enc_out.get_modulus() as u64;
        accumulator.get_mut_mask().as_mut().fill(0u64);
        let N_poly: usize = accumulator.get_mut_body().as_mut().len();    //(N degree of the polynomial)

        if p != 2{ 

            let accu_data = Self::create_accumulator(enc_in, enc_out);
        

            let const_shift = N_poly / (2 * p) as usize;   //half a window

            let mut buffer_value : u64 = ((1 << 64) / new_p as u128) as u64 * accu_data[0] as u64;    //value to be written in the accumulator, put in a u64 to enhance the precision of the / operation
            accumulator.get_mut_body().as_mut()[..const_shift].fill(buffer_value as u64);   //filling of the first half window
            for k in 1..accu_data.len(){
                buffer_value = ((1 << 64) / new_p as u128) as u64 * accu_data[k] as u64;
                accumulator.get_mut_body().as_mut()[const_shift + (k - 1) * N_poly / p as usize..const_shift + k * N_poly / p as usize].fill(buffer_value as u64); //filling of the (k+1)th window
            }
            buffer_value = ((1 << 64) / new_p as u128) as u64 * ((enc_out.get_modulus() - accu_data[0]) % enc_out.get_modulus()) as u64;
            accumulator.get_mut_body().as_mut()[N_poly  - const_shift..].fill(buffer_value as u64);//filling of the last half-window
        }
        else{
            //check that we have negacyclicity
            let new_false = enc_out.get_part_single_value_if_canonical(0);
            let new_true = enc_out.get_part_single_value_if_canonical(1);

            assert!(new_false == (new_p as u64 - new_true) % new_p as u64);
            //Is the 0 window true or false ?
            let (new_0, new_1) = match enc_in.is_partition_containing(1, 0){
                true => (new_true, new_false),
                false => (new_false, new_true)
            };
            //filling of the accu
            let mut buffer_value = ((1 << 64) / new_p as u128) as u64 * new_0 as u64;
            accumulator.get_mut_body().as_mut()[..N_poly / 2].fill(buffer_value as u64);   //filling of the first half window
            buffer_value = ((1 << 64) / new_p as u128) as u64 * new_1 as u64;
            accumulator.get_mut_body().as_mut()[N_poly / 2..].fill(buffer_value as u64);   //filling of the second half window
        }

        BuffersRef {
            lookup_table: accumulator,
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }
}




/// A structure containing the server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone)]
pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub(crate) pbs_order: PBSOrder
}

impl ServerKey {
    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.as_view().data().as_ref().len()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.bootstrapping_key_size_elements() * std::mem::size_of::<concrete_fft::c64>()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        self.key_switching_key_size_elements() * std::mem::size_of::<u64>()
    }
}


/// Perform ciphertext bootstraps on the CPU
pub(crate) struct Bootstrapper {
    memory: Memory,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    #[allow(dead_code)]
    pub(crate) seeder: DeterministicSeeder<ActivatedRandomGenerator>,
}


impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        Self {
            memory: Memory::default(),
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: ComputationBuffers::default(),
            seeder: DeterministicSeeder::<_>::new(seeder.seed()),
        }
    }

    pub(crate) fn new_server_key(&mut self, cks: &ClientKey) -> ServerKey {
        let standard_bootstrapping_key: LweBootstrapKeyOwned<u64> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
                CiphertextModulus::new_native(),
                &mut self.encryption_generator,
            );

        // creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            standard_bootstrapping_key.input_lwe_dimension(),
            standard_bootstrapping_key.glwe_size(),
            standard_bootstrapping_key.polynomial_size(),
            standard_bootstrapping_key.decomposition_base_log(),
            standard_bootstrapping_key.decomposition_level_count(),
        );

        let fft = Fft::new(standard_bootstrapping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_requirement(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );

        // Conversion to fourier domain
        par_convert_standard_lwe_bootstrap_key_to_fourier(
            &standard_bootstrapping_key,
            &mut fourier_bsk,
        );

        // Convert the GLWE secret key into an LWE secret key:
        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            CiphertextModulus::new_native(),
            &mut self.encryption_generator,
        );



        ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
            pbs_order: cks.parameters.encryption_key_choice.into(),
        }
    }





    pub(crate) fn bootstrap(
        &mut self,
        input: &LweCiphertextOwned<u64>,
        accumulator : &GlweCiphertext<Vec<u64>>,
        server_key: &ServerKey) -> LweCiphertextOwned<u64> {
        // let BuffersRef {
        //     lookup_table: accumulator,
        //     mut buffer_lwe_after_pbs,
        //     ..
        // } = self.memory.as_buffers(server_key);

        let mut buffer_lwe_after_pbs = LweCiphertext::new(0u64, server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size(), CiphertextModulus::new_native());

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();


        let mut output_glwe = GlweCiphertext::new(0u64, accumulator.glwe_size(), accumulator.polynomial_size(), accumulator.ciphertext_modulus());
        // programmable_bootstrap_lwe_ciphertext_mem_optimized(
        //     input,
        //     &mut buffer_lwe_after_pbs,
        //     &accumulator,
        //     fourier_bsk,
        //     fft,
        //     stack,
        // );

        programmable_bootstrap_lwe_ciphertext_without_sample_extract_mem_optimized(
            input, 
            &mut output_glwe, 
            &accumulator, 
            fourier_bsk, fft, stack);

        // Self::decrypt_glwe_with_builtin_function(&client_key_debug, &output_glwe);
        
        extract_lwe_sample_from_glwe_ciphertext(&output_glwe, &mut buffer_lwe_after_pbs, MonomialDegree(0));

        LweCiphertext::from_container(
            buffer_lwe_after_pbs.as_ref().to_owned(),
            input.ciphertext_modulus(),
        )
    }




    pub(crate) fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u64>,
        enc_inter : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey,
    ) -> Ciphertext{
        let BuffersRef {
            lookup_table: accumulator,
            mut buffer_lwe_after_pbs,
            ..
        } = self.memory.as_buffers(server_key, enc_inter, enc_out);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a key switch to get back to input key
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ciphertext::EncodingEncrypted(ciphertext, enc_out.clone())
    }




    pub(crate) fn keyswitch_bootstrap(
            &mut self,
            mut ciphertext: LweCiphertextOwned<u64>,
            enc_inter : &Encoding,
            enc_out : &Encoding,
            server_key: &ServerKey,
    ) -> Ciphertext {
        let BuffersRef {
            lookup_table,
            mut buffer_lwe_after_ks,
            ..
        } = self.memory.as_buffers(server_key, enc_inter, enc_out);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Keyswitch from large LWE key to the small one
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &ciphertext,
            &mut buffer_lwe_after_ks,
        );


        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &buffer_lwe_after_ks,
            &mut ciphertext,
            &lookup_table,
            fourier_bsk,
            fft,
            stack
        );

        Ciphertext::EncodingEncrypted(ciphertext, enc_out.clone())
    }

    
    pub(crate) fn apply_bootstrapping_pattern(
        &mut self,
        ct: LweCiphertextOwned<u64>,
        enc_inter : &Encoding,
        enc_out : &Encoding,
        server_key: &ServerKey,
    ) -> Ciphertext {
        match server_key.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.keyswitch_bootstrap(ct, enc_inter, enc_out, server_key),
            PBSOrder::BootstrapKeyswitch => self.bootstrap_keyswitch(ct, enc_inter, enc_out, server_key),
        }
    }
}


impl ServerKey {
    pub(crate) fn keyswitch(&self, input: &LweCiphertextOwned<u64>) -> LweCiphertextOwned<u64> {
        // Allocate the output of the KS
        let mut output = LweCiphertext::new(
            0u64,
            self.bootstrapping_key.input_lwe_dimension().to_lwe_size(),
            input.ciphertext_modulus(),
        );

        keyswitch_lwe_ciphertext(&self.key_switching_key, input, &mut output);

        output
    }
}
