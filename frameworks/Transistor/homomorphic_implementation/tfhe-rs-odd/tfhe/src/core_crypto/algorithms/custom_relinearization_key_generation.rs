#![allow(non_snake_case)]
//! Module containing primitives pertaining to [`LWE relinearizaion keys
//! generation`](`RelinearizationKey`).

use std::cmp::max;

use crate::core_crypto::algorithms::encrypt_glwe_ciphertext_list;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::{DecompositionLevel, DecompositionTerm};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::{
    GlweSecretKey, RelinearizationKey, RelinearizationKeyOwned,
    PlaintextListOwned};
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_karatsuba_wrapping_mul;
use crate::core_crypto::prelude::Polynomial;

/// Fill an [`Relinearization key](`RelinearizationKey`) with an actual relinearization key constructed from an input [`GlWE secret key`](`GlweSecretKey`).
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for RelinearizationKey creation
/// let input_lwe_dimension = LweDimension(742);
/// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
/// let output_glwe_dimension = GlweDimension(1);
/// let output_polynomial_size = PolynomialSize(2048);
/// let decomp_base_log = DecompositionBaseLog(23);
/// let decomp_level_count = DecompositionLevelCount(1);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the LweSecretKey
/// let input_lwe_secret_key =
///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
/// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     output_glwe_dimension,
///     output_polynomial_size,
///     &mut secret_generator,
/// );
///
/// let mut pksk = RelinearizationKey::new(
///     0u64,
///     decomp_base_log,
///     decomp_level_count,
///     input_lwe_dimension,
///     output_glwe_dimension,
///     output_polynomial_size,
///     ciphertext_modulus,
/// );
///
/// generate_lwe_packing_keyswitch_key(
///     &input_lwe_secret_key,
///     &output_glwe_secret_key,
///     &mut pksk,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
///
/// assert!(pksk.as_ref().iter().all(|&x| x == 0) == false);
/// ```
pub fn generate_relinearization_key<Scalar, InputKeyCont, KSKeyCont, Gen>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    relinearization_key: &mut RelinearizationKey<KSKeyCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    KSKeyCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        relinearization_key.input_key_glwe_dimension() == input_glwe_sk.glwe_dimension(),
        "The destination RelinearizationKey output LweDimension is not equal \
    to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
        relinearization_key.input_key_glwe_dimension(),
        input_glwe_sk.glwe_dimension()
    );
    assert!(
        relinearization_key.output_key_polynomial_size() == input_glwe_sk.polynomial_size(),
        "The destination RelinearizationKey output PolynomialSize is not equal \
        to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
        relinearization_key.output_key_polynomial_size(),
        input_glwe_sk.polynomial_size()
    );

    let glwe_dimension = relinearization_key.input_key_glwe_dimension();    //k
    let decomp_base_log = relinearization_key.decomposition_base_log();
    let decomp_level_count = relinearization_key.decomposition_level_count();
    let polynomial_size = relinearization_key.output_polynomial_size();
    let ciphertext_modulus = relinearization_key.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    // The plaintexts used to encrypt a key element will be stored in this buffer
    let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(  //un GLev
        Scalar::ZERO,
        PlaintextCount(decomp_level_count.0 * polynomial_size.0),
    );


    let triangular_numbers: Vec<usize> = (0..=glwe_dimension.0).map(|i| i * (i+1) / 2).collect();

    for (n, mut relinearization_key_block) in relinearization_key.iter_mut().enumerate(){
        // to find i and j, we use the fact that i is the "root" of the greater triangular number smaller equal of n
        let mut i = 0;
        while triangular_numbers[i] <= n{
            i = i + 1;
        }
        i = max(1, i);
        i = i-1;
        let j = n - triangular_numbers[i];
    
        // On calcule le produit des deux polynomes à multiplier
        let poly_list = input_glwe_sk.as_polynomial_list();
        let S_i = poly_list.get(i).clone();
        let S_j = poly_list.get(j).clone();

        let mut product = Polynomial::new(Scalar::ZERO, polynomial_size);
        polynomial_karatsuba_wrapping_mul(&mut product, &S_i, &S_j);

    
        // We fill the buffer with the powers of the key elements
        for (level, mut messages) in (1..=decomp_level_count.0)
            .rev()
            .map(DecompositionLevel)
            .zip(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
        {
           
            // Here  we take the decomposition term from the native torus, bring it to the torus we
            // are working with by dividing by the scaling factor and the encryption will take care
            // of mapping that back to the native torus
            
            for (i, coeff_poly_input) in product.iter().enumerate(){
                *messages.get_mut(i).0 =  DecompositionTerm::new(level, decomp_base_log, *coeff_poly_input)
                                                .to_recomposition_summand()
                                                .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
                }
               
        }

        encrypt_glwe_ciphertext_list(
            input_glwe_sk,
            &mut relinearization_key_block,
            &decomposition_plaintexts_buffer,
            noise_parameters,
            generator,
        );
    }
    
}

/// Allocate a new [`RelinearizationKey`](`RelinearizationKey`) and fill it with an
/// actual packing keyswitching key constructed from an input [`LWE secret key`](`LweSecretKey`) and
/// an output [`GLWE secret key`](`GlweSecretKey`).
///
/// See [`keyswitch_lwe_ciphertext_into_glwe_ciphertext`](`super::keyswitch_lwe_ciphertext_into_glwe_ciphertext`)
///  for usage.
pub fn allocate_and_generate_new_relinearization_key<
    Scalar,
    InputKeyCont,
    Gen,
>(
    input_glwe_sk: &GlweSecretKey<InputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_parameters: impl DispersionParameter,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> RelinearizationKeyOwned<Scalar>
where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut new_relinearization_key = RelinearizationKeyOwned::new(
        Scalar::ZERO,
        decomp_base_log,
        decomp_level_count,
        input_glwe_sk.glwe_dimension(),
        input_glwe_sk.polynomial_size(),
        ciphertext_modulus,
    );

    generate_relinearization_key(
        input_glwe_sk,
        &mut new_relinearization_key,
        noise_parameters,
        generator,
    );

    new_relinearization_key
}

// /// Fill an [`LWE keyswitch key`](`SeededRelinearizationKey`) with an actual keyswitching key
// /// constructed from an input [`LWE secret key`](`LweSecretKey`) and an output
// /// [`GLWE secret key`](`GlweSecretKey`).
// ///
// /// ```
// /// use tfhe::core_crypto::prelude::*;
// ///
// /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
// /// // computations
// /// // Define parameters for RelinearizationKey creation
// /// let input_lwe_dimension = LweDimension(742);
// /// let glwe_modular_std_dev = StandardDev(0.00000000000000029403601535432533);
// /// let output_glwe_dimension = GlweDimension(1);
// /// let output_polynomial_size = PolynomialSize(2048);
// /// let decomp_base_log = DecompositionBaseLog(23);
// /// let decomp_level_count = DecompositionLevelCount(1);
// /// let ciphertext_modulus = CiphertextModulus::new_native();
// ///
// /// // Create the PRNG
// /// let mut seeder = new_seeder();
// /// let seeder = seeder.as_mut();
// /// let mut encryption_generator =
// ///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
// /// let mut secret_generator =
// ///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
// ///
// /// // Create the LweSecretKey
// /// let input_lwe_secret_key =
// ///     allocate_and_generate_new_binary_lwe_secret_key(input_lwe_dimension, &mut secret_generator);
// /// let output_glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
// ///     output_glwe_dimension,
// ///     output_polynomial_size,
// ///     &mut secret_generator,
// /// );
// ///
// /// let mut seeded_pksk = SeededRelinearizationKey::new(
// ///     0u64,
// ///     decomp_base_log,
// ///     decomp_level_count,
// ///     input_lwe_dimension,
// ///     output_glwe_dimension,
// ///     output_polynomial_size,
// ///     seeder.seed().into(),
// ///     ciphertext_modulus,
// /// );
// ///
// /// generate_seeded_lwe_packing_keyswitch_key(
// ///     &input_lwe_secret_key,
// ///     &output_glwe_secret_key,
// ///     &mut seeded_pksk,
// ///     glwe_modular_std_dev,
// ///     seeder,
// /// );
// ///
// /// assert!(seeded_pksk.as_ref().iter().all(|&x| x == 0) == false);
// /// ```
// pub fn generate_seeded_lwe_packing_keyswitch_key<
//     Scalar,
//     InputKeyCont,
//     OutputKeyCont,
//     KSKeyCont,
//     NoiseSeeder,
// >(
//     input_lwe_sk: &LweSecretKey<InputKeyCont>,
//     output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
//     lwe_packing_keyswitch_key: &mut SeededRelinearizationKey<KSKeyCont>,
//     noise_parameters: impl DispersionParameter,
//     noise_seeder: &mut NoiseSeeder,
// ) where
//     Scalar: UnsignedTorus,
//     InputKeyCont: Container<Element = Scalar>,
//     OutputKeyCont: Container<Element = Scalar>,
//     KSKeyCont: ContainerMut<Element = Scalar>,
//     // Maybe Sized allows to pass Box<dyn Seeder>.
//     NoiseSeeder: Seeder + ?Sized,
// {
//     assert!(
//         lwe_packing_keyswitch_key.input_key_lwe_dimension() == input_lwe_sk.lwe_dimension(),
//         "The destination RelinearizationKey input LweDimension is not equal \
//     to the input LweSecretKey LweDimension. Destination: {:?}, input: {:?}",
//         lwe_packing_keyswitch_key.input_key_lwe_dimension(),
//         input_lwe_sk.lwe_dimension()
//     );
//     assert!(
//         lwe_packing_keyswitch_key.output_key_glwe_dimension() == output_glwe_sk.glwe_dimension(),
//         "The destination RelinearizationKey output LweDimension is not equal \
//     to the output GlweSecretKey GlweDimension. Destination: {:?}, output: {:?}",
//         lwe_packing_keyswitch_key.output_key_glwe_dimension(),
//         output_glwe_sk.glwe_dimension()
//     );
//     assert!(
//         lwe_packing_keyswitch_key.output_key_polynomial_size() == output_glwe_sk.polynomial_size(),
//         "The destination RelinearizationKey output PolynomialSize is not equal \
//         to the output GlweSecretKey PolynomialSize. Destination: {:?}, output: {:?}",
//         lwe_packing_keyswitch_key.output_key_polynomial_size(),
//         output_glwe_sk.polynomial_size()
//     );

//     let decomp_base_log = lwe_packing_keyswitch_key.decomposition_base_log();
//     let decomp_level_count = lwe_packing_keyswitch_key.decomposition_level_count();
//     let polynomial_size = lwe_packing_keyswitch_key.output_polynomial_size();
//     let ciphertext_modulus = lwe_packing_keyswitch_key.ciphertext_modulus();
//     assert!(ciphertext_modulus.is_compatible_with_native_modulus());

//     // The plaintexts used to encrypt a key element will be stored in this buffer
//     let mut decomposition_plaintexts_buffer = PlaintextListOwned::new(
//         Scalar::ZERO,
//         PlaintextCount(decomp_level_count.0 * polynomial_size.0),
//     );

//     let mut generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
//         lwe_packing_keyswitch_key.compression_seed().seed,
//         noise_seeder,
//     );

//     // Iterate over the input key elements and the destination lwe_packing_keyswitch_key memory
//     for (input_key_element, mut packing_keyswitch_key_block) in input_lwe_sk
//         .as_ref()
//         .iter()
//         .zip(lwe_packing_keyswitch_key.iter_mut())
//     {
//         // We fill the buffer with the powers of the key elements
//         for (level, mut messages) in (1..=decomp_level_count.0)
//             .rev()
//             .map(DecompositionLevel)
//             .zip(decomposition_plaintexts_buffer.chunks_exact_mut(polynomial_size.0))
//         {
//             // Here  we take the decomposition term from the native torus, bring it to the torus we
//             // are working with by dividing by the scaling factor and the encryption will take care
//             // of mapping that back to the native torus
//             *messages.get_mut(0).0 =
//                 DecompositionTerm::new(level, decomp_base_log, *input_key_element)
//                     .to_recomposition_summand()
//                     .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());
//         }

//         encrypt_seeded_glwe_ciphertext_list_with_existing_generator(
//             output_glwe_sk,
//             &mut packing_keyswitch_key_block,
//             &decomposition_plaintexts_buffer,
//             noise_parameters,
//             &mut generator,
//         );
//     }
// }

// /// Allocate a new [`seeded LWE keyswitch key`](`SeededRelinearizationKey`) and fill it with an
// /// actual packing keyswitching key constructed from an input [`LWE secret key`](`LweSecretKey`) and
// /// an output [`GLWE secret key`](`GlweSecretKey`).
// pub fn allocate_and_generate_new_seeded_lwe_packing_keyswitch_key<
//     Scalar,
//     InputKeyCont,
//     OutputKeyCont,
//     NoiseSeeder,
// >(
//     input_lwe_sk: &LweSecretKey<InputKeyCont>,
//     output_glwe_sk: &GlweSecretKey<OutputKeyCont>,
//     decomp_base_log: DecompositionBaseLog,
//     decomp_level_count: DecompositionLevelCount,
//     noise_parameters: impl DispersionParameter,
//     ciphertext_modulus: CiphertextModulus<Scalar>,
//     noise_seeder: &mut NoiseSeeder,
// ) -> SeededRelinearizationKeyOwned<Scalar>
// where
//     Scalar: UnsignedTorus,
//     InputKeyCont: Container<Element = Scalar>,
//     OutputKeyCont: Container<Element = Scalar>,
//     // Maybe Sized allows to pass Box<dyn Seeder>.
//     NoiseSeeder: Seeder + ?Sized,
// {
//     let mut new_lwe_packing_keyswitch_key = SeededRelinearizationKeyOwned::new(
//         Scalar::ZERO,
//         decomp_base_log,
//         decomp_level_count,
//         input_lwe_sk.lwe_dimension(),
//         output_glwe_sk.glwe_dimension(),
//         output_glwe_sk.polynomial_size(),
//         noise_seeder.seed().into(),
//         ciphertext_modulus,
//     );

//     generate_seeded_lwe_packing_keyswitch_key(
//         input_lwe_sk,
//         output_glwe_sk,
//         &mut new_lwe_packing_keyswitch_key,
//         noise_parameters,
//         noise_seeder,
//     );

//     new_lwe_packing_keyswitch_key
// }
