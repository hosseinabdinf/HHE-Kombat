use std::cmp::max;

use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::*;
use crate::core_crypto::prelude::polynomial_algorithms::{
    polynomial_karatsuba_wrapping_mul, polynomial_wrapping_add_assign
};




// only works if both input have the same encoding, and that this encoding is a power of two
pub fn glwe_mult(
    lhs: &GlweCiphertext<Vec<u64>>,
    rhs: &GlweCiphertext<Vec<u64>>,
    rlk: &RelinearizationKey<Vec<u64>>,
    log_p: usize,
    _client_key_debug: &GlweSecretKey<Vec<u64>>
) -> GlweCiphertext<Vec<u64>>
{


    let mut lhs_modswitch = GlweCiphertext::new(
        0u64,
        lhs.glwe_size(),
        lhs.polynomial_size(),
        lhs.ciphertext_modulus(),
    );


    let mut rhs_modswitch = GlweCiphertext::new(
        0u64,
        lhs.glwe_size(),
        lhs.polynomial_size(),
        lhs.ciphertext_modulus(),
    );
    modswitches_before_glwe_mult(lhs, rhs, log_p, &mut lhs_modswitch, &mut rhs_modswitch);

    /////Debug///////:
    // println!("LHS after modswitch:");
    // let mut plaintext_list = PlaintextList::new(3u64, PlaintextCount(lhs_modswitch.polynomial_size().0));
    // decrypt_glwe_ciphertext(&client_key_debug, &lhs_modswitch, &mut plaintext_list);
    // plaintext_list.iter().for_each(|plaintext| print!("{}| ", plaintext.0));
    //////////////////

    // //noise analysis
    // clear_input.iter_mut().for_each(|x_i: &mut u64| *x_i >>= 32);
    // compute_noise_in_glwe_ciphertext(
    //     &lhs_modswitch,
    //     sk_debug,
    //     &clear_input.clone(),
    //     "modswitch",
    //     32,
    // );

    let mut result: GlweCiphertext<Vec<u64>> = GlweCiphertext::new(
        0u64,
        lhs.glwe_size(),
        lhs.polynomial_size(),
        lhs.ciphertext_modulus(),
    );
    glwe_ciphertext_mult_core(&mut result, &lhs_modswitch, &rhs_modswitch, &rlk);
    result
}

fn _print_glwe_secret_key(glwe_secret_key: GlweSecretKey<Vec<u32>>){
    glwe_secret_key.as_polynomial_list().iter().for_each(|poly|{
        poly.iter().for_each(|x| print!("{}|", x));
        println!();
    })
}



fn modswitches_before_glwe_mult(
    lhs: &GlweCiphertext<Vec<u64>>,
    rhs: &GlweCiphertext<Vec<u64>>,
    log_p: usize,
    lhs_modswitch : &mut GlweCiphertext<Vec<u64>>,
    rhs_modswitch : &mut GlweCiphertext<Vec<u64>>
)
{
    assert_eq!(log_p % 2, 0);


    lhs_modswitch
        .get_mut_mask()
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(lhs.get_mask().as_polynomial_list().iter())
        .for_each(|(mut output_polynomial, input_polynomial)| {
            output_polynomial
                .iter_mut()
                .zip(input_polynomial.iter())
                .for_each(|(out, inp)| {
                    *out = *inp >> (32 - log_p / 2);
                });
        });


    rhs_modswitch
        .get_mut_mask()
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(rhs.get_mask().as_polynomial_list().iter())
        .for_each(|(mut output_polynomial, input_polynomial)| {
            output_polynomial
                .iter_mut()
                .zip(input_polynomial.iter())
                .for_each(|(out, inp)| {
                    *out = *inp >> (32 - log_p / 2);
                });
        });

    lhs_modswitch
        .get_mut_body()
        .as_mut_polynomial()
        .iter_mut()
        .zip(lhs.get_body().as_polynomial().iter())
        .for_each(|(out, inp)| {
            *out = *inp >> (32 - log_p / 2);
        });

    rhs_modswitch
        .get_mut_body()
        .as_mut_polynomial()
        .iter_mut()
        .zip(rhs.get_body().as_polynomial().iter())
        .for_each(|(out, inp)| {
            *out = *inp >> (32 - log_p / 2);
        });
}

pub fn glwe_ciphertext_mult_core(
    output: &mut GlweCiphertext<Vec<u64>>,
    lhs: &GlweCiphertext<Vec<u64>>,
    rhs: &GlweCiphertext<Vec<u64>>,
    rlk: &RelinearizationKey<Vec<u64>>,
)
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        lhs.polynomial_size(),
        rhs.polynomial_size(),
        "Mismatched polynomial size between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.polynomial_size(),
        rhs.polynomial_size()
    );

    assert_eq!(
        output.polynomial_size(),
        rhs.polynomial_size(),
        "Mismatched polynomial_size between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.polynomial_size(),
        rhs.polynomial_size()
    );

    assert_eq!(
        output.glwe_size(),
        rhs.glwe_size(),
        "Mismatched glwe_size between output ({:?}) and rhs ({:?}) GlweCiphertext",
        output.glwe_size(),
        rhs.glwe_size()
    );

    assert_eq!(
        lhs.glwe_size(),
        rhs.glwe_size(),
        "Mismatched glwe_size between lhs ({:?}) and rhs ({:?}) GlweCiphertext",
        lhs.glwe_size(),
        rhs.glwe_size()
    );

    let polynomial_size = output.polynomial_size();
    let glwe_size = output.glwe_size();

    /* Tensor product */

    let t: Vec<_> = lhs
        .get_mask()
        .as_polynomial_list()
        .iter()
        .zip(rhs.as_polynomial_list().iter())
        .map(|(lhs_poly, rhs_poly)| {
            let mut ka_mul = Polynomial::new(0u64, polynomial_size);
            polynomial_karatsuba_wrapping_mul(&mut ka_mul, &lhs_poly, &rhs_poly);
            ka_mul
        })
        .collect();

    let k = lhs.glwe_size().0 - 1; //vérifier le -1

    let r_prime: Vec<Vec<_>> = (0..k)
        .map(|i| {
            (0..i)
                .map(|j| {
                    let mut buf1 = Polynomial::new(0u64, polynomial_size);
                    polynomial_karatsuba_wrapping_mul(
                        &mut buf1,
                        &lhs.as_polynomial_list().get(i),
                        &rhs.as_polynomial_list().get(j),
                    );
                    let mut buf2 = Polynomial::new(0u64, polynomial_size);
                    polynomial_karatsuba_wrapping_mul(
                        &mut buf2,
                        &lhs.as_polynomial_list().get(j),
                        &rhs.as_polynomial_list().get(i),
                    );
                    polynomial_wrapping_add_assign(&mut buf1, &buf2);
                    buf1
                })
                .collect()
        })
        .collect();

    let a_prime: Vec<_> = lhs
        .get_mask()
        .as_polynomial_list()
        .iter()
        .zip(rhs.get_mask().as_polynomial_list().iter())
        .map(|(lhs_poly, rhs_poly)| {
            let mut buf1 = Polynomial::new(0u64, polynomial_size);
            polynomial_karatsuba_wrapping_mul(
                &mut buf1,
                &lhs_poly,
                &rhs.get_body().as_polynomial(),
            );
            let mut buf2 = Polynomial::new(0u64, polynomial_size);
            polynomial_karatsuba_wrapping_mul(
                &mut buf2,
                &rhs_poly,
                &lhs.get_body().as_polynomial(),
            );
            polynomial_wrapping_add_assign(&mut buf1, &buf2);
            buf1
        })
        .collect();

    let mut b_prime = Polynomial::new(0u64, polynomial_size);
    polynomial_karatsuba_wrapping_mul(
        &mut b_prime,
        &lhs.get_body().as_polynomial(),
        &rhs.get_body().as_polynomial(),
    );

    //Relinearization

    output
        .get_mut_mask()
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(a_prime.iter())
        .for_each(|(mut lhs, rhs)| {
            polynomial_wrapping_add_assign(&mut lhs, &rhs);
        });
    polynomial_wrapping_add_assign(&mut output.get_mut_body().as_mut_polynomial(), &b_prime);

    //first sum
    //instantiate the decomposer
    let decomposer = SignedDecomposer::new(
        rlk.decomposition_base_log(),
        rlk.decomposition_level_count(),
    );

    let triangular_numbers: Vec<usize> = (0..=glwe_size.0 - 1).map(|i| i * (i + 1) / 2).collect();
    rlk.iter().enumerate().for_each(|(n, rlk_block)| {
        // to find i and j, we use the fact that i is the "root" of the greater triangular number smaller equal of n
        let mut i = 0;
        while triangular_numbers[i] <= n {
            i = i + 1;
        }
        i = max(1, i);
        i = i - 1;
        let j = n - triangular_numbers[i];

        let mut decomposition = if i == j {
            decomposer.decompose_polynomial(t[i].clone())
        } else {
            decomposer.decompose_polynomial(r_prime[i][j].clone())
        };

        for rlk_block_ciphertext in rlk_block.iter() {
            //on reconstruit le index-ieme polynome décomposé
            let decomposed_values: Vec<u64> = decomposition
                .iter_mut()
                .map(|coeff_decomposition_iter| {
                    coeff_decomposition_iter.next().unwrap().value()
                })
                .collect();
            let decomposed_polynomial_item = Polynomial::from_container(decomposed_values);

            output
                .as_mut_polynomial_list()
                .iter_mut()
                .zip(rlk_block_ciphertext.as_polynomial_list().iter())
                .for_each(|(mut output_poly, rlk_poly)| {
                    let mut buffer = Polynomial::new(0u64, polynomial_size);
                    polynomial_karatsuba_wrapping_mul(
                        &mut buffer,
                        &rlk_poly,
                        &decomposed_polynomial_item,
                    );
                    polynomial_wrapping_add_assign(&mut output_poly, &buffer);
                })
        }
    })
}
