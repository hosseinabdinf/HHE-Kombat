use crate::{multiplexer::Multiplexer, EncryptedBit, Torus};
use concrete_commons::{
    dispersion::StandardDev,
    key_kinds::BinaryKeyKind,
    parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    },
};
use concrete_core::{
    crypto::{
        bootstrap::{FourierBootstrapKey, StandardBootstrapKey},
        glwe::GlweCiphertext,
        secret::{generators::EncryptionRandomGenerator, GlweSecretKey, LweSecretKey},
    },
    math::{
        fft::{Complex64, FourierPolynomial},
        tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor},
    },
    zip_args,
};
use concrete_fftw::array::AlignedVec;
use serde::{Deserialize, Serialize};
use std::ops::{BitAnd, Not};

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeyBit(FourierBootstrapKey<AlignedVec<Complex64>, Torus>);

impl BitAnd<EncryptedBit> for EncryptedKeyBit {
    type Output = EncryptedBit;

    fn bitand(self, rhs: EncryptedBit) -> Self::Output {
        let mut ret = EncryptedBit::allocate(rhs.as_glwe().polynomial_size(), rhs.as_glwe().size());
        let ggsw = self.0.ggsw_iter().next().unwrap();
        self.0
            .external_product(ret.as_mut_glwe(), &ggsw, rhs.as_glwe());
        ret
    }
}

impl Not for EncryptedKeyBit {
    type Output = Self;

    fn not(self) -> Self::Output {
        let mut gadget = Self::one_with_fhe_parameters(
            Some(self.0.polynomial_size()),
            Some(self.0.glwe_size()),
            Some(self.0.level_count()),
            Some(self.0.base_log()),
        );
        gadget
            .0
            .as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .zip(self.0.as_tensor().as_slice().iter())
            .for_each(|(coef_out, coef_in)| *coef_out -= coef_in);
        gadget
    }
}

impl Multiplexer for EncryptedKeyBit {
    type Bit = EncryptedBit;
    fn zero(
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
    ) -> Self {
        let sk = sk.unwrap();
        let mut generator = EncryptionRandomGenerator::new(None);

        // We create a lwe secret key with one bit set to zero
        let lwe_sk = LweSecretKey::binary_from_container(vec![0]);

        // allocation and generation of the key in coef domain:
        let mut coef_bsk = StandardBootstrapKey::allocate(
            0,
            sk.key_size().to_glwe_size(),
            sk.polynomial_size(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        coef_bsk.fill_with_new_key(&lwe_sk, &sk, noise_parameters.unwrap(), &mut generator);

        // allocation for the bootstrapping key
        let mut fourier_bsk = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            sk.key_size().to_glwe_size(),
            sk.polynomial_size(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        fourier_bsk.fill_with_forward_fourier(&coef_bsk);
        EncryptedKeyBit(fourier_bsk)
    }

    fn one(
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
    ) -> Self {
        let sk = sk.unwrap();
        let mut generator = EncryptionRandomGenerator::new(None);

        // We create a lwe secret key with one bit set to one
        let lwe_sk = LweSecretKey::binary_from_container(vec![1]);

        // allocation and generation of the key in coef domain:
        let mut coef_bsk = StandardBootstrapKey::allocate(
            0,
            sk.key_size().to_glwe_size(),
            sk.polynomial_size(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        coef_bsk.fill_with_new_key(&lwe_sk, &sk, noise_parameters.unwrap(), &mut generator);

        // allocation for the bootstrapping key
        let mut fourier_bsk = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            sk.key_size().to_glwe_size(),
            sk.polynomial_size(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        fourier_bsk.fill_with_forward_fourier(&coef_bsk);
        EncryptedKeyBit(fourier_bsk)
    }

    fn zero_with_fhe_parameters(
        poly_size: Option<PolynomialSize>,
        size: Option<GlweSize>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self {
        let fake_key = GlweSecretKey::binary_from_container(
            vec![0; size.unwrap().to_glwe_dimension().0 * poly_size.unwrap().0],
            poly_size.unwrap(),
        );
        let mut generator = EncryptionRandomGenerator::new(Some(0)); // We don't want this function to be random

        // We create a lwe secret key with one bit set to zero
        let lwe_sk = LweSecretKey::binary_from_container(vec![0]);

        // allocation and generation of the key in coef domain:
        let mut coef_bsk = StandardBootstrapKey::allocate(
            0,
            size.unwrap(),
            poly_size.unwrap(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        coef_bsk.fill_with_new_trivial_key(
            &lwe_sk,
            &fake_key,
            StandardDev::from_standard_dev(0.),
            &mut generator,
        );

        // allocation for the bootstrapping key
        let mut fourier_bsk = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            size.unwrap(),
            poly_size.unwrap(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        fourier_bsk.fill_with_forward_fourier(&coef_bsk);
        EncryptedKeyBit(fourier_bsk)
    }

    fn one_with_fhe_parameters(
        poly_size: Option<PolynomialSize>,
        size: Option<GlweSize>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self {
        let fake_key = GlweSecretKey::binary_from_container(
            vec![0; size.unwrap().to_glwe_dimension().0 * poly_size.unwrap().0],
            poly_size.unwrap(),
        );
        let mut generator = EncryptionRandomGenerator::new(Some(0)); // We don't want this function to be random

        // We create a lwe secret key with one bit set to zero
        let lwe_sk = LweSecretKey::binary_from_container(vec![1]);

        // allocation and generation of the key in coef domain:
        let mut coef_bsk = StandardBootstrapKey::allocate(
            0,
            size.unwrap(),
            poly_size.unwrap(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        coef_bsk.fill_with_new_trivial_key(
            &lwe_sk,
            &fake_key,
            StandardDev::from_standard_dev(0.),
            &mut generator,
        );

        // allocation for the bootstrapping key
        let mut fourier_bsk = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            size.unwrap(),
            poly_size.unwrap(),
            decomp_level.unwrap(),
            decomp_base_log.unwrap(),
            LweDimension(1),
        );
        fourier_bsk.fill_with_forward_fourier(&coef_bsk);
        EncryptedKeyBit(fourier_bsk)
    }

    fn mux(&self, o1: &Self::Bit, o0: &Self::Bit) -> Self::Bit {
        let mut res = o0.clone();
        let ggsw = self.0.ggsw_iter().next().unwrap();
        self.0
            .cmux(res.as_mut_glwe(), o1.clone().as_mut_glwe(), &ggsw);
        res
    }

    fn as_bit(&self) -> Self::Bit {
        let mut b = GlweCiphertext::from_container(
            self.0
                .ggsw_iter()
                .next()
                .unwrap()
                .level_matrix_iter()
                .next()
                .unwrap()
                .row_iter()
                .last()
                .unwrap()
                .into_glwe()
                .as_tensor()
                .as_slice()
                .to_vec(),
            self.0.polynomial_size(),
        );
        let mut output = GlweCiphertext::allocate(0, self.0.polynomial_size(), self.0.glwe_size());
        let mut _output_bind = output.as_mut_polynomial_list();
        let mut iterator = _output_bind.polynomial_iter_mut().zip(
            b.as_mut_tensor()
                .subtensor_iter_mut(self.0.polynomial_size().0)
                .map(FourierPolynomial::from_container),
        );
        loop {
            match (iterator.next(), iterator.next()) {
                (Some(first), Some(second)) => {
                    // We unpack the iterates
                    let zip_args!(mut first_output, mut first_fourier) = first;
                    let zip_args!(mut second_output, mut second_fourier) = second;
                    // We perform the backward transform
                    self.0.fft.add_backward_two_as_torus(
                        &mut first_output,
                        &mut second_output,
                        &mut first_fourier,
                        &mut second_fourier,
                    );
                }
                (Some(first), None) => {
                    // We unpack the iterates
                    let (mut first_output, mut first_fourier) = first;
                    // We perform the backward transform
                    self.0
                        .fft
                        .add_backward_as_torus(&mut first_output, &mut first_fourier);
                }
                _ => break,
            }
        }
        drop(iterator);
        output
            .as_mut_tensor()
            .update_with_scalar_mul(&(1 << (self.0.base_log().0 - 1)));
        EncryptedBit::new(output)
    }

    fn not_inplace(&mut self) {
        let gadget = Self::one_with_fhe_parameters(
            Some(self.0.polynomial_size()),
            Some(self.0.glwe_size()),
            Some(self.0.level_count()),
            Some(self.0.base_log()),
        );

        self.0
            .as_mut_tensor()
            .update_with_one(gadget.0.as_tensor(), |t, g| *t = *g - *t);
    }

    fn descriptor() -> String {
        "encrypted".to_string()
    }
}

#[cfg(test)]
mod test {
    use concrete_commons::{
        dispersion::StandardDev,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PlaintextCount,
            PolynomialSize,
        },
    };
    use concrete_core::{
        crypto::{
            encoding::PlaintextList,
            secret::{generators::SecretRandomGenerator, GlweSecretKey},
        },
        math::tensor::{AsRefSlice, AsRefTensor},
    };

    use crate::{
        multiplexer::{encrypted_key_bit::EncryptedKeyBit, Multiplexer},
        Torus,
    };

    #[test]
    fn ggsw_as_bit() {
        let mut generator = SecretRandomGenerator::new(None);
        let sk =
            GlweSecretKey::generate_binary(GlweDimension(1), PolynomialSize(1024), &mut generator);
        let decomp_level = DecompositionLevelCount(2);
        let decomp_base_log = DecompositionBaseLog(1);
        let noise_parameters = StandardDev::from_standard_dev(2_f64.powf(-14.));
        for _ in 0..100 {
            let zero = EncryptedKeyBit::zero(
                Some(&sk),
                Some(decomp_level),
                Some(decomp_base_log),
                Some(noise_parameters),
            );
            let lwe_zero = zero.as_bit();
            let mut decrypted_zero = PlaintextList::allocate(0, PlaintextCount(1024));
            sk.decrypt_glwe(&mut decrypted_zero, lwe_zero.as_glwe());
            let mut decoded_zero =
                decrypted_zero.as_tensor().as_slice()[0] >> (Torus::BITS as usize - 2);
            if decoded_zero % 2 == 1 {
                decoded_zero += 2;
            }
            decoded_zero >>= 1;
            decoded_zero %= 2;
            assert_eq!(decoded_zero, 0);
        }
        for _ in 0..100 {
            let one = EncryptedKeyBit::one(
                Some(&sk),
                Some(decomp_level),
                Some(decomp_base_log),
                Some(noise_parameters),
            );
            let lwe_one = one.as_bit();
            let mut decrypted_one = PlaintextList::allocate(0, PlaintextCount(1024));
            sk.decrypt_glwe(&mut decrypted_one, lwe_one.as_glwe());
            let mut decoded_one =
                decrypted_one.as_tensor().as_slice()[0] >> (Torus::BITS as usize - 2);
            if decoded_one % 2 == 1 {
                decoded_one += 2;
            }
            decoded_one >>= 1;
            decoded_one %= 2;
            assert_eq!(decoded_one, 1);
        }
    }

    #[test]
    fn ggsw_not() {
        let mut generator = SecretRandomGenerator::new(None);
        let sk =
            GlweSecretKey::generate_binary(GlweDimension(1), PolynomialSize(1024), &mut generator);
        let decomp_level = DecompositionLevelCount(2);
        let decomp_base_log = DecompositionBaseLog(1);
        let noise_parameters = StandardDev::from_standard_dev(2_f64.powf(-14.));
        for _ in 0..100 {
            let one = EncryptedKeyBit::one(
                Some(&sk),
                Some(decomp_level),
                Some(decomp_base_log),
                Some(noise_parameters),
            );
            let lwe_zero = (!one).as_bit();
            let mut decrypted_zero = PlaintextList::allocate(0, PlaintextCount(1024));
            sk.decrypt_glwe(&mut decrypted_zero, lwe_zero.as_glwe());
            let mut decoded_zero =
                decrypted_zero.as_tensor().as_slice()[0] >> (Torus::BITS as usize - 2);
            if decoded_zero % 2 == 1 {
                decoded_zero += 2;
            }
            decoded_zero >>= 1;
            decoded_zero %= 2;
            assert_eq!(decoded_zero, 0);
        }
        for _ in 0..100 {
            let zero = EncryptedKeyBit::zero(
                Some(&sk),
                Some(decomp_level),
                Some(decomp_base_log),
                Some(noise_parameters),
            );
            let lwe_one = (!zero).as_bit();
            let mut decrypted_one = PlaintextList::allocate(0, PlaintextCount(1024));
            sk.decrypt_glwe(&mut decrypted_one, lwe_one.as_glwe());
            let mut decoded_one =
                decrypted_one.as_tensor().as_slice()[0] >> (Torus::BITS as usize - 2);
            if decoded_one % 2 == 1 {
                decoded_one += 2;
            }
            decoded_one >>= 1;
            decoded_one %= 2;
            assert_eq!(decoded_one, 1);
        }
    }
}
