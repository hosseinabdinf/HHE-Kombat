use std::ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign, Not};

use concrete_commons::{
    numeric::Numeric,
    parameters::{GlweSize, PolynomialSize},
};
use concrete_core::{
    crypto::glwe::GlweCiphertext,
    math::tensor::{AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor},
};

use crate::Bit;
use crate::{multiplexer::EncryptedKeyBit, Torus};

#[derive(Clone)]
pub struct EncryptedBit(GlweCiphertext<Vec<Torus>>);

impl EncryptedBit {
    pub fn new(glwe: GlweCiphertext<Vec<Torus>>) -> Self {
        Self(glwe)
    }

    pub fn allocate(poly_size: PolynomialSize, glwe_size: GlweSize) -> Self {
        Self(GlweCiphertext::allocate(0, poly_size, glwe_size))
    }

    pub fn as_glwe(&self) -> &GlweCiphertext<Vec<Torus>> {
        &self.0
    }

    pub fn as_mut_glwe(&mut self) -> &mut GlweCiphertext<Vec<Torus>> {
        &mut self.0
    }
}

impl Not for EncryptedBit {
    type Output = Self;

    fn not(self) -> Self {
        let mut ret = self.clone();
        ret.not_inplace();
        ret
    }
}

impl BitAndAssign<EncryptedKeyBit> for EncryptedBit {
    fn bitand_assign(&mut self, rhs: EncryptedKeyBit) {
        let ret = rhs & self.clone();
        self.0
            .as_mut_tensor()
            .as_mut_slice()
            .clone_from_slice(ret.0.as_tensor().as_slice());
    }
}

impl BitXorAssign for EncryptedBit {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0
            .as_mut_tensor()
            .update_with_wrapping_add(rhs.0.as_tensor());
    }
}

impl BitXor for EncryptedBit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut ret = self.clone();
        ret.0
            .as_mut_tensor()
            .update_with_wrapping_add(rhs.0.as_tensor());
        ret
    }
}

impl BitAnd<EncryptedKeyBit> for EncryptedBit {
    type Output = Self;

    fn bitand(self, rhs: EncryptedKeyBit) -> Self::Output {
        rhs & self
    }
}

impl Bit<EncryptedKeyBit> for EncryptedBit {
    fn zero(poly_size: Option<PolynomialSize>, size: Option<GlweSize>) -> Self {
        EncryptedBit(GlweCiphertext::allocate(
            0,
            poly_size.unwrap(),
            size.unwrap(),
        ))
    }

    fn one(poly_size: Option<PolynomialSize>, size: Option<GlweSize>) -> Self {
        let mut ret = Self::zero(poly_size, size);
        ret.0
            .as_mut_tensor()
            .iter_mut()
            .for_each(|c| *c = c.wrapping_neg());
        ret.0.get_mut_body().as_mut_tensor().as_mut_slice()[0] +=
            1 << (<Torus as Numeric>::BITS - 1);
        ret
    }

    fn not_inplace(&mut self) {
        self.0.as_mut_tensor().update_with_wrapping_neg();
        self.0.get_mut_body().as_mut_tensor().as_mut_slice()[0] +=
            1 << (<Torus as Numeric>::BITS - 1);
    }
}
