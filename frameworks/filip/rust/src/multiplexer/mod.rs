mod bit_bool;
mod encrypted_key_bit;

use crate::{Bit, Torus};
use concrete_commons::{
    dispersion::StandardDev,
    key_kinds::BinaryKeyKind,
    parameters::{DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize},
};
use concrete_core::crypto::secret::GlweSecretKey;
use serde::{de::DeserializeOwned, Serialize};
use std::ops::{BitAnd, Not};

pub use encrypted_key_bit::EncryptedKeyBit;

pub trait Multiplexer:
    Clone + Not<Output = Self> + BitAnd<Self::Bit, Output = Self::Bit> + Serialize + DeserializeOwned
{
    type Bit: Bit<Self>;
    fn zero(
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
    ) -> Self;
    fn one(
        sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<Torus>>>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
        noise_parameters: Option<StandardDev>,
    ) -> Self;
    fn zero_with_fhe_parameters(
        poly_size: Option<PolynomialSize>,
        size: Option<GlweSize>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self;
    fn one_with_fhe_parameters(
        poly_size: Option<PolynomialSize>,
        size: Option<GlweSize>,
        decomp_level: Option<DecompositionLevelCount>,
        decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self;

    fn mux(&self, o1: &Self::Bit, o0: &Self::Bit) -> Self::Bit;
    fn as_bit(&self) -> Self::Bit;

    fn not_inplace(&mut self);

    fn descriptor() -> String;
}
