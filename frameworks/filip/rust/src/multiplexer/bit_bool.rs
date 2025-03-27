use crate::multiplexer::Multiplexer;
use concrete_commons::{
    dispersion::StandardDev,
    key_kinds::BinaryKeyKind,
    parameters::{DecompositionBaseLog, DecompositionLevelCount, GlweSize, PolynomialSize},
};
use concrete_core::crypto::secret::GlweSecretKey;

impl Multiplexer for bool {
    type Bit = bool;
    fn zero(
        _sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<crate::Torus>>>,
        _decomp_level: Option<DecompositionLevelCount>,
        _decomp_base_log: Option<DecompositionBaseLog>,
        _noise_parameters: Option<StandardDev>,
    ) -> Self {
        false
    }

    fn one(
        _sk: Option<&GlweSecretKey<BinaryKeyKind, Vec<crate::Torus>>>,
        _decomp_level: Option<DecompositionLevelCount>,
        _decomp_base_log: Option<DecompositionBaseLog>,
        _noise_parameters: Option<StandardDev>,
    ) -> Self {
        true
    }

    fn zero_with_fhe_parameters(
        _poly_size: Option<PolynomialSize>,
        _size: Option<GlweSize>,
        _decomp_level: Option<DecompositionLevelCount>,
        _decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self {
        false
    }

    fn one_with_fhe_parameters(
        _poly_size: Option<PolynomialSize>,
        _size: Option<GlweSize>,
        _decomp_level: Option<DecompositionLevelCount>,
        _decomp_base_log: Option<DecompositionBaseLog>,
    ) -> Self {
        true
    }

    fn mux(&self, o1: &bool, o0: &bool) -> bool {
        if *self {
            *o1
        } else {
            *o0
        }
    }

    fn as_bit(&self) -> bool {
        *self
    }

    fn not_inplace(&mut self) {
        *self = !*self;
    }

    fn descriptor() -> String {
        "clear".to_string()
    }
}
