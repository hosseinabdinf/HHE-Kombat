use concrete_commons::parameters::{GlweSize, PolynomialSize};

use crate::Bit;

impl Bit<bool> for bool {
    fn zero(_poly_size: Option<PolynomialSize>, _size: Option<GlweSize>) -> Self {
        false
    }

    fn one(_poly_size: Option<PolynomialSize>, _size: Option<GlweSize>) -> Self {
        true
    }

    fn not_inplace(&mut self) {
        *self = !*self
    }
}
