mod bit_bool;
mod encrypted_bit;

use concrete_commons::parameters::{GlweSize, PolynomialSize};
use std::ops::{BitAndAssign, BitXor, BitXorAssign, Not};

pub use bit_bool::*;
pub use encrypted_bit::*;

pub trait Bit<Other>:
    Clone + Not<Output = Self> + BitXor<Output = Self> + BitXorAssign + BitAndAssign<Other>
{
    fn zero(poly_size: Option<PolynomialSize>, size: Option<GlweSize>) -> Self;
    fn one(poly_size: Option<PolynomialSize>, size: Option<GlweSize>) -> Self;

    fn not_inplace(&mut self);
}
