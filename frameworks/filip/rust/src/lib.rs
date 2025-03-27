#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(non_snake_case)]

mod bit;
mod encrypter;
mod filter;
mod multiplexer;
mod symmetric_key;

pub use bit::{Bit, EncryptedBit};
pub use encrypter::{Encrypter, SystemParameters};
pub use multiplexer::{EncryptedKeyBit, Multiplexer};

pub type Torus = u64;
