//! The public key for homomorphic computation.
//!
//! This module implements the generation of the server's public key, together with all the
//! available homomorphic Boolean gates ($\mathrm{AND}$, $\mathrm{MUX}$, $\mathrm{NAND}$,
//! $\mathrm{NOR}$,
//! $\mathrm{NOT}$, $\mathrm{OR}$, $\mathrm{XNOR}$, $\mathrm{XOR}$).

#[cfg(test)]
mod tests;


use itertools::Itertools;

use crate::gadget::prelude::*;
use crate::gadget::client_key::ClientKey;
pub use crate::gadget::engine::bootstrapping::ServerKey;
use crate::gadget::engine::{
    GadgetEngine, WithThreadLocalEngine,
};

use super::client_key;


impl ServerKey {
  
    pub fn apply_lut(&self, input : &Ciphertext, encoding_out : &Encoding, f : &dyn Fn(u64) -> u64) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.apply_lut(input, encoding_out, f, self))
    }
    
    
    ///Encoding Switching : universal
    pub fn encoding_switching_lut(&self, input : &Ciphertext, encoding_out : &Encoding) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.apply_lut(input, encoding_out, &|x|{x}, self))
    }

    //transforme un encodage en un autre avec un external product par un coefficient donné
    pub fn encoding_switching_mul_constant(&self, input : &Ciphertext, coefficient : u64) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.encoding_switching_mul_constant(input, coefficient, &self))
    }

    pub fn encoding_switching_sum_constant(&self, input : &Ciphertext, constant : u64, modulus : u64) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.encoding_switching_sum_constant(input, constant, modulus,&self))
    }
    ////////////////////////


    //simple sum : no check is performed so use it wisely
    pub fn simple_sum(&self, input : &Vec<Ciphertext>) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.simple_sum(input, &self))
    }

    pub fn simple_plaintext_sum(&self, input : &Ciphertext, constant : u64, modulus : u64) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.simple_plaintext_sum(input, constant, modulus,&self))
    }

    pub fn simple_mul_constant(&self, input : &Ciphertext, coeff : u64, modulus:u64) -> Ciphertext{
        GadgetEngine::with_thread_local_mut(|engine| engine.simple_mul_constant(input, coeff, modulus,  &self))
    }


    //Same: all inputs should have the same encoding
    pub fn linear_combination(&self, input : &Vec<Ciphertext>, coefficients : &Vec<u64>, modulus : u64) -> Ciphertext{
        let buffer : Vec<Ciphertext>= input.iter().zip(coefficients).map(|(ct, coeff)| self.simple_mul_constant(ct, *coeff, modulus)).collect();

        GadgetEngine::with_thread_local_mut(|engine| engine.simple_sum(
            &buffer,
            self)
        )
    }


}






impl ServerKey {
    pub fn new(cks: &ClientKey) -> Self {
        GadgetEngine::with_thread_local_mut(|engine| engine.create_server_key(cks))
    }

    pub fn trivial_encrypt(&self, message: u64) -> Ciphertext {
        Ciphertext::Trivial(message)
    }
}

