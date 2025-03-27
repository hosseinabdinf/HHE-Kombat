#![allow(clippy::too_long_first_doc_paragraph)]

mod static_deque;

mod kreyvium;
pub use kreyvium::{KreyviumStream, KreyviumStreamByte, KreyviumStreamShortint};

mod trivium;
pub use trivium::{TriviumStream, TriviumStreamByte, TriviumStreamShortint};

mod trans_ciphering;
mod cpu_cycle;
pub use cpu_cycle::{print_cpu_and_mem};

pub use trans_ciphering::TransCiphering;
