use std::time::Instant;

use lfsr::LFSR;
use parameters::{TRANSISTOR_ODD_PARAMETERS, TRANSISTOR_ODD_PARAMETERS_128};
use tfhe::gadget::prelude::*;
use shake::shake_keygen;

pub mod lfsr;
pub mod parameters;
pub mod shake;

struct Transistor {
    a: usize,
    r: usize,
    p: u64,

    whitening_lsfr: LFSR,
    pseudo_ks_lsfr: LFSR,

    state: Vec<Vec<Ciphertext>>,

    s_box: Vec<u64>,
    matrix_mc: Vec<Vec<u64>>,
    filter: Vec<Vec<bool>>,
}

impl Transistor {
    pub fn instantiate(params: TransistorParameters) -> Self {
        assert_eq!(params.s_box.len(), params.p as usize);

        assert_eq!(params.matrix_mc.len(), params.a);
        params.matrix_mc.iter().for_each(|row| {
            assert_eq!(row.len(), params.a);
            row.iter().for_each(|x| assert!(*x < params.p))
        });

        assert_eq!(params.filter.len(), params.a);
        params.filter.iter().for_each(|row| {
            assert_eq!(row.len(), params.a);
        });

        Self {
            a: params.a,
            r: params.r,
            p: params.p,

            whitening_lsfr: LFSR::new(params.w, params.p),
            pseudo_ks_lsfr: LFSR::new(params.k, params.p),

            state: vec![],
            s_box: params.s_box,
            matrix_mc: params.matrix_mc,
            filter: params.filter,
        }
    }




    pub fn initialize(&mut self, seed_whitening: &Vec<u64>, seed_ks: &Vec<u64>, ck: &ClientKey) {
        self.whitening_lsfr.encrypt_and_seed(seed_whitening, ck);
        self.pseudo_ks_lsfr.encrypt_and_seed(seed_ks, ck);

        let encoding = Encoding::new_trivial(self.p);
        self.state = vec![vec![ck.encrypt_arithmetic(0, &encoding); self.a]; self.a];
    }

    fn get_col(&self, j: usize) -> Vec<Ciphertext> {
        assert!(j < self.a);
        self.state.iter().map(|row| row[j].clone()).collect()
    }


    fn pretty_print(&self, ck_debug : &ClientKey){
        self.state.iter().for_each(|row| {
            print!("| ");
            row.iter().for_each(|x| print!("{} |", ck_debug.decrypt(x)));
            println!();
        });
        println!("______________________");
    }

}



impl Transistor {
    pub fn sub_bytes(&mut self, sk: &ServerKey, client_key_debug : &ClientKey) {
        self.state = self
            .state
            .iter()
            .map(|row| {
                row.iter()
                    .map(|x| {
                        sk.apply_lut(x, &Encoding::new_trivial(self.p), &|x| {self.s_box[x as usize]})
                    })
                    .collect()
            })
            .collect();
    }

    pub fn shift_rows(&mut self) {
        self.state
            .iter_mut()
            .enumerate()
            .for_each(|(i, row)| row.rotate_left(i))
    }

    pub fn mix_columns(&mut self, sk: &ServerKey) {
        self.state = (0..self.a)
            .map(|i_row| {
                (0..self.a)
                    .map(|i_col| {
                        sk.linear_combination(
                            &self.get_col(i_col),
                            &self.matrix_mc[i_row],
                            self.p,
                        )
                    })
                    .collect()
            })
            .collect();
    }

    pub fn add_round_key(&mut self, sk: &ServerKey, ck_debug : &ClientKey) {
        self
            .state
            .iter_mut()
            .for_each(|row_state| {
                row_state
                    .iter_mut()
                    .for_each(|x| *x = sk.simple_sum(&vec![x.clone(), self.pseudo_ks_lsfr.silent_clock(&sk, &ck_debug)]))
            })
    }


    pub fn filter_output(&self) -> Vec<Ciphertext> {
        let mut output = vec![];
        self.state
            .iter()
            .zip(&self.filter)
            .for_each(|(row, row_filter)| {
                row.iter().zip(row_filter).for_each(|(c, b)| {
                    if *b {
                        output.push(c.clone())
                    }
                })
            });
        assert_eq!(output.len(), self.r);
        output
    }


    pub fn white_output(&mut self, input : Vec<Ciphertext>, sk : &ServerKey, ck_debug : &ClientKey) -> Vec<Ciphertext>{
        input.into_iter().map(|x| sk.simple_sum(&vec![x, self.whitening_lsfr.silent_clock(&sk, &ck_debug)])).collect()
    }


    pub fn clock(&mut self, sk: &ServerKey, ck_debug : &ClientKey) -> Vec<Ciphertext> {
        
        // add round key
        self.add_round_key(&sk, &ck_debug);
 
        // apply sbox
        self.sub_bytes(&sk, &ck_debug);

        //extract r bits and whiten them
        let filtered = self.filter_output();

        let output: Vec<Ciphertext> = self.white_output(filtered, &sk, &ck_debug);

        //linear layer
        self.shift_rows();

        self.mix_columns(&sk);

        output
    }
}


struct TransistorParameters {
    p: u64,
    w: usize,
    k: usize,
    s_box: Vec<u64>,
    matrix_mc: Vec<Vec<u64>>,
    filter: Vec<Vec<bool>>,
    a: usize,
    r: usize,
}



fn main() {

    let transistor_parameters: TransistorParameters = TransistorParameters {
        p: 17,
        w: 32,
        k: 64,
        s_box: vec![1,12,6,11,14,3,15,5,10,9,13,16,7,8,0,2,4],
        matrix_mc: vec![
            vec![16, 16, 16, 2],
            vec![16, 1, 2, 16],
            vec![16, 2, 1, 1],
            vec![2, 1, 16, 1],
        ],
        filter: vec![
            vec![false, false, false, false],
            vec![true, false, true, false],
            vec![false, false, false, false],
            vec![true, false, true, false],
        ],
        a: 4,
        r: 4,
    };

    let mut transistor = Transistor::instantiate(transistor_parameters);

    let (ck, sk) = gen_keys(&TRANSISTOR_ODD_PARAMETERS);
    let (seed_w, seed_ks) = shake_keygen(b"0123456789abcdef", 64, 32, b"");

    transistor.initialize(&seed_w, &seed_ks, &ck);

    for _ in 0..10{
        let start = Instant::now();
        let output = transistor.clock(&sk, &ck);
        let stop = start.elapsed();
        println!("Time for a round :{:?}", stop);
        let output_clear : Vec<u64>= output.iter().map(|c| ck.decrypt(c)).collect();
        println!("result:{:?}", output_clear);
    }
}
