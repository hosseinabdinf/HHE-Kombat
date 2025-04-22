use tfhe::gadget::prelude::*;

#[derive(Clone, Debug)]
pub struct LFSR {
    length: usize,
    p: u64,
    pub state: Vec<Ciphertext>,
    taps: Vec<u64>,
    current_coefficients: Vec<u64>,
}

impl LFSR {
    pub fn new(size: usize, p: u64) -> Self {
        let taps = match (p, size){
           (17, 32) => vec![3, 14, 6, 13, 15, 7, 1, 9, 13, 1, 16, 13, 3, 14, 15, 6, 13, 6, 5, 2, 5, 14, 14, 14, 10, 12, 6, 1, 14, 14, 14, 8, 1],
           (17, 64) => vec![3, 12, 9, 15, 12, 6, 3, 9, 16, 3, 16, 15, 14, 13, 3, 16, 8, 15, 4, 7, 10, 14, 11, 13, 10, 1, 1, 10, 13, 14, 15, 10, 6, 14, 14, 16, 3, 6, 7, 6, 6, 4, 9, 8, 8, 1, 8, 4, 4, 11, 12, 8, 12, 15, 9, 3, 16, 6, 6, 8, 4, 6, 4, 9, 1],
           _ => panic!("Please enter the coefficients of the primitive polynomial, from high to low degree")
        };

        // taps are high degree to low degree
        assert_eq!(taps.len() - 1, size);
        taps.iter().for_each(|c| assert!(*c < p));
        Self {
            length: size,
            p,
            state: vec![],
            taps,
            current_coefficients: vec![vec![1], vec![0; size - 1]].concat(),
        }
    }

    pub fn encrypt_and_seed(&mut self, seed: &Vec<u64>, client_key: &ClientKey) {
        // sanity check
        assert_eq!(self.length, seed.len());
        seed.iter().for_each(|s| assert!(*s < self.p));

        let encoding = Encoding::new_trivial(self.p);
        self.state = seed
            .iter()
            .rev()
            .map(|slot| client_key.encrypt_arithmetic(*slot, &encoding))
            .collect()
    }

    //to match with the spec and test,, but we do not actually use it
    pub fn clock_fibonacci(&mut self, server_key: &ServerKey) -> Ciphertext {
        let feedback = server_key.linear_combination(
            &self.state,
            &self.taps[..self.length].to_vec(), //The last tap is useless
            self.p,
        );

        let output = self.state[0].clone();

        self.state.rotate_left(1);
        self.state[self.length - 1] = feedback;
        output
    }

    fn silent_clock_internal(&mut self) {
        let last = self.current_coefficients[self.length - 1];
        self.current_coefficients.rotate_right(1);
        self.current_coefficients[0] = 0;
        self.current_coefficients
            .iter_mut()
            .zip(&self.taps)
            .for_each(|(c, t)| *c = (*c + last * t) % self.p)
    }

    pub fn silent_output(&self, server_key: &ServerKey) -> Ciphertext {
        server_key.linear_combination(&self.state, &self.current_coefficients, self.p)
    }

    pub fn silent_clock(&mut self, server_key: &ServerKey, ck_debug: &ClientKey) -> Ciphertext {
        let output = self.silent_output(&server_key);
        self.silent_clock_internal();
        output
    }

    pub fn decrypt_current_state(&self, ck: &ClientKey) -> Vec<u64> {
        self.state.iter().map(|slot| ck.decrypt(slot)).collect()
    }

    pub fn pretty_print(&self, ck: &ClientKey) {
        let data = self.decrypt_current_state(&ck);
        data.iter().for_each(|x| println!("{}  ", *x));
        println!();
    }
}
