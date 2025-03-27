mod dsm;
mod xor_thr;

use crate::multiplexer::Multiplexer;
use dsm::*;
use xor_thr::*;

#[derive(Clone)]
pub enum FilterType {
    DSM,
    XorThr,
}

#[derive(Clone)]
pub struct Filter {
    category: FilterType,
    parameters: Vec<usize>,
}

impl Filter {
    pub fn new(filter: FilterType, parameters: &[usize]) -> Self {
        Self {
            category: filter,
            parameters: parameters.to_vec(),
        }
    }

    pub fn call<M: Multiplexer>(&self, x: &[M]) -> M::Bit {
        match self.category {
            FilterType::DSM => dsm(x, &self.parameters),
            FilterType::XorThr => xor_thr(x, self.parameters[0], self.parameters[1]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_thr() {
        let f = Filter::new(FilterType::XorThr, &[2, 4]);
        let result = f.call(&[false, false, true, true, true, true, false, true, false]);
        assert_eq!(result, true);
    }

    #[test]
    fn dsm() {
        let f = Filter::new(FilterType::DSM, &[2, 0, 1]);
        let result = f.call(&[true, true, false, true, true]);
        assert_eq!(result, false);
    }
}
