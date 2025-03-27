use crate::multiplexer::Multiplexer;

fn threshold<M: Multiplexer>(x: &[M], d: usize) -> M::Bit {
    let mut acc = vec![!x[0].as_bit(), x[0].as_bit()];
    for (i, x_i) in x.iter().enumerate().skip(1) {
        acc.push(x_i.clone() & acc.last().unwrap().clone());
        for j in (1..acc.len() - 1).rev() {
            acc[j] = x_i.mux(&acc[j - 1], &acc[j]);
        }
        if i < d - 1 {
            acc[0] = !x_i.clone() & acc.first().unwrap().clone();
        } else {
            acc.remove(0);
            if i > d - 1 {
                let last = acc.pop().unwrap();
                *acc.last_mut().unwrap() ^= last;
            }
        }
    }
    acc[0].clone()
}

pub(super) fn xor_thr<M: Multiplexer>(x: &[M], k: usize, d: usize) -> M::Bit {
    let mut returnValue = x[0].as_bit();

    for v in x[1..k].iter() {
        returnValue ^= v.as_bit();
    }
    returnValue ^ threshold(&x[k..], d)
}
