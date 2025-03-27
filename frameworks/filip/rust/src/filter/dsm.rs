use crate::multiplexer::Multiplexer;

pub(super) fn dsm<M: Multiplexer>(x: &[M], m: &[usize]) -> M::Bit {
    let mut j = 0;
    let mut returnValue = x[j].as_bit();
    j += 1;
    for x_j in x.iter().take(m[0]).skip(1) {
        returnValue ^= x_j.as_bit();
        j += 1;
    }

    for (i, &m_i) in m.iter().enumerate().skip(1) {
        for _ in 0..m_i {
            let mut temp = x[j].as_bit();
            j += 1;
            for _ in 0..i {
                temp &= x[j].clone();
                j += 1;
            }
            returnValue ^= temp;
        }
    }
    returnValue
}
