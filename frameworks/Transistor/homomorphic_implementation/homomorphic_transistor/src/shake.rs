use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};

pub fn shake_keygen(master_key: &[u8], k: usize, w: usize, iv: &[u8]) -> (Vec<u64>, Vec<u64>) {
    assert_eq!(master_key.len(), 16, "Master key must be 16 bytes long");

    // Prepare data to feed into SHAKE128
    let mut to_shake = Vec::new();
    to_shake.extend_from_slice(master_key);
    to_shake.extend_from_slice(iv);
    to_shake.push(b'1'); 

    // Generate more than k + w bytes for rejection sampling
    let mut shake = Shake128::default();
    shake.update(&to_shake);
    let mut reader = shake.finalize_xof();
    let mut tmp = vec![0u8; k + w + 30]; // Extra length for rejection sampling
    reader.read(&mut tmp);

    let mut cursor = 0;

    // Generate K vector
    let mut k_content = Vec::new();
    while k_content.len() < k {
        let x = tmp[cursor];
        if x < 255 {
            k_content.push((x / 15) as u64);
        }
        cursor += 1;
    }

    // Generate W vector
    let mut w_content = Vec::new();
    while w_content.len() < w {
        let x = tmp[cursor];
        if x < 255 {
            w_content.push((x / 15) as u64);
        }
        cursor += 1;
    }

    (w_content, k_content)
}