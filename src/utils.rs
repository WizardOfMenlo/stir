use std::collections::BTreeSet;

use ark_crypto_primitives::sponge::CryptographicSponge;

pub fn is_power_of_two(n: usize) -> bool {
    n & (n - 1) == 0
}

pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

pub fn proof_of_work(
    sponge: &mut impl CryptographicSponge,
    proof_of_work_bits: usize,
) -> Option<usize> {
    assert!(proof_of_work_bits <= 32);
    if proof_of_work_bits == 0 {
        return None;
    }

    let mut buf = [0; 4];
    let mut nonce: usize = 0;
    loop {
        let mut new_sponge = sponge.clone();
        let nonce_bytes = nonce.to_le_bytes();
        new_sponge.absorb(&nonce_bytes.as_slice());
        let pow_bytes = new_sponge.squeeze_bytes(4);
        buf.copy_from_slice(&pow_bytes[..]);
        let pow = u32::from_le_bytes(buf);
        if pow.trailing_zeros() as usize >= proof_of_work_bits {
            sponge.absorb(&nonce_bytes.as_slice());
            sponge.squeeze_bytes(4);
            return Some(nonce);
        }
        nonce += 1;
    }
}

pub fn proof_of_work_verify(
    sponge: &mut impl CryptographicSponge,
    proof_of_work_bits: usize,
    pow_nonce: Option<usize>,
) -> bool {
    assert!(proof_of_work_bits <= 32);
    if proof_of_work_bits == 0 {
        return true;
    }

    if pow_nonce.is_none() {
        return false;
    }
    let nonce = pow_nonce.unwrap();
    sponge.absorb(&nonce.to_le_bytes().as_slice());
    let pow_bytes = sponge.squeeze_bytes(4);
    let mut buf = [0; 4];
    buf.copy_from_slice(&pow_bytes[..]);
    let pow = u32::from_le_bytes(buf);
    pow.trailing_zeros() as usize >= proof_of_work_bits
}

pub fn squeeze_integer(sponge: &mut impl CryptographicSponge, range: usize) -> usize {
    assert!(is_power_of_two(range));
    let mut bytes_array = [0; 8];
    let bytes = sponge.squeeze_bytes(8);
    bytes_array.copy_from_slice(&bytes);
    let candidate = usize::from_le_bytes(bytes_array);
    // This is uniform as long as the range is a power of two
    candidate % range
}

// Deduplicates AND orders a vector
pub fn dedup<T: Ord>(v: impl IntoIterator<Item = T>) -> Vec<T> {
    Vec::from_iter(BTreeSet::from_iter(v))
}

// Takes the vector of evaluations (assume that evals[i] = f(omega^i))
// and folds them into a vector of such that folded_evals[i] = [f(omega^(i + k * j)) for j in 0..folding_factor]
pub fn stack_evaluations<F: Copy>(evals: Vec<F>, folding_factor: usize) -> Vec<Vec<F>> {
    assert!(evals.len() % folding_factor == 0);
    let size_of_new_domain = evals.len() / folding_factor;

    let mut stacked_evaluations = vec![];
    for i in 0..size_of_new_domain {
        let mut new_evals = vec![];
        for j in 0..folding_factor {
            new_evals.push(evals[i + j * size_of_new_domain]);
        }
        stacked_evaluations.push(new_evals);
    }

    stacked_evaluations
}
