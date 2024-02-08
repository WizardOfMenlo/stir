use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

pub const BASE_THRESHOLD: usize = 1;

// TODO: Check BASE_THRESHOLD
// This is a FFT that works where the poly degree is larger than the domain size
pub fn fft<F: Field>(coeffs: &[F], generator: F, coset_offset: F, size: usize) -> Vec<F> {
    if size <= BASE_THRESHOLD {
        let poly = DensePolynomial::from_coefficients_slice(coeffs);
        let mut evaluations = vec![];
        let mut scale = F::ONE;
        for _ in 0..size {
            evaluations.push(poly.evaluate(&(coset_offset * scale)));
            scale *= generator;
        }
        return evaluations;
    }

    let next_power_of_two = (coeffs.len()).next_power_of_two();
    let mut coeffs = coeffs.to_vec();
    coeffs.resize(next_power_of_two, F::ZERO);

    let odd = coeffs
        .iter()
        .skip(1)
        .step_by(2)
        .cloned()
        .collect::<Vec<_>>();
    let even = coeffs.iter().step_by(2).cloned().collect::<Vec<_>>();

    let gen2 = generator * generator;
    let off2 = coset_offset * coset_offset;
    let size2 = size / 2;
    let odd_evals = fft(&odd, gen2, off2, size2);
    let even_evals = fft(&even, gen2, off2, size2);

    let mut res = vec![];
    let mut scale = F::ONE;
    for i in 0..size {
        let even = even_evals[i % even_evals.len()];
        let odd = odd_evals[i % odd_evals.len()];

        res.push(even + (coset_offset * scale) * odd);
        scale *= generator;
    }

    res
}
