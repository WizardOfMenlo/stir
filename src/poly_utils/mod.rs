pub mod bs08;
pub mod fft;
pub mod folding;
pub mod interpolation;
pub mod quotient;

use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};

pub fn scale<F: Field>(poly: &DensePolynomial<F>, scale: F) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(poly.iter().map(|x| *x * scale).collect())
}

pub fn scale_and_shift<F: Field>(
    poly: &DensePolynomial<F>,
    scale: F,
    shift: usize,
) -> DensePolynomial<F> {
    DensePolynomial::from_coefficients_vec(
        std::iter::repeat(F::ZERO)
            .take(shift)
            .chain(poly.iter().map(|x| *x * scale))
            .collect(),
    )
}
