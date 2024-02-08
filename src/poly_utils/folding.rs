use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::poly_utils::interpolation;

use super::bs08;

pub fn poly_fold<F: Field>(
    f: &DensePolynomial<F>,
    folding_factor: usize,
    folding_randomness: F,
) -> DensePolynomial<F> {
    let degree = f.degree() + 1;
    let q_poly = bs08::to_coefficient_matrix(f, degree.div_ceil(folding_factor), folding_factor);
    q_poly.fold_by_col(folding_randomness)
}

// f_answers is a vector containg B_l and f(B_l) for l the evaluation point
// Recall that B_l has x \in B_l \iff x^k = l
pub fn fold<F: Field>(f_answers: Vec<(F, F)>, folding_factor: usize, folding_randomness: F) -> F {
    assert_eq!(f_answers.len(), folding_factor);
    interpolation::evaluate_interpolation(f_answers.iter(), folding_randomness)
}

#[cfg(test)]
mod tests {
    use ark_ff::FftField;
    use ark_poly::DenseUVPolynomial;

    use super::*;
    use crate::crypto::fields::Field64 as TestField;

    #[test]
    fn test_folding() {
        let mut rng = ark_std::test_rng();
        let poly = DensePolynomial::rand(16, &mut rng);

        let folding_factor = 2;
        let folding_randomness = TestField::from(5);

        let poly_fold = poly_fold(&poly, folding_factor, folding_randomness);

        let root_of_unity = TestField::get_root_of_unity(256).unwrap();

        let evalpoint = root_of_unity.pow([folding_factor as u64]);
        let beta_l = &[root_of_unity, root_of_unity.pow([1 + 128])];

        for beta in beta_l {
            assert_eq!(beta.pow([folding_factor as u64]), evalpoint,);
        }

        let f_answers = beta_l
            .iter()
            .map(|x| (*x, poly.evaluate(x)))
            .collect::<Vec<_>>();

        assert_eq!(
            poly_fold.evaluate(&evalpoint),
            fold(f_answers, folding_factor, folding_randomness)
        );
    }
}
