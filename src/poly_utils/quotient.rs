use ark_ff::{FftField, Field};
use ark_poly::{univariate::DensePolynomial, Polynomial};

use super::interpolation;

// Compute the quotient
pub fn poly_quotient<F: FftField>(poly: &DensePolynomial<F>, points: &[F]) -> DensePolynomial<F> {
    let evaluations: Vec<_> = points.iter().map(|x| (*x, poly.evaluate(x))).collect();
    let ans_polynomial = interpolation::naive_interpolation(evaluations.iter());
    let vanishing_poly = interpolation::vanishing_poly(points);
    let numerator = poly + &ans_polynomial;

    // TODO: Is this efficient or should FFT?
    &numerator / &vanishing_poly
}

// This is Quotient(f, S, Ans, Fill) in the paper
pub fn quotient<'a, F: Field>(
    claimed_eval: F,
    evaluation_point: F,
    answers: impl IntoIterator<Item = &'a (F, F)>,
) -> F {
    let answers: Vec<_> = answers.into_iter().copied().collect();

    // Check if the evaluation point is in the domain
    for (dom, _) in answers.iter() {
        if evaluation_point == *dom {
            panic!("Evaluation point is in the domain");
        }
    }
    // Now, compute the ans polynomial
    let ans_polynomial = interpolation::naive_interpolation(&answers);
    let ans_eval = ans_polynomial.evaluate(&evaluation_point);

    let num = claimed_eval - ans_eval;
    let denom = answers
        .iter()
        .map(|x| evaluation_point - x.0)
        .product::<F>();

    num * denom.inverse().unwrap()
}

// Allows to amortize the evaluation of the quotient polynomial
pub fn quotient_with_hint<'a, F: Field>(
    claimed_eval: F,
    evaluation_point: F,
    quotient_set: impl IntoIterator<Item = &'a F>,
    //ans_polynomial: &DensePolynomial<F>,
    denom_hint: F,
    ans_eval: F,
) -> F {
    let quotient_set: Vec<_> = quotient_set.into_iter().copied().collect();

    // Check if the evaluation point is in the domain
    for dom in quotient_set.iter() {
        if evaluation_point == *dom {
            panic!("Evaluation point is in the domain");
        }
    }

    let num = claimed_eval - ans_eval;

    num * denom_hint
}

#[cfg(test)]
mod tests {
    use ark_poly::DenseUVPolynomial;
    use rand::Rng;

    use super::*;
    use crate::crypto::fields::Field64 as TestField;

    #[test]
    fn test_quotient() {
        let mut rng = ark_std::test_rng();

        let poly = DensePolynomial::rand(10, &mut rng);
        let points = vec![TestField::from(0), TestField::from(1)];

        let quotient_poly = poly_quotient(&poly, &points);
        let ans = points
            .iter()
            .map(|x| (*x, poly.evaluate(x)))
            .collect::<Vec<_>>();

        let test_point = rng.gen(); // Test at random point
        assert_eq!(
            quotient(poly.evaluate(&test_point), test_point, &ans,),
            quotient_poly.evaluate(&test_point)
        );
    }
}
