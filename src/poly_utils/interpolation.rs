use ark_ff::{batch_inversion, FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Evaluations, Polynomial, Radix2EvaluationDomain,
};

use crate::utils;

// Computes a polynomial that vanishes on points
pub fn vanishing_poly<'a, F: Field>(points: impl IntoIterator<Item = &'a F>) -> DensePolynomial<F> {
    // Compute the denominator (which is \prod_a(x - a))
    let mut vanishing_poly: DensePolynomial<_> =
        DensePolynomial::from_coefficients_slice(&[F::ONE]);
    for a in points {
        vanishing_poly =
            vanishing_poly.naive_mul(&DensePolynomial::from_coefficients_slice(&[-*a, F::ONE]));
    }
    vanishing_poly
}

// Computes a polynomial that interpolates the given points with the given answers
pub fn naive_interpolation<'a, F: Field>(
    points: impl IntoIterator<Item = &'a (F, F)>,
) -> DensePolynomial<F> {
    let points: Vec<_> = points.into_iter().collect();
    let vanishing_poly = vanishing_poly(points.iter().map(|(a, _)| a));

    // Compute the ans polynomial (this is just a naive interpolation)
    let mut ans_polynomial = DensePolynomial::from_coefficients_slice(&[]);
    for (a, eval) in points.iter() {
        // Computes the vanishing (apart from x - a)
        let vanishing_adjusted =
            &vanishing_poly / &DensePolynomial::from_coefficients_slice(&[-*a, F::ONE]);

        // Now, we can scale to get the right weigh
        let scale_factor = *eval / vanishing_adjusted.evaluate(a);
        ans_polynomial = ans_polynomial
            + DensePolynomial::from_coefficients_vec(
                vanishing_adjusted
                    .iter()
                    .map(|x| *x * scale_factor)
                    .collect(),
            );
    }
    ans_polynomial
}

// Given a generator and a coset offset, computes the interpolating offset
pub fn fft_interpolate_naive<'a, F: FftField>(
    generator: F,
    coset_offset: F,
    points: impl IntoIterator<Item = &'a F>,
) -> DensePolynomial<F> {
    let points: Vec<_> = points.into_iter().cloned().collect();
    let folding_factor = points.len();
    assert!(utils::is_power_of_two(folding_factor));

    let size_as_field_element = F::from(folding_factor as u64);

    // Do some batch inversion
    let mut to_invert = vec![size_as_field_element, coset_offset, generator];
    batch_inversion(&mut to_invert);
    let size_inv = to_invert[0];
    let coset_offset_inv = to_invert[1];
    let generator_inv = to_invert[2];

    let domain = Radix2EvaluationDomain {
        size: folding_factor as u64,
        log_size_of_group: folding_factor.ilog2(),
        size_as_field_element,
        size_inv,
        group_gen: generator,
        group_gen_inv: generator_inv,
        offset: coset_offset,
        offset_inv: coset_offset_inv,
        offset_pow_size: coset_offset.pow([folding_factor as u64]),
    };

    let evaluations = Evaluations::from_vec_and_domain(points, domain);

    evaluations.interpolate()
}

// Given a generator and a coset offset, computes the interpolating offset
// Requires to be given the inversion of the generator and coset offset (and thus can be more
// efficient)
pub fn fft_interpolate<'a, F: FftField>(
    generator: F,
    coset_offset: F,
    generator_inv: F,
    coset_offset_inv: F,
    size_inv: F,
    points: impl IntoIterator<Item = &'a F>,
) -> DensePolynomial<F> {
    let points: Vec<_> = points.into_iter().cloned().collect();
    let folding_factor = points.len();
    assert!(utils::is_power_of_two(folding_factor));

    let size_as_field_element = F::from(folding_factor as u64);

    let domain = Radix2EvaluationDomain {
        size: folding_factor as u64,
        log_size_of_group: folding_factor.ilog2(),
        size_as_field_element,
        size_inv,
        group_gen: generator,
        group_gen_inv: generator_inv,
        offset: coset_offset,
        offset_inv: coset_offset_inv,
        offset_pow_size: coset_offset.pow([folding_factor as u64]),
    };

    let evaluations = Evaluations::from_vec_and_domain(points, domain);

    evaluations.interpolate()
}

// Computes a polynomial that interpolates the given points with the given answers
pub fn evaluate_interpolation<'a, F: Field>(
    points: impl IntoIterator<Item = &'a (F, F)>,
    point: F,
) -> F {
    let points = points.into_iter().collect::<Vec<_>>();

    for (p, a) in points.iter() {
        if p == &point {
            return *a;
        }
    }

    let denominators: Vec<_> = points
        .iter()
        .map(|(p, _)| p)
        .enumerate()
        .map(|(i, xi)| {
            points
                .iter()
                .map(|(p, _)| p)
                .enumerate()
                .filter(|(j, _)| &i != j)
                .map(|(_, xj)| *xi - *xj)
                .product::<F>()
        })
        .collect();

    // Do a batch inversion
    let mut denominators = points
        .iter()
        .zip(denominators)
        .map(|((xi, _), d)| d * (point - xi))
        .collect::<Vec<_>>();
    batch_inversion(&mut denominators);

    let res: F = points
        .iter()
        .zip(denominators)
        .map(|((_, a), d)| *a * d)
        .sum();

    res * points.iter().map(|(xi, _)| point - xi).product::<F>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::fields::Field64 as TestField, domain::Domain};
    use ark_poly::domain::EvaluationDomain;

    #[test]
    fn test_ans_polynomial() {
        let points = vec![
            (TestField::from(5), TestField::from(10)),
            (TestField::from(9), TestField::from(7)),
        ];
        let ans_poly = naive_interpolation(&points);
        for (x, y) in points.clone() {
            assert_eq!(ans_poly.evaluate(&x), y);
            assert_eq!(evaluate_interpolation(&points, x), y);
        }

        let ood_point = TestField::from(4999);

        assert_eq!(
            ans_poly.evaluate(&ood_point),
            evaluate_interpolation(&points, ood_point)
        );
    }

    #[test]
    fn test_fft_interpolate() {
        let degree = 16;
        let folding_factor = 8;
        let polynomial = DensePolynomial::from_coefficients_vec(vec![TestField::from(1); degree]);
        let domain = Domain::<TestField>::new(degree, 3).unwrap();
        let evals = polynomial
            .evaluate_over_domain_by_ref(domain.backing_domain)
            .evals;
        let elements = domain.backing_domain.elements().collect::<Vec<_>>();
        let reshaped_elements = utils::stack_evaluations(elements, folding_factor);
        let reshaped_evaluations = utils::stack_evaluations(evals, folding_factor);

        // Computed using the naive interpolation
        let g_evaluations: Vec<_> = reshaped_evaluations
            .iter()
            .enumerate()
            .map(|(i, evals)| {
                let interpol = evals
                    .iter()
                    .enumerate()
                    .map(|(j, &e)| (reshaped_elements[i][j], e))
                    .collect::<Vec<_>>();

                naive_interpolation(&interpol)
            })
            .collect();

        let generator = domain
            .backing_domain
            .element(domain.size() / folding_factor);
        let g_fft_evaluations: Vec<_> = reshaped_evaluations
            .iter()
            .enumerate()
            .map(|(i, evals)| {
                let coset_offset = domain.backing_domain.element(i);
                fft_interpolate_naive(generator, coset_offset, evals)
            })
            .collect();

        let generator_inv = generator.inverse().unwrap();
        let size_inv = TestField::from(folding_factor as u64).inverse().unwrap();
        let g_fft_fast_evaluations: Vec<_> = reshaped_evaluations
            .iter()
            .enumerate()
            .map(|(i, evals)| {
                let coset_offset = domain.backing_domain.element(i);
                let coset_offset_inv = domain.backing_domain.element(domain.size() - i);
                fft_interpolate(
                    generator,
                    coset_offset,
                    generator_inv,
                    coset_offset_inv,
                    size_inv,
                    evals,
                )
            })
            .collect();

        assert_eq!(g_evaluations, g_fft_evaluations);
        assert_eq!(g_evaluations, g_fft_fast_evaluations);
    }

    #[test]
    fn test_vanishing_poly() {
        let points = vec![
            TestField::from(5),
            TestField::from(10),
            TestField::from(9),
            TestField::from(7),
        ];
        let vanishing_poly = vanishing_poly(&points);
        for x in points {
            assert_eq!(vanishing_poly.evaluate(&x), TestField::ZERO);
        }
    }
}
