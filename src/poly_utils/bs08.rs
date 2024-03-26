use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};

use crate::utils;

pub struct BivariatePolynomial<F: Field>(pub Vec<Vec<F>>);

// Takes a polynomial and interprets it as a matrix of coefficients
// this exactly corresponds to computing the BS08 bivariate polynomial with
// q(X) = X^cols
pub fn to_coefficient_matrix<F: Field>(
    f: &DensePolynomial<F>,
    rows: usize,
    cols: usize,
) -> BivariatePolynomial<F> {
    if f.degree() + 1 > rows * cols {
        panic!("Degree of polynomial is too large for matrix");
    }

    let mut matrix = vec![vec![F::ZERO; cols]; rows];

    for (i, coeff) in f.coeffs.iter().enumerate() {
        matrix[i / cols][i % cols] = *coeff;
    }

    BivariatePolynomial(matrix)
}

impl<F> BivariatePolynomial<F>
where
    F: Field,
{
    pub fn degree_x(&self) -> usize {
        self.rows() - 1
    }

    pub fn rows(&self) -> usize {
        self.0.len()
    }

    pub fn degree_y(&self) -> usize {
        self.cols() - 1
    }

    pub fn cols(&self) -> usize {
        self.0[0].len()
    }

    pub fn evaluate(&self, x: F, y: F) -> F {
        let mut res = F::zero();
        for row in 0..self.rows() {
            for col in 0..self.cols() {
                res += self.0[row][col] * x.pow([row as u64]) * y.pow([col as u64]);
            }
        }
        res
    }

    pub fn fold_by_col(&self, alpha: F) -> DensePolynomial<F> {
        let transposed = utils::transpose(self.0.clone());

        let mut res = DensePolynomial::from_coefficients_vec(vec![]);

        let mut pow = F::ONE;
        for c in transposed {
            res += &DensePolynomial::from_coefficients_vec(c.iter().map(|f| pow * f).collect());
            pow *= alpha;
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::crypto::fields::Field64 as TestField;
    use ark_ff::AdditiveGroup;

    fn test_bivariate(
        poly: &DensePolynomial<TestField>,
        matrix: &BivariatePolynomial<TestField>,
        cols: usize,
    ) {
        let mut rng = ark_std::test_rng();

        let point: TestField = rng.gen();
        assert_eq!(
            poly.evaluate(&point),
            matrix.evaluate(point.pow([cols as u64]), point)
        );
    }

    #[test]
    fn neat_example() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            TestField::from(0),
            TestField::from(1),
            TestField::from(2),
            TestField::from(3),
            TestField::from(4),
            TestField::from(5),
        ]);
        let matrix = to_coefficient_matrix(&poly, 3, 2);

        for r in 0..3 {
            for c in 0..2 {
                assert_eq!(matrix.0[r][c], TestField::from((2 * r + c) as u8));
            }
        }
        test_bivariate(&poly, &matrix, 2);
    }

    #[test]
    fn shorter_than_expected() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            TestField::from(0),
            TestField::from(1),
            TestField::from(2),
            TestField::from(3),
            TestField::from(4),
            TestField::from(5),
        ]);
        let matrix = to_coefficient_matrix(&poly, 4, 2);

        for r in 0..3 {
            for c in 0..2 {
                assert_eq!(matrix.0[r][c], TestField::from((2 * r + c) as u8));
            }
        }
        for c in 0..2 {
            assert_eq!(matrix.0[3][c], TestField::ZERO);
        }
        test_bivariate(&poly, &matrix, 2);
    }

    #[test]
    #[should_panic]
    fn longer_than_expected() {
        let poly = DensePolynomial::from_coefficients_vec(vec![
            TestField::from(0),
            TestField::from(1),
            TestField::from(2),
            TestField::from(3),
            TestField::from(4),
            TestField::from(5),
        ]);
        let _matrix = to_coefficient_matrix(&poly, 2, 2);
    }
}
