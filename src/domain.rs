use std::ops::Deref;

use ark_ff::FftField;
use ark_poly::{
    EvaluationDomain, GeneralEvaluationDomain, MixedRadixEvaluationDomain, Radix2EvaluationDomain,
};

#[derive(Debug, Clone)]
pub struct Domain<F: FftField> {
    pub root_of_unity: F,
    pub root_of_unity_inv: F,
    pub backing_domain: GeneralEvaluationDomain<F>,
}

impl<F: FftField> Domain<F> {
    pub fn new(degree: usize, log_rho_inv: usize) -> Option<Self> {
        let size = degree * (1 << log_rho_inv);
        let backing_domain = GeneralEvaluationDomain::new(size)?;
        let root_of_unity: F = match backing_domain {
            GeneralEvaluationDomain::Radix2(r2) => r2.group_gen,
            GeneralEvaluationDomain::MixedRadix(mr) => mr.group_gen,
        };
        let root_of_unity_inv = match backing_domain {
            GeneralEvaluationDomain::Radix2(r2) => r2.group_gen_inv,
            GeneralEvaluationDomain::MixedRadix(mr) => mr.group_gen_inv,
        };
        Some(Self {
            backing_domain,
            root_of_unity,
            root_of_unity_inv,
        })
    }

    pub fn size(&self) -> usize {
        self.backing_domain.size()
    }

    // Takes the underlying backing_domain = <w>, and computes the new domain
    // <w^power> (note this will have size |L| / power)
    // NOTE: This should not be mixed with scale_offset
    fn scale_generator_by(&self, power: usize) -> GeneralEvaluationDomain<F> {
        let starting_size = self.size();
        assert_eq!(starting_size % power, 0);
        let new_size = starting_size / power;
        let log_size_of_group = new_size.trailing_zeros();
        let size_as_field_element = F::from(new_size as u64);

        match self.backing_domain {
            GeneralEvaluationDomain::Radix2(r2) => {
                let group_gen = r2.group_gen.pow([power as u64]);
                let group_gen_inv = group_gen.inverse().unwrap();

                let offset = r2.offset.pow([power as u64]);
                let offset_inv = r2.offset_inv.pow([power as u64]);
                let offset_pow_size = offset.pow([new_size as u64]);

                GeneralEvaluationDomain::Radix2(Radix2EvaluationDomain {
                    size: new_size as u64,
                    log_size_of_group,
                    size_as_field_element,
                    size_inv: size_as_field_element.inverse().unwrap(),
                    group_gen,
                    group_gen_inv,
                    offset,
                    offset_inv,
                    offset_pow_size,
                })
            }
            GeneralEvaluationDomain::MixedRadix(mr) => {
                let group_gen = mr.group_gen.pow([power as u64]);
                let group_gen_inv = mr.group_gen_inv.pow([power as u64]);

                let offset = mr.offset.pow([power as u64]);
                let offset_inv = mr.offset_inv.pow([power as u64]);
                let offset_pow_size = offset.pow([new_size as u64]);

                GeneralEvaluationDomain::MixedRadix(MixedRadixEvaluationDomain {
                    size: new_size as u64,
                    log_size_of_group,
                    size_as_field_element,
                    size_inv: size_as_field_element.inverse().unwrap(),
                    group_gen,
                    group_gen_inv,
                    offset,
                    offset_inv,
                    offset_pow_size,
                })
            }
        }
    }

    // Take a domain L_0 = o * <w> and compute a new domain L_1 = w * o^power * <w^power>.
    // Note that L_0^k \cap L_1 = \emptyset for k > power.
    fn scale_with_offset(&self, power: usize) -> GeneralEvaluationDomain<F> {
        let starting_size = self.size();
        assert_eq!(starting_size % power, 0);
        let new_size = starting_size / power;
        let log_size_of_group = new_size.trailing_zeros();
        let size_as_field_element = F::from(new_size as u64);
        match self.backing_domain {
            GeneralEvaluationDomain::Radix2(r2) => {
                let group_gen = r2.group_gen.pow([power as u64]);
                let group_gen_inv = r2.group_gen_inv.pow([power as u64]);

                let offset = r2.offset.pow([power as u64]) * self.root_of_unity;
                let offset_inv = r2.offset_inv.pow([power as u64]) * self.root_of_unity_inv;

                GeneralEvaluationDomain::Radix2(Radix2EvaluationDomain {
                    size: new_size as u64,
                    log_size_of_group,
                    size_as_field_element,
                    size_inv: size_as_field_element.inverse().unwrap(),
                    group_gen,
                    group_gen_inv,
                    offset,
                    offset_inv,
                    offset_pow_size: offset.pow([new_size as u64]),
                })
            }
            GeneralEvaluationDomain::MixedRadix(mr) => {
                let group_gen = mr.group_gen.pow([power as u64]);
                let group_gen_inv = mr.group_gen_inv.pow([power as u64]);

                let offset = mr.offset.pow([power as u64]) * self.root_of_unity;
                let offset_inv = mr.offset_inv.pow([power as u64]) * self.root_of_unity_inv;

                GeneralEvaluationDomain::MixedRadix(MixedRadixEvaluationDomain {
                    size: new_size as u64,
                    log_size_of_group,
                    size_as_field_element,
                    size_inv: size_as_field_element.inverse().unwrap(),
                    group_gen,
                    group_gen_inv,
                    offset,
                    offset_inv,
                    offset_pow_size: offset.pow([new_size as u64]),
                })
            }
        }
    }

    pub fn scale(&self, power: usize) -> Self {
        Self {
            backing_domain: self.scale_generator_by(power),
            ..*self
        }
    }

    pub fn scale_offset(&self, power: usize) -> Self {
        Self {
            backing_domain: self.scale_with_offset(power),
            ..*self
        }
    }
}

impl<F: FftField> Deref for Domain<F> {
    type Target = GeneralEvaluationDomain<F>;

    fn deref(&self) -> &Self::Target {
        &self.backing_domain
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::crypto::fields::Field64 as TestField;

    #[test]
    fn test_non_overlapping() {
        let folding_factor = 16;

        let l_0 = Domain::<TestField>::new(64, 2).unwrap();

        let l_0_k = l_0.scale(folding_factor);
        let l_1 = l_0.scale_offset(2);
        let l_1_k = l_1.scale_offset(folding_factor);
        let l_2 = l_1.scale_offset(2);

        let l_0_k_elements: HashSet<_> = l_0_k.elements().collect();
        let l_1_elements: HashSet<_> = l_1.elements().collect();
        let l_1_k_elements: HashSet<_> = l_1_k.elements().collect();
        let l_2_elements: HashSet<_> = l_2.elements().collect();

        assert_eq!(l_0_k_elements.intersection(&l_1_elements).count(), 0);
        assert_eq!(l_1_k_elements.intersection(&l_2_elements).count(), 0);
    }
}
