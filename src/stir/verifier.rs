use ark_crypto_primitives::{
    merkle_tree::Config,
    sponge::{Absorb, CryptographicSponge},
};
use ark_ff::{batch_inversion, FftField, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};

use itertools::izip;

use crate::{domain::Domain, ldt::Verifier, parameters::Parameters, poly_utils, utils};

use super::{common::*, parameters::FullParameters};

#[derive(Debug)]
pub struct VirtualFunction<F: FftField> {
    comb_randomness: F,
    interpolating_polynomial: DensePolynomial<F>,
    quotient_set: Vec<F>,
}

#[derive(Debug)]
pub enum OracleType<F: FftField> {
    Initial,
    Virtual(VirtualFunction<F>),
}

impl<F: FftField> VerificationState<F> {
    // Now, I need to query f_i at a given point.
    // This induces some query to the previous oracle, whose answer I get
    pub fn query(
        &self,
        evaluation_point: F,
        value_of_prev_oracle: F,
        common_factors_inverse: F,
        denom_hint: F,
        ans_eval: F,
    ) -> F {
        match &self.oracle {
            OracleType::Initial => value_of_prev_oracle, // In case this is the initial function, we just return the value of the previous oracle
            OracleType::Virtual(virtual_function) => {
                let num_terms = virtual_function.quotient_set.len();
                let quotient_evaluation = poly_utils::quotient::quotient_with_hint(
                    value_of_prev_oracle,
                    evaluation_point,
                    &virtual_function.quotient_set,
                    denom_hint,
                    ans_eval,
                );

                let common_factor = evaluation_point * virtual_function.comb_randomness;

                let scale_factor = if common_factor != F::ONE {
                    (F::ONE - common_factor.pow([(num_terms + 1) as u64])) * common_factors_inverse
                } else {
                    F::from((num_terms + 1) as u64)
                };

                quotient_evaluation * scale_factor
            }
        }
    }
}

#[derive(Debug)]
pub struct VerificationState<F: FftField> {
    oracle: OracleType<F>,
    domain_gen: F,
    domain_size: usize,
    domain_offset: F,
    root_of_unity: F,
    folding_randomness: F,
    num_round: usize,
}

pub struct StirVerifier<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    pub(crate) parameters: FullParameters<F, MerkleConfig, FSConfig>,
}

impl<F, MerkleConfig, FSConfig> Verifier<F, MerkleConfig, FSConfig>
    for StirVerifier<F, MerkleConfig, FSConfig>
where
    F: FftField + PrimeField + Absorb,
    MerkleConfig: Config<Leaf = Vec<F>>,
    MerkleConfig::InnerDigest: Absorb,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type FullParameter = FullParameters<F, MerkleConfig, FSConfig>;
    type Commitment = Commitment<MerkleConfig>;
    type Proof = Proof<F, MerkleConfig>;

    fn new(parameters: Parameters<F, MerkleConfig, FSConfig>) -> Self {
        Self {
            parameters: parameters.into(),
        }
    }

    fn new_full(full_parameters: Self::FullParameter) -> Self {
        Self {
            parameters: full_parameters,
        }
    }

    fn verify(
        &self,
        commitment: &Commitment<MerkleConfig>,
        proof: &Proof<F, MerkleConfig>,
    ) -> bool {
        if proof.final_polynomial.degree() + 1 > self.parameters.stopping_degree {
            return false;
        }

        // First we verify all Merkle paths
        let mut current_root = commitment.root.clone();
        for round_proof in &proof.round_proofs {
            if !round_proof
                .queries_to_prev
                .1
                .verify(
                    &self.parameters.leaf_hash_params,
                    &self.parameters.two_to_one_params,
                    &current_root,
                    round_proof.queries_to_prev.0.clone(),
                )
                .unwrap()
            {
                return false;
            }
            current_root = round_proof.g_root.clone();
        }
        if !proof
            .queries_to_final
            .1
            .verify(
                &self.parameters.leaf_hash_params,
                &self.parameters.two_to_one_params,
                &current_root,
                proof.queries_to_final.0.clone(),
            )
            .unwrap()
        {
            return false;
        }

        // Now, we recompute
        let mut sponge = FSConfig::new(&self.parameters.fiat_shamir_config);
        sponge.absorb(&commitment.root);
        let folding_randomness = sponge.squeeze_field_elements(1)[0];

        let domain = Domain::<F>::new(
            self.parameters.starting_degree,
            self.parameters.starting_rate,
        )
        .unwrap();

        let domain_gen = domain.element(1);
        let domain_size = domain.size();

        let mut verification_state = VerificationState {
            oracle: OracleType::Initial,
            domain_gen,
            domain_size,
            domain_offset: F::ONE,
            root_of_unity: domain_gen,
            num_round: 0,
            folding_randomness,
        };

        for round_proof in &proof.round_proofs {
            let round_result = self.round(&mut sponge, round_proof, verification_state);
            if round_result.is_none() {
                return false;
            }
            verification_state = round_result.unwrap();
        }

        // Now, we sample the last points that we want to check consisntency at
        let final_repetitions = self.parameters.repetitions[self.parameters.num_rounds];
        let scaling_factor = verification_state.domain_size / self.parameters.folding_factor;
        let final_randomness_indexes = utils::dedup(
            (0..final_repetitions).map(|_| utils::squeeze_integer(&mut sponge, scaling_factor)),
        );

        if !utils::proof_of_work_verify(
            &mut sponge,
            self.parameters.pow_bits[self.parameters.num_rounds],
            proof.pow_nonce,
        ) {
            return false;
        }

        // First, we want to query back the last oracle at this point, which is, again, just a
        // lookup
        let oracle_answers = proof.queries_to_final.0.clone();

        let folded_answers = self.compute_folded_evaluations(
            &verification_state,
            final_randomness_indexes,
            oracle_answers,
        );

        folded_answers
            .into_iter()
            .all(|(point, value)| proof.final_polynomial.evaluate(&point) == value)
    }
}

impl<F, MerkleConfig, FSConfig> StirVerifier<F, MerkleConfig, FSConfig>
where
    F: FftField + PrimeField + Absorb,
    MerkleConfig: Config<Leaf = Vec<F>>,
    MerkleConfig::InnerDigest: Absorb,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    fn compute_folded_evaluations(
        &self,
        verification_state: &VerificationState<F>,
        stir_randomness_indexes: Vec<usize>,
        oracle_answers: Vec<Vec<F>>,
    ) -> Vec<(F, F)> {
        let scaling_factor = verification_state.domain_size / self.parameters.folding_factor;
        let generator = verification_state.domain_gen.pow([scaling_factor as u64]);

        // We do a single batch inversion
        let coset_offsets: Vec<_> = stir_randomness_indexes
            .iter()
            .map(|stir_randomness_index| {
                verification_state.domain_offset
                    * verification_state
                        .domain_gen
                        .pow([*stir_randomness_index as u64])
            })
            .collect();

        // We use this to more efficiently compute query_sets
        let scales: Vec<F> = std::iter::successors(Some(F::ONE), |&prev| Some(prev * generator))
            .take(self.parameters.folding_factor)
            .collect();

        let query_sets: Vec<_> = coset_offsets
            .iter()
            .map(|coset_offset| {
                (0..self.parameters.folding_factor)
                    .map(|j| *coset_offset * scales[j])
                    .collect::<Vec<_>>()
            })
            .collect();

        let common_factor_scale = match &verification_state.oracle {
            OracleType::Initial => F::ZERO,
            OracleType::Virtual(virtual_function) => virtual_function.comb_randomness,
        };

        let global_common_factors = query_sets
            .iter()
            .map(|query_set| query_set.iter().map(|x| F::ONE - common_factor_scale * x));

        let global_denominators =
            query_sets
                .iter()
                .map(|query_set| match &verification_state.oracle {
                    OracleType::Initial => vec![F::ONE; query_set.len()],
                    OracleType::Virtual(virtual_function) => query_set
                        .iter()
                        .map(|eval_point| {
                            virtual_function
                                .quotient_set
                                .iter()
                                .map(|x| *eval_point - x)
                                .product::<F>()
                        })
                        .collect::<Vec<_>>(),
                });

        // To invert contains a bunch of stuff offsets, generator, size, and common factors
        let size = F::from(self.parameters.folding_factor as u64);
        let mut to_invert = vec![];
        let global_common_factors_len = global_common_factors.len();
        for common_factors in global_common_factors {
            to_invert.extend(common_factors);
        }
        for denominators in global_denominators {
            to_invert.extend(denominators);
        }
        to_invert.extend(coset_offsets.iter());
        to_invert.push(generator);
        to_invert.push(size);
        batch_inversion(&mut to_invert);
        let size_inv = to_invert.pop().unwrap();
        let generator_inv = to_invert.pop().unwrap();
        let coset_offsets_inv = to_invert.split_off(to_invert.len() - coset_offsets.len());
        let chunked: Vec<Vec<_>> = to_invert
            .chunks(self.parameters.folding_factor)
            .map(|x| x.to_vec())
            .collect();

        // TODO: Could be split_off
        let common_factors_inv = chunked[0..global_common_factors_len].to_vec();
        let denominators_inv = chunked[global_common_factors_len..].to_vec();

        let evaluations_of_ans: Vec<_> = coset_offsets
            .iter()
            .zip(&coset_offsets_inv)
            .map(
                |(coset_offset, coset_offset_inv)| match &verification_state.oracle {
                    OracleType::Initial => vec![F::ONE; self.parameters.folding_factor],
                    OracleType::Virtual(virtual_function) => {
                        let domain = Radix2EvaluationDomain {
                            size: self.parameters.folding_factor as u64,
                            log_size_of_group: self.parameters.folding_factor.ilog2(),
                            size_as_field_element: size,
                            size_inv,
                            group_gen: generator,
                            group_gen_inv: generator_inv,
                            offset: *coset_offset,
                            offset_inv: *coset_offset_inv,
                            offset_pow_size: coset_offset
                                .pow([self.parameters.folding_factor as u64]),
                        };

                        virtual_function
                            .interpolating_polynomial
                            .clone()
                            .evaluate_over_domain(domain)
                            .evals
                    }
                },
            )
            .collect();

        let scaled_offset = verification_state
            .domain_offset
            .pow([self.parameters.folding_factor as u64]);

        izip!(
            stir_randomness_indexes.iter(),
            coset_offsets,
            coset_offsets_inv,
            query_sets,
            common_factors_inv,
            denominators_inv,
            evaluations_of_ans
        )
        .enumerate()
        .map(
            |(
                i,
                (
                    stir_randomness_index,
                    coset_offset,
                    coset_offset_inv,
                    query_set,
                    common_factors_inv,
                    denominators_inv,
                    evaluation_of_ans,
                ),
            )| {
                // This is the point that we are querying at
                let stir_randomness = scaled_offset
                    * verification_state
                        .domain_gen
                        .pow([(self.parameters.folding_factor * stir_randomness_index) as u64]);

                let f_answers: Vec<_> = query_set
                    .into_iter()
                    .enumerate()
                    .map(|(j, x)| {
                        verification_state.query(
                            x,
                            oracle_answers[i][j],
                            common_factors_inv[j],
                            denominators_inv[j],
                            evaluation_of_ans[j],
                        )
                    })
                    .collect();

                // This is the folding
                let folded_answer = poly_utils::interpolation::fft_interpolate(
                    generator,
                    coset_offset,
                    generator_inv,
                    coset_offset_inv,
                    size_inv,
                    &f_answers,
                )
                .evaluate(&verification_state.folding_randomness);

                // Return the folded answer
                (stir_randomness, folded_answer)
            },
        )
        .collect()
    }

    fn round(
        &self,
        sponge: &mut impl CryptographicSponge,
        round_proof: &RoundProof<F, MerkleConfig>,
        verification_state: VerificationState<F>,
    ) -> Option<VerificationState<F>> {
        // Redo FS
        sponge.absorb(&round_proof.g_root);
        let ood_randomness = sponge.squeeze_field_elements(self.parameters.ood_samples);
        sponge.absorb(&round_proof.betas);
        let comb_randomness = sponge.squeeze_field_elements(1)[0];
        let new_folding_randomness = sponge.squeeze_field_elements(1)[0];
        let scaling_factor = verification_state.domain_size / self.parameters.folding_factor;

        let num_repetitions = self.parameters.repetitions[verification_state.num_round];
        let stir_randomness_indexes = utils::dedup(
            (0..num_repetitions).map(|_| utils::squeeze_integer(sponge, scaling_factor)),
        );

        // PoW verification
        if !utils::proof_of_work_verify(
            sponge,
            self.parameters.pow_bits[verification_state.num_round],
            round_proof.pow_nonce,
        ) {
            return None;
        }

        let shake_randomness = sponge.squeeze_field_elements(1)[0];

        // Now, we are starting to define the next function.
        // First, we need to query the previous oracle (which is either f_0 or g_i)
        // At the indexes B_i for i in stir_randomness_indexes
        // Since we previously verified the Merkle paths, this is easy
        // TODO: We should probably check the indexes
        let oracle_answers = round_proof.queries_to_prev.0.clone();

        // Now, for each of the selected random points, we need to compute the folding of the
        // previous oracle
        let folded_answers = self.compute_folded_evaluations(
            &verification_state,
            stir_randomness_indexes,
            oracle_answers,
        );

        // The quotient definining the function
        let quotient_answers: Vec<_> = ood_randomness
            .into_iter()
            .zip(&round_proof.betas)
            .map(|(alpha, beta)| (alpha, *beta))
            .chain(folded_answers)
            .collect();
        let interpolating_polynomial = round_proof.ans_polynomial.clone();

        let ans_eval = interpolating_polynomial.evaluate(&shake_randomness);
        let shake_eval = round_proof.shake_polynomial.evaluate(&shake_randomness);

        let mut denoms: Vec<_> = quotient_answers
            .iter()
            .map(|(x, _)| shake_randomness - x)
            .collect();

        batch_inversion(&mut denoms);
        // TODO: This maybe should be better
        if shake_eval
            != quotient_answers
                .iter()
                .zip(denoms)
                .map(|((_, y), d)| (ans_eval - y) * d)
                .sum()
        {
            return None;
        }

        let quotient_set = quotient_answers
            .into_iter()
            .map(|(x, _)| x)
            .collect::<Vec<_>>();

        Some(VerificationState {
            oracle: OracleType::Virtual(VirtualFunction {
                comb_randomness,
                quotient_set,
                interpolating_polynomial,
            }),
            // TODO: We can optimize
            domain_size: verification_state.domain_size / 2,
            domain_gen: verification_state.domain_gen * verification_state.domain_gen,
            domain_offset: verification_state.domain_offset
                * verification_state.domain_offset
                * verification_state.root_of_unity,
            root_of_unity: verification_state.root_of_unity,
            folding_randomness: new_folding_randomness,
            num_round: verification_state.num_round + 1,
        })
    }
}
