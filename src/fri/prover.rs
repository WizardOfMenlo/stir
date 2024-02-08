use ark_crypto_primitives::{
    merkle_tree::{Config, MerkleTree},
    sponge::{Absorb, CryptographicSponge},
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};
use derivative::Derivative;

use crate::{
    fri::{common::*, parameters::FullParameters},
    ldt::Prover,
    poly_utils, utils,
};

use crate::{domain::Domain, parameters::Parameters};

#[derive(Derivative)]
#[derivative(Clone(bound = "F: Clone"))]
pub struct Witness<F: FftField, MerkleConfig: Config> {
    pub(crate) domain: Domain<F>,
    pub(crate) polynomial: DensePolynomial<F>,
    pub(crate) merkle_tree: MerkleTree<MerkleConfig>,
    pub(crate) folded_evals: Vec<Vec<F>>,
}

pub struct FriProver<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    pub(crate) parameters: FullParameters<F, MerkleConfig, FSConfig>,
}

impl<F, MerkleConfig, FSConfig> Prover<F, MerkleConfig, FSConfig>
    for FriProver<F, MerkleConfig, FSConfig>
where
    F: FftField + PrimeField + Absorb,
    MerkleConfig: Config<Leaf = Vec<F>>,
    MerkleConfig::InnerDigest: Absorb,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type FullParameter = FullParameters<F, MerkleConfig, FSConfig>;
    type Commitment = Commitment<MerkleConfig>;
    type Witness = Witness<F, MerkleConfig>;
    type Proof = Proof<F, MerkleConfig>;

    fn new(parameters: Parameters<F, MerkleConfig, FSConfig>) -> Self {
        Self::new_full(parameters.into())
    }

    fn new_full(full_parameters: Self::FullParameter) -> Self {
        Self {
            parameters: full_parameters,
        }
    }

    // TODO: Better name for testing
    fn commit(
        &self,
        witness_polynomial: DensePolynomial<F>,
    ) -> (Commitment<MerkleConfig>, Witness<F, MerkleConfig>) {
        let domain = Domain::<F>::new(
            self.parameters.starting_degree,
            self.parameters.starting_rate,
        )
        .unwrap();
        let evals = witness_polynomial
            .evaluate_over_domain_by_ref(domain.backing_domain)
            .evals;
        let folded_evals = utils::stack_evaluations(evals, self.parameters.folding_factor);
        let merkle_tree = MerkleTree::<MerkleConfig>::new(
            &self.parameters.leaf_hash_params,
            &self.parameters.two_to_one_params,
            &folded_evals,
        )
        .unwrap();

        let initial_commitment = merkle_tree.root();

        (
            Commitment {
                root: initial_commitment,
            },
            Witness {
                domain,
                polynomial: witness_polynomial,
                merkle_tree,
                folded_evals,
            },
        )
    }

    fn prove(&self, witness: Witness<F, MerkleConfig>) -> Proof<F, MerkleConfig> {
        assert!(witness.polynomial.degree() < self.parameters.starting_degree);

        let mut sponge = FSConfig::new(&self.parameters.fiat_shamir_config);
        sponge.absorb(&witness.merkle_tree.root());

        let mut g_domain = witness.domain.clone();
        let mut g_poly = witness.polynomial.clone();

        // Commit phase
        let mut commitments = vec![];
        let mut merkle_trees = vec![witness.merkle_tree.clone()];
        let mut folded_evals = vec![witness.folded_evals];

        let mut folding_randomness = sponge.squeeze_field_elements(1)[0];
        for _ in 0..self.parameters.num_rounds {
            // Fold the initial polynomial
            g_poly = poly_utils::folding::poly_fold(
                &g_poly,
                self.parameters.folding_factor,
                folding_randomness,
            );

            let prev_evals = folded_evals.last().unwrap();

            // The following lines are just precomputations, to avoid having to do inversion
            // and exponentiations in the inner loop
            let domain_size = g_domain.size();
            let generator = g_domain
                .backing_domain
                .element(domain_size / self.parameters.folding_factor);
            let generator_inv = generator.inverse().unwrap();
            let size_inv = F::from(self.parameters.folding_factor as u64)
                .inverse()
                .unwrap();
            let coset_offsets: Vec<_> = g_domain
                .backing_domain
                .elements()
                .take(prev_evals.len())
                .collect();
            let mut counter = F::ONE;
            let scale = g_domain.backing_domain.element(1).inverse().unwrap();
            let mut coset_offsets_inv: Vec<_> = vec![];
            for _ in 0..prev_evals.len() {
                coset_offsets_inv.push(counter);
                counter *= scale;
            }

            // Compute the evalations of the folded polynomial
            let g_evaluations: Vec<_> = prev_evals
                .iter()
                .zip(coset_offsets.into_iter())
                .zip(coset_offsets_inv.into_iter())
                .map(|((e, c), ci)| (e, c, ci))
                .map(|(evals, coset_offset, coset_offset_inv)| {
                    poly_utils::interpolation::fft_interpolate(
                        generator,
                        coset_offset,
                        generator_inv,
                        coset_offset_inv,
                        size_inv,
                        evals,
                    )
                    .evaluate(&folding_randomness)
                })
                .collect();

            /*
             * The following codes are other attempts at doing this
            let domain_points = g_domain.backing_domain.elements().collect::<Vec<_>>();
            let folded_domains =
                utils::stack_evaluations(domain_points, self.parameters.folding_factor);
            let g_evaluations = prev_evals
                .iter()
                .enumerate()
                .map(|(i, evals)| {
                    let interpol = evals
                        .iter()
                        .enumerate()
                        .map(|(j, &e)| (folded_domains[i][j], e))
                        .collect();

                    poly_utils::folding::fold(
                        interpol,
                        self.parameters.folding_factor,
                        folding_randomness,
                    )
                })
                .collect();
            */

            g_domain = g_domain.scale(self.parameters.folding_factor);
            //let g_evaluations = g_poly.evaluate_over_domain_by_ref(g_domain.backing_domain).evals;

            let g_folded_evaluations =
                utils::stack_evaluations(g_evaluations, self.parameters.folding_factor);
            let g_merkle = MerkleTree::<MerkleConfig>::new(
                &self.parameters.leaf_hash_params,
                &self.parameters.two_to_one_params,
                &g_folded_evaluations,
            )
            .unwrap();
            let g_root = g_merkle.root();
            sponge.absorb(&g_root);

            folding_randomness = sponge.squeeze_field_elements(1)[0];

            commitments.push(g_root);
            merkle_trees.push(g_merkle);
            folded_evals.push(g_folded_evaluations);
        }

        g_poly = poly_utils::folding::poly_fold(
            &g_poly,
            self.parameters.folding_factor,
            folding_randomness,
        );

        // Query phase
        let mut folded_evals_len = witness.domain.size() / self.parameters.folding_factor;
        let mut query_indexes = utils::dedup(
            (0..self.parameters.repetitions)
                .map(|_| utils::squeeze_integer(&mut sponge, folded_evals_len)),
        );

        // Note that we include final round as well
        let mut round_proofs = vec![];
        for round in 0..=self.parameters.num_rounds {
            let queries_to_prev_ans = query_indexes
                .iter()
                .map(|&index| folded_evals[round][index].clone())
                .collect();
            let queries_to_prev_proof = merkle_trees[round]
                .generate_multi_proof(query_indexes.clone())
                .unwrap();
            let queries_to_prev = (queries_to_prev_ans, queries_to_prev_proof);

            folded_evals_len = folded_evals_len / self.parameters.folding_factor;
            query_indexes = utils::dedup(query_indexes.into_iter().map(|i| i % folded_evals_len));

            round_proofs.push(RoundProofs { queries_to_prev });
        }

        Proof {
            final_polynomial: g_poly,
            commitments,
            round_proofs,
            pow_nonce: utils::proof_of_work(&mut sponge, self.parameters.pow_bits),
        }
    }
}
