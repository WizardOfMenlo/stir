use ark_crypto_primitives::{merkle_tree::Config, sponge::CryptographicSponge};
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;

use crate::parameters::Parameters;

pub trait LowDegreeTest<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type Prover: Prover<
        F,
        MerkleConfig,
        FSConfig,
        Commitment = <Self::Verifier as Verifier<F, MerkleConfig, FSConfig>>::Commitment,
        Proof = <Self::Verifier as Verifier<F, MerkleConfig, FSConfig>>::Proof,
    >;
    type Verifier: Verifier<F, MerkleConfig, FSConfig>;

    fn display(parameters: Parameters<F, MerkleConfig, FSConfig>);

    fn instantiate(
        parameters: Parameters<F, MerkleConfig, FSConfig>,
    ) -> (Self::Prover, Self::Verifier) {
        let prover = Self::Prover::new(parameters.clone());
        let verifier = Self::Verifier::new(parameters);

        (prover, verifier)
    }
}

pub trait Prover<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type FullParameter;

    type Commitment;

    type Witness: Clone;
    type Proof;

    fn new(parameters: Parameters<F, MerkleConfig, FSConfig>) -> Self;
    fn new_full(full_parameters: Self::FullParameter) -> Self;

    fn commit(&self, polynomial: DensePolynomial<F>) -> (Self::Commitment, Self::Witness);

    fn prove(&self, witness: Self::Witness) -> Self::Proof;
}

pub trait Verifier<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type FullParameter;

    type Commitment;

    type Proof: CanonicalSerialize;

    fn new(parameters: Parameters<F, MerkleConfig, FSConfig>) -> Self;
    fn new_full(full_parameters: Self::FullParameter) -> Self;

    fn verify(&self, commitment: &Self::Commitment, proof: &Self::Proof) -> bool;
}
