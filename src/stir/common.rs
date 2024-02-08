use ark_crypto_primitives::merkle_tree::{Config, MultiPath};
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<MerkleConfig>
where
    MerkleConfig: Config,
{
    pub(crate) root: MerkleConfig::InnerDigest,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: FftField, MerkleConfig: Config> {
    pub(crate) round_proofs: Vec<RoundProof<F, MerkleConfig>>,
    pub(crate) final_polynomial: DensePolynomial<F>,
    pub(crate) queries_to_final: (Vec<Vec<F>>, MultiPath<MerkleConfig>),
    pub(crate) pow_nonce: Option<usize>,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RoundProof<F: FftField, MerkleConfig: Config> {
    pub(crate) g_root: MerkleConfig::InnerDigest,
    pub(crate) betas: Vec<F>,
    pub(crate) ans_polynomial: DensePolynomial<F>,
    pub(crate) queries_to_prev: (Vec<Vec<F>>, MultiPath<MerkleConfig>),
    pub(crate) shake_polynomial: DensePolynomial<F>,
    pub(crate) pow_nonce: Option<usize>,
}
