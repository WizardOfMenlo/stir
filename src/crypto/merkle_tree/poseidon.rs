use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::crh::poseidon;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;

use crate::crypto::fs;

use super::HashCounter;

// We need 2 field elements for security
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonDigest<F: PrimeField>([F; 2]);

impl<DigestField: PrimeField + Absorb> Absorb for PoseidonDigest<DigestField> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.0[0].to_sponge_bytes(dest);
        self.0[1].to_sponge_bytes(dest);
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.0[0].to_sponge_field_elements(dest);
        self.0[1].to_sponge_field_elements(dest);
    }
}

pub struct PoseidonCRH<F>(PhantomData<F>);

impl<F: PrimeField + Absorb> CRHScheme for PoseidonCRH<F> {
    type Input = Vec<F>;
    type Output = PoseidonDigest<F>;
    type Parameters = <poseidon::CRH<F> as CRHScheme>::Parameters;

    fn setup<R: RngCore>(_rng: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(fs::poseidon::default_fs_config::<F>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        HashCounter::add();
        let mut sponge = PoseidonSponge::new(parameters);
        for el in input.borrow() {
            sponge.absorb(el);
        }
        let res = sponge.squeeze_field_elements::<F>(2);
        Ok(PoseidonDigest([res[0], res[1]]))
    }
}

pub struct PoseidonTwoToOneCRH<F>(PhantomData<F>);

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for PoseidonTwoToOneCRH<F> {
    type Input = PoseidonDigest<F>;
    type Output = PoseidonDigest<F>;
    type Parameters = <poseidon::TwoToOneCRH<F> as TwoToOneCRHScheme>::Parameters;

    fn setup<R: RngCore>(_rng: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(fs::poseidon::default_fs_config::<F>())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        HashCounter::add();
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();
        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(&left_input.0[0]);
        sponge.absorb(&left_input.0[1]);
        sponge.absorb(&right_input.0[0]);
        sponge.absorb(&right_input.0[1]);
        let res = sponge.squeeze_field_elements::<F>(2);
        Ok(PoseidonDigest([res[0], res[1]]))

    }
}

pub type LeafH<F> = PoseidonCRH<F>;
pub type CompressH<F> = PoseidonTwoToOneCRH<F>;

#[derive(Debug, Default, Clone)]
pub struct MerkleTreeParams<F>(PhantomData<F>);

impl<F: PrimeField + Absorb> Config for MerkleTreeParams<F> {
    type Leaf = Vec<F>;

    type LeafDigest = <LeafH<F> as CRHScheme>::Output;
    type LeafInnerDigestConverter = IdentityDigestConverter<PoseidonDigest<F>>;
    type InnerDigest = <CompressH<F> as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH<F>;
    type TwoToOneHash = CompressH<F>;
}

pub fn default_config<F: PrimeField + Absorb>(
    rng: &mut impl RngCore,
    _leaf_arity: usize,
) -> (
    <LeafH<F> as CRHScheme>::Parameters,
    <CompressH<F> as TwoToOneCRHScheme>::Parameters,
) {
    let leaf_hash_params = <LeafH<F> as CRHScheme>::setup(rng).unwrap();
    let two_to_one_params = <CompressH<F> as TwoToOneCRHScheme>::setup(rng).unwrap();

    (leaf_hash_params, two_to_one_params)
}
