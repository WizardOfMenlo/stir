use ark_crypto_primitives::merkle_tree::{Config, LeafParam, TwoToOneParam};
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::FftField;
use derivative::Derivative;
use std::fmt::Display;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub enum SoundnessType {
    Provable,
    Conjecture,
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub struct Parameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    // The targeted security level of the whole construction
    pub security_level: usize,

    // The targeted security level of the protocol
    pub protocol_security_level: usize,

    pub starting_degree: usize,
    pub stopping_degree: usize,
    pub folding_factor: usize,

    // log_inv_rate
    pub starting_rate: usize,

    pub soundness_type: SoundnessType,

    // Merkle tree parameters
    #[derivative(Debug = "ignore")]
    pub leaf_hash_params: LeafParam<MerkleConfig>,
    #[derivative(Debug = "ignore")]
    pub two_to_one_params: TwoToOneParam<MerkleConfig>,

    // FiatShamir parameters
    #[derivative(Debug = "ignore")]
    pub fiat_shamir_config: FSConfig::Config,

    #[derivative(Debug = "ignore")]
    pub _field: PhantomData<F>,
}

impl<F, MerkleConfig, FSConfig> Parameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    pub(crate) fn repetitions(&self, log_inv_rate: usize) -> usize {
        let constant = match self.soundness_type {
            SoundnessType::Provable => 2,
            SoundnessType::Conjecture => 1,
        };
        ((constant * self.protocol_security_level) as f64 / log_inv_rate as f64).ceil() as usize
    }

    pub(crate) fn pow_bits(&self, log_inv_rate: usize) -> usize {
        let repetitions = self.repetitions(log_inv_rate);
        // TODO: This will change with eta
        let scaling_factor = match self.soundness_type {
            SoundnessType::Provable => 2.,
            SoundnessType::Conjecture => 1.,
        };
        let achieved_security_bits = (log_inv_rate as f64 / scaling_factor) * repetitions as f64;
        let remaining_security_bits = self.security_level as f64 - achieved_security_bits;

        if remaining_security_bits <= 0. {
            0
        } else {
            remaining_security_bits.ceil() as usize
        }
    }
}

impl<F, MerkleConfig, FSConfig> Display for Parameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let starting_degree_log = (self.starting_degree as f64).log2() as usize;
        let stopping_degree_log = (self.stopping_degree as f64).log2() as usize;

        writeln!(
            f,
            "Targeting {}-bits of security - protocol running at {}-bits - soundness: {:?}",
            self.security_level, self.protocol_security_level, self.soundness_type
        )?;
        writeln!(
            f,
            "Starting degree: 2^{}, stopping_degree: 2^{}",
            starting_degree_log, stopping_degree_log
        )?;
        writeln!(
            f,
            "Starting rate: 2^-{}, folding_factor: {}",
            self.starting_rate, self.folding_factor
        )
    }
}
