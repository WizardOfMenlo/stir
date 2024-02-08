use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::FftField;
use derivative::Derivative;
use std::fmt::Display;
use std::ops::Deref;

use crate::parameters::Parameters;
use crate::utils;

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub struct FullParameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    #[derivative(Debug(bound = "F: std::fmt::Debug"))]
    pub(crate) parameters: Parameters<F, MerkleConfig, FSConfig>,
    pub(crate) num_rounds: usize,
    pub(crate) repetitions: usize,
    pub(crate) pow_bits: usize,
    pub(crate) degrees: Vec<usize>,
}

impl<F, MerkleConfig, FSConfig> Display for FullParameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Parameters::fmt(&self.parameters, f)?;
        writeln!(f, "Number of rounds: {}", self.num_rounds)?;
        writeln!(f, "PoW bits: {}", self.pow_bits)?;
        writeln!(f, "Repetitions: {:?}", self.repetitions)
    }
}

impl<F, MerkleConfig, FSConfig> From<Parameters<F, MerkleConfig, FSConfig>>
    for FullParameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    fn from(parameters: Parameters<F, MerkleConfig, FSConfig>) -> Self {
        assert!(utils::is_power_of_two(parameters.folding_factor));
        assert!(utils::is_power_of_two(parameters.starting_degree));
        assert!(utils::is_power_of_two(parameters.stopping_degree));

        // TODO: I don't even need to iterate but I don't pay for these cycles
        let mut d = parameters.starting_degree;
        let mut degrees = vec![d];
        let mut num_rounds = 0;
        while d > parameters.stopping_degree {
            assert!(d % parameters.folding_factor == 0);
            d /= parameters.folding_factor;
            degrees.push(d);
            num_rounds += 1;
        }

        num_rounds -= 1;
        degrees.pop();

        let repetitions = parameters.repetitions(parameters.starting_rate);
        let pow_bits = parameters.pow_bits(parameters.starting_rate);
        Self {
            parameters,
            num_rounds,
            degrees,
            repetitions,
            pow_bits,
        }
    }
}

impl<F, MerkleConfig, FSConfig> Deref for FullParameters<F, MerkleConfig, FSConfig>
where
    F: FftField,
    MerkleConfig: Config,
    FSConfig: CryptographicSponge,
    FSConfig::Config: Clone,
{
    type Target = Parameters<F, MerkleConfig, FSConfig>;

    fn deref(&self) -> &Parameters<F, MerkleConfig, FSConfig> {
        &self.parameters
    }
}
