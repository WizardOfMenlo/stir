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
    pub(crate) rates: Vec<usize>,
    pub(crate) repetitions: Vec<usize>,
    pub(crate) pow_bits: Vec<usize>,
    pub(crate) ood_samples: usize,
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

        writeln!(
            f,
            "Number of rounds: {}. OOD samples: {}",
            self.num_rounds, self.ood_samples
        )?;
        writeln!(
            f,
            "Rates: {}",
            self.rates
                .iter()
                .map(|i| format!("2^-{}", i))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(f, "PoW bits: {:?}", self.pow_bits)?;
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

        let mut rates = vec![parameters.starting_rate];
        let log_folding = parameters.folding_factor.ilog2() as usize;
        rates.extend((1..num_rounds + 1).map(|i| parameters.starting_rate + i * (log_folding - 1)));
        let pow_bits: Vec<_> = rates
            .iter()
            .map(|&log_inv_rate| parameters.pow_bits(log_inv_rate))
            .collect();
        let mut repetitions: Vec<_> = rates
            .iter()
            .map(|&log_inv_rate| parameters.repetitions(log_inv_rate))
            .collect();

        // Note, this skips the last repetition
        for i in 0..num_rounds {
            repetitions[i] = repetitions[i].min(degrees[i] / parameters.folding_factor);
        }

        assert_eq!(num_rounds + 1, rates.len());
        assert_eq!(num_rounds + 1, repetitions.len());

        Self {
            parameters,
            num_rounds,
            degrees,
            rates,
            pow_bits,
            ood_samples: 2,
            repetitions,
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
