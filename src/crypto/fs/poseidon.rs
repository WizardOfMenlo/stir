use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_ff::PrimeField;
use poseidon_paramgen::v1::generate;

pub type Sponge<F> = PoseidonSponge<F>;

// PoseidonSponge for testing
pub fn default_fs_config<F: PrimeField>() -> PoseidonConfig<F> {
    // initialize params
    let security_level_bits: usize = 128;
    let width_hash_function: usize = 3; // In this case, we do 2-to-1
    let allow_inverse: bool = false;
    let poseidon_parameters = generate::<F>(
        security_level_bits,
        width_hash_function,
        F::MODULUS,
        allow_inverse,
    );
    // generate the config
    PoseidonConfig::new(
        poseidon_parameters.rounds.full(),
        poseidon_parameters.rounds.partial(),
        // Note: enum Alpha could be exported so we don't have to assume the value it takes is Exponent(u32)
        //  https://github.com/penumbra-zone/poseidon377/blob/11afbcdd65b52d72de7e891028cfac137d7ff62e/poseidon-parameters/src/alpha.rs#L3
        u32::from_le_bytes(poseidon_parameters.alpha.to_bytes_le()) as u64,
        poseidon_parameters.mds.into(),
        poseidon_parameters.arc.into(),
        1, // rate
        2, // capacity
    )
}
