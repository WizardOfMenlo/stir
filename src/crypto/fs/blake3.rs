use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use blake3::Hasher;

#[derive(Default, Clone, Copy)]
pub struct Blake3Config;

pub fn default_fs_config() -> Blake3Config {
    Blake3Config
}

#[derive(Default, Clone)]
pub struct Sponge(Hasher);

impl CryptographicSponge for Sponge {
    type Config = Blake3Config;

    fn new(_config: &Self::Config) -> Self {
        Self::default()
    }

    fn absorb(&mut self, input: &impl Absorb) {
        self.0.update(&input.to_sponge_bytes_as_vec());
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut xof = self.0.finalize_xof();
        let mut output = vec![0u8; num_bytes];
        xof.fill(&mut output);
        // Need to now update the hasher
        self.0.update(&output);
        output
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut xof = self.0.finalize_xof();
        let mut output = vec![0u8; (num_bits + 7) / 8];
        xof.fill(&mut output);
        self.0.update(&output);

        output
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .take(num_bits)
            .collect()
    }
}
