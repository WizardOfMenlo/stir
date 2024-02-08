use std::{
    fs::OpenOptions,
    time::{Duration, Instant},
};

use serde::Serialize;

use stir::{
    crypto::{
        fields,
        fs::{
            self,
            blake3::{Blake3Config, Sponge},
        },
        merkle_tree::{self, HashCounter},
    },
    fri::Fri,
    ldt::{LowDegreeTest, Verifier},
    parameters::{Parameters, SoundnessType},
    stir::Stir,
};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'l', long, default_value = "128")]
    security_level: usize,

    #[arg(short = 'p', long, default_value = "106")]
    protocol_security_level: usize,

    #[arg(short = 'd', long, default_value = "20")]
    initial_degree: usize,

    #[arg(short = 'f', long, default_value = "6")]
    final_degree: usize,

    #[arg(short = 'r', long, default_value = "2")]
    rate: usize,

    #[arg(long = "reps", default_value = "1000")]
    verifier_repetitions: usize,

    #[arg(long = "sk", default_value = "16")]
    stir_folding_factor: usize,

    #[arg(long = "fk", default_value = "8")]
    fri_folding_factor: usize,
}

#[derive(Debug, Serialize)]
struct VerifierOutput {
    security_level: usize,
    protocol_security_level: usize,
    starting_degree: usize,
    stopping_degree: usize,
    starting_rate: usize,
    repetitions: usize,
    stir_folding_factor: usize,
    fri_folding_factor: usize,
    stir_verifier_time: Duration,
    stir_verifier_hashes: usize,
    fri_verifier_time: Duration,
    fri_verifier_hashes: usize,
}

fn main() {
    type F = fields::Field192;
    use merkle_tree::sha3 as merkle_tree;

    let args = Args::parse();

    let security_level = args.security_level;
    let protocol_security_level = args.protocol_security_level;
    let starting_degree = 1 << args.initial_degree;
    let stopping_degree = 1 << args.final_degree;
    let starting_rate = args.rate;
    let soundness_type = SoundnessType::Conjecture;
    let reps = args.verifier_repetitions;

    let mut rng = ark_std::test_rng();
    let fiat_shamir_config: Blake3Config = fs::blake3::default_fs_config();

    // STIR
    let (stir_verifier_time, stir_verifier_hashes) = {
        println!("=========================================");
        println!("STIR - Shaken");
        let (leaf_hash_params, two_to_one_params) =
            merkle_tree::default_config::<F>(&mut rng, args.stir_folding_factor);
        let params: Parameters<F, merkle_tree::MerkleTreeParams<F>, Sponge> = Parameters {
            security_level,
            protocol_security_level,
            starting_degree,
            stopping_degree,
            folding_factor: args.stir_folding_factor,
            starting_rate,
            soundness_type,

            leaf_hash_params,
            two_to_one_params,
            fiat_shamir_config,
            _field: Default::default(),
        };

        Stir::display(params.clone());

        let (_, verifier) = Stir::instantiate(params);

        let mut proofs = vec![];
        for i in 0..reps {
            let file_contents = std::fs::read(format!("artifacts/stir_proof{}", i)).unwrap();
            let (commitment, proof): (
                stir::stir::common::Commitment<merkle_tree::MerkleTreeParams<F>>,
                stir::stir::common::Proof<F, merkle_tree::MerkleTreeParams<F>>,
            ) = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                &mut &file_contents[..],
            )
            .unwrap();
            proofs.push((commitment, proof));
        }

        let stir_verifier_time = Instant::now();
        for (commitment, proof) in proofs {
            verifier.verify(&commitment, &proof);
        }
        let stir_verifier_time = stir_verifier_time.elapsed();
        let stir_verifier_hashes = HashCounter::get() / reps;
        HashCounter::reset();
        println!("STIR verifier time: {:?}", stir_verifier_time);
        println!(
            "STIR verifier hashes: {:?}",
            stir_verifier_hashes
        );
        (stir_verifier_time, stir_verifier_hashes)
    };

    //FRI
    let (fri_verifier_time, fri_verifier_hashes) = {
        println!("=========================================");
        println!("FRI");
        let (leaf_hash_params, two_to_one_params) =
            merkle_tree::default_config::<F>(&mut rng, args.fri_folding_factor);
        let params: Parameters<F, merkle_tree::MerkleTreeParams<F>, Sponge> = Parameters {
            security_level,
            protocol_security_level,
            starting_degree,
            stopping_degree,
            folding_factor: args.fri_folding_factor,
            starting_rate,
            soundness_type,

            leaf_hash_params,
            two_to_one_params,
            fiat_shamir_config,
            _field: Default::default(),
        };

        Fri::display(params.clone());

        let (_, verifier) = Fri::instantiate(params);

        let mut proofs = vec![];
        for i in 0..reps {
            let file_contents = std::fs::read(format!("artifacts/fri_proof{}", i)).unwrap();
            let (commitment, proof): (
                stir::fri::common::Commitment<merkle_tree::MerkleTreeParams<F>>,
                stir::fri::common::Proof<F, merkle_tree::MerkleTreeParams<F>>,
            ) = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                &mut &file_contents[..],
            )
            .unwrap();
            proofs.push((commitment, proof));
        }

        let fri_verifier_time = Instant::now();
        for (commitment, proof) in proofs {
            verifier.verify(&commitment, &proof);
        }
        let fri_verifier_time = fri_verifier_time.elapsed();
        let fri_verifier_hashes = HashCounter::get() / reps;
        println!("FRI verifier time: {:?}", fri_verifier_time);
        println!("FRI verifier hashes: {:?}", fri_verifier_hashes);
        (fri_verifier_time, fri_verifier_hashes)
    };

    let output = VerifierOutput {
        security_level,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        starting_rate,
        stir_folding_factor: args.stir_folding_factor,
        fri_folding_factor: args.fri_folding_factor,
        repetitions: reps,
        stir_verifier_time,
        fri_verifier_time,
        stir_verifier_hashes,
        fri_verifier_hashes,
    };

    let mut out_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("outputs/verifier_output.json")
        .unwrap();
    use std::io::Write;
    writeln!(out_file, "{}", serde_json::to_string(&output).unwrap()).unwrap();
}
