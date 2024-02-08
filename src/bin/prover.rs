use std::{
    fs::OpenOptions,
    time::{Duration, Instant},
};

use serde::Serialize;

use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;

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
    ldt::{LowDegreeTest, Prover},
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
struct ProverOutput {
    security_level: usize,
    protocol_security_level: usize,
    starting_degree: usize,
    stopping_degree: usize,
    starting_rate: usize,
    repetitions: usize,
    stir_folding_factor: usize,
    fri_folding_factor: usize,
    stir_prover_time: Duration,
    stir_prover_hashes: usize,
    fri_prover_time: Duration,
    fri_prover_hashes: usize,
    stir_argument_size: usize,
    fri_argument_size: usize,
}

fn main() {
    type F = fields::Field192;
    use merkle_tree::sha3 as merkle_tree;
    let soundness_type = SoundnessType::Conjecture;

    let args = Args::parse();

    let security_level = args.security_level;
    let protocol_security_level = args.protocol_security_level;
    let starting_degree = 1 << args.initial_degree;
    let stopping_degree = 1 << args.final_degree;
    let starting_rate = args.rate;
    let reps = args.verifier_repetitions;

    let mut rng = ark_std::test_rng();
    let poly = DensePolynomial::<F>::rand(starting_degree - 1, &mut rng);

    let fiat_shamir_config: Blake3Config = fs::blake3::default_fs_config();

    std::fs::create_dir_all("artifacts").unwrap();
    std::fs::create_dir_all("outputs").unwrap();

    // STIR
    let (stir_prover_time, stir_prover_hashes, stir_argument_size) = {
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

        let stir_prover_time = Instant::now();
        let (prover, _) = Stir::instantiate(params);
        let (commitment, witness) = prover.commit(poly.clone());

        let proof = prover.prove(witness);
        let stir_prover_time = stir_prover_time.elapsed();
        let stir_prover_hashes = HashCounter::get();
        HashCounter::reset();
        dbg!(stir_prover_time);
        dbg!(stir_prover_hashes);

        let mut serialized_bytes = vec![];
        (commitment, proof)
            .serialize_compressed(&mut serialized_bytes)
            .unwrap();

        let stir_argument_size = serialized_bytes.len();

        for i in 0..reps {
            std::fs::write(
                format!("artifacts/stir_proof{}", i),
                serialized_bytes.clone(),
            )
            .unwrap();
        }

        (
            stir_prover_time,
            stir_prover_hashes,
            stir_argument_size,
        )
    };

    //FRI
    let (fri_prover_time, fri_prover_hashes, fri_argument_size) = {
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

        let fri_prover_time = Instant::now();
        let (prover, _) = Fri::instantiate(params);
        let (commitment, witness) = prover.commit(poly);

        let proof = prover.prove(witness);
        let fri_prover_time = fri_prover_time.elapsed();
        let fri_prover_hashes = HashCounter::get();
        HashCounter::reset();
        dbg!(fri_prover_time);
        dbg!(fri_prover_hashes);

        let mut serialized_bytes = vec![];
        (commitment, proof)
            .serialize_compressed(&mut serialized_bytes)
            .unwrap();

        let fri_argument_size = serialized_bytes.len();

        for i in 0..reps {
            std::fs::write(
                format!("artifacts/fri_proof{}", i),
                serialized_bytes.clone(),
            )
            .unwrap();
        }
        (fri_prover_time, fri_prover_hashes, fri_argument_size)
    };

    let output = ProverOutput {
        security_level,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        starting_rate,
        repetitions: reps,
        stir_folding_factor: args.stir_folding_factor,
        fri_folding_factor: args.fri_folding_factor,
        stir_prover_time,
        fri_prover_time,
        stir_prover_hashes,
        fri_prover_hashes,
        stir_argument_size,
        fri_argument_size,
    };

    let mut out_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("outputs/prover_output.json")
        .unwrap();
    use std::io::Write;
    writeln!(out_file, "{}", serde_json::to_string(&output).unwrap()).unwrap();
}
