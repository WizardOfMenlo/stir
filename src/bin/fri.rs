use std::time::Instant;

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
    ldt::{LowDegreeTest, Prover, Verifier},
    parameters::{Parameters, SoundnessType},
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

    #[arg(short = 'k', long, default_value = "8")]
    folding_factor: usize,
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
    let folding_factor = args.folding_factor;
    let soundness_type = SoundnessType::Conjecture;
    let reps = args.verifier_repetitions;

    let mut rng = ark_std::test_rng();
    let poly = DensePolynomial::<F>::rand(starting_degree - 1, &mut rng);

    let (leaf_hash_params, two_to_one_params) =
        merkle_tree::default_config::<F>(&mut rng, folding_factor);
    let fiat_shamir_config: Blake3Config = fs::blake3::default_fs_config();

    println!("=========================================");
    println!("FRI");
    let params: Parameters<F, merkle_tree::MerkleTreeParams<F>, Sponge> = Parameters {
        security_level,
        protocol_security_level,
        starting_degree,
        stopping_degree,
        folding_factor,
        starting_rate,
        soundness_type,

        leaf_hash_params,
        two_to_one_params,
        fiat_shamir_config,
        _field: Default::default(),
    };

    Fri::display(params.clone());

    let fri_prover_time = Instant::now();
    let (prover, verifier) = Fri::instantiate(params);
    let (commitment, witness) = prover.commit(poly);

    let proof = prover.prove(witness);
    dbg!(fri_prover_time.elapsed());
    dbg!(proof.serialized_size(ark_serialize::Compress::Yes));
    let prover_hashes = HashCounter::get();
    dbg!(prover_hashes);
    HashCounter::reset();

    let fri_verifier_time = Instant::now();
    for _ in 0..reps {
        let res = verifier.verify(&commitment, &proof);
        assert!(res);
    }
    dbg!(fri_verifier_time.elapsed());
    let verifier_hashes = HashCounter::get() / reps;
    dbg!(verifier_hashes);
    HashCounter::reset();
}
