#!/bin/bash

cargo run --release --bin prover -- "$@"
cargo run --release --bin verifier -- "$@"
