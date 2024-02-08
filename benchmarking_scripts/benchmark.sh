#!/bin/bash

# Redirect to a file
exec >> "benchmark.log"
exec 2>&1

#degrees="18 20"
degrees="18 20 22 24 26 28 30"
rates="1 2 3 4"

for rate in $rates
do
    for degree in $degrees
    do
        echo ****************************************************
        echo "Degree: $degree, Rate: $rate"
        cargo run --release --bin prover -- -d $degree -r $rate --reps 1000
        cargo run --release --bin verifier -- -d $degree -r $rate --reps 1000
        rm -r artifacts
        echo ****************************************************
    done
done

