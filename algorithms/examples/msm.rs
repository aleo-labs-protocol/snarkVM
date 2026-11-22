// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use snarkvm_algorithms::msm::*;
use snarkvm_curves::{
    bls12_377::{Fr, G1Projective},
    traits::ProjectiveCurve,
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{
    cfg_into_iter,
    rand::{TestRng, Uniform},
};

use anyhow::Result;
use rayon::prelude::*;

const DEFAULT_POWER_OF_TWO: usize = 20;

/// Run the following command to perform the MSM(s).
/// `cargo run --release --example msm [variant] [power of 2] [number of MSM
/// iterations]`
pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Invalid number of arguments. Given: {} - Required: 3", args.len() - 1);
        return Ok(());
    }

    // Parse the power of two to sample.
    let power_of_two = match args[2].as_str().parse::<usize>() {
        Ok(power_of_two) => power_of_two,
        Err(_) => {
            eprintln!("Failed to parse the power of 2, using the default: 1 << {DEFAULT_POWER_OF_TWO}");
            DEFAULT_POWER_OF_TWO
        }
    };

    println!("\nSampling 1 << {power_of_two} pairs for the vMSM...");

    // Sample the bases and scalars.
    let samples = 1 << power_of_two;

    let scalars = cfg_into_iter!(0..samples)
        .step_by(1 << 16)
        .flat_map(|_| {
            let rng = &mut TestRng::fixed(123456789);
            (0..(1 << 16)).map(|_| Fr::rand(rng).to_bigint()).collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    println!("Sampled 1 << {power_of_two} scalars.");

    let bases = G1Projective::batch_normalization_into_affine(
        cfg_into_iter!(0..samples)
            .step_by(1 << 16)
            .flat_map(|_| {
                let rng = &mut TestRng::fixed(123456789);
                (0..(1 << 16)).map(|_| G1Projective::rand(rng)).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );

    println!("Sampled 1 << {power_of_two} bases.");

    // Parse the number of MSM iterations.
    let num_iterations = match args[3].as_str().parse::<usize>() {
        Ok(num_iterations) => num_iterations,
        Err(_) => {
            eprintln!("\nFailed to parse the number of iterations, using the default: 1");
            1
        }
    };

    println!("\nPerforming the vMSM...");

    for i in 0..num_iterations {
        let timer = std::time::Instant::now();

        // Parse the variant.
        match args[1].as_str() {
            "batched" => batched::msm(bases.as_slice(), scalars.as_slice()),
            "standard" => standard::msm(bases.as_slice(), scalars.as_slice()),
            _ => panic!("Invalid variant: use 'batched' or 'standard'"),
        };

        println!("{i} - Performed the vMSM in {} milliseconds.", timer.elapsed().as_millis());
    }

    Ok(())
}
