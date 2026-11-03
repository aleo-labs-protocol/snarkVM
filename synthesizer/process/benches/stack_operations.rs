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

#[macro_use]
extern crate criterion;

use snarkvm_console::{
    network::MainnetV0,
    program::{Identifier, ProgramID},
    types::Field,
};
use snarkvm_synthesizer_process::{Process, Stack};
use snarkvm_synthesizer_program::{Program, StackTrait};

use criterion::{BatchSize, Criterion};
use rand::{RngExt as _, distr::Alphanumeric};
use snarkvm_circuit::prelude::bail;
use snarkvm_console::{network::Network, prelude::SizeInDataBits};
use snarkvm_utilities::TestRng;
use std::str::FromStr;

type CurrentNetwork = MainnetV0;

fn bench_stack_new(c: &mut Criterion) {
    // The depths to benchmark.
    const DEPTHS: [usize; 6] = [1, 2, 4, 8, 16, 31];

    // Initialize an RNG.
    let mut rng = TestRng::default();

    // Initialize a process.
    let mut process = Process::load().unwrap();

    // Benchmark the base case.
    c.bench_function("Depth 0 | Stack::new", |b| {
        b.iter_batched_ref(
            || {
                // Sample a random identifier.
                let identifier = sample_identifier_as_string::<CurrentNetwork>(&mut rng).unwrap();
                // Construct the program.
                Program::from_str(&format!("program {identifier}.aleo; function foo:")).unwrap()
            },
            |program| Stack::<CurrentNetwork>::new(&process, program),
            BatchSize::PerIteration,
        )
    });

    // Add the 0th program to the process.
    add_program_at_depth(&mut process, 0);

    // Track the depth.
    let mut depth = 1;

    for i in DEPTHS {
        // Add programs up to the current depth.
        while depth < i {
            // Add the program to the process.
            add_program_at_depth(&mut process, depth);
            // Increment the depth.
            depth += 1;
        }

        // Benchmark at each depth.
        c.bench_function(&format!("Depth {i} | Stack::new"), |b| {
            b.iter_batched_ref(
                || {
                    // Sample a random identifier.
                    let identifier = sample_identifier_as_string::<CurrentNetwork>(&mut rng).unwrap();
                    // Construct the program.
                    Program::from_str(&format!(
                        "program {identifier}.aleo; function foo: call test_{i}.aleo/foo;",
                        identifier = identifier,
                        i = i - 1
                    ))
                    .unwrap()
                },
                |program| Stack::<CurrentNetwork>::new(&process, program),
                BatchSize::PerIteration,
            )
        });
    }
}

fn bench_stack_get_minimum_number_of_calls(c: &mut Criterion) {
    // The depths to benchmark.
    const DEPTHS: [usize; 6] = [1, 2, 4, 8, 16, 30];

    // Initialize a process.
    let mut process = Process::load().unwrap();

    // Add the 0th program to the process.
    add_program_at_depth(&mut process, 0);

    // Benchmark the `get_minumum_number_of_calls` method for the base case.
    c.bench_function("Depth 0 | Stack::get_minimum_number_of_calls", |b| {
        b.iter(|| {
            // Get the `Stack` for the 0th program.
            let stack = process.get_stack(ProgramID::from_str("test_0.aleo").unwrap()).unwrap();
            // Benchmark the `get_minimum_number_of_calls` method.
            stack.get_minimum_number_of_calls(&Identifier::from_str("foo").unwrap())
        })
    });

    // Track the depth.
    let mut depth = 1;

    for i in DEPTHS {
        // Add programs up to the current depth.
        while depth <= i {
            // Add the program to the process.
            add_program_at_depth(&mut process, depth);
            // Increment the depth.
            depth += 1;
        }

        // Get the `Stack` for the current test program.
        let stack = process.get_stack(ProgramID::from_str(&format!("test_{i}.aleo")).unwrap()).unwrap();

        // Benchmark the `get_minimum_number_of_calls` method.
        c.bench_function(&format!("Depth {i} | Stack::get_minimum_number_of_calls"), |b| {
            b.iter(|| stack.get_minimum_number_of_calls(&Identifier::from_str("foo").unwrap()))
        });
    }
}

// Adds a program with a given call depth to the process.
fn add_program_at_depth(process: &mut Process<CurrentNetwork>, depth: usize) {
    // Construct the program.
    let program = if depth == 0 {
        Program::from_str(r"program test_0.aleo; function foo:").unwrap()
    } else {
        Program::from_str(&format!(
            "import test_{import}.aleo; program test_{current}.aleo; function foo: call test_{import}.aleo/foo;",
            import = depth - 1,
            current = depth
        ))
        .unwrap()
    };

    // Add the program to the process.
    process.lock().add_program(&program).unwrap();
}

// Samples a random identifier as a string.
fn sample_identifier_as_string<N: Network>(rng: &mut TestRng) -> snarkvm_console::prelude::Result<String> {
    // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
    let string = "a".to_string()
        + &rng
            .sample_iter(&Alphanumeric)
            .take(Field::<N>::size_in_data_bits() / (8 * 2))
            .map(char::from)
            .collect::<String>();
    // Ensure identifier fits within the data capacity of the base field.
    let max_bytes = Field::<N>::size_in_data_bits() / 8; // Note: This intentionally rounds down.
    match string.len() <= max_bytes {
        // Return the identifier.
        true => Ok(string.to_lowercase()),
        false => bail!("Identifier exceeds the maximum capacity allowed"),
    }
}

criterion_group! {
    name = stack_operations;
    config = Criterion::default().sample_size(10);
    targets = bench_stack_new, bench_stack_get_minimum_number_of_calls
}
criterion_main!(stack_operations);
