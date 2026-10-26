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

mod utilities;

use snarkvm_console::{
    account::PrivateKey,
    network::prelude::*,
    program::{Identifier, Literal, ProgramID, Value},
    types::Boolean,
};
use snarkvm_synthesizer_process::Process;
use utilities::*;

use rayon::prelude::*;
use std::panic::AssertUnwindSafe;

#[test]
fn test_process_execute() {
    // Load the tests.
    let tests = load_tests::<_, ProgramTest>("./tests/process/execute", "./expectations/process/execute");

    // Run each test and compare it against its corresponding expectation.
    tests.par_iter().for_each(|test| {
        // Initialize a process.
        let process = Process::<CurrentNetwork>::load().unwrap();
        // Run the test.
        let output = run_test(&process, test);
        // Check against the expected output.
        let res = test.check(&output);
        if let Err(err) = &res {
            println!("Error running test {:?}: {}", test.path(), err);
        }
        res.unwrap();
        // Save the output when valid.
        test.save(&output).unwrap();
    });
}

// A helper function to run the test and extract the outputs as YAML, to be compared against the expectation.
fn run_test(process: &Process<CurrentNetwork>, test: &ProgramTest) -> serde_yaml::Mapping {
    // Initialize the output.
    let mut output = serde_yaml::Mapping::new();
    output.insert(
        serde_yaml::Value::String("errors".to_string()),
        serde_yaml::Value::Sequence(serde_yaml::Sequence::new()),
    );

    // Add the programs into the process.
    for program in test.programs() {
        if let Err(err) = process.lock().add_program(program) {
            output
                .get_mut(serde_yaml::Value::String("errors".to_string()))
                .unwrap()
                .as_sequence_mut()
                .unwrap()
                .push(serde_yaml::Value::String(err.to_string()));
            output.insert(
                serde_yaml::Value::String("outputs".to_string()),
                serde_yaml::Value::Sequence(serde_yaml::Sequence::new()),
            );
            return output;
        }
    }

    // Initialize the RNG.
    let rng = &mut match test.randomness() {
        None => TestRng::default(),
        Some(randomness) => TestRng::fixed(randomness),
    };

    output.insert(
        serde_yaml::Value::String("outputs".to_string()),
        serde_yaml::Value::Sequence(
            test.cases()
                .iter()
                .map(|value| {
                    // Extract the function name, inputs, and optional private key.
                    let value = value.as_mapping().expect("expected mapping for test case");
                    let program_id = ProgramID::<CurrentNetwork>::from_str(
                        value
                            .get("program")
                            .expect("expected program name for test case")
                            .as_str()
                            .expect("expected string for program name"),
                    )
                    .expect("unable to parse program name");
                    let function_name = Identifier::<CurrentNetwork>::from_str(
                        value
                            .get("function")
                            .expect("expected function name for test case")
                            .as_str()
                            .expect("expected string for function name"),
                    )
                    .expect("unable to parse function name");
                    let inputs = value
                        .get("inputs")
                        .expect("expected inputs for test case")
                        .as_sequence()
                        .expect("expected sequence for inputs")
                        .iter()
                        .map(|input| match &input {
                            serde_yaml::Value::Bool(bool) => {
                                Value::<CurrentNetwork>::from(Literal::Boolean(Boolean::new(*bool)))
                            }
                            _ => Value::<CurrentNetwork>::from_str(input.as_str().expect("expected string for input"))
                                .expect("unable to parse input"),
                        })
                        .collect_vec();
                    let private_key = match value.get("private_key") {
                        Some(private_key) => PrivateKey::<CurrentNetwork>::from_str(
                            private_key.as_str().expect("expected string for private key"),
                        )
                        .expect("unable to parse private key"),
                        None => PrivateKey::new(rng).unwrap(),
                    };

                    let mut run_test = || -> serde_yaml::Value {
                        // Authorize the execution.
                        let authorization = match process.authorize::<CurrentAleo, _>(
                            &private_key,
                            program_id,
                            function_name,
                            inputs.iter(),
                            rng,
                        ) {
                            Ok(authorization) => authorization,
                            Err(err) => return serde_yaml::Value::String(err.to_string()),
                        };
                        // Execute the authorization and extract the output as YAML.
                        std::panic::catch_unwind(AssertUnwindSafe(|| {
                            match process.execute::<CurrentAleo, _>(authorization, rng) {
                                Ok((response, _)) => serde_yaml::Value::Sequence(
                                    response
                                        .outputs()
                                        .iter()
                                        .map(|output| serde_yaml::Value::String(output.to_string()))
                                        .collect_vec(),
                                ),
                                Err(err) => serde_yaml::Value::String(err.to_string()),
                            }
                        }))
                        .unwrap_or(serde_yaml::Value::String(
                            "Compiler panicked when calling `Process::execute`".to_string(),
                        ))
                    };
                    run_test()
                })
                .collect::<serde_yaml::Sequence>(),
        ),
    );

    output
}
