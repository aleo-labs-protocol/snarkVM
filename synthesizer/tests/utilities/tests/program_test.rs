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

use crate::{CurrentNetwork, ExpectedTest, get_expectation_path, print_difference};

use snarkvm_console::{account::PrivateKey, program::Identifier};
use snarkvm_synthesizer::program::Program;

use anyhow::{Result, bail};
use itertools::Itertools;
use serde_yaml::{Mapping, Sequence, Value};
use snarkvm_console::{network::ConsensusVersion, prelude::Network};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
// TODO: Handle tests where the execution panics or fails.
//  One approach is to create an enum `ExpectedOutput` which can be `Ok(Vec<Value>)` or `Err(String)`.

/// A test for a program, containing the program definition, an optional seed for the RNG, and a set of test cases.
// Note: We use YAML for `cases` and `expected` to allow for flexible definitions across various types of tests.
pub struct ProgramTest {
    /// The program.
    programs: Vec<Program<CurrentNetwork>>,
    /// The set of test cases.
    cases: Vec<Value>,
    /// The expected output of the test.
    expected: serde_yaml::Mapping,
    /// The path to the expectation file.
    path: PathBuf,
    /// Whether the expectation file should be rewritten.
    rewrite: bool,
    /// The seed for the RNG.
    randomness: Option<u64>,
    /// Additional keys for the test.
    keys: Vec<PrivateKey<CurrentNetwork>>,
    /// The start height for the test.
    start_height: u32,
}

impl ProgramTest {
    /// Returns the program.
    pub fn programs(&self) -> &[Program<CurrentNetwork>] {
        &self.programs
    }

    /// Returns the test cases.
    pub fn cases(&self) -> &[Value] {
        &self.cases
    }

    /// Returns the optional seed for the RNG.
    pub fn randomness(&self) -> Option<u64> {
        self.randomness
    }

    /// Returns the additional keys for the test.
    pub fn keys(&self) -> &[PrivateKey<CurrentNetwork>] {
        &self.keys
    }

    /// Returns the start height for the test.
    pub fn start_height(&self) -> u32 {
        self.start_height
    }

    /// Returns the path to the expectation file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl ExpectedTest for ProgramTest {
    type Output = serde_yaml::Mapping;

    /// Loads the test from a given path.
    fn load<P: AsRef<Path>>(test_path: P, expectation_dir: P) -> Self {
        // Check if the expectation file should be rewritten.
        let rewrite = std::env::var("REWRITE_EXPECTATIONS").is_ok();

        // Read the contents of the test file.
        let source = std::fs::read_to_string(&test_path).expect("Failed to read test file.");

        // Parse out the first comment, denoted by `/* ... */`.
        let first_comment_start =
            source.find("/*").unwrap_or_else(|| panic!("Test file '{:?}' must contain a comment", test_path.as_ref()));
        let end_first_comment = source[first_comment_start + 2..]
            .find("*/")
            .unwrap_or_else(|| panic!("Test file '{:?}' must contain a comment", test_path.as_ref()));

        let comment = &source[first_comment_start + 2..first_comment_start + 2 + end_first_comment];

        // Parse the comment into the test configuration.
        let test_config = serde_yaml::from_str::<Mapping>(comment).expect("invalid test configuration");

        // If the `randomness` field is present in the config, parse it as a `u64`.
        let randomness = test_config.get("randomness").map(|value| value.as_u64().expect("`randomness` must be a u64"));

        // If the `start_height` field is present in the config, parse it as a `u32`.
        // Otherwise use the latest consensus height as the default.
        let start_height = test_config
            .get("start_height")
            .map(|value| value.as_u64().expect("`start_height` must be a u32"))
            .unwrap_or(
                CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::latest()).expect("Expected consensus height") as u64
            ) as u32;

        // If the `keys` field is present in the config, parse it as a sequence of `PrivateKey`s.
        let keys = match test_config.get("keys") {
            None => Vec::new(),
            Some(value) => value
                .as_sequence()
                .expect("`keys` must be a sequence")
                .iter()
                .map(|value| {
                    PrivateKey::<CurrentNetwork>::from_str(value.as_str().expect("private key must be a string"))
                        .expect("invalid private key")
                })
                .collect::<Vec<_>>(),
        };

        // Extract the test cases from the config.
        let cases = test_config
            .get("cases")
            .expect("configuration must contain `cases`")
            .as_sequence()
            .expect("cases must be a sequence")
            .clone();

        // Parse the remainder of the test file into a program.
        let programs = source[first_comment_start + 2 + end_first_comment + 2..]
            .split("/////////////////////////////////////////////////")
            .map(|string| Program::<CurrentNetwork>::from_str(string).expect("Failed to parse program."))
            .collect::<Vec<_>>();

        // Construct the path to the expectation file.
        let path = get_expectation_path(&test_path, &expectation_dir);
        // If the expectation file should be rewritten, then there is no need to read the expectation file.
        let expected = match rewrite {
            true => serde_yaml::Mapping::default(),
            false => {
                let source = std::fs::read_to_string(&path).expect("Failed to read expectation file.");
                serde_yaml::from_str::<Mapping>(&source).expect("invalid expectation")
            }
        };

        Self { programs, cases, expected, path, rewrite, randomness, keys, start_height }
    }

    fn check(&self, output: &Self::Output) -> Result<()> {
        // Initialize space to accumulate failed tests.
        let mut failed = Vec::new();
        // If the expectation file should be rewritten, then there is no need to check the output.
        if !self.rewrite {
            // Check that the errors match.
            let expected_errors =
                self.expected.get(Value::String("errors".to_string())).unwrap().as_sequence().unwrap();
            let actual_errors = output.get(Value::String("errors".to_string())).unwrap().as_sequence().unwrap();
            expected_errors.iter().zip_eq(actual_errors.iter()).for_each(|(expected, actual)| {
                if expected != actual {
                    let expected =
                        serde_yaml::to_string(expected).expect("failed to serialize expected error to string");
                    let actual = serde_yaml::to_string(actual).expect("failed to serialize actual error to string");
                    failed.push(print_difference("errors", expected, actual));
                }
            });
            // Check that the outputs match.
            let expected_outputs =
                self.expected.get(Value::String("outputs".to_string())).unwrap().as_sequence().unwrap();
            let actual_outputs = output.get(Value::String("outputs".to_string())).unwrap().as_sequence().unwrap();
            self.cases.iter().zip_eq(expected_outputs.iter().zip_eq(actual_outputs.iter())).for_each(
                |(test, (expected, actual))| {
                    if expected != actual {
                        let test = serde_yaml::to_string(test).expect("failed to serialize test to string");
                        let expected =
                            serde_yaml::to_string(expected).expect("failed to serialize expected output to string");
                        let actual =
                            serde_yaml::to_string(actual).expect("failed to serialize actual output to string");
                        failed.push(print_difference(test, expected, actual));
                    }
                },
            );
        };
        // Write the errors, if any.
        match failed.is_empty() {
            true => Ok(()),
            false => bail!("{}", failed.iter().join("\n\n")),
        }
    }

    fn save(&self, output: &Self::Output) -> Result<()> {
        if self.rewrite {
            // Strip the `additional` field before writing. It holds concrete output values (record
            // ciphertexts, nonces, transition IDs) that `check` never compares and that change on every
            // run due to randomness and block height. Persisting them would bloat the expectation files
            // and produce spurious diffs on every regeneration.
            let mut output = output.clone();
            output.remove(Value::String("additional".to_string()));
            std::fs::write(&self.path, serde_yaml::to_string(&output).expect("failed to serialize output to string"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::{Mapping, Value};
    use std::path::PathBuf;

    // Constructs a minimal `ProgramTest` for exercising `save`; only `path` and `rewrite` are used.
    fn program_test_for_save(path: PathBuf, rewrite: bool) -> ProgramTest {
        ProgramTest {
            programs: Vec::new(),
            cases: Vec::new(),
            expected: Mapping::new(),
            path,
            rewrite,
            randomness: None,
            keys: Vec::new(),
            start_height: 0,
        }
    }

    // Constructs a sample output with the checked `errors` and `outputs` fields, along with the
    // unchecked `additional` field that holds concrete, fragile output values.
    fn sample_output() -> Mapping {
        let mut output = Mapping::new();
        output.insert(Value::String("errors".to_string()), Value::Sequence(Vec::new()));
        output
            .insert(Value::String("outputs".to_string()), Value::Sequence(vec![Value::String("verified".to_string())]));
        output.insert(
            Value::String("additional".to_string()),
            Value::Sequence(vec![Value::String("record1qvqs...".to_string())]),
        );
        output
    }

    #[test]
    fn test_save_strips_concrete_output_values() {
        let dir = tempfile::tempdir().expect("failed to create temporary directory");
        let path = dir.path().join("expectation.out");
        let test = program_test_for_save(path.clone(), true);

        test.save(&sample_output()).expect("failed to save expectation");

        let written = std::fs::read_to_string(&path).expect("failed to read expectation");
        let parsed = serde_yaml::from_str::<Mapping>(&written).expect("failed to parse expectation");
        // The unchecked `additional` field (concrete, fragile output values) must not be persisted.
        assert!(!parsed.contains_key(Value::String("additional".to_string())));
        // The checked fields must be persisted.
        assert!(parsed.contains_key(Value::String("errors".to_string())));
        assert!(parsed.contains_key(Value::String("outputs".to_string())));
    }

    #[test]
    fn test_save_does_nothing_without_rewrite() {
        let dir = tempfile::tempdir().expect("failed to create temporary directory");
        let path = dir.path().join("expectation.out");
        let test = program_test_for_save(path.clone(), false);

        test.save(&sample_output()).expect("failed to save expectation");

        // No file should be written when the rewrite flag is disabled.
        assert!(!path.exists());
    }
}
