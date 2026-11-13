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

//! This module defines a set of utilities for testing Aleo programs.
//!
//! Users define tests in the `tests/tests` directory, and the expected output in the `tests/expectations` directory.
//! Users should separate their tests into different files, and name the expectation files with the same name as the test files.
//! Tests should also be separated into different directories depending on the type of test.
//!
//! When the `TEST_FILTER` environment variable is set, then only the tests whose filenames match the filter are run.
//! When the `TEST_WORKERS` environment variable is set, then `test_vm_execute_and_finalize` runs that many test files at once.
//! When the `REWRITE_EXPECTATIONS` environment variable is set, then the expectation files are rewritten.
//! Otherwise, the output is compared against the expectation files.

#![allow(unused)]

pub type CurrentAleo = snarkvm_circuit::network::AleoV0;
pub type CurrentNetwork = snarkvm_console::network::MainnetV0;

pub mod expectation;
pub use expectation::*;

pub mod tests;
pub use tests::*;
