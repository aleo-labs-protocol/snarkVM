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

#![allow(non_snake_case)]

mod circuit;
pub(crate) use circuit::*;

mod circuit_info;
pub(crate) use circuit_info::*;

mod constraint_system;
#[cfg(feature = "test")]
pub use constraint_system::*;
#[cfg(not(feature = "test"))]
pub(crate) use constraint_system::*;

mod indexer;

/// Represents a matrix.
pub(crate) type Matrix<F> = Vec<Vec<(F, usize)>>;

pub(crate) fn num_non_zero<F>(joint_matrix: &Matrix<F>) -> usize {
    joint_matrix.iter().map(|row| row.len()).sum()
}
