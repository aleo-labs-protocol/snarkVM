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

mod bytes;
mod serialize;
mod string;
mod to_bits;

use snarkvm_console_network::prelude::*;
use snarkvm_console_types::Field;

/// The Merkle leaf for a function or transition in the transaction.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct TransactionLeaf<N: Network> {
    /// The variant of the Merkle leaf.
    variant: u8,
    /// The index of the Merkle leaf.
    index: u16,
    /// The ID.
    id: Field<N>,
}

impl<N: Network> TransactionLeaf<N> {
    /// Initializes a new instance of `TransactionLeaf`.
    pub const fn new_deployment(index: u16, id: Field<N>) -> Self {
        Self { variant: 0, index, id }
    }

    /// Initializes a new instance of `TransactionLeaf`.
    pub const fn new_execution(index: u16, id: Field<N>) -> Self {
        Self { variant: 1, index, id }
    }

    /// Initializes a new instance of `TransactionLeaf`.
    pub const fn new_fee(index: u16, id: Field<N>) -> Self {
        Self { variant: 1, index, id }
    }

    /// Initializes a new instance of `TransactionLeaf`.
    pub const fn from(variant: u8, index: u16, id: Field<N>) -> Self {
        Self { variant, index, id }
    }

    /// Returns the variant of the Merkle leaf.
    pub const fn variant(&self) -> u8 {
        self.variant
    }

    /// Returns the index of the Merkle leaf.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Returns the ID in the Merkle leaf.
    pub const fn id(&self) -> Field<N> {
        self.id
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    pub(super) fn sample_leaf(rng: &mut TestRng) -> TransactionLeaf<CurrentNetwork> {
        // Construct a new leaf.
        TransactionLeaf::from(rng.random(), rng.random(), Uniform::rand(rng))
    }
}
