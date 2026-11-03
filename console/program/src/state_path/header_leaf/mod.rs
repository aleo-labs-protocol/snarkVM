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

/// The Merkle leaf for the block header.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct HeaderLeaf<N: Network> {
    /// The index of the Merkle leaf.
    index: u8,
    /// The ID.
    id: Field<N>,
}

impl<N: Network> HeaderLeaf<N> {
    /// Initializes a new instance of `HeaderLeaf`.
    pub const fn new(index: u8, id: Field<N>) -> Self {
        Self { index, id }
    }

    /// Returns the index of the Merkle leaf.
    pub const fn index(&self) -> u8 {
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

    pub(super) fn sample_leaf(rng: &mut TestRng) -> HeaderLeaf<CurrentNetwork> {
        // Construct a new leaf.
        HeaderLeaf::new(rng.random(), Uniform::rand(rng))
    }
}
