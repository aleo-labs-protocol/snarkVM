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

use snarkvm_console_algorithms::{BHP, Keccak, Poseidon};
use snarkvm_console_types::prelude::*;

use crate::kary_merkle_tree::BooleanHash;
use rayon::prelude::*;

/// A trait for a Merkle leaf hash function.
pub trait LeafHash: Clone + Send + Sync {
    type Hash: Copy + Clone + Debug + Default + PartialEq + Eq + FromBytes + ToBytes + Send + Sync;
    type Leaf: Clone + Send + Sync;

    /// Returns the hash of the given leaf node.
    fn hash_leaf(&self, leaf: &Self::Leaf) -> Result<Self::Hash>;

    /// Returns the hash for each leaf node.
    fn hash_leaves(&self, leaves: &[Self::Leaf]) -> Result<Vec<Self::Hash>> {
        match leaves.len() {
            0 => Ok(vec![]),
            1..=100 => leaves.iter().map(|leaf| self.hash_leaf(leaf)).collect(),
            _ => cfg_iter!(leaves).map(|leaf| self.hash_leaf(leaf)).collect(),
        }
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> LeafHash for BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    type Hash = Field<E>;
    type Leaf = Vec<bool>;

    /// Returns the hash of the given leaf node.
    fn hash_leaf(&self, leaf: &Self::Leaf) -> Result<Self::Hash> {
        let mut input = Vec::with_capacity(1 + leaf.len());
        // Prepend the leaf with a `false` bit.
        input.push(false);
        input.extend(leaf);
        // Hash the input.
        Hash::hash(self, &input)
    }
}

impl<E: Environment, const RATE: usize> LeafHash for Poseidon<E, RATE> {
    type Hash = Field<E>;
    type Leaf = Vec<Self::Hash>;

    /// Returns the hash of the given leaf node.
    fn hash_leaf(&self, leaf: &Self::Leaf) -> Result<Self::Hash> {
        let mut input = Vec::with_capacity(1 + leaf.len());
        // Prepend the leaf with a `0field` element.
        input.push(Self::Hash::zero());
        input.extend(leaf);
        // Hash the input.
        Hash::hash(self, &input)
    }
}

impl<const TYPE: u8, const VARIANT: usize> LeafHash for Keccak<TYPE, VARIANT> {
    type Hash = BooleanHash<VARIANT>;
    type Leaf = Vec<bool>;

    /// Returns the hash of the given leaf node.
    fn hash_leaf(&self, leaf: &Self::Leaf) -> Result<Self::Hash> {
        let mut input = Vec::with_capacity(1 + leaf.len());
        // Prepend the leaf with a `false` bit.
        input.push(false);
        input.extend(leaf);
        // Hash the input.
        let output = Hash::hash(self, &input)?;
        // Read the first VARIANT bits.
        let mut result = BooleanHash::new();
        result.0.copy_from_slice(&output[..VARIANT]);
        Ok(result)
    }
}
