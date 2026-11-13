// Copyright (c) 2019-2025 Provable Inc.
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

use crate::sparse_kary_merkle_tree::BooleanHash;
use snarkvm_console_algorithms::{BHP, Keccak, Poseidon};
use snarkvm_console_types::prelude::*;

/// A trait for a Merkle path hash function.
pub trait PathHash: Clone + Send + Sync {
    type Hash: Copy + Clone + Debug + Default + PartialEq + Eq + FromBytes + ToBytes + Send + Sync;

    /// Returns the hash of the given child nodes.
    fn hash_children(&self, children: &[Self::Hash]) -> Result<Self::Hash>;

    /// Returns the empty hash.
    fn hash_empty<const ARITY: u8>(&self) -> Result<Self::Hash> {
        let children = vec![Self::Hash::default(); ARITY as usize];
        self.hash_children(&children)
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> PathHash for BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    type Hash = Field<E>;

    /// Returns the hash of the given child nodes.
    fn hash_children(&self, children: &[Self::Hash]) -> Result<Self::Hash> {
        let mut input = Vec::new();
        // Prepend the nodes with `false` & `true` bits.
        input.push(false);
        input.push(true);
        for child in children {
            child.write_bits_le(&mut input);
        }
        // Hash the input.
        Hash::hash(self, &input)
    }
}

impl<E: Environment, const RATE: usize> PathHash for Poseidon<E, RATE> {
    type Hash = Field<E>;

    /// Returns the hash of the given child nodes.
    fn hash_children(&self, children: &[Self::Hash]) -> Result<Self::Hash> {
        let mut input = Vec::with_capacity(1 + children.len());
        // Prepend the nodes with a `1field` byte.
        input.push(Self::Hash::one());
        for child in children {
            input.push(*child);
        }
        // Hash the input.
        Hash::hash(self, &input)
    }
}

impl<const TYPE: u8, const VARIANT: usize> PathHash for Keccak<TYPE, VARIANT> {
    type Hash = BooleanHash<VARIANT>;

    /// Returns the hash of the given child nodes.
    fn hash_children(&self, children: &[Self::Hash]) -> Result<Self::Hash> {
        let mut input = Vec::new();
        // Prepend the nodes with `false` & `true` bits.
        input.push(false);
        input.push(true);
        for child in children {
            input.extend_from_slice(child.as_slice());
        }
        // Hash the input.
        let output = Hash::hash(self, &input)?;
        // Read the first VARIANT bits.
        let mut result = BooleanHash::new();
        result.0.copy_from_slice(&output[..VARIANT]);
        Ok(result)
    }
}
