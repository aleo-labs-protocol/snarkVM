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

pub mod hasher;
use hasher::BHPHasher;

mod commit;
mod commit_uncompressed;
mod hash;
mod hash_uncompressed;

use snarkvm_console_types::prelude::*;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

const BHP_CHUNK_SIZE: usize = 3;

/// BHP256 is a collision-resistant hash function that processes 256-bit chunks.
pub type BHP256<E> = BHP<E, 3, 57>; // Supports inputs up to 261 bits (1 u8 + 1 Fq).
/// BHP512 is a collision-resistant hash function that processes inputs in 512-bit chunks.
pub type BHP512<E> = BHP<E, 6, 43>; // Supports inputs up to 522 bits (2 u8 + 2 Fq).
/// BHP768 is a collision-resistant hash function that processes inputs in 768-bit chunks.
pub type BHP768<E> = BHP<E, 15, 23>; // Supports inputs up to 783 bits (3 u8 + 3 Fq).
/// BHP1024 is a collision-resistant hash function that processes inputs in 1024-bit chunks.
pub type BHP1024<E> = BHP<E, 8, 54>; // Supports inputs up to 1044 bits (4 u8 + 4 Fq).

/// BHP is a collision-resistant hash function that takes a variable-length input.
/// The BHP hash function does *not* behave like a random oracle, see Poseidon for one.
///
/// ## Design
/// The BHP hash function splits the given input into blocks, and processes them iteratively.
///
/// The first iteration is initialized as follows:
/// ```text
/// DIGEST_0 = BHP([ 0...0 || DOMAIN || LENGTH(INPUT) || INPUT[0..BLOCK_SIZE] ]);
/// ```
/// Each subsequent iteration is initialized as follows:
/// ```text
/// DIGEST_N+1 = BHP([ DIGEST_N[0..DATA_BITS] || INPUT[(N+1)*BLOCK_SIZE..(N+2)*BLOCK_SIZE] ]);
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "E: Serialize + DeserializeOwned")]
pub struct BHP<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> {
    /// The domain separator for the BHP hash function.
    domain: Vec<bool>,
    /// The internal BHP hasher used to process one iteration.
    hasher: BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE>,
    /// The Merkle empty hash of this instance, once something has asked for it.
    ///
    /// Not serialized, so a deserialized hasher recomputes it from its own domain and bases.
    #[serde(skip)]
    empty_hash: OnceLock<Field<E>>,
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> PartialEq for BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// Ignores the cached empty hash, which is derived from the domain and bases.
    fn eq(&self, other: &Self) -> bool {
        // Destructured so that a new field must be considered here.
        let Self { domain, hasher, empty_hash: _ } = self;
        *domain == other.domain && *hasher == other.hasher
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// Initializes a new instance of BHP with the given domain.
    pub fn setup(domain: &str) -> Result<Self> {
        // Ensure the given domain is within the allowed size in bits.
        let num_bits = domain.len().saturating_mul(8);
        let max_bits = Field::<E>::size_in_data_bits() - 64; // 64 bits encode the length.
        ensure!(num_bits <= max_bits, "Domain cannot exceed {max_bits} bits, found {num_bits} bits");

        // Initialize the BHP hasher.
        let hasher = BHPHasher::<E, NUM_WINDOWS, WINDOW_SIZE>::setup(domain)?;

        // Convert the domain into a boolean vector.
        let mut domain = domain.as_bytes().to_bits_le();
        // Pad the domain with zeros up to the maximum size in bits.
        domain.resize(max_bits, false);
        // Reverse the domain so that it is: [ 0...0 || DOMAIN ].
        // (For advanced users): This optimizes the initial costs during hashing.
        domain.reverse();

        Ok(Self { domain, hasher, empty_hash: OnceLock::new() })
    }

    /// Returns the domain separator for the BHP hash function.
    pub fn domain(&self) -> &[bool] {
        &self.domain
    }

    /// Returns the Merkle empty hash of this instance, computing it on first use.
    ///
    /// This is `PathHash::hash_children(0, 0)` from `snarkvm-console-collections`, and
    /// `test_cached_empty_hash_matches_the_computed_one` checks that the two agree. The
    /// hash depends on the domain and bases, so it is cached per instance, not per type.
    pub fn merkle_empty_hash(&self) -> Result<Field<E>> {
        if let Some(empty_hash) = self.empty_hash.get() {
            return Ok(*empty_hash);
        }
        let mut input = Vec::with_capacity(1 + Field::<E>::size_in_bits() * 2);
        // Prepend the nodes with a `true` bit.
        input.push(true);
        Field::<E>::zero().write_bits_le(&mut input);
        Field::<E>::zero().write_bits_le(&mut input);
        let empty_hash = Hash::hash(self, &input)?;
        Ok(*self.empty_hash.get_or_init(|| empty_hash))
    }

    /// Returns the bases.
    pub fn bases(&self) -> &Arc<Vec<Vec<Group<E>>>> {
        self.hasher.bases()
    }

    /// Returns the random base window.
    pub fn random_base(&self) -> &Arc<Vec<Group<E>>> {
        self.hasher.random_base()
    }

    /// Returns the number of windows.
    pub fn num_windows(&self) -> u8 {
        NUM_WINDOWS
    }

    /// Returns the window size.
    pub fn window_size(&self) -> u8 {
        WINDOW_SIZE
    }
}
