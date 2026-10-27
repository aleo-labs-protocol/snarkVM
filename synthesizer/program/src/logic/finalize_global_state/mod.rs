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

use console::network::prelude::*;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FinalizeGlobalState {
    /// The block round.
    block_round: u64,
    /// The block height.
    block_height: u32,
    /// The block timestamp.
    block_timestamp: Option<i64>, // TODO (raychu86): Consider adding the entire Metadata here instead.
    /// The block-specific random seed.
    random_seed: [u8; 32],
    /// The block spend limit.
    block_spend_limit: Option<u64>,
    /// The block synthesis limit.
    block_synthesis_limit: Option<u64>,
}

impl FinalizeGlobalState {
    /// Initializes a new genesis global state.
    #[inline]
    pub fn new_genesis<N: Network>() -> Result<Self> {
        // Initialize the parameters.
        let block_round = 0;
        let block_height = 0;
        let block_cumulative_weight = 0;
        let block_cumulative_proof_target = 0;
        let previous_block_hash = N::BlockHash::default();
        // Return the new global state.
        Self::new::<N>(
            block_round,
            block_height,
            None,
            block_cumulative_weight,
            block_cumulative_proof_target,
            previous_block_hash,
            None,
            None,
        )
    }

    /// Initializes a new global state from the given inputs.
    #[inline]
    pub fn new<N: Network>(
        block_round: u64,
        block_height: u32,
        block_timestamp: Option<i64>,
        block_cumulative_weight: u128,
        block_cumulative_proof_target: u128,
        previous_block_hash: N::BlockHash,
        block_spend_limit: Option<u64>,
        block_synthesis_limit: Option<u64>,
    ) -> Result<Self> {
        // Initialize the preimage, optionally including the block timestamp.
        let preimage = to_bits_le![
            block_round,
            block_height,
            block_cumulative_weight,
            block_cumulative_proof_target,
            (*previous_block_hash); 605
        ]
        .into_iter()
        .chain(block_timestamp.into_iter().flat_map(|ts| to_bits_le![ts]))
        .collect::<Vec<_>>();

        // Hash the preimage to get the random seed.
        let seed = N::hash_bhp768(&preimage)?.to_bytes_le()?;
        // Ensure the seed is 32-bytes.
        ensure!(seed.len() == 32, "Invalid seed length for finalize global state.");

        // Convert the seed into a 32-byte array.
        let mut random_seed = [0u8; 32];
        random_seed.copy_from_slice(&seed[..32]);

        Ok(Self { block_round, block_height, block_timestamp, random_seed, block_spend_limit, block_synthesis_limit })
    }

    /// Initializes a new global state.
    #[inline]
    pub const fn from(
        block_round: u64,
        block_height: u32,
        block_timestamp: Option<i64>,
        random_seed: [u8; 32],
        block_spend_limit: Option<u64>,
        block_synthesis_limit: Option<u64>,
    ) -> Self {
        Self { block_round, block_height, block_timestamp, random_seed, block_spend_limit, block_synthesis_limit }
    }

    /// Returns the block round.
    #[inline]
    pub const fn block_round(&self) -> u64 {
        self.block_round
    }

    /// Returns the block height.
    #[inline]
    pub const fn block_height(&self) -> u32 {
        self.block_height
    }

    /// Returns the random seed.
    #[inline]
    pub const fn random_seed(&self) -> &[u8; 32] {
        &self.random_seed
    }

    /// Returns the block timestamp.
    #[inline]
    pub const fn block_timestamp(&self) -> Option<i64> {
        self.block_timestamp
    }

    /// Returns the block spend limit.
    #[inline]
    pub const fn block_spend_limit(&self) -> Option<u64> {
        self.block_spend_limit
    }

    /// Returns the block synthesis limit.
    #[inline]
    pub const fn block_synthesis_limit(&self) -> Option<u64> {
        self.block_synthesis_limit
    }
}
