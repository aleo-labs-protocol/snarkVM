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

use console::{
    network::Network,
    prelude::{FromBytes, ToBits as TBits, ToBytes, Uniform, cfg_into_iter},
    types::Field,
};
use snarkvm_ledger_puzzle::PuzzleTrait;
use snarkvm_utilities::rand::gen_range_inclusive_legacy;

use anyhow::Result;
use core::marker::PhantomData;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

const MIN_NUMBER_OF_LEAVES: usize = 100_000;
const MAX_NUMBER_OF_LEAVES: usize = 200_000;

pub struct MerklePuzzle<N: Network>(PhantomData<N>);

impl<N: Network> PuzzleTrait<N> for MerklePuzzle<N> {
    /// Initializes a new instance of the puzzle.
    fn new() -> Self {
        Self(PhantomData)
    }

    /// Returns the leaves for the puzzle, given the epoch hash and seeded RNG.
    fn to_leaves(&self, epoch_hash: N::BlockHash, rng: &mut ChaChaRng) -> Result<Vec<Vec<bool>>> {
        // Sample a random number of leaves.
        let num_leaves = self.num_leaves(epoch_hash)?;
        // Sample random field elements for each of the leaves, and convert them to bits.
        let leaves = (0..num_leaves).map(|_| Field::<N>::rand(rng).to_bits_le()).collect::<Vec<_>>();
        // Return the leaves.
        Ok(leaves)
    }

    /// Returns the batches of leaves for the puzzle, given the epoch hash and seeded RNGs.
    fn to_all_leaves(&self, epoch_hash: N::BlockHash, rngs: Vec<ChaChaRng>) -> Result<Vec<Vec<Vec<bool>>>> {
        // Sample a random number of leaves.
        let num_leaves = self.num_leaves(epoch_hash)?;
        // Construct the epoch inputs.
        let leaves = cfg_into_iter!(rngs)
            .map(|mut rng| {
                // Sample random field elements for each of the leaves, and convert them to bits.
                (0..num_leaves).map(|_| Field::<N>::rand(&mut rng).to_bits_le()).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // Return the leaves.
        Ok(leaves)
    }
}

impl<N: Network> MerklePuzzle<N> {
    /// Returns the number of leaves given the epoch hash.
    pub fn num_leaves(&self, epoch_hash: N::BlockHash) -> Result<usize> {
        // Prepare the seed.
        let seed = u64::from_bytes_le(&epoch_hash.to_bytes_le()?[0..8])?;
        // Seed a random number generator from the epoch hash.
        let mut epoch_rng = ChaChaRng::seed_from_u64(seed);
        // Sample a random number of leaves.
        let num_leaves = gen_range_inclusive_legacy(MIN_NUMBER_OF_LEAVES, MAX_NUMBER_OF_LEAVES, &mut epoch_rng);

        Ok(num_leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_num_leaves() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = MerklePuzzle::<CurrentNetwork>::new();
        // Sample the number of leaves.
        let num_leaves = puzzle.num_leaves(epoch_hash).unwrap();
        assert_eq!(num_leaves, 102436);
        // Ensure the number of leaves is within the expected range.
        assert!((MIN_NUMBER_OF_LEAVES..=MAX_NUMBER_OF_LEAVES).contains(&num_leaves));
    }

    #[test]
    fn test_to_leaves() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = MerklePuzzle::<CurrentNetwork>::new();
        // Sample the number of leaves.
        let num_leaves = puzzle.num_leaves(epoch_hash).unwrap();
        // Sample the leaves.
        let leaves = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(0)).unwrap();
        // Ensure the number of leaves is within the expected range.
        assert_eq!(leaves.len(), num_leaves);
    }

    #[test]
    fn test_to_all_leaves() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = MerklePuzzle::<CurrentNetwork>::new();
        // Sample the number of leaves.
        let num_leaves = puzzle.num_leaves(epoch_hash).unwrap();
        // Sample the leaves.
        let leaves =
            puzzle.to_all_leaves(epoch_hash, vec![ChaChaRng::seed_from_u64(0), ChaChaRng::seed_from_u64(1)]).unwrap();
        // Ensure the number of leaves is within the expected range.
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].len(), num_leaves);
        assert_eq!(leaves[1].len(), num_leaves);

        // Now, ensure it matches with the call to `to_leaves`.
        let leaves_single = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(0)).unwrap();
        assert_eq!(leaves_single, leaves[0]);

        let leaves_single = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(1)).unwrap();
        assert_eq!(leaves_single, leaves[1]);
    }
}
