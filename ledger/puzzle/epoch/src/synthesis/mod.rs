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

mod helpers;
pub use helpers::*;

mod program;
pub use program::*;

use circuit::Aleo;
use console::network::Network;
use snarkvm_ledger_puzzle::PuzzleTrait;
use snarkvm_utilities::locks::RwLock;

use anyhow::{Result, bail};
use core::{marker::PhantomData, num::NonZeroUsize};
use lru::LruCache;
use rand_chacha::ChaChaRng;
use std::sync::Arc;

pub struct SynthesisPuzzle<N: Network, A: Aleo<Network = N>> {
    /// The LRU cache of epoch programs.
    epoch_program_cache: Arc<RwLock<LruCache<N::BlockHash, EpochProgram<N>>>>,
    /// PhantomData.
    _phantom: PhantomData<A>,
}

impl<N: Network, A: Aleo<Network = N>> PuzzleTrait<N> for SynthesisPuzzle<N, A> {
    /// Initializes a new instance of the puzzle.
    fn new() -> Self {
        Self {
            epoch_program_cache: Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(16).unwrap()))),
            _phantom: PhantomData,
        }
    }

    /// Returns the leaves for the puzzle, given the epoch hash and seeded RNG.
    ///
    /// Note: This function uses a thread to ensure the circuit is synthesized in a thread-safe environment.
    /// This ensures that `SynthesisPuzzle` can be used in a multi-threaded environment.
    fn to_leaves(&self, epoch_hash: N::BlockHash, rng: &mut ChaChaRng) -> Result<Vec<Vec<bool>>> {
        // Retrieve the epoch program.
        let epoch_program = self.get_epoch_program(epoch_hash)?;
        // Construct the epoch program inputs.
        let inputs = epoch_program.construct_inputs(rng)?;
        // Spawn a thread to ensure the circuit is synthesized in a thread-safe environment.
        let handle = std::thread::spawn(move || {
            // Synthesize the circuit and return the assignment.
            epoch_program.to_leaves::<A>(inputs)
        });
        // Return the leaves.
        match handle.join() {
            Ok(Ok(leaves)) => Ok(leaves),
            Ok(Err(error)) => Err(error),
            Err(error) => bail!("Failed to join thread in 'SynthesisPuzzle::to_leaves': {error:?}"),
        }
    }

    /// Returns the batches of leaves for the puzzle, given the epoch hash and seeded RNGs.
    ///
    /// Note: This function uses a thread to ensure the circuit is synthesized in a thread-safe environment.
    /// This ensures that `SynthesisPuzzle` can be used in a multi-threaded environment.
    fn to_all_leaves(&self, epoch_hash: N::BlockHash, rngs: Vec<ChaChaRng>) -> Result<Vec<Vec<Vec<bool>>>> {
        // Retrieve the number of instances.
        let num_instances = rngs.len();
        // Retrieve the epoch program.
        let epoch_program = self.get_epoch_program(epoch_hash)?;
        // Initialize the list of handles.
        let mut handles = Vec::with_capacity(num_instances);
        // Construct the epoch program inputs.
        for mut rng in rngs {
            let epoch_program = epoch_program.clone();
            // Spawn a thread to ensure the circuit is synthesized in a thread-safe environment.
            handles.push(std::thread::spawn(move || {
                // Construct the epoch program inputs.
                let inputs = epoch_program.construct_inputs(&mut rng)?;
                // Synthesize the circuit and return the assignment.
                epoch_program.to_leaves::<A>(inputs)
            }));
        }
        // Collect the leaves.
        let mut leaves = Vec::with_capacity(num_instances);
        for handle in handles {
            leaves.push(match handle.join() {
                Ok(Ok(leaves)) => leaves,
                Ok(Err(error)) => return Err(error),
                Err(error) => bail!("Failed to join threads in 'SynthesisPuzzle::to_all_leaves': {error:?}"),
            });
        }
        // Return the leaves.
        Ok(leaves)
    }
}

impl<N: Network, A: Aleo<Network = N>> SynthesisPuzzle<N, A> {
    /// Returns the epoch program for the given epoch hash.
    pub fn get_epoch_program(&self, epoch_hash: N::BlockHash) -> Result<EpochProgram<N>> {
        // If the epoch program is in the cache, return it.
        if let Some(epoch_program) = self.epoch_program_cache.write().get(&epoch_hash) {
            return Ok(epoch_program.clone());
        }

        // Initialize the epoch program.
        let epoch_program = EpochProgram::new(epoch_hash)?;
        // Insert the epoch program into the cache.
        self.epoch_program_cache.write().put(epoch_hash, epoch_program.clone());
        // Return the epoch program.
        Ok(epoch_program)
    }
}

/// Attention: This is *safe* because we do not instantiate `N` or `A` in this struct.
/// This implementation of `Send` and `Sync` cannot be applied to `A` directly for thread safety.
unsafe impl<N: Network, A: Aleo<Network = N>> Send for SynthesisPuzzle<N, A> {}
unsafe impl<N: Network, A: Aleo<Network = N>> Sync for SynthesisPuzzle<N, A> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    type CurrentNetwork = console::network::MainnetV0;
    type CurrentAleo = circuit::AleoV0;

    #[test]
    fn test_get_epoch_program() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = SynthesisPuzzle::<CurrentNetwork, CurrentAleo>::new();
        // Sample the epoch program, and ensure it succeeds.
        let program_0 = puzzle.get_epoch_program(epoch_hash).unwrap();

        // Fetch the epoch program again, and ensure it matches (from the cache).
        let program_1 = puzzle.get_epoch_program(epoch_hash).unwrap();
        assert_eq!(program_0, program_1);
    }

    #[test]
    fn test_to_leaves() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = SynthesisPuzzle::<CurrentNetwork, CurrentAleo>::new();

        // Sample the epoch program.
        let program = puzzle.get_epoch_program(epoch_hash).unwrap();
        // Directly construct the leaves.
        let inputs = program.construct_inputs(&mut ChaChaRng::seed_from_u64(0)).unwrap();
        let leaves_0 = program.to_leaves::<CurrentAleo>(inputs).unwrap();

        // Sample the leaves.
        let leaves_1 = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(0)).unwrap();
        // Ensure the leaves match.
        assert_eq!(leaves_0, leaves_1);
    }

    #[test]
    fn test_to_all_leaves() {
        // Initialize the epoch hash.
        let epoch_hash = <CurrentNetwork as Network>::BlockHash::default();
        // Initialize the puzzle.
        let puzzle = SynthesisPuzzle::<CurrentNetwork, CurrentAleo>::new();

        // Sample the leaves.
        let leaves =
            puzzle.to_all_leaves(epoch_hash, vec![ChaChaRng::seed_from_u64(0), ChaChaRng::seed_from_u64(1)]).unwrap();
        // Ensure the number of leaves is within the expected range.
        assert_eq!(leaves.len(), 2);

        // Now, ensure it matches with the call to `to_leaves`.
        let leaves_single = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(0)).unwrap();
        assert_eq!(leaves_single, leaves[0]);

        let leaves_single = puzzle.to_leaves(epoch_hash, &mut ChaChaRng::seed_from_u64(1)).unwrap();
        assert_eq!(leaves_single, leaves[1]);
    }
}
