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

use crate::{
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::network::prelude::*;
use snarkvm_ledger_committee::Committee;

use aleo_std_storage::StorageMode;
use anyhow::Result;
use core::marker::PhantomData;

const ROUND_KEY: u8 = 0;

/// A trait for committee storage.
pub trait CommitteeStorage<N: Network>: 'static + Clone + Send + Sync {
    /// The mapping of `()` to `current round`.
    type CurrentRoundMap: for<'a> Map<'a, u8, u64>;
    /// The mapping of `round` to `height`.
    type RoundToHeightMap: for<'a> Map<'a, u64, u32>;
    /// The mapping of `block height` to `committee`.
    type CommitteeMap: for<'a> Map<'a, u32, Committee<N>>;

    /// Initializes the committee storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the current round map.
    fn current_round_map(&self) -> &Self::CurrentRoundMap;
    /// Returns the round to height map.
    fn round_to_height_map(&self) -> &Self::RoundToHeightMap;
    /// Returns the committee map.
    fn committee_map(&self) -> &Self::CommitteeMap;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode;

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.current_round_map().start_atomic();
        self.round_to_height_map().start_atomic();
        self.committee_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.current_round_map().is_atomic_in_progress()
            || self.round_to_height_map().is_atomic_in_progress()
            || self.committee_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.current_round_map().atomic_checkpoint();
        self.round_to_height_map().atomic_checkpoint();
        self.committee_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.current_round_map().clear_latest_checkpoint();
        self.round_to_height_map().clear_latest_checkpoint();
        self.committee_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.current_round_map().atomic_rewind();
        self.round_to_height_map().atomic_rewind();
        self.committee_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.current_round_map().abort_atomic();
        self.round_to_height_map().abort_atomic();
        self.committee_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.current_round_map().finish_atomic()?;
        self.round_to_height_map().finish_atomic()?;
        self.committee_map().finish_atomic()
    }

    /// Stores the given `(next height, committee)` pair into storage,
    /// and indexes storage up to the `next round`.
    fn insert(&self, next_height: u32, committee: Committee<N>) -> Result<()> {
        // Retrieve the next round.
        let next_round = committee.starting_round();
        // Ensure the next round is at least the next height.
        ensure!(next_round >= next_height as u64, "Next round must be at least the next height");

        // Check the next round.
        match self.current_round() {
            // If the current round is 0, ensure the next round is 0.
            Err(..) => ensure!(next_round == 0, "Next round must be block round 0"),
            // Otherwise, ensure the next round sequentially follows the current round.
            Ok(current_round) => ensure!(
                next_round > current_round,
                "Next round {next_round} must be greater than current round {current_round}"
            ),
        }

        // Check the next height.
        match self.current_height() {
            // If the current height is 0, ensure the next height is 0.
            Err(..) => ensure!(next_height == 0, "Next height must be block height 0"),
            // Otherwise, ensure the next height sequentially follows the current height.
            Ok(current_height) => ensure!(next_height == current_height + 1, "Next height must be sequential"),
        }

        // If the next round already exists, then return an error.
        ensure!(
            !self.round_to_height_map().contains_key_confirmed(&next_round)?,
            "Next round {next_round} already exists in committee storage"
        );

        // Determine the catch up round.
        let catch_up_round = match self.current_round() {
            Err(..) => 0,
            Ok(current_round) => current_round + 1,
        };

        // Start an atomic batch.
        atomic_batch_scope!(self, {
            // Store the next round.
            self.current_round_map().insert(ROUND_KEY, next_round)?;

            // If the current height exists, then store missing rounds up to the *next* height.
            if let Ok(current_height) = self.current_height() {
                // Store the round to height mappings.
                for round in catch_up_round..next_round {
                    // Note: We store the 'current_height' as the *next* round starts the *next* height.
                    self.round_to_height_map().insert(round, current_height)?;
                }
            }
            // Store the next round's height.
            self.round_to_height_map().insert(next_round, next_height)?;

            // Store the committee.
            self.committee_map().insert(next_height, committee)?;
            Ok(())
        })
    }

    /// Removes the committee for the given `height`, in the process
    /// removing all round to height entries back to the previous committee.
    fn remove(&self, height: u32) -> Result<()> {
        // Retrieve the current round.
        let current_round = self.current_round()?;
        // Retrieve the current height.
        let current_height = self.current_height()?;
        // Retrieve the committee for the given height.
        let Some(committee) = self.get_committee(height)? else {
            bail!("Committee not found for height {height} in committee storage");
        };
        // Retrieve the round for the given height.
        let committee_round = committee.starting_round();

        // If the current height matches the given height, it means we are removing the latest committee,
        // and we will need to update the current round.
        let is_latest_committee = current_height == height;

        // Find the earliest round to be removed (inclusive).
        let mut earliest_round = committee_round;
        while earliest_round > 0 && self.get_height_for_round(earliest_round)? == Some(height) {
            earliest_round = earliest_round.saturating_sub(1);
        }
        let is_multiple = earliest_round != committee_round;
        if is_multiple {
            earliest_round += 1;
        }

        // Find the latest round to be removed (exclusive).
        let mut latest_round = committee_round;
        while self.get_height_for_round(latest_round)? == Some(height) {
            latest_round = latest_round.saturating_add(1);
        }

        // If we are removing the latest committee, determine the next current round.
        let mut next_current_round = current_round.saturating_sub(1);
        if is_latest_committee {
            while next_current_round > 0 {
                // If the next current height is less than the current height, then we have found the next current round.
                if let Some(next_current_height) = self.get_height_for_round(next_current_round)?
                    && next_current_height < current_height
                {
                    break;
                }
                // Otherwise, decrement the next current round.
                next_current_round = next_current_round.saturating_sub(1);
            }
        }

        // Start an atomic batch.
        atomic_batch_scope!(self, {
            // Update the current round, if this is the latest round.
            if is_latest_committee {
                // Remove the current round.
                self.current_round_map().remove(&ROUND_KEY)?;
                // If the next current round is greater than 0, then insert it.
                if current_round != next_current_round && next_current_round > 0 {
                    // Insert the previous round.
                    self.current_round_map().insert(ROUND_KEY, next_current_round)?;
                }
            }
            // Remove the round to height mappings.
            for round in earliest_round..latest_round {
                self.round_to_height_map().remove(&round)?;
            }
            // Remove the committee.
            self.committee_map().remove(&height)?;

            Ok(())
        })
    }

    /// Returns the current round.
    fn current_round(&self) -> Result<u64> {
        let Some(round) = self.current_round_map().get_confirmed(&ROUND_KEY)? else {
            bail!("Current round not found in committee storage");
        };
        Ok(*round)
    }

    /// Returns the current height.
    fn current_height(&self) -> Result<u32> {
        // Retrieve the current round.
        let current_round = self.current_round()?;
        // Retrieve the current height.
        let Some(height) = self.round_to_height_map().get_confirmed(&current_round)? else {
            bail!("Current height not found in committee storage");
        };
        Ok(*height)
    }

    /// Returns the current committee.
    fn current_committee(&self) -> Result<Committee<N>> {
        self.get_committee(self.current_height()?)?
            .ok_or_else(|| anyhow!("Current committee not found in committee storage"))
    }

    /// Returns the height for the given `round`.
    fn get_height_for_round(&self, round: u64) -> Result<Option<u32>> {
        Ok(self.round_to_height_map().get_confirmed(&round)?.map(|x| *x))
    }

    /// Returns the committee for the given `height`.
    fn get_committee(&self, height: u32) -> Result<Option<Committee<N>>> {
        Ok(self.committee_map().get_confirmed(&height)?.map(|x| x.into_owned()))
    }

    /// Returns the committee for the given `round`.
    fn get_committee_for_round(&self, round: u64) -> Result<Option<Committee<N>>> {
        // Retrieve the height for the given round.
        match self.get_height_for_round(round)? {
            // Retrieve the committee for the given height.
            Some(height) => Ok(self.get_committee(height)?),
            None => Ok(None),
        }
    }
}

/// The committee store.
#[derive(Clone)]
pub struct CommitteeStore<N: Network, C: CommitteeStorage<N>> {
    /// The committee storage.
    storage: C,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, C: CommitteeStorage<N>> CommitteeStore<N, C> {
    /// Initializes the committee store.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        // Initialize the committee storage.
        let storage = C::open(storage)?;
        // Return the committee store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a committee store from storage.
    pub fn from(storage: C) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Starts an atomic batch write operation.
    pub fn start_atomic(&self) {
        self.storage.start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    pub fn is_atomic_in_progress(&self) -> bool {
        self.storage.is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    pub fn atomic_checkpoint(&self) {
        self.storage.atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    pub fn clear_latest_checkpoint(&self) {
        self.storage.clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    pub fn atomic_rewind(&self) {
        self.storage.atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    pub fn abort_atomic(&self) {
        self.storage.abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    pub fn finish_atomic(&self) -> Result<()> {
        self.storage.finish_atomic()
    }

    /// Returns the storage mode.
    pub fn storage_mode(&self) -> &StorageMode {
        self.storage.storage_mode()
    }
}

impl<N: Network, C: CommitteeStorage<N>> CommitteeStore<N, C> {
    /// Stores the given `(next height, committee)` pair into storage,
    /// and indexes storage up to the `next round`.
    pub fn insert(&self, next_height: u32, committee: Committee<N>) -> Result<()> {
        self.storage.insert(next_height, committee)
    }

    /// Removes the committee for the given `height`, in the process
    /// removing all round to height entries back to the previous committee.
    pub fn remove(&self, height: u32) -> Result<()> {
        self.storage.remove(height)
    }
}

impl<N: Network, C: CommitteeStorage<N>> CommitteeStore<N, C> {
    /// Returns the current round.
    pub fn current_round(&self) -> Result<u64> {
        self.storage.current_round()
    }

    /// Returns the current height.
    pub fn current_height(&self) -> Result<u32> {
        self.storage.current_height()
    }

    /// Returns the current committee.
    pub fn current_committee(&self) -> Result<Committee<N>> {
        self.storage.current_committee()
    }

    /// Returns the height for the given `round`.
    pub fn get_height_for_round(&self, round: u64) -> Result<Option<u32>> {
        self.storage.get_height_for_round(round)
    }

    /// Returns the committee for the given `height`.
    pub fn get_committee(&self, height: u32) -> Result<Option<Committee<N>>> {
        self.storage.get_committee(height)
    }

    /// Returns the committee for the given `round`.
    pub fn get_committee_for_round(&self, round: u64) -> Result<Option<Committee<N>>> {
        self.storage.get_committee_for_round(round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::CommitteeMemory;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the committee.
        let committee_0 = snarkvm_ledger_committee::test_helpers::sample_committee_for_round(0, rng);

        // Initialize a new committee store.
        let store = CommitteeStore::<CurrentNetwork, CommitteeMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(store.current_round().is_err());
        assert!(store.current_height().is_err());
        assert!(store.current_committee().is_err());
        assert_eq!(store.get_height_for_round(rng.random()).unwrap(), None);
        assert_eq!(store.get_committee(rng.random()).unwrap(), None);
        assert_eq!(store.get_committee_for_round(rng.random()).unwrap(), None);

        // Insert the committee.
        store.insert(0, committee_0.clone()).unwrap();
        assert_eq!(store.current_round().unwrap(), 0);
        assert_eq!(store.current_height().unwrap(), 0);
        assert_eq!(store.current_committee().unwrap(), committee_0);

        assert_eq!(store.get_height_for_round(0).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(1).unwrap(), None);
        assert_eq!(store.get_height_for_round(2).unwrap(), None);
        assert_eq!(store.get_height_for_round(3).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee(1).unwrap(), None);
        assert_eq!(store.get_committee(2).unwrap(), None);

        assert_eq!(store.get_committee_for_round(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(1).unwrap(), None);
        assert_eq!(store.get_committee_for_round(2).unwrap(), None);
        assert_eq!(store.get_committee_for_round(3).unwrap(), None);

        // Sample another committee.
        let committee_1 = snarkvm_ledger_committee::test_helpers::sample_committee_for_round(5, rng);

        // Insert the committee.
        store.insert(1, committee_1.clone()).unwrap();
        assert_eq!(store.current_round().unwrap(), 5);
        assert_eq!(store.current_height().unwrap(), 1);
        assert_eq!(store.current_committee().unwrap(), committee_1);

        assert_eq!(store.get_height_for_round(0).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(1).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(2).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(3).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(4).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(5).unwrap().unwrap(), 1);
        assert_eq!(store.get_height_for_round(6).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee(1).unwrap().unwrap(), committee_1);
        assert_eq!(store.get_committee(2).unwrap(), None);
        assert_eq!(store.get_committee(3).unwrap(), None);

        assert_eq!(store.get_committee_for_round(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(1).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(2).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(3).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(4).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(5).unwrap().unwrap(), committee_1);
        assert_eq!(store.get_committee_for_round(6).unwrap(), None);

        // Remove the committee.
        assert!(store.remove(2).is_err());
        store.remove(1).unwrap();
        assert!(store.remove(1).is_err());
        assert_eq!(store.current_round().unwrap(), 4);
        assert_eq!(store.current_height().unwrap(), 0);
        assert_eq!(store.current_committee().unwrap(), committee_0);

        assert_eq!(store.get_height_for_round(0).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(1).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(2).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(3).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(4).unwrap().unwrap(), 0);
        assert_eq!(store.get_height_for_round(5).unwrap(), None);
        assert_eq!(store.get_height_for_round(6).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee(1).unwrap(), None);
        assert_eq!(store.get_committee(2).unwrap(), None);
        assert_eq!(store.get_committee(3).unwrap(), None);

        assert_eq!(store.get_committee_for_round(0).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(1).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(2).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(3).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(4).unwrap().unwrap(), committee_0);
        assert_eq!(store.get_committee_for_round(5).unwrap(), None);
        assert_eq!(store.get_committee_for_round(6).unwrap(), None);

        // Remove the committee.
        store.remove(0).unwrap();
        assert!(store.current_round().is_err());
        assert!(store.current_height().is_err());
        assert!(store.current_committee().is_err());

        assert_eq!(store.get_height_for_round(0).unwrap(), None);
        assert_eq!(store.get_height_for_round(1).unwrap(), None);
        assert_eq!(store.get_height_for_round(2).unwrap(), None);
        assert_eq!(store.get_height_for_round(3).unwrap(), None);
        assert_eq!(store.get_height_for_round(4).unwrap(), None);
        assert_eq!(store.get_height_for_round(5).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap(), None);
        assert_eq!(store.get_committee(1).unwrap(), None);
        assert_eq!(store.get_committee(2).unwrap(), None);
        assert_eq!(store.get_committee(3).unwrap(), None);

        assert_eq!(store.get_committee_for_round(0).unwrap(), None);
        assert_eq!(store.get_committee_for_round(1).unwrap(), None);
        assert_eq!(store.get_committee_for_round(2).unwrap(), None);
        assert_eq!(store.get_committee_for_round(3).unwrap(), None);
        assert_eq!(store.get_committee_for_round(4).unwrap(), None);
        assert_eq!(store.get_committee_for_round(5).unwrap(), None);
    }

    #[test]
    fn test_remove_hole() {
        let rng = &mut TestRng::default();

        // Sample the committee.
        let committee_0 = snarkvm_ledger_committee::test_helpers::sample_committee_for_round(0, rng);

        // Initialize a new committee store.
        let store = CommitteeStore::<CurrentNetwork, CommitteeMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        assert!(store.current_round().is_err());
        assert!(store.current_height().is_err());
        assert!(store.current_committee().is_err());

        // Insert the committee.
        store.insert(0, committee_0.clone()).unwrap();
        assert_eq!(store.current_round().unwrap(), 0);
        assert_eq!(store.current_height().unwrap(), 0);
        assert_eq!(store.current_committee().unwrap(), committee_0);

        // Sample another committee.
        let committee_1 = snarkvm_ledger_committee::test_helpers::sample_committee_for_round(5, rng);

        // Insert the committee.
        store.insert(1, committee_1.clone()).unwrap();
        assert_eq!(store.current_round().unwrap(), 5);
        assert_eq!(store.current_height().unwrap(), 1);
        assert_eq!(store.current_committee().unwrap(), committee_1);

        // Observe: We remove the committee for round 2, but the current committee is still the one for round 5.

        // Remove the committee.
        store.remove(0).unwrap();
        assert_eq!(store.current_round().unwrap(), 5);
        assert_eq!(store.current_height().unwrap(), 1);
        assert_eq!(store.current_committee().unwrap(), committee_1);

        assert_eq!(store.get_height_for_round(1).unwrap(), None);
        assert_eq!(store.get_height_for_round(2).unwrap(), None);
        assert_eq!(store.get_height_for_round(3).unwrap(), None);
        assert_eq!(store.get_height_for_round(4).unwrap(), None);
        assert_eq!(store.get_height_for_round(5).unwrap().unwrap(), 1);
        assert_eq!(store.get_height_for_round(6).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap(), None);
        assert_eq!(store.get_committee(1).unwrap().unwrap(), committee_1);
        assert_eq!(store.get_committee(2).unwrap(), None);
        assert_eq!(store.get_committee(3).unwrap(), None);

        assert_eq!(store.get_committee_for_round(1).unwrap(), None);
        assert_eq!(store.get_committee_for_round(2).unwrap(), None);
        assert_eq!(store.get_committee_for_round(3).unwrap(), None);
        assert_eq!(store.get_committee_for_round(4).unwrap(), None);
        assert_eq!(store.get_committee_for_round(5).unwrap().unwrap(), committee_1);
        assert_eq!(store.get_committee_for_round(6).unwrap(), None);

        // Remove the committee.
        store.remove(1).unwrap();
        assert!(store.current_round().is_err());
        assert!(store.current_height().is_err());
        assert!(store.current_committee().is_err());

        assert_eq!(store.get_height_for_round(1).unwrap(), None);
        assert_eq!(store.get_height_for_round(2).unwrap(), None);
        assert_eq!(store.get_height_for_round(3).unwrap(), None);
        assert_eq!(store.get_height_for_round(4).unwrap(), None);
        assert_eq!(store.get_height_for_round(5).unwrap(), None);

        assert_eq!(store.get_committee(0).unwrap(), None);
        assert_eq!(store.get_committee(1).unwrap(), None);
        assert_eq!(store.get_committee(2).unwrap(), None);
        assert_eq!(store.get_committee(3).unwrap(), None);

        assert_eq!(store.get_committee_for_round(1).unwrap(), None);
        assert_eq!(store.get_committee_for_round(2).unwrap(), None);
        assert_eq!(store.get_committee_for_round(3).unwrap(), None);
        assert_eq!(store.get_committee_for_round(4).unwrap(), None);
        assert_eq!(store.get_committee_for_round(5).unwrap(), None);
    }
}
