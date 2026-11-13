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
    TransitionStorage,
    TransitionStore,
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::network::prelude::*;
use snarkvm_ledger_block::Fee;
use snarkvm_synthesizer_snark::Proof;
use snarkvm_utilities::StorageMode;

use anyhow::Result;
use core::marker::PhantomData;

/// A trait for fee storage.
pub trait FeeStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transaction ID` to `(fee transition ID, global state root, proof)`.
    type FeeMap: for<'a> Map<'a, N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>;
    /// The mapping of `fee transition ID` to `transaction ID`.
    type ReverseFeeMap: for<'a> Map<'a, N::TransitionID, N::TransactionID>;

    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the fee storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self>;

    /// Returns the fee map.
    fn fee_map(&self) -> &Self::FeeMap;
    /// Returns the reverse fee map.
    fn reverse_fee_map(&self) -> &Self::ReverseFeeMap;
    /// Returns the transition storage.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage>;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        self.transition_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.fee_map().start_atomic();
        self.reverse_fee_map().start_atomic();
        self.transition_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.fee_map().is_atomic_in_progress()
            || self.reverse_fee_map().is_atomic_in_progress()
            || self.transition_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.fee_map().atomic_checkpoint();
        self.reverse_fee_map().atomic_checkpoint();
        self.transition_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.fee_map().clear_latest_checkpoint();
        self.reverse_fee_map().clear_latest_checkpoint();
        self.transition_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.fee_map().atomic_rewind();
        self.reverse_fee_map().atomic_rewind();
        self.transition_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.fee_map().abort_atomic();
        self.reverse_fee_map().abort_atomic();
        self.transition_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.fee_map().finish_atomic()?;
        self.reverse_fee_map().finish_atomic()?;
        self.transition_store().finish_atomic()
    }

    /// Stores the given `(transaction ID, fee)` pair into storage.
    fn insert(&self, transaction_id: N::TransactionID, fee: &Fee<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            // Store the fee.
            self.fee_map()
                .insert(transaction_id, (*fee.transition_id(), fee.global_state_root(), fee.proof().cloned()))?;
            self.reverse_fee_map().insert(*fee.transition_id(), transaction_id)?;

            // Store the fee transition.
            self.transition_store().insert(fee)?;

            Ok(())
        })
    }

    /// Removes the fee for the given `transaction ID`.
    fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        // Retrieve the fee transition ID.
        let Some((transition_id, _, _)) = self.fee_map().get_confirmed(transaction_id)?.map(|x| x.into_owned()) else {
            bail!("Failed to locate the fee transition ID for transaction '{transaction_id}'");
        };

        atomic_batch_scope!(self, {
            // Remove the fee.
            self.fee_map().remove(transaction_id)?;
            self.reverse_fee_map().remove(&transition_id)?;

            // Remove the fee transition.
            self.transition_store().remove(&transition_id)?;

            Ok(())
        })
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        Ok(self.reverse_fee_map().get_confirmed(transition_id)?.map(|x| *x))
    }

    /// Returns the fee for the given `transaction ID`.
    fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        // Retrieve the fee transition ID.
        let Some((fee_transition_id, global_state_root, proof)) =
            self.fee_map().get_confirmed(transaction_id)?.map(|x| x.into_owned())
        else {
            return Ok(None);
        };
        // Retrieve the fee transition.
        match self.transition_store().get_transition(&fee_transition_id)? {
            Some(transition) => Ok(Some(Fee::from_unchecked(transition, global_state_root, proof))),
            None => bail!("Failed to locate the fee transition for transaction '{transaction_id}'"),
        }
    }
}

/// The fee store.
#[derive(Clone)]
pub struct FeeStore<N: Network, F: FeeStorage<N>> {
    /// The fee storage.
    storage: F,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Initializes the fee store.
    pub fn open(transition_store: TransitionStore<N, F::TransitionStorage>) -> Result<Self> {
        // Initialize the fee storage.
        let storage = F::open(transition_store)?;
        // Return the fee store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a fee store from storage.
    pub fn from(storage: F) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Stores the given `(transaction_id, fee)` into storage.
    pub fn insert(&self, transaction_id: N::TransactionID, fee: &Fee<N>) -> Result<()> {
        self.storage.insert(transaction_id, fee)
    }

    /// Removes the fee for the given `transaction ID`.
    pub fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        self.storage.remove(transaction_id)
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, F::TransitionStorage> {
        self.storage.transition_store()
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

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Returns the fee for the given `transaction ID`.
    pub fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        self.storage.get_fee(transaction_id)
    }
}

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Returns the transaction ID that deployed the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_transition_id(transition_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::FeeMemory;
    use snarkvm_ledger_block::Transaction;

    #[test]
    #[ignore]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the fee transactions.
        let transaction_0 = snarkvm_ledger_test_helpers::sample_fee_private_transaction(rng);
        let transaction_1 = snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng);
        let transactions = vec![transaction_0, transaction_1];

        for transaction in transactions {
            let (transaction_id, fee) = match transaction {
                Transaction::Fee(id, fee) => (id, fee),
                _ => unreachable!("Invalid transaction type - expected a fee transaction"),
            };

            // Initialize a new transition store.
            let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
            // Initialize a new fee store.
            let fee_store = FeeMemory::open(transition_store).unwrap();

            // Ensure the fee transaction does not exist.
            let candidate = fee_store.get_fee(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the fee transaction.
            fee_store.insert(transaction_id, &fee).unwrap();

            // Retrieve the fee.
            let candidate = fee_store.get_fee(&transaction_id).unwrap();
            assert_eq!(Some(fee), candidate);

            // Remove the fee transaction.
            fee_store.remove(&transaction_id).unwrap();

            // Ensure the fee does not exist.
            let candidate = fee_store.get_fee(&transaction_id).unwrap();
            assert_eq!(None, candidate);
        }
    }

    #[test]
    #[ignore]
    fn test_find_transaction_id() {
        let rng = &mut TestRng::default();

        // Sample the fee transactions.
        let transaction_0 = snarkvm_ledger_test_helpers::sample_fee_private_transaction(rng);
        let transaction_1 = snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng);
        let transactions = vec![transaction_0, transaction_1];

        for transaction in transactions {
            let (transaction_id, fee) = match transaction {
                Transaction::Fee(id, fee) => (id, fee),
                _ => unreachable!("Invalid transaction type - expected a fee transaction"),
            };
            let fee_transition_id = fee.id();

            // Initialize a new transition store.
            let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
            // Initialize a new fee store.
            let fee_store = FeeMemory::open(transition_store).unwrap();

            // Ensure the fee does not exist.
            let candidate = fee_store.get_fee(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Ensure the transaction ID is not found.
            let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the fee transaction.
            fee_store.insert(transaction_id, &fee).unwrap();

            // Find the transaction ID.
            let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
            assert_eq!(Some(transaction_id), candidate);

            // Remove the fee transaction.
            fee_store.remove(&transaction_id).unwrap();

            // Ensure the transaction ID is not found.
            let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
            assert_eq!(None, candidate);
        }
    }
}
