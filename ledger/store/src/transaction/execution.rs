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
    FeeStorage,
    FeeStore,
    TransitionStore,
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::network::prelude::*;
use snarkvm_ledger_block::{Execution, Transaction, Transition};
use snarkvm_synthesizer_snark::Proof;

use aleo_std_storage::StorageMode;
use anyhow::Result;
use core::marker::PhantomData;
use std::borrow::Cow;

/// A trait for execution storage.
pub trait ExecutionStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transaction ID` to `([transition ID], has_fee)`.
    type IDMap: for<'a> Map<'a, N::TransactionID, (Vec<N::TransitionID>, bool)>;
    /// The mapping of `transition ID` to `transaction ID`.
    type ReverseIDMap: for<'a> Map<'a, N::TransitionID, N::TransactionID>;
    /// The mapping of `transaction ID` to `(global state root, (optional) proof)`.
    type InclusionMap: for<'a> Map<'a, N::TransactionID, (N::StateRoot, Option<Proof<N>>)>;
    /// The fee storage.
    type FeeStorage: FeeStorage<N>;

    /// Initializes the execution storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self>;

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap;
    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap;
    /// Returns the inclusion map.
    fn inclusion_map(&self) -> &Self::InclusionMap;
    /// Returns the fee store.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage>;
    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, <Self::FeeStorage as FeeStorage<N>>::TransitionStorage> {
        self.fee_store().transition_store()
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        self.transition_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.id_map().start_atomic();
        self.reverse_id_map().start_atomic();
        self.inclusion_map().start_atomic();
        self.fee_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.id_map().is_atomic_in_progress()
            || self.reverse_id_map().is_atomic_in_progress()
            || self.inclusion_map().is_atomic_in_progress()
            || self.fee_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.id_map().atomic_checkpoint();
        self.reverse_id_map().atomic_checkpoint();
        self.inclusion_map().atomic_checkpoint();
        self.fee_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.id_map().clear_latest_checkpoint();
        self.reverse_id_map().clear_latest_checkpoint();
        self.inclusion_map().clear_latest_checkpoint();
        self.fee_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.id_map().atomic_rewind();
        self.reverse_id_map().atomic_rewind();
        self.inclusion_map().atomic_rewind();
        self.fee_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.id_map().abort_atomic();
        self.reverse_id_map().abort_atomic();
        self.inclusion_map().abort_atomic();
        self.fee_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.id_map().finish_atomic()?;
        self.reverse_id_map().finish_atomic()?;
        self.inclusion_map().finish_atomic()?;
        self.fee_store().finish_atomic()
    }

    /// Stores the given `execution transaction` pair into storage.
    fn insert(&self, transaction: &Transaction<N>) -> Result<()> {
        // Ensure the transaction is a execution.
        let (transaction_id, execution, fee) = match transaction {
            Transaction::Deploy(..) => bail!("Attempted to insert a deploy transaction into execution storage."),
            Transaction::Execute(transaction_id, _, execution, fee) => (transaction_id, execution, fee),
            Transaction::Fee(..) => bail!("Attempted to insert a fee transaction into execution storage."),
        };

        // Retrieve the transitions.
        let transitions = execution.transitions();
        // Retrieve the transition IDs.
        let transition_ids = execution.transitions().map(Transition::id).copied().collect();
        // Retrieve the global state root.
        let global_state_root = execution.global_state_root();
        // Retrieve the proof.
        let proof = execution.proof().cloned();

        atomic_batch_scope!(self, {
            // Store the transition IDs.
            self.id_map().insert(*transaction_id, (transition_ids, fee.is_some()))?;

            // Store the execution.
            for transition in transitions {
                // Store the transition ID.
                self.reverse_id_map().insert(*transition.id(), *transaction_id)?;
                // Store the transition.
                self.transition_store().insert(transition)?;
            }

            // Store the global state root and proof.
            self.inclusion_map().insert(*transaction_id, (global_state_root, proof))?;

            // Store the fee.
            if let Some(fee) = fee {
                // Store the fee.
                self.fee_store().insert(*transaction_id, fee)?;
            }

            Ok(())
        })
    }

    /// Removes the execution transaction for the given `transaction ID`.
    fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        // Retrieve the transition IDs and fee boolean.
        let Some((transition_ids, has_fee)) = self.id_map().get_confirmed(transaction_id)?.map(|x| x.into_owned())
        else {
            bail!("Failed to get the transition IDs for the transaction '{transaction_id}'");
        };

        atomic_batch_scope!(self, {
            // Remove the transition IDs.
            self.id_map().remove(transaction_id)?;

            // Remove the execution.
            for transition_id in transition_ids {
                // Remove the transition ID.
                self.reverse_id_map().remove(&transition_id)?;
                // Remove the transition.
                self.transition_store().remove(&transition_id)?;
            }

            // Remove the global state root and proof.
            self.inclusion_map().remove(transaction_id)?;

            // Remove the fee.
            if has_fee {
                // Remove the fee.
                self.fee_store().remove(transaction_id)?;
            }

            Ok(())
        })
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        // First, check if the transition ID is in the fee store.
        if let Some(transaction_id) = self.fee_store().find_transaction_id_from_transition_id(transition_id)? {
            return Ok(Some(transaction_id));
        }
        // Otherwise, check if the transition ID is in the reverse ID map.
        Ok(self.reverse_id_map().get_confirmed(transition_id)?.map(|x| *x))
    }

    /// Returns the execution for the given `transaction ID`.
    fn get_execution(&self, transaction_id: &N::TransactionID) -> Result<Option<Execution<N>>> {
        // Retrieve the transition IDs.
        let Some((transition_ids, _)) = self.id_map().get_confirmed(transaction_id)?.map(|x| x.into_owned()) else {
            return Ok(None);
        };

        // Retrieve the global state root and proof.
        let Some((global_state_root, proof)) =
            self.inclusion_map().get_confirmed(transaction_id)?.map(|x| x.into_owned())
        else {
            bail!("Failed to get the proof for the transaction '{transaction_id}'");
        };

        // Initialize a vector for the transitions.
        let mut transitions = Vec::new();

        // Retrieve the transitions.
        for transition_id in &transition_ids {
            match self.transition_store().get_transition(transition_id)? {
                Some(transition) => transitions.push(transition),
                None => bail!("Failed to get transition '{transition_id}' for transaction '{transaction_id}'"),
            };
        }

        // Return the execution.
        Ok(Some(Execution::from(transitions.into_iter(), global_state_root, proof)?))
    }

    /// Returns the transaction for the given `transaction ID`.
    fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        // Retrieve the transition IDs and fee boolean.
        let Some((transition_ids, has_fee)) = self.id_map().get_confirmed(transaction_id)?.map(|x| x.into_owned())
        else {
            return Ok(None);
        };

        // Retrieve the global state root and proof.
        let Some((global_state_root, proof)) =
            self.inclusion_map().get_confirmed(transaction_id)?.map(|x| x.into_owned())
        else {
            bail!("Failed to get the proof for the transaction '{transaction_id}'");
        };

        // Initialize a vector for the transitions.
        let mut transitions = Vec::new();

        // Retrieve the transitions.
        for transition_id in &transition_ids {
            match self.transition_store().get_transition(transition_id)? {
                Some(transition) => transitions.push(transition),
                None => bail!("Failed to get transition '{transition_id}' for transaction '{transaction_id}'"),
            };
        }

        // Construct the execution.
        let execution = Execution::from(transitions.into_iter(), global_state_root, proof)?;

        // Retrieve the fee.
        let fee = match has_fee {
            true => {
                let Some(fee) = self.fee_store().get_fee(transaction_id)? else {
                    bail!("Failed to get the fee for transaction '{transaction_id}'");
                };
                Some(fee)
            }
            false => None,
        };

        // Construct the transaction.
        let execution_id = execution.to_execution_id()?;
        Ok(Some(Transaction::Execute(*transaction_id, execution_id, Box::new(execution), fee)))
    }
}

/// The execution store.
#[derive(Clone)]
pub struct ExecutionStore<N: Network, E: ExecutionStorage<N>> {
    /// The execution storage.
    storage: E,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, E: ExecutionStorage<N>> ExecutionStore<N, E> {
    /// Initializes the execution store.
    pub fn open(fee_store: FeeStore<N, E::FeeStorage>) -> Result<Self> {
        // Initialize the execution storage.
        let storage = E::open(fee_store)?;
        // Return the execution store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes an execution store from storage.
    pub fn from(storage: E) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Stores the given `execution transaction` into storage.
    pub fn insert(&self, transaction: &Transaction<N>) -> Result<()> {
        self.storage.insert(transaction)
    }

    /// Removes the transaction for the given `transaction ID`.
    pub fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        self.storage.remove(transaction_id)
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

impl<N: Network, E: ExecutionStorage<N>> ExecutionStore<N, E> {
    /// Returns the transaction for the given `transaction ID`.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        self.storage.get_transaction(transaction_id)
    }

    /// Returns the execution for the given `transaction ID`.
    pub fn get_execution(&self, transaction_id: &N::TransactionID) -> Result<Option<Execution<N>>> {
        self.storage.get_execution(transaction_id)
    }
}

impl<N: Network, E: ExecutionStorage<N>> ExecutionStore<N, E> {
    /// Returns the transaction ID that executed the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_transition_id(transition_id)
    }
}

impl<N: Network, E: ExecutionStorage<N>> ExecutionStore<N, E> {
    /// Returns an iterator over the execution transaction IDs, for all executions.
    pub fn execution_transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.storage.id_map().keys_confirmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransitionStore, helpers::memory::ExecutionMemory};

    type CurrentNetwork = console::network::MainnetV0;

    fn insert_get_remove(transaction: Transaction<CurrentNetwork>) -> Result<()> {
        let transaction_id = transaction.id();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None))?;
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new execution store.
        let execution_store = ExecutionMemory::open(fee_store)?;

        // Ensure the execution transaction does not exist.
        let candidate = execution_store.get_transaction(&transaction_id)?;
        assert_eq!(None, candidate);

        // Insert the execution transaction.
        execution_store.insert(&transaction)?;

        // Retrieve the execution transaction.
        let candidate = execution_store.get_transaction(&transaction_id)?;
        assert_eq!(Some(transaction), candidate);

        // Remove the execution.
        execution_store.remove(&transaction_id)?;

        // Ensure the execution transaction does not exist.
        let candidate = execution_store.get_transaction(&transaction_id)?;
        assert_eq!(None, candidate);

        Ok(())
    }

    fn find_transaction_id(transaction: Transaction<CurrentNetwork>) -> Result<()> {
        let transaction_id = transaction.id();

        // Ensure the transaction is an Execution.
        if matches!(transaction, Transaction::Deploy(..)) {
            bail!("Invalid transaction type");
        }

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None))?;
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new execution store.
        let execution_store = ExecutionMemory::open(fee_store)?;

        // Ensure the execution transaction does not exist.
        let candidate = execution_store.get_transaction(&transaction_id)?;
        assert_eq!(None, candidate);

        for transition_id in transaction.transition_ids() {
            // Ensure the transaction ID is not found.
            let candidate = execution_store.find_transaction_id_from_transition_id(transition_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the execution.
            execution_store.insert(&transaction)?;

            // Find the transaction ID.
            let candidate = execution_store.find_transaction_id_from_transition_id(transition_id).unwrap();
            assert_eq!(Some(transaction_id), candidate);

            // Remove the execution.
            execution_store.remove(&transaction_id)?;

            // Ensure the transaction ID is not found.
            let candidate = execution_store.find_transaction_id_from_transition_id(transition_id).unwrap();
            assert_eq!(None, candidate);
        }

        Ok(())
    }

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the execution transaction.
        let transaction = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        insert_get_remove(transaction).unwrap();

        // Sample the execution transaction.
        let transaction = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0);
        insert_get_remove(transaction).unwrap();
    }

    #[test]
    fn test_find_transaction_id() {
        let rng = &mut TestRng::default();

        // Sample the execution transaction.
        let transaction = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        find_transaction_id(transaction).unwrap();

        // Sample the execution transaction.
        let transaction = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0);
        find_transaction_id(transaction).unwrap();
    }
}
