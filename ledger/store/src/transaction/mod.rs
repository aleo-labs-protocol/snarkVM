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

mod deployment;
pub use deployment::*;

mod execution;
pub use execution::*;

mod fee;
pub use fee::*;

use crate::{
    TransitionStorage,
    TransitionStore,
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::{
    network::prelude::*,
    program::{Identifier, ProgramID},
};
use snarkvm_ledger_block::{Deployment, Execution, Transaction};
use snarkvm_synthesizer_program::Program;
use snarkvm_synthesizer_snark::{Certificate, VerifyingKey};

use aleo_std_storage::StorageMode;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionType {
    /// A transaction that is a deployment.
    Deploy,
    /// A transaction that is an execution.
    Execute,
    /// A transaction that is a fee.
    Fee,
}

/// A trait for transaction storage.
pub trait TransactionStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transaction ID` to `transaction type`.
    type IDMap: for<'a> Map<'a, N::TransactionID, TransactionType>;
    /// The deployment storage.
    type DeploymentStorage: DeploymentStorage<N, FeeStorage = Self::FeeStorage>;
    /// The execution storage.
    type ExecutionStorage: ExecutionStorage<N, FeeStorage = Self::FeeStorage>;
    /// The fee storage.
    type FeeStorage: FeeStorage<N, TransitionStorage = Self::TransitionStorage>;
    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the transaction storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self>;

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap;
    /// Returns the deployment store.
    fn deployment_store(&self) -> &DeploymentStore<N, Self::DeploymentStorage>;
    /// Returns the execution store.
    fn execution_store(&self) -> &ExecutionStore<N, Self::ExecutionStorage>;
    /// Returns the fee store.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage>;
    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage> {
        debug_assert!(self.deployment_store().storage_mode() == self.execution_store().storage_mode());
        debug_assert!(self.execution_store().storage_mode() == self.fee_store().storage_mode());
        self.fee_store().transition_store()
    }

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        self.transition_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.id_map().start_atomic();
        self.deployment_store().start_atomic();
        self.execution_store().start_atomic();
        self.fee_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.id_map().is_atomic_in_progress()
            || self.deployment_store().is_atomic_in_progress()
            || self.execution_store().is_atomic_in_progress()
            || self.fee_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.id_map().atomic_checkpoint();
        self.deployment_store().atomic_checkpoint();
        self.execution_store().atomic_checkpoint();
        self.fee_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.id_map().clear_latest_checkpoint();
        self.deployment_store().clear_latest_checkpoint();
        self.execution_store().clear_latest_checkpoint();
        self.fee_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.id_map().atomic_rewind();
        self.deployment_store().atomic_rewind();
        self.execution_store().atomic_rewind();
        self.fee_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.id_map().abort_atomic();
        self.deployment_store().abort_atomic();
        self.execution_store().abort_atomic();
        self.fee_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.id_map().finish_atomic()?;
        self.deployment_store().finish_atomic()?;
        self.execution_store().finish_atomic()?;
        self.fee_store().finish_atomic()
    }

    /// Stores the given `transaction` into storage.
    fn insert(&self, transaction: &Transaction<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            match transaction {
                Transaction::Deploy(..) => {
                    // Store the transaction type.
                    self.id_map().insert(transaction.id(), TransactionType::Deploy)?;
                    // Store the deployment transaction.
                    self.deployment_store().insert(transaction)?;
                }
                Transaction::Execute(..) => {
                    // Store the transaction type.
                    self.id_map().insert(transaction.id(), TransactionType::Execute)?;
                    // Store the execution transaction.
                    self.execution_store().insert(transaction)?;
                }
                Transaction::Fee(_, fee) => {
                    // Store the transaction type.
                    self.id_map().insert(transaction.id(), TransactionType::Fee)?;
                    // Store the fee transaction.
                    self.fee_store().insert(transaction.id(), fee)?;
                }
            }
            Ok(())
        })
    }

    /// Removes the transaction for the given `transaction ID`.
    fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        // Retrieve the transaction type.
        let Some(transaction_type) = self.id_map().get_confirmed(transaction_id)?.map(|x| *x) else {
            bail!("Failed to get the type for transaction '{transaction_id}'");
        };

        atomic_batch_scope!(self, {
            // Remove the transaction type.
            self.id_map().remove(transaction_id)?;
            // Remove the transaction.
            match transaction_type {
                // Remove the deployment transaction.
                TransactionType::Deploy => self.deployment_store().remove(transaction_id)?,
                // Remove the execution transaction.
                TransactionType::Execute => self.execution_store().remove(transaction_id)?,
                // Remove the fee transaction.
                TransactionType::Fee => self.fee_store().remove(transaction_id)?,
            }
            Ok(())
        })
    }

    /// Returns the latest transaction ID that contains the given `program ID`.
    /// If amendments exist for the latest edition, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID for the latest edition.
    fn find_latest_transaction_id_from_program_id(
        &self,
        program_id: &ProgramID<N>,
    ) -> Result<Option<N::TransactionID>> {
        self.deployment_store().find_latest_transaction_id_from_program_id(program_id)
    }

    /// Returns the original deployment transaction ID for the given `program ID` and `edition`.
    /// This returns the initial deployment, not any subsequent amendments.
    fn find_original_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.deployment_store().find_original_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the latest transaction ID for the given `program ID` and `edition`.
    /// If amendments exist, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    fn find_latest_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.deployment_store().find_latest_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the transaction ID for the given `program ID`, `edition`, and `amendment_index`.
    /// Returns `None` if no such amendment exists.
    fn find_transaction_id_from_program_id_edition_and_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<N::TransactionID>> {
        self.deployment_store().find_transaction_id_from_program_id_edition_and_amendment(
            program_id,
            edition,
            amendment_index,
        )
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.execution_store().find_transaction_id_from_transition_id(transition_id)
    }

    /// Returns the transaction for the given `transaction ID`.
    fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        // Retrieve the transaction type.
        let Some(transaction_type) = self.id_map().get_confirmed(transaction_id)?.map(|x| *x) else {
            return Ok(None);
        };
        // Retrieve the transaction.
        match transaction_type {
            // Return the deployment transaction.
            TransactionType::Deploy => self.deployment_store().get_transaction(transaction_id),
            // Return the execution transaction.
            TransactionType::Execute => self.execution_store().get_transaction(transaction_id),
            // Return the fee transaction.
            TransactionType::Fee => match self.fee_store().get_fee(transaction_id)? {
                Some(fee) => Ok(Some(Transaction::Fee(*transaction_id, fee))),
                None => bail!("Failed to get fee for transaction '{transaction_id}'"),
            },
        }
    }
}

/// The transaction store.
#[derive(Clone)]
pub struct TransactionStore<N: Network, T: TransactionStorage<N>> {
    /// The map of `transaction ID` to `transaction type`.
    transaction_ids: T::IDMap,
    /// The transaction storage.
    storage: T,
}

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Initializes the transaction store.
    pub fn open(transition_store: TransitionStore<N, T::TransitionStorage>) -> Result<Self> {
        // Initialize the transaction storage.
        let storage = T::open(transition_store)?;
        // Return the transaction store.
        Ok(Self { transaction_ids: storage.id_map().clone(), storage })
    }

    /// Initializes a transaction store from storage.
    pub fn from(storage: T) -> Self {
        Self { transaction_ids: storage.id_map().clone(), storage }
    }

    /// Stores the given `transaction` into storage.
    pub fn insert(&self, transaction: &Transaction<N>) -> Result<()> {
        self.storage.insert(transaction)
    }

    /// Removes the transaction for the given `transaction ID`.
    pub fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        self.storage.remove(transaction_id)
    }

    /// Returns the deployment store.
    pub fn deployment_store(&self) -> &DeploymentStore<N, T::DeploymentStorage> {
        self.storage.deployment_store()
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, T::TransitionStorage> {
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

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Returns the transaction for the given `transaction ID`.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        self.storage.get_transaction(transaction_id)
    }

    /// Returns the deployment for the given `transaction ID`.
    pub fn get_deployment(&self, transaction_id: &N::TransactionID) -> Result<Option<Deployment<N>>> {
        // Retrieve the transaction type.
        let Some(transaction_type) = self.transaction_ids.get_confirmed(transaction_id)?.map(|x| *x) else {
            bail!("Failed to get the type for transaction '{transaction_id}'");
        };
        // Retrieve the deployment.
        match transaction_type {
            // Return the deployment.
            TransactionType::Deploy => self.storage.deployment_store().get_deployment(transaction_id),
            // Throw an error.
            TransactionType::Execute => bail!("Tried to get a deployment for execution transaction '{transaction_id}'"),
            // Throw an error.
            TransactionType::Fee => bail!("Tried to get a deployment for fee transaction '{transaction_id}'"),
        }
    }

    /// Returns the execution for the given `transaction ID`.
    pub fn get_execution(&self, transaction_id: &N::TransactionID) -> Result<Option<Execution<N>>> {
        // Retrieve the transaction type.
        let Some(transaction_type) = self.transaction_ids.get_confirmed(transaction_id)?.map(|x| *x) else {
            bail!("Failed to get the type for transaction '{transaction_id}'");
        };
        // Retrieve the execution.
        match transaction_type {
            // Throw an error.
            TransactionType::Deploy => bail!("Tried to get an execution for deployment transaction '{transaction_id}'"),
            // Return the execution.
            TransactionType::Execute => self.storage.execution_store().get_execution(transaction_id),
            // Throw an error.
            TransactionType::Fee => bail!("Tried to get an execution for fee transaction '{transaction_id}'"),
        }
    }

    /// Returns the latest edition for the given `program ID`.
    pub fn get_latest_edition_for_program(&self, program_id: &ProgramID<N>) -> Result<Option<u16>> {
        self.storage.deployment_store().get_latest_edition_for_program(program_id)
    }

    /// Returns the edition for the given `transaction ID`.
    pub fn get_edition(&self, transaction_id: &N::TransactionID) -> Result<Option<u16>> {
        // Retrieve the transaction type.
        let Some(transaction_type) = self.transaction_ids.get_confirmed(transaction_id)?.map(|x| *x) else {
            bail!("Failed to get the type for transaction '{transaction_id}'");
        };
        // Retrieve the edition.
        match transaction_type {
            TransactionType::Deploy => self.storage.deployment_store().get_edition_for_transaction(transaction_id),
            // Return 'None'.
            TransactionType::Execute => Ok(None),
            // Return 'None'.
            TransactionType::Fee => Ok(None),
        }
    }

    /// Returns the program ID for the given `transaction ID`.
    pub fn get_program_id(&self, transaction_id: &N::TransactionID) -> Result<Option<ProgramID<N>>> {
        self.storage.deployment_store().get_program_id(transaction_id)
    }

    /// Returns the latest program for the given `program ID`.
    pub fn get_latest_program(&self, program_id: &ProgramID<N>) -> Result<Option<Program<N>>> {
        self.storage.deployment_store().get_latest_program(program_id)
    }

    /// Returns the program for the given `program ID` and `edition`.
    pub fn get_program_for_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<Program<N>>> {
        self.storage.deployment_store().get_program_for_edition(program_id, edition)
    }

    /// Returns the latest verifying key for the given `(program ID, resource name)`.
    pub fn get_latest_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.deployment_store().get_latest_verifying_key(program_id, resource_name)
    }

    /// Returns the latest verifying key for the given `(program ID, resource name, edition)`.
    /// If amendments exist for the given edition, returns the verifying key from the latest amendment.
    pub fn get_latest_verifying_key_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.deployment_store().get_latest_verifying_key_with_edition(program_id, resource_name, edition)
    }

    /// Returns the original verifying key for the given `(program ID, resource name, edition)`.
    /// This method ignores any amendments and always returns the VK from the original deployment.
    pub fn get_original_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.deployment_store().get_original_verifying_key(program_id, resource_name, edition)
    }

    /// Returns the latest certificate for the given `(program ID, resource name)`.
    pub fn get_latest_certificate(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.deployment_store().get_latest_certificate(program_id, resource_name)
    }

    /// Returns the latest certificate for the given `(program ID, resource name, edition)`.
    /// If amendments exist for the given edition, returns the certificate from the latest amendment.
    pub fn get_latest_certificate_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.deployment_store().get_latest_certificate_with_edition(program_id, resource_name, edition)
    }

    /// Returns the original certificate for the given `(program ID, resource name, edition)`.
    /// This method ignores any amendments and always returns the certificate from the original deployment.
    pub fn get_original_certificate(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.deployment_store().get_original_certificate(program_id, resource_name, edition)
    }
}

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Returns the latest transaction ID that contains the given `program ID`.
    /// If amendments exist for the latest edition, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID for the latest edition.
    pub fn find_latest_transaction_id_from_program_id(
        &self,
        program_id: &ProgramID<N>,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.deployment_store().find_latest_transaction_id_from_program_id(program_id)
    }

    /// Returns the original deployment transaction ID for the given `program ID` and `edition`.
    /// This returns the initial deployment, not any subsequent amendments.
    pub fn find_original_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.deployment_store().find_original_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the latest transaction ID for the given `program ID` and `edition`.
    /// If amendments exist, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    pub fn find_latest_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.deployment_store().find_latest_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the transaction ID for the given `program ID`, `edition`, and `amendment_index`.
    /// Returns `None` if no such amendment exists.
    pub fn find_transaction_id_from_program_id_edition_and_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.deployment_store().find_transaction_id_from_program_id_edition_and_amendment(
            program_id,
            edition,
            amendment_index,
        )
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_transition_id(transition_id)
    }
}

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Returns `true` if the given transaction ID exists.
    pub fn contains_transaction_id(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.transaction_ids.contains_key_confirmed(transaction_id)
    }

    /// Returns `true` if the given program ID exists.
    pub fn contains_program_id(&self, program_id: &ProgramID<N>) -> Result<bool> {
        self.storage.deployment_store().contains_program_id(program_id)
    }

    /// Returns `true` if the given program ID and edition exist.
    pub fn contains_program_id_and_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<bool> {
        self.storage.deployment_store().contains_program_id_and_edition(program_id, edition)
    }
}

type ProgramIDEdition<N> = (ProgramID<N>, u16);
type ProgramTriplet<N> = (ProgramID<N>, Identifier<N>, u16);

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Returns an iterator over the transaction IDs, for all transactions.
    pub fn transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.transaction_ids.keys_confirmed()
    }

    /// Returns an iterator over the deployment transaction IDs, for all deployments.
    /// Note: This includes amendments.
    pub fn deployment_transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.storage.deployment_store().deployment_transaction_ids()
    }

    /// Returns an iterator over the execution transaction IDs, for all executions.
    pub fn execution_transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.storage.execution_store().execution_transaction_ids()
    }

    /// Returns an iterator over the program IDs, for all deployments.
    /// Note: If a program upgraded, this method will return duplicates of the program ID.
    pub fn program_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, ProgramID<N>>> {
        self.storage.deployment_store().program_ids()
    }

    /// Returns an iterator over the program IDs and latest editions.
    pub fn program_ids_and_latest_editions(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramID<N>>, Cow<'_, u16>)> {
        self.storage.deployment_store().program_ids_and_latest_editions()
    }

    /// Returns an iterator over the programs, for all deployments.
    /// If a program has been upgraded, all instances of the program will be returned.
    pub fn programs(&self) -> impl '_ + Iterator<Item = Cow<'_, Program<N>>> {
        self.storage.deployment_store().programs()
    }

    /// Returns an iterator over the programs and editions, for all deployments.
    pub fn programs_with_editions(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, ProgramIDEdition<N>>, Cow<'_, Program<N>>)> {
        self.storage.deployment_store().programs_with_editions()
    }

    /// Returns an iterator over the `((program ID, function name, edition), verifying key)`, for all deployments.
    /// Note: This does not include amendments. Use `amendment_verifying_keys()` for amendment verifying keys.
    pub fn verifying_keys(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramTriplet<N>>, Cow<'_, VerifyingKey<N>>)> {
        self.storage.deployment_store().verifying_keys()
    }

    /// Returns an iterator over the `((program ID, function name, edition), certificate)`, for all deployments.
    /// Note: This does not include amendments. Use `amendment_certificates()` for amendment certificates.
    pub fn certificates(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramTriplet<N>>, Cow<'_, Certificate<N>>)> {
        self.storage.deployment_store().certificates()
    }
}

type AmendmentKey<N> = (ProgramID<N>, u16, u64);
type AmendmentVKKey<N> = (ProgramID<N>, Identifier<N>, u16, u64);

impl<N: Network, T: TransactionStorage<N>> TransactionStore<N, T> {
    /// Returns the number of amendments for the given `program ID` and `edition`.
    pub fn get_amendment_count(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<u64>> {
        self.storage.deployment_store().get_amendment_count(program_id, edition)
    }

    /// Returns `true` if the given `transaction ID` is an amendment.
    pub fn is_amendment(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.storage.deployment_store().is_amendment(transaction_id)
    }

    /// Returns the amendment info `(program ID, edition, amendment index)` for the given `transaction ID`.
    pub fn get_amendment_info(&self, transaction_id: &N::TransactionID) -> Result<Option<(ProgramID<N>, u16, u64)>> {
        self.storage.deployment_store().get_amendment_info(transaction_id)
    }

    /// Returns the verifying key for a specific amendment.
    pub fn get_verifying_key_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.deployment_store().get_verifying_key_for_amendment(
            program_id,
            function_name,
            edition,
            amendment_index,
        )
    }

    /// Returns the certificate for a specific amendment.
    pub fn get_certificate_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.deployment_store().get_certificate_for_amendment(
            program_id,
            function_name,
            edition,
            amendment_index,
        )
    }

    /// Returns the deployment for a specific amendment.
    pub fn get_deployment_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Deployment<N>>> {
        self.storage.deployment_store().get_deployment_for_amendment(program_id, edition, amendment_index)
    }

    /// Returns an iterator over the amendment transaction IDs.
    pub fn amendment_transaction_ids(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentKey<N>>, Cow<'_, N::TransactionID>)> {
        self.storage.deployment_store().amendment_transaction_ids()
    }

    /// Returns an iterator over the amendment verifying keys.
    pub fn amendment_verifying_keys(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentVKKey<N>>, Cow<'_, VerifyingKey<N>>)> {
        self.storage.deployment_store().amendment_verifying_keys()
    }

    /// Returns an iterator over the amendment certificates.
    pub fn amendment_certificates(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentVKKey<N>>, Cow<'_, Certificate<N>>)> {
        self.storage.deployment_store().amendment_certificates()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::{TransactionMemory, TransitionMemory};

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::<_, TransitionMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Initialize a new transaction store.
        let transaction_store = TransactionStore::<_, TransactionMemory<_>>::open(transition_store).unwrap();

        // Sample the transactions.
        for transaction in [
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 0, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 1, false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, true, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, true, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, true, true, rng),
            // Note: V3 deployments (amendments) are not tested here as they require a proper base deployment setup.
            // See test_v14.rs and deployment.rs tests for amendment coverage.
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0),
            snarkvm_ledger_test_helpers::sample_fee_private_transaction(rng),
            snarkvm_ledger_test_helpers::sample_fee_public_transaction(rng),
        ] {
            let transaction_id = transaction.id();

            // Ensure the transaction does not exist.
            let candidate = transaction_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the transaction.
            transaction_store.insert(&transaction).unwrap();

            // Retrieve the transaction.
            let candidate = transaction_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(Some(transaction.clone()), candidate);

            // Remove the transaction.
            transaction_store.remove(&transaction_id).unwrap();

            // Ensure the transaction does not exist.
            let candidate = transaction_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the transaction again.
            transaction_store.insert(&transaction).unwrap();
        }
    }

    #[test]
    fn test_find_transaction_id() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::<_, TransitionMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Initialize a new transaction store.
        let transaction_store = TransactionStore::<_, TransactionMemory<_>>::open(transition_store).unwrap();

        // Sample the transactions.
        for transaction in [
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 0, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 1, false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, false, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, false, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, true, true, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, true, false, rng),
            snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, true, true, rng),
            // Note: V3 deployments (amendments) are not tested here as they require a proper base deployment setup.
            // See test_v14.rs and deployment.rs tests for amendment coverage.
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 1),
            Transaction::from_fee(snarkvm_ledger_test_helpers::sample_fee_private(
                snarkvm_console::types::Field::rand(rng),
                rng,
            ))
            .unwrap(),
            Transaction::from_fee(snarkvm_ledger_test_helpers::sample_fee_public(
                snarkvm_console::types::Field::rand(rng),
                rng,
            ))
            .unwrap(),
        ] {
            let transaction_id = transaction.id();
            let transition_ids = transaction.transition_ids();

            // Ensure the execution transaction does not exist.
            let candidate = transaction_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            for transition_id in transition_ids {
                // Ensure the transition ID is not found.
                let candidate = transaction_store.find_transaction_id_from_transition_id(transition_id).unwrap();
                assert_eq!(None, candidate);

                // Insert the transaction.
                transaction_store.insert(&transaction).unwrap();

                // Find the transaction ID.
                let candidate = transaction_store.find_transaction_id_from_transition_id(transition_id).unwrap();
                assert_eq!(Some(transaction_id), candidate);

                // Remove the transaction.
                transaction_store.remove(&transaction_id).unwrap();

                // Ensure the transaction ID is not found.
                let candidate = transaction_store.find_transaction_id_from_transition_id(transition_id).unwrap();
                assert_eq!(None, candidate);
            }

            // Insert the transaction.
            transaction_store.insert(&transaction).unwrap();

            // If the transaction was a deployment, find it through the other getters.
            if let Some(deployment) = transaction.deployment() {
                // Get the program ID.
                let program_id = deployment.program().id();
                // Get the edition.
                let edition = deployment.edition();
                // Get and check the latest transaction ID for the program ID.
                let candidate = transaction_store.find_latest_transaction_id_from_program_id(program_id).unwrap();
                assert_eq!(Some(transaction_id), candidate);
                // Get the check the original transaction ID for the program ID and edition.
                let candidate = transaction_store
                    .find_original_transaction_id_from_program_id_and_edition(program_id, edition)
                    .unwrap();
                assert_eq!(Some(transaction_id), candidate);
            }
        }
    }
}
