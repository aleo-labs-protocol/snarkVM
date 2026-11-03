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
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::{
    network::prelude::*,
    program::{Identifier, ProgramID, ProgramOwner},
    types::U8,
};
use snarkvm_ledger_block::{Deployment, DeploymentVersion, Fee, Transaction};
use snarkvm_synthesizer_program::Program;
use snarkvm_synthesizer_snark::{Certificate, VerifyingKey};

use aleo_std_storage::StorageMode;
use anyhow::Result;
use core::marker::PhantomData;
use std::borrow::Cow;

/// A trait for deployment storage.
/// The deployment storage contains the `Deployment`s for all programs deployed on the network.
/// The storage has been migrated a few to times to support new features.
/// Here we describe the changes made to the storage and the invariants that must hold.
/// - **ConsensusVersion::V1..V7**: The deployment edition is always zero. The `IDEditionMap` and `ChecksumMap` did not exist.
/// - **ConsensusVersion::V8**: The deployment edition is either zero or one. The `IDEditionMap` is introduced and the `EditionMap`
///   is interpreted as the latest edition for the program ID. The `ChecksumMap` did not exist.
/// - **ConsensusVersion::V9**: The deployment edition can be any value from zero to `u16::MAX`. The `ChecksumMap` is introduced and
///   stores the program checksum, required in each deployment after `ConsensusVersion::V9`.
/// - **ConsensusVersion::V14**: V3 deployments (amendments) are introduced. Amendments update VKs for an existing
///   `(program ID, edition)` without changing the edition. Amendments must target the latest edition
///   and require at least one VK to differ from the existing deployment.
pub trait DeploymentStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transaction ID` to `program ID`.
    type IDMap: for<'a> Map<'a, N::TransactionID, ProgramID<N>>;
    /// The mapping of `transaction ID` to `edition`.
    /// This was introduced in `ConsensusVersion::V8`.
    type IDEditionMap: for<'a> Map<'a, N::TransactionID, u16>;
    /// The mapping of `program ID` to the **latest** `edition`.
    type EditionMap: for<'a> Map<'a, ProgramID<N>, u16>;
    /// The mapping of `(program ID, edition)` to `transaction ID`.
    type ReverseIDMap: for<'a> Map<'a, (ProgramID<N>, u16), N::TransactionID>;
    /// The mapping of `(program ID, edition)` to `ProgramOwner`.
    type OwnerMap: for<'a> Map<'a, (ProgramID<N>, u16), ProgramOwner<N>>;
    /// The mapping of `(program ID, edition)` to `program`.
    type ProgramMap: for<'a> Map<'a, (ProgramID<N>, u16), Program<N>>;
    /// The mapping of `(program ID, edition)` to `checksum`.
    /// This was introduced in `ConsensusVersion::V9`.
    type ChecksumMap: for<'a> Map<'a, (ProgramID<N>, u16), [U8<N>; 32]>;
    /// The mapping of `(program ID, resource name, edition)` to `verifying key`.
    /// The resource name is a function or record identifier.
    type VerifyingKeyMap: for<'a> Map<'a, (ProgramID<N>, Identifier<N>, u16), VerifyingKey<N>>;
    /// The mapping of `(program ID, resource name, edition)` to `certificate`.
    /// The resource name is a function or record identifier.
    type CertificateMap: for<'a> Map<'a, (ProgramID<N>, Identifier<N>, u16), Certificate<N>>;
    /// The fee storage.
    type FeeStorage: FeeStorage<N>;
    /// The mapping of `(program ID, edition)` to the next amendment index.
    type AmendmentNextIndexMap: for<'a> Map<'a, (ProgramID<N>, u16), u64>;
    /// The mapping of `(program ID, edition, amendment index)` to `transaction ID`.
    type AmendmentIDMap: for<'a> Map<'a, (ProgramID<N>, u16, u64), N::TransactionID>;
    /// The mapping of `transaction ID` to `(program ID, edition, amendment index)`.
    type ReverseAmendmentIDMap: for<'a> Map<'a, N::TransactionID, (ProgramID<N>, u16, u64)>;
    /// The mapping of `(program ID, resource name, edition, amendment index)` to `verifying key`.
    /// The resource name is a function or record identifier.
    type AmendmentVerifyingKeyMap: for<'a> Map<'a, (ProgramID<N>, Identifier<N>, u16, u64), VerifyingKey<N>>;
    /// The mapping of `(program ID, resource name, edition, amendment index)` to `certificate`.
    /// The resource name is a function or record identifier.
    type AmendmentCertificateMap: for<'a> Map<'a, (ProgramID<N>, Identifier<N>, u16, u64), Certificate<N>>;
    /// The mapping of `(program ID, edition, amendment index)` to `ProgramOwner`.
    type AmendmentOwnerMap: for<'a> Map<'a, (ProgramID<N>, u16, u64), ProgramOwner<N>>;

    /// Initializes the deployment storage.
    fn open(fee_store: FeeStore<N, Self::FeeStorage>) -> Result<Self>;

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap;
    /// Returns the ID edition map.
    fn id_edition_map(&self) -> &Self::IDEditionMap;
    /// Returns the edition map.
    fn edition_map(&self) -> &Self::EditionMap;
    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap;
    /// Returns the owner map.
    fn owner_map(&self) -> &Self::OwnerMap;
    /// Returns the program map.
    fn program_map(&self) -> &Self::ProgramMap;
    /// Returns the checksum map.
    fn checksum_map(&self) -> &Self::ChecksumMap;
    /// Returns the verifying key map.
    fn verifying_key_map(&self) -> &Self::VerifyingKeyMap;
    /// Returns the certificate map.
    fn certificate_map(&self) -> &Self::CertificateMap;
    /// Returns the fee storage.
    fn fee_store(&self) -> &FeeStore<N, Self::FeeStorage>;
    /// Returns the amendment next index map.
    fn amendment_next_index_map(&self) -> &Self::AmendmentNextIndexMap;
    /// Returns the amendment ID map.
    fn amendment_id_map(&self) -> &Self::AmendmentIDMap;
    /// Returns the reverse amendment ID map.
    fn reverse_amendment_id_map(&self) -> &Self::ReverseAmendmentIDMap;
    /// Returns the amendment verifying key map.
    fn amendment_verifying_key_map(&self) -> &Self::AmendmentVerifyingKeyMap;
    /// Returns the amendment certificate map.
    fn amendment_certificate_map(&self) -> &Self::AmendmentCertificateMap;
    /// Returns the amendment owner map.
    fn amendment_owner_map(&self) -> &Self::AmendmentOwnerMap;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        self.fee_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.id_map().start_atomic();
        self.id_edition_map().start_atomic();
        self.edition_map().start_atomic();
        self.reverse_id_map().start_atomic();
        self.owner_map().start_atomic();
        self.program_map().start_atomic();
        self.checksum_map().start_atomic();
        self.verifying_key_map().start_atomic();
        self.certificate_map().start_atomic();
        self.fee_store().start_atomic();
        self.amendment_next_index_map().start_atomic();
        self.amendment_id_map().start_atomic();
        self.reverse_amendment_id_map().start_atomic();
        self.amendment_verifying_key_map().start_atomic();
        self.amendment_certificate_map().start_atomic();
        self.amendment_owner_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.id_map().is_atomic_in_progress()
            || self.id_edition_map().is_atomic_in_progress()
            || self.edition_map().is_atomic_in_progress()
            || self.reverse_id_map().is_atomic_in_progress()
            || self.owner_map().is_atomic_in_progress()
            || self.program_map().is_atomic_in_progress()
            || self.checksum_map().is_atomic_in_progress()
            || self.verifying_key_map().is_atomic_in_progress()
            || self.certificate_map().is_atomic_in_progress()
            || self.fee_store().is_atomic_in_progress()
            || self.amendment_next_index_map().is_atomic_in_progress()
            || self.amendment_id_map().is_atomic_in_progress()
            || self.reverse_amendment_id_map().is_atomic_in_progress()
            || self.amendment_verifying_key_map().is_atomic_in_progress()
            || self.amendment_certificate_map().is_atomic_in_progress()
            || self.amendment_owner_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.id_map().atomic_checkpoint();
        self.id_edition_map().atomic_checkpoint();
        self.edition_map().atomic_checkpoint();
        self.reverse_id_map().atomic_checkpoint();
        self.owner_map().atomic_checkpoint();
        self.program_map().atomic_checkpoint();
        self.checksum_map().atomic_checkpoint();
        self.verifying_key_map().atomic_checkpoint();
        self.certificate_map().atomic_checkpoint();
        self.fee_store().atomic_checkpoint();
        self.amendment_next_index_map().atomic_checkpoint();
        self.amendment_id_map().atomic_checkpoint();
        self.reverse_amendment_id_map().atomic_checkpoint();
        self.amendment_verifying_key_map().atomic_checkpoint();
        self.amendment_certificate_map().atomic_checkpoint();
        self.amendment_owner_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.id_map().clear_latest_checkpoint();
        self.id_edition_map().clear_latest_checkpoint();
        self.edition_map().clear_latest_checkpoint();
        self.reverse_id_map().clear_latest_checkpoint();
        self.owner_map().clear_latest_checkpoint();
        self.program_map().clear_latest_checkpoint();
        self.checksum_map().clear_latest_checkpoint();
        self.verifying_key_map().clear_latest_checkpoint();
        self.certificate_map().clear_latest_checkpoint();
        self.fee_store().clear_latest_checkpoint();
        self.amendment_next_index_map().clear_latest_checkpoint();
        self.amendment_id_map().clear_latest_checkpoint();
        self.reverse_amendment_id_map().clear_latest_checkpoint();
        self.amendment_verifying_key_map().clear_latest_checkpoint();
        self.amendment_certificate_map().clear_latest_checkpoint();
        self.amendment_owner_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.id_map().atomic_rewind();
        self.id_edition_map().atomic_rewind();
        self.edition_map().atomic_rewind();
        self.reverse_id_map().atomic_rewind();
        self.owner_map().atomic_rewind();
        self.program_map().atomic_rewind();
        self.checksum_map().atomic_rewind();
        self.verifying_key_map().atomic_rewind();
        self.certificate_map().atomic_rewind();
        self.fee_store().atomic_rewind();
        self.amendment_next_index_map().atomic_rewind();
        self.amendment_id_map().atomic_rewind();
        self.reverse_amendment_id_map().atomic_rewind();
        self.amendment_verifying_key_map().atomic_rewind();
        self.amendment_certificate_map().atomic_rewind();
        self.amendment_owner_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.id_map().abort_atomic();
        self.id_edition_map().abort_atomic();
        self.edition_map().abort_atomic();
        self.reverse_id_map().abort_atomic();
        self.owner_map().abort_atomic();
        self.program_map().abort_atomic();
        self.checksum_map().abort_atomic();
        self.verifying_key_map().abort_atomic();
        self.certificate_map().abort_atomic();
        self.fee_store().abort_atomic();
        self.amendment_next_index_map().abort_atomic();
        self.amendment_id_map().abort_atomic();
        self.reverse_amendment_id_map().abort_atomic();
        self.amendment_verifying_key_map().abort_atomic();
        self.amendment_certificate_map().abort_atomic();
        self.amendment_owner_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.id_map().finish_atomic()?;
        self.id_edition_map().finish_atomic()?;
        self.edition_map().finish_atomic()?;
        self.reverse_id_map().finish_atomic()?;
        self.owner_map().finish_atomic()?;
        self.program_map().finish_atomic()?;
        self.checksum_map().finish_atomic()?;
        self.verifying_key_map().finish_atomic()?;
        self.certificate_map().finish_atomic()?;
        self.fee_store().finish_atomic()?;
        self.amendment_next_index_map().finish_atomic()?;
        self.amendment_id_map().finish_atomic()?;
        self.reverse_amendment_id_map().finish_atomic()?;
        self.amendment_verifying_key_map().finish_atomic()?;
        self.amendment_certificate_map().finish_atomic()?;
        self.amendment_owner_map().finish_atomic()
    }

    /// Stores the given `deployment transaction` into storage.
    fn insert(&self, transaction: &Transaction<N>) -> Result<()> {
        // Ensure the transaction is a deployment.
        let (transaction_id, owner, deployment, fee) = match transaction {
            Transaction::Deploy(transaction_id, _, owner, deployment, fee) => (transaction_id, owner, deployment, fee),
            Transaction::Execute(..) => bail!("Attempted to insert an execute transaction into deployment storage."),
            Transaction::Fee(..) => bail!("Attempted to insert fee transaction into deployment storage."),
        };

        // Ensure the deployment is ordered.
        if let Err(error) = deployment.check_is_ordered() {
            bail!("Failed to insert malformed deployment transaction: {error}")
        }

        // Retrieve the edition.
        let edition = deployment.edition();
        // Retrieve the program.
        let program = deployment.program();
        // Retrieve the program ID.
        let program_id = *program.id();
        // Retrieve the checksum.
        let checksum = deployment.program_checksum();
        // Check if this is an amendment.
        let is_amendment = deployment.version()? == DeploymentVersion::V3;

        // Handle amendments separately from regular deployments.
        if is_amendment {
            // Amendments must target the latest edition of the program.
            let Some(latest_edition) = self.edition_map().get_confirmed(&program_id)?.map(|e| *e) else {
                bail!(
                    "Failed to insert amendment transaction '{transaction_id}' for program '{program_id}': program does not exist"
                );
            };
            ensure!(
                edition == latest_edition,
                "Failed to insert amendment transaction '{transaction_id}' for program '{program_id}': expected edition {latest_edition}, found edition {edition}"
            );

            // Get the current amendment count, or initialize to 0 if this is the first amendment.
            // This is the only site that assigns and increments amendment indices.
            let amendment_index =
                self.amendment_next_index_map().get_confirmed(&(program_id, edition))?.map(|c| *c).unwrap_or(0);

            atomic_batch_scope!(self, {
                // Store the program ID.
                self.id_map().insert(*transaction_id, program_id)?;
                // Store the edition for the transaction ID.
                // Note: Amendments reuse the same `(program_id, edition)` as the base deployment.
                self.id_edition_map().insert(*transaction_id, edition)?;

                // Store the amendment ID mapping for (program_id, edition, amendment_index) -> transaction_id.
                self.amendment_id_map().insert((program_id, edition, amendment_index), *transaction_id)?;
                // Store the reverse amendment ID mapping for transaction_id -> (program_id, edition, amendment_index).
                self.reverse_amendment_id_map().insert(*transaction_id, (program_id, edition, amendment_index))?;
                // Store the amendment owner.
                self.amendment_owner_map().insert((program_id, edition, amendment_index), *owner)?;

                // Store all verifying keys and certificates (unified: functions + records).
                for (name, (verifying_key, certificate)) in deployment.verifying_keys() {
                    // Store the verifying key.
                    self.amendment_verifying_key_map()
                        .insert((program_id, *name, edition, amendment_index), verifying_key.clone())?;
                    // Store the certificate.
                    self.amendment_certificate_map()
                        .insert((program_id, *name, edition, amendment_index), certificate.clone())?;
                }

                // Increment the amendment count.
                // Note: Overflow is unreachable in practice — this is the only site that increments
                // the counter, and each increment requires a full transaction with a fee. If overflow
                // somehow occurred, this bail would cause a liveness failure (valid-looking blocks that
                // fail at storage insertion), so the single-increment invariant must be preserved.
                let next_index = amendment_index.checked_add(1).ok_or_else(|| {
                    anyhow!("Amendment index overflow for program '{program_id}' (edition {edition})")
                })?;
                self.amendment_next_index_map().insert((program_id, edition), next_index)?;

                // Store the fee transition.
                self.fee_store().insert(*transaction_id, fee)?;

                Ok(())
            })
        } else {
            // Ensure the edition is incremented correctly.
            let expected_edition = match self.get_latest_edition_for_program(&program_id)? {
                Some(latest_edition) => latest_edition.saturating_add(1),
                None => 0,
            };
            ensure!(
                edition == expected_edition,
                "Failed to insert deployment transaction '{transaction_id}' for program '{program_id}', expected edition {expected_edition}, found edition {edition}"
            );

            atomic_batch_scope!(self, {
                // Store the program ID.
                self.id_map().insert(*transaction_id, program_id)?;
                // Store the latest edition for the program ID.
                self.edition_map().insert(program_id, edition)?;

                // Store the reverse program ID.
                self.reverse_id_map().insert((program_id, edition), *transaction_id)?;
                // Store the owner.
                self.owner_map().insert((program_id, edition), *owner)?;
                // Store the program.
                self.program_map().insert((program_id, edition), program.clone())?;

                // Store the edition in the ID edition map.
                self.id_edition_map().insert(*transaction_id, edition)?;

                // If the checksum exists, then store it into the `ChecksumMap`.
                if let Some(checksum) = checksum {
                    self.checksum_map().insert((program_id, edition), checksum)?;
                }

                // Store all verifying keys and certificates (unified: functions + records).
                for (name, (verifying_key, certificate)) in deployment.verifying_keys() {
                    // Store the verifying key.
                    self.verifying_key_map().insert((program_id, *name, edition), verifying_key.clone())?;
                    // Store the certificate.
                    self.certificate_map().insert((program_id, *name, edition), certificate.clone())?;
                }

                // Store the fee transition.
                self.fee_store().insert(*transaction_id, fee)?;

                Ok(())
            })
        }
    }

    /// Removes the deployment transaction for the given `transaction ID`.
    fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        // Check if this is an amendment.
        if let Some(amendment_info) = self.reverse_amendment_id_map().get_confirmed(transaction_id)? {
            let (program_id, edition, amendment_index) = *amendment_info;

            // Retrieve the current amendment count.
            let Some(current_count) = self.amendment_next_index_map().get_confirmed(&(program_id, edition))? else {
                bail!("Failed to locate amendment count for program '{program_id}' (edition {edition})");
            };
            let count = *current_count;

            // Verify that we're removing the latest amendment.
            let latest_index = count.checked_sub(1).ok_or_else(|| {
                anyhow!(
                    "Amendment count is zero for program '{program_id}' (edition {edition}), but an amendment exists"
                )
            })?;
            ensure!(
                amendment_index == latest_index,
                "Failed to remove amendment for transaction '{transaction_id}' because it is not the latest amendment"
            );

            // Retrieve the program to get function names.
            let Some(program) = self.program_map().get_confirmed(&(program_id, edition))?.map(|x| x.into_owned())
            else {
                bail!("Failed to locate program '{program_id}' for transaction '{transaction_id}'");
            };

            atomic_batch_scope!(self, {
                // Remove from id_map and id_edition_map.
                self.id_map().remove(transaction_id)?;
                self.id_edition_map().remove(transaction_id)?;

                // Remove the amendment ID mapping.
                self.amendment_id_map().remove(&(program_id, edition, amendment_index))?;
                // Remove the amendment reverse ID mapping.
                self.reverse_amendment_id_map().remove(transaction_id)?;
                // Remove the amendment owner.
                self.amendment_owner_map().remove(&(program_id, edition, amendment_index))?;

                // Remove all verifying keys and certificates (unified: functions + records).
                // Note: This enumerates from the program's functions and records, which is equivalent
                // to the `deployment.verifying_keys()` used during insert, as `check_is_ordered` guarantees
                // the deployment contains exactly one VK per function followed by one VK per record.
                for function_name in program.functions().keys() {
                    self.amendment_verifying_key_map().remove(&(
                        program_id,
                        *function_name,
                        edition,
                        amendment_index,
                    ))?;
                    self.amendment_certificate_map().remove(&(program_id, *function_name, edition, amendment_index))?;
                }
                for record_name in program.records().keys() {
                    self.amendment_verifying_key_map().remove(&(program_id, *record_name, edition, amendment_index))?;
                    self.amendment_certificate_map().remove(&(program_id, *record_name, edition, amendment_index))?;
                }

                // Update the amendment count.
                // Note: `count` is guaranteed >= 1 from the `checked_sub(1)` above.
                match count == 1 {
                    // If this was the only amendment, remove the count entry entirely.
                    true => self.amendment_next_index_map().remove(&(program_id, edition))?,
                    // Otherwise, decrement the count. Safe because count >= 2 in this branch.
                    false => {
                        let decremented = count.checked_sub(1).ok_or_else(|| {
                            anyhow!("Amendment count underflow for program '{program_id}' (edition {edition})")
                        })?;
                        self.amendment_next_index_map().insert((program_id, edition), decremented)?
                    }
                }

                // Remove the fee transition.
                self.fee_store().remove(transaction_id)?;

                Ok(())
            })
        } else {
            // Retrieve the program ID.
            let Some(program_id) = self.get_program_id(transaction_id)? else {
                bail!("Failed to get the program ID for transaction '{transaction_id}'");
            };
            // Retrieve the edition for the transaction ID.
            let Some(edition) = self.get_edition_for_transaction(transaction_id)? else {
                bail!("Failed to locate the edition for transaction '{transaction_id}'");
            };
            // Retrieve the latest edition for the program ID.
            let Some(latest_edition) = self.get_latest_edition_for_program(&program_id)? else {
                bail!("Failed to locate the latest edition for program '{program_id}'");
            };
            // Verify that the removed edition is latest edition.
            ensure!(
                edition == latest_edition,
                "Failed to remove the deployment for transaction '{transaction_id}' because it is not the latest edition"
            );
            // Verify that no amendments exist for this deployment.
            let amendment_count =
                self.amendment_next_index_map().get_confirmed(&(program_id, edition))?.map(|c| *c).unwrap_or(0);
            ensure!(
                amendment_count == 0,
                "Failed to remove deployment for program '{program_id}' (edition {edition}): {amendment_count} amendment(s) must be removed first"
            );
            // Retrieve the program.
            let Some(program) = self.program_map().get_confirmed(&(program_id, edition))?.map(|x| x.into_owned())
            else {
                bail!("Failed to locate program '{program_id}' for transaction '{transaction_id}'");
            };

            atomic_batch_scope!(self, {
                // Remove the program ID.
                self.id_map().remove(transaction_id)?;
                // Remove the edition for the transaction ID.
                self.id_edition_map().remove(transaction_id)?;
                // Update the latest edition.
                match edition.is_zero() {
                    // If the removed edition is 0, then remove the program ID from the latest edition map.
                    true => self.edition_map().remove(&program_id)?,
                    // Otherwise, decrement the edition.
                    false => self.edition_map().insert(program_id, edition.saturating_sub(1))?,
                }

                // Remove the reverse program ID.
                self.reverse_id_map().remove(&(program_id, edition))?;
                // Remove the owner.
                self.owner_map().remove(&(program_id, edition))?;
                // Remove the program.
                self.program_map().remove(&(program_id, edition))?;
                // Remove the checksum.
                self.checksum_map().remove(&(program_id, edition))?;

                // Remove the verifying keys and certificates.
                for function_name in program.functions().keys() {
                    // Remove the verifying key.
                    self.verifying_key_map().remove(&(program_id, *function_name, edition))?;
                    // Remove the certificate.
                    self.certificate_map().remove(&(program_id, *function_name, edition))?;
                }

                // Remove the record verifying keys and certificates.
                for record_name in program.records().keys() {
                    // Remove the verifying key.
                    self.verifying_key_map().remove(&(program_id, *record_name, edition))?;
                    // Remove the certificate.
                    self.certificate_map().remove(&(program_id, *record_name, edition))?;
                }

                // Remove the fee transition.
                self.fee_store().remove(transaction_id)?;

                Ok(())
            })
        }
    }

    /// Returns the latest transaction ID that contains the given `program ID`.
    /// If amendments exist for the latest edition, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    fn find_latest_transaction_id_from_program_id(
        &self,
        program_id: &ProgramID<N>,
    ) -> Result<Option<N::TransactionID>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve the latest edition.
        let Some(edition) = self.get_latest_edition_for_program(program_id)? else {
            return Ok(None);
        };

        // If amendments exist, return the latest amendment transaction ID.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(transaction_id) = self.amendment_id_map().get_confirmed(&(*program_id, edition, latest_index))?
            else {
                bail!(
                    "Failed to find the amendment transaction ID for program '{program_id}' (edition {edition}, index {latest_index})"
                );
            };
            return Ok(Some(*transaction_id));
        }

        // No amendments, retrieve the base deployment transaction ID.
        let Some(transaction_id) = self.reverse_id_map().get_confirmed(&(*program_id, edition))? else {
            bail!("Failed to find the transaction ID for program '{program_id}' (edition {edition})");
        };
        Ok(Some(*transaction_id))
    }

    /// Returns the original deployment transaction ID for the given `program ID` and `edition`.
    /// This returns the initial deployment, not any subsequent amendments.
    fn find_original_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }
        // Retrieve the transaction ID.
        match self.reverse_id_map().get_confirmed(&(*program_id, edition))? {
            Some(transaction_id) => Ok(Some(*transaction_id)),
            None => Ok(None),
        }
    }

    /// Returns the latest transaction ID for the given `program ID` and `edition`.
    /// If amendments exist, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    fn find_latest_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // If amendments exist, return the latest amendment transaction ID.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(transaction_id) = self.amendment_id_map().get_confirmed(&(*program_id, edition, latest_index))?
            else {
                bail!(
                    "Failed to find the amendment transaction ID for program '{program_id}' (edition {edition}, index {latest_index})"
                );
            };
            return Ok(Some(*transaction_id));
        }

        // No amendments, return the original deployment transaction ID.
        match self.reverse_id_map().get_confirmed(&(*program_id, edition))? {
            Some(transaction_id) => Ok(Some(*transaction_id)),
            None => Ok(None),
        }
    }

    /// Returns the transaction ID for the given `program ID`, `edition`, and `amendment_index`.
    /// Returns `None` if no such amendment exists.
    fn find_transaction_id_from_program_id_edition_and_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<N::TransactionID>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve the amendment transaction ID.
        match self.amendment_id_map().get_confirmed(&(*program_id, edition, amendment_index))? {
            Some(transaction_id) => Ok(Some(*transaction_id)),
            None => Ok(None),
        }
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.fee_store().find_transaction_id_from_transition_id(transition_id)
    }

    /// Returns the program ID for the given `transaction ID`.
    fn get_program_id(&self, transaction_id: &N::TransactionID) -> Result<Option<ProgramID<N>>> {
        Ok(self.id_map().get_confirmed(transaction_id)?.map(|x| *x))
    }

    /// Returns the latest edition for the given `program ID`.
    fn get_latest_edition_for_program(&self, program_id: &ProgramID<N>) -> Result<Option<u16>> {
        Ok(self.edition_map().get_confirmed(program_id)?.map(|x| *x))
    }

    /// Returns the edition for the given `transaction ID`.
    fn get_edition_for_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<u16>> {
        match self.id_edition_map().get_confirmed(transaction_id)? {
            Some(edition) => Ok(Some(*edition)),
            None => {
                // Check if the program exists in the store.
                match self.id_map().get_confirmed(transaction_id)?.is_none() {
                    true => Ok(None),
                    // If a program is not in the `IDEditionMap` but exists in the `IDMap`,
                    // then it was deployed before `ConsensusVersion::V8` when editions were not tracked.
                    // These deployments are always edition zero, so returning `Some(0)` is safe.
                    false => Ok(Some(0)),
                }
            }
        }
    }

    /// Returns the latest program for the given `program ID`.
    fn get_latest_program(&self, program_id: &ProgramID<N>) -> Result<Option<Program<N>>> {
        // Retrieve the latest edition.
        let edition = match self.get_latest_edition_for_program(program_id)? {
            Some(edition) => edition,
            None => return Ok(None),
        };
        // Retrieve the program.
        let Some(program) = self.program_map().get_confirmed(&(*program_id, edition))? else {
            bail!("Failed to get program '{program_id}' (edition {edition})");
        };
        Ok(Some(program.into_owned()))
    }

    /// Returns the program for the given `program ID` and `edition`.
    fn get_program_for_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<Program<N>>> {
        self.program_map().get_confirmed(&(*program_id, edition)).map(|p| p.map(|p| p.into_owned()))
    }

    /// Returns the latest verifying key for the given `program ID` and `resource name`.
    /// If amendments exist, returns the verifying key from the latest amendment.
    /// Bails if the program exists but the key is missing.
    fn get_latest_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<VerifyingKey<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            // Load the verifying key.
            let verifying_key = if resource_name == &Identifier::from_str("credits")? {
                N::translation_credits_verifying_key()
            } else {
                N::get_credits_verifying_key(resource_name.to_string())?
            };
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Return the verifying key.
            return Ok(Some(VerifyingKey::new(verifying_key.clone(), num_variables)));
        }

        // Retrieve the latest edition.
        let Some(edition) = self.get_latest_edition_for_program(program_id)? else {
            return Ok(None);
        };

        // Check if there are amendments for this program/edition.
        // If amendments exist, return the verifying key from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(verifying_key) = self.amendment_verifying_key_map().get_confirmed(&(
                *program_id,
                *resource_name,
                edition,
                latest_index,
            ))?
            else {
                bail!(
                    "Failed to get the amendment verifying key for '{program_id}/{resource_name}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(verifying_key.into_owned()));
        }

        // No amendments, retrieve from regular verifying key map.
        let Some(verifying_key) = self.verifying_key_map().get_confirmed(&(*program_id, *resource_name, edition))?
        else {
            bail!("Failed to get the verifying key for '{program_id}/{resource_name}' (edition {edition})");
        };
        Ok(Some(verifying_key.into_owned()))
    }

    /// Returns the verifying key for the given `program ID`, `resource name` and `edition`.
    /// If amendments exist for the given edition, returns the verifying key from the latest amendment.
    /// Bails if the program exists but the key is missing.
    fn get_latest_verifying_key_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            // Load the verifying key.
            let verifying_key = if resource_name == &Identifier::from_str("credits")? {
                N::translation_credits_verifying_key()
            } else {
                N::get_credits_verifying_key(resource_name.to_string())?
            };
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Return the verifying key.
            return Ok(Some(VerifyingKey::new(verifying_key.clone(), num_variables)));
        }

        // Check if there are amendments for this program/edition.
        // If amendments exist, return the verifying key from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(verifying_key) = self.amendment_verifying_key_map().get_confirmed(&(
                *program_id,
                *resource_name,
                edition,
                latest_index,
            ))?
            else {
                bail!(
                    "Failed to get the amendment verifying key for '{program_id}/{resource_name}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(verifying_key.into_owned()));
        }

        // No amendments, retrieve from regular verifying key map.
        match self.verifying_key_map().get_confirmed(&(*program_id, *resource_name, edition))? {
            Some(verifying_key) => Ok(Some(verifying_key.into_owned())),
            None => bail!("Failed to get the verifying key for '{program_id}/{resource_name}' (edition {edition})"),
        }
    }

    /// Returns the original verifying key for the given `program ID`, `resource name` and `edition`.
    /// This method ignores any amendments and always returns the VK from the original deployment.
    /// Returns `None` if the key was not stored (e.g., record VKs before V14).
    fn get_original_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            // Load the verifying key.
            let verifying_key = if resource_name == &Identifier::from_str("credits")? {
                N::translation_credits_verifying_key()
            } else {
                N::get_credits_verifying_key(resource_name.to_string())?
            };
            // Retrieve the number of public and private variables.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Return the verifying key.
            return Ok(Some(VerifyingKey::new(verifying_key.clone(), num_variables)));
        }

        // Retrieve from the original verifying key map, ignoring any amendments.
        match self.verifying_key_map().get_confirmed(&(*program_id, *resource_name, edition))? {
            Some(verifying_key) => Ok(Some(verifying_key.into_owned())),
            None => Ok(None),
        }
    }

    /// Returns the latest certificate for the given `program ID` and `resource name`.
    /// If amendments exist, returns the certificate from the latest amendment.
    /// Bails if the program exists but the certificate is missing.
    fn get_latest_certificate(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<Certificate<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve the latest edition.
        let Some(edition) = self.get_latest_edition_for_program(program_id)? else {
            return Ok(None);
        };

        // If amendments exist, return the certificate from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(certificate) = self.amendment_certificate_map().get_confirmed(&(
                *program_id,
                *resource_name,
                edition,
                latest_index,
            ))?
            else {
                bail!(
                    "Failed to get the amendment certificate for '{program_id}/{resource_name}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(certificate.into_owned()));
        }

        // No amendments, retrieve from regular certificate map.
        let Some(certificate) = self.certificate_map().get_confirmed(&(*program_id, *resource_name, edition))? else {
            bail!("Failed to get the certificate for '{program_id}/{resource_name}' (edition {edition})");
        };
        Ok(Some(certificate.into_owned()))
    }

    /// Returns the certificate for the given `program ID`, `resource name`, and `edition`.
    /// If amendments exist for the given edition, returns the certificate from the latest amendment.
    /// Bails if the program exists but the certificate is missing.
    fn get_latest_certificate_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // If amendments exist, return the certificate from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(certificate) = self.amendment_certificate_map().get_confirmed(&(
                *program_id,
                *resource_name,
                edition,
                latest_index,
            ))?
            else {
                bail!(
                    "Failed to get the amendment certificate for '{program_id}/{resource_name}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(certificate.into_owned()));
        }

        // No amendments, retrieve from regular certificate map.
        match self.certificate_map().get_confirmed(&(*program_id, *resource_name, edition))? {
            Some(certificate) => Ok(Some(certificate.into_owned())),
            None => {
                bail!("Failed to get the certificate for '{program_id}/{resource_name}' (edition {edition})")
            }
        }
    }

    /// Returns the original certificate for the given `program ID`, `resource name` and `edition`.
    /// This method ignores any amendments and always returns the certificate from the original deployment.
    /// Returns `None` if the certificate was not stored (e.g., record certificates before V14).
    fn get_original_certificate(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve from the original certificate map, ignoring any amendments.
        match self.certificate_map().get_confirmed(&(*program_id, *resource_name, edition))? {
            Some(certificate) => Ok(Some(certificate.into_owned())),
            None => Ok(None),
        }
    }

    /// Returns the deployment for the given `transaction ID`.
    /// If the transaction is an amendment, returns the deployment with updated VKs and no owner.
    /// Use `get_transaction()` to retrieve the amendment owner.
    /// Otherwise, returns the original base deployment.
    fn get_deployment(&self, transaction_id: &N::TransactionID) -> Result<Option<Deployment<N>>> {
        // Check if this is an amendment.
        if let Some(amendment_info) = self.reverse_amendment_id_map().get_confirmed(transaction_id)? {
            let (program_id, edition, amendment_index) = *amendment_info;

            // Retrieve the program.
            let Some(program) = self.program_map().get_confirmed(&(program_id, edition))?.map(|x| x.into_owned())
            else {
                bail!("Failed to get the deployed program '{program_id}' (edition {edition})");
            };

            // Initialize a vector for the verifying keys and certificates.
            let mut verifying_keys = Vec::with_capacity(program.functions().len() + program.records().len());

            // Amendments derive the checksum from the program.
            let program_checksum = Some(program.to_checksum());

            // Amendments have no owner in the Deployment struct.
            let program_owner = None;

            // Retrieve the verifying keys and certificates.
            for function_name in program.functions().keys() {
                let Some(verifying_key) = self
                    .amendment_verifying_key_map()
                    .get_confirmed(&(program_id, *function_name, edition, amendment_index))?
                    .map(|x| x.into_owned())
                else {
                    bail!(
                        "Failed to get the verifying key for '{program_id}/{function_name}' (edition {edition}, amendment {amendment_index})"
                    );
                };
                let Some(certificate) = self
                    .amendment_certificate_map()
                    .get_confirmed(&(program_id, *function_name, edition, amendment_index))?
                    .map(|x| x.into_owned())
                else {
                    bail!(
                        "Failed to get the certificate for '{program_id}/{function_name}' (edition {edition}, amendment {amendment_index})"
                    );
                };
                verifying_keys.push((*function_name, (verifying_key, certificate)));
            }

            // Retrieve the translation (record) verifying keys and certificates from amendment maps.
            // Note: V3 amendments require V14+, which mandates record VKs for all records.
            for record_name in program.records().keys() {
                let Some(verifying_key) = self
                    .amendment_verifying_key_map()
                    .get_confirmed(&(program_id, *record_name, edition, amendment_index))?
                    .map(|x| x.into_owned())
                else {
                    bail!(
                        "Failed to get the translation verifying key for '{program_id}/{record_name}' (edition {edition}, amendment {amendment_index})"
                    );
                };
                let Some(certificate) = self
                    .amendment_certificate_map()
                    .get_confirmed(&(program_id, *record_name, edition, amendment_index))?
                    .map(|x| x.into_owned())
                else {
                    bail!(
                        "Failed to get the translation certificate for '{program_id}/{record_name}' (edition {edition}, amendment {amendment_index})"
                    );
                };
                verifying_keys.push((*record_name, (verifying_key, certificate)));
            }

            // V3 deployments use a unified verifying keys vector (functions followed by records).
            return Ok(Some(Deployment::new(edition, program, verifying_keys, program_checksum, program_owner)?));
        }

        // Retrieve the program ID.
        let Some(program_id) = self.get_program_id(transaction_id)? else {
            return Ok(None);
        };
        // Retrieve the edition.
        let Some(edition) = self.get_edition_for_transaction(transaction_id)? else {
            bail!("Failed to get the edition for program '{program_id}'");
        };

        // Retrieve the program.
        let Some(program) = self.program_map().get_confirmed(&(program_id, edition))?.map(|x| x.into_owned()) else {
            bail!("Failed to get the deployed program '{program_id}' (edition {edition})");
        };

        // Retrieve the checksum.
        let program_checksum =
            self.checksum_map().get_confirmed(&(program_id, edition))?.map(|checksum| checksum.into_owned());
        // If the checksum is present, retrieve the owner address.
        // For base deployments, both must be present (V2) or both absent (V1).
        // Note that amendments were handled in the separate branch above, so we are guaranteed to be retrieving a base deployment.
        let program_owner = match program_checksum.is_some() {
            false => None,
            true => match self.owner_map().get_confirmed(&(program_id, edition))? {
                Some(owner) => Some(owner.address()),
                None => bail!("Failed to get the owner for program '{program_id}' (edition {edition})"),
            },
        };

        // Determine if the deployment contains record verifying keys by probing the first record name.
        // Record VKs are all-or-nothing: either every record has a VK or none do.
        let contains_record_keys = match program.records().keys().next() {
            Some(record_name) => {
                self.verifying_key_map().get_confirmed(&(program_id, *record_name, edition))?.is_some()
            }
            None => false,
        };

        // Initialize a vector for the verifying keys and certificates.
        let num_functions = program.functions().len();
        let num_records = if contains_record_keys { program.records().len() } else { 0 };
        let mut verifying_keys = Vec::with_capacity(num_functions + num_records);

        // Retrieve the function verifying keys and certificates.
        for function_name in program.functions().keys() {
            // Retrieve the verifying key.
            let Some(verifying_key) =
                self.verifying_key_map().get_confirmed(&(program_id, *function_name, edition))?.map(|x| x.into_owned())
            else {
                bail!("Failed to get the verifying key for '{program_id}/{function_name}' (edition {edition})");
            };
            // Retrieve the certificate.
            let Some(certificate) =
                self.certificate_map().get_confirmed(&(program_id, *function_name, edition))?.map(|x| x.into_owned())
            else {
                bail!("Failed to get the certificate for '{program_id}/{function_name}' (edition {edition})");
            };
            // Add the verifying key and certificate to the deployment.
            verifying_keys.push((*function_name, (verifying_key, certificate)));
        }

        // If the deployment contains record verifying keys, load and append them.
        if contains_record_keys {
            for record_name in program.records().keys() {
                // Retrieve the verifying key.
                let Some(verifying_key) = self
                    .verifying_key_map()
                    .get_confirmed(&(program_id, *record_name, edition))?
                    .map(|x| x.into_owned())
                else {
                    bail!(
                        "Missing record verifying key for '{program_id}/{record_name}' (edition {edition}) - record VKs must either all exist or none exist"
                    );
                };
                // Retrieve the certificate.
                let Some(certificate) =
                    self.certificate_map().get_confirmed(&(program_id, *record_name, edition))?.map(|x| x.into_owned())
                else {
                    bail!(
                        "Missing record certificate for '{program_id}/{record_name}' (edition {edition}) - record VKs must either all exist or none exist"
                    );
                };
                // Append the record verifying key and certificate.
                verifying_keys.push((*record_name, (verifying_key, certificate)));
            }
        }

        // Return the deployment.
        Ok(Some(Deployment::new(edition, program, verifying_keys, program_checksum, program_owner)?))
    }

    /// Returns the fee for the given `transaction ID`.
    fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        self.fee_store().get_fee(transaction_id)
    }

    /// Returns the latest owner for the given `program ID`.
    /// If amendments exist for the latest edition, returns the owner from the latest amendment.
    /// Otherwise, returns the original deployment owner.
    // TODO (raychu86): Consider program upgrades and edition changes.
    fn get_latest_owner(&self, program_id: &ProgramID<N>) -> Result<Option<ProgramOwner<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve the latest edition.
        let Some(edition) = self.get_latest_edition_for_program(program_id)? else {
            return Ok(None);
        };

        // Check if there are amendments for this program/edition.
        // If amendments exist, return the owner from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(owner) = self.amendment_owner_map().get_confirmed(&(*program_id, edition, latest_index))? else {
                bail!(
                    "Failed to get the amendment owner for '{program_id}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(*owner));
        }

        // No amendments, retrieve from the base owner map.
        let Some(owner) = self.owner_map().get_confirmed(&(*program_id, edition))? else {
            bail!("Failed to find the Owner for program '{program_id}' (edition {edition})");
        };
        Ok(Some(*owner))
    }

    /// Returns the owner for the given `program ID` and `edition`.
    /// If amendments exist for the given edition, returns the owner from the latest amendment.
    /// Otherwise, returns the original deployment owner.
    fn get_latest_owner_with_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<ProgramOwner<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Check if there are amendments for this program/edition.
        // If amendments exist, return the owner from the latest amendment.
        if let Some(latest_index) = self.get_latest_amendment_index(program_id, edition)? {
            let Some(owner) = self.amendment_owner_map().get_confirmed(&(*program_id, edition, latest_index))? else {
                bail!(
                    "Failed to get the amendment owner for '{program_id}' (edition {edition}, amendment {latest_index})"
                );
            };
            return Ok(Some(*owner));
        }

        // No amendments, retrieve from the base owner map.
        match self.owner_map().get_confirmed(&(*program_id, edition))? {
            Some(owner) => Ok(Some(*owner)),
            None => bail!("Failed to find the Owner for program '{program_id}' (edition {edition})"),
        }
    }

    /// Returns the original deployment owner for the given `program ID` and `edition`.
    /// This method ignores any amendments and always returns the owner from the base deployment.
    /// Returns `None` for `credits.aleo`.
    fn get_original_owner(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<ProgramOwner<N>>> {
        // Check if the program ID is for 'credits.aleo'.
        // This case is handled separately, as it is a default program of the VM.
        // TODO (howardwu): After we update 'fee' rules and 'Ratify' in genesis, we can remove this.
        if program_id == &ProgramID::from_str("credits.aleo")? {
            return Ok(None);
        }

        // Retrieve the owner from the base deployment, ignoring any amendments.
        match self.owner_map().get_confirmed(&(*program_id, edition))? {
            Some(owner) => Ok(Some(*owner)),
            None => bail!("Failed to find the Owner for program '{program_id}' (edition {edition})"),
        }
    }

    /// Returns the transaction for the given `transaction ID`.
    /// If the transaction is an amendment, reconstructs it using amendment-specific VKs and owner.
    /// Otherwise, returns the original deployment transaction.
    fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        // Check if this is an amendment.
        if let Some(amendment_info) = self.reverse_amendment_id_map().get_confirmed(transaction_id)? {
            let (program_id, edition, amendment_index) = *amendment_info;

            // Retrieve the deployment.
            let Some(deployment) = self.get_deployment(transaction_id)? else {
                bail!("Failed to get the deployment for transaction '{transaction_id}'");
            };
            // Retrieve the fee.
            let Some(fee) = self.get_fee(transaction_id)? else {
                bail!("Failed to get the fee for transaction '{transaction_id}'");
            };
            // Retrieve the owner.
            let Some(owner) = self
                .amendment_owner_map()
                .get_confirmed(&(program_id, edition, amendment_index))?
                .map(|o| o.into_owned())
            else {
                bail!("Failed to get the owner for transaction '{transaction_id}'");
            };

            // Construct the deployment transaction.
            let deployment_id = deployment.to_deployment_id()?;
            return Ok(Some(Transaction::Deploy(*transaction_id, deployment_id, owner, Box::new(deployment), fee)));
        }

        // Retrieve the deployment.
        let Some(deployment) = self.get_deployment(transaction_id)? else {
            return Ok(None);
        };
        // Retrieve the fee.
        let Some(fee) = self.get_fee(transaction_id)? else {
            bail!("Failed to get the fee for transaction '{transaction_id}'");
        };
        // Retrieve the owner.
        let Some(owner) = self.get_original_owner(deployment.program_id(), deployment.edition())? else {
            bail!("Failed to get the owner for transaction '{transaction_id}'");
        };

        // Construct the deployment transaction.
        let deployment_id = deployment.to_deployment_id()?;
        Ok(Some(Transaction::Deploy(*transaction_id, deployment_id, owner, Box::new(deployment), fee)))
    }

    /// Returns the number of amendments for the given `program ID` and `edition`.
    fn get_amendment_count(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<u64>> {
        Ok(self.amendment_next_index_map().get_confirmed(&(*program_id, edition))?.map(|c| *c))
    }

    /// Returns the latest amendment index for the given `program ID` and `edition`.
    /// Returns `None` if no amendments exist or the count is zero.
    fn get_latest_amendment_index(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<u64>> {
        match self.amendment_next_index_map().get_confirmed(&(*program_id, edition))? {
            // The `count > 0` guard ensures the subtraction does not underflow.
            Some(count) if *count > 0 => Ok(Some(*count - 1)),
            _ => Ok(None),
        }
    }

    /// Returns `true` if the given `transaction ID` is an amendment.
    fn is_amendment(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.reverse_amendment_id_map().contains_key_confirmed(transaction_id)
    }

    /// Returns the amendment info `(program ID, edition, amendment index)` for the given `transaction ID`.
    /// Returns `None` if the transaction is not an amendment.
    fn get_amendment_info(&self, transaction_id: &N::TransactionID) -> Result<Option<(ProgramID<N>, u16, u64)>> {
        Ok(self.reverse_amendment_id_map().get_confirmed(transaction_id)?.map(|info| *info))
    }

    /// Returns the verifying key for a specific amendment.
    fn get_verifying_key_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<VerifyingKey<N>>> {
        Ok(self
            .amendment_verifying_key_map()
            .get_confirmed(&(*program_id, *function_name, edition, amendment_index))?
            .map(|vk| vk.into_owned()))
    }

    /// Returns the certificate for a specific amendment.
    fn get_certificate_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Certificate<N>>> {
        Ok(self
            .amendment_certificate_map()
            .get_confirmed(&(*program_id, *function_name, edition, amendment_index))?
            .map(|cert| cert.into_owned()))
    }

    /// Returns the deployment for a specific amendment.
    /// This reconstructs the deployment using the amendment's verifying keys and certificates.
    fn get_deployment_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Deployment<N>>> {
        // Check if this amendment exists.
        let Some(count) = self.amendment_next_index_map().get_confirmed(&(*program_id, edition))? else {
            return Ok(None);
        };
        if amendment_index >= *count {
            return Ok(None);
        }

        // Retrieve the program.
        let Some(program) = self.program_map().get_confirmed(&(*program_id, edition))?.map(|x| x.into_owned()) else {
            bail!("Failed to get the deployed program '{program_id}' (edition {edition})");
        };

        // Initialize a vector for the verifying keys and certificates.
        let mut verifying_keys = Vec::with_capacity(program.functions().len() + program.records().len());

        // Amendments derive the checksum from the program.
        let program_checksum = Some(program.to_checksum());

        // Amendments have no owner in the Deployment struct.
        let program_owner = None;

        // Retrieve the verifying keys and certificates from amendment maps.
        for function_name in program.functions().keys() {
            // Retrieve the verifying key from amendment map.
            let Some(verifying_key) = self
                .amendment_verifying_key_map()
                .get_confirmed(&(*program_id, *function_name, edition, amendment_index))?
                .map(|x| x.into_owned())
            else {
                bail!(
                    "Failed to get the amendment verifying key for '{program_id}/{function_name}' (edition {edition}, amendment {amendment_index})"
                );
            };
            // Retrieve the certificate from amendment map.
            let Some(certificate) = self
                .amendment_certificate_map()
                .get_confirmed(&(*program_id, *function_name, edition, amendment_index))?
                .map(|x| x.into_owned())
            else {
                bail!(
                    "Failed to get the amendment certificate for '{program_id}/{function_name}' (edition {edition}, amendment {amendment_index})"
                );
            };
            // Add the verifying key and certificate to the deployment.
            verifying_keys.push((*function_name, (verifying_key, certificate)));
        }

        // Retrieve the translation (record) verifying keys and certificates from amendment maps.
        // Note: V3 amendments require V14+, which mandates record VKs for all records.
        for record_name in program.records().keys() {
            let Some(verifying_key) = self
                .amendment_verifying_key_map()
                .get_confirmed(&(*program_id, *record_name, edition, amendment_index))?
                .map(|x| x.into_owned())
            else {
                bail!(
                    "Failed to get the amendment translation verifying key for '{program_id}/{record_name}' (edition {edition}, amendment {amendment_index})"
                );
            };
            let Some(certificate) = self
                .amendment_certificate_map()
                .get_confirmed(&(*program_id, *record_name, edition, amendment_index))?
                .map(|x| x.into_owned())
            else {
                bail!(
                    "Failed to get the amendment translation certificate for '{program_id}/{record_name}' (edition {edition}, amendment {amendment_index})"
                );
            };
            verifying_keys.push((*record_name, (verifying_key, certificate)));
        }

        // Return the deployment.
        // V3 deployments use a unified verifying keys vector (functions followed by records).
        Ok(Some(Deployment::new(edition, program, verifying_keys, program_checksum, program_owner)?))
    }
}

/// The deployment store.
#[derive(Clone)]
pub struct DeploymentStore<N: Network, D: DeploymentStorage<N>> {
    /// The deployment storage.
    storage: D,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Initializes the deployment store.
    pub fn open(fee_store: FeeStore<N, D::FeeStorage>) -> Result<Self> {
        // Initialize the deployment storage.
        let storage = D::open(fee_store)?;

        // Do not introduce any records if the storage is used in readonly mode,
        // as a secondary RocksDB instance.
        if !matches!(storage.storage_mode(), StorageMode::Custom(_, Some(_))) {
            // Insert `credits.aleo`, which is the default program.
            let credits_id = ProgramID::from_str("credits.aleo")?;
            storage.edition_map().insert(credits_id, 0)?;
            storage.program_map().insert((credits_id, 0), Program::credits()?)?;
        }

        // Return the deployment store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a deployment store from storage.
    pub fn from(storage: D) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Stores the given `deployment transaction` into storage.
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

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns the transaction for the given `transaction ID`.
    pub fn get_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<Transaction<N>>> {
        self.storage.get_transaction(transaction_id)
    }

    /// Returns the deployment for the given `transaction ID`.
    pub fn get_deployment(&self, transaction_id: &N::TransactionID) -> Result<Option<Deployment<N>>> {
        self.storage.get_deployment(transaction_id)
    }

    /// Returns the latest edition for the given `program ID`.
    pub fn get_latest_edition_for_program(&self, program_id: &ProgramID<N>) -> Result<Option<u16>> {
        self.storage.get_latest_edition_for_program(program_id)
    }

    /// Returns the edition for the given `transaction ID`.
    pub fn get_edition_for_transaction(&self, transaction_id: &N::TransactionID) -> Result<Option<u16>> {
        self.storage.get_edition_for_transaction(transaction_id)
    }

    /// Returns the program ID for the given `transaction ID`.
    pub fn get_program_id(&self, transaction_id: &N::TransactionID) -> Result<Option<ProgramID<N>>> {
        self.storage.get_program_id(transaction_id)
    }

    /// Returns the latest program for the given `program ID`.
    pub fn get_latest_program(&self, program_id: &ProgramID<N>) -> Result<Option<Program<N>>> {
        self.storage.get_latest_program(program_id)
    }

    /// Returns the program for the given `program ID` and `edition`.
    pub fn get_program_for_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<Program<N>>> {
        self.storage.get_program_for_edition(program_id, edition)
    }

    /// Returns the latest verifying key for the given `(program ID, function or record name)`.
    pub fn get_latest_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.get_latest_verifying_key(program_id, resource_name)
    }

    /// Returns the verifying key for the given `(program ID, function or record name, edition)`.
    pub fn get_latest_verifying_key_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.get_latest_verifying_key_with_edition(program_id, resource_name, edition)
    }

    /// Returns the original verifying key for the given `(program ID, function name, edition)`.
    /// This method ignores any amendments and always returns the VK from the original deployment.
    pub fn get_original_verifying_key(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.get_original_verifying_key(program_id, function_name, edition)
    }

    /// Returns the latest certificate for the given `(program ID, function or record name)`.
    pub fn get_latest_certificate(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.get_latest_certificate(program_id, resource_name)
    }

    /// Returns the certificate for the given `(program ID, function or record name, edition)`.
    pub fn get_latest_certificate_with_edition(
        &self,
        program_id: &ProgramID<N>,
        resource_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.get_latest_certificate_with_edition(program_id, resource_name, edition)
    }

    /// Returns the original certificate for the given `(program ID, function name, edition)`.
    /// This method ignores any amendments and always returns the certificate from the original deployment.
    pub fn get_original_certificate(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.get_original_certificate(program_id, function_name, edition)
    }

    /// Returns the fee for the given `transaction ID`.
    pub fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        self.storage.get_fee(transaction_id)
    }

    /// Returns the latest owner for the given `program ID`.
    /// If amendments exist, returns the owner from the latest amendment.
    pub fn get_latest_owner(&self, program_id: &ProgramID<N>) -> Result<Option<ProgramOwner<N>>> {
        self.storage.get_latest_owner(program_id)
    }

    /// Returns the owner for the given `program ID` and `edition`.
    /// If amendments exist for the given edition, returns the owner from the latest amendment.
    pub fn get_latest_owner_with_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<ProgramOwner<N>>> {
        self.storage.get_latest_owner_with_edition(program_id, edition)
    }

    /// Returns the original deployment owner for the given `program ID` and `edition`.
    /// This method ignores any amendments and always returns the owner from the base deployment.
    pub fn get_original_owner(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<ProgramOwner<N>>> {
        self.storage.get_original_owner(program_id, edition)
    }
}

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns the latest transaction ID that deployed or upgraded the given `program ID`.
    pub fn find_latest_transaction_id_from_program_id(
        &self,
        program_id: &ProgramID<N>,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_latest_transaction_id_from_program_id(program_id)
    }

    /// Returns the original deployment transaction ID for the given `program ID` and `edition`.
    /// This returns the initial deployment, not any subsequent amendments.
    pub fn find_original_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_original_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the latest transaction ID for the given `program ID` and `edition`.
    /// If amendments exist, returns the latest amendment transaction ID.
    /// Otherwise, returns the original deployment transaction ID.
    pub fn find_latest_transaction_id_from_program_id_and_edition(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_latest_transaction_id_from_program_id_and_edition(program_id, edition)
    }

    /// Returns the transaction ID for the given `program ID`, `edition`, and `amendment_index`.
    /// Returns `None` if no such amendment exists.
    pub fn find_transaction_id_from_program_id_edition_and_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_program_id_edition_and_amendment(program_id, edition, amendment_index)
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_transition_id(transition_id)
    }
}

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns `true` if the given program ID exists.
    pub fn contains_program_id(&self, program_id: &ProgramID<N>) -> Result<bool> {
        self.storage.edition_map().contains_key_confirmed(program_id)
    }

    /// Returns `true` if the given program ID and edition exist.
    pub fn contains_program_id_and_edition(&self, program_id: &ProgramID<N>, edition: u16) -> Result<bool> {
        self.storage.reverse_id_map().contains_key_confirmed(&(*program_id, edition))
    }
}

type ProgramIDEdition<N> = (ProgramID<N>, u16);
type ProgramTriplet<N> = (ProgramID<N>, Identifier<N>, u16);

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns an iterator over the deployment transaction IDs, for all deployments.
    pub fn deployment_transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.storage.id_map().keys_confirmed()
    }

    /// Returns an iterator over the program IDs, for all deployments.
    /// Note: If a program upgraded, this method will return duplicates of the program ID.
    pub fn program_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, ProgramID<N>>> {
        self.storage.id_map().values_confirmed().map(|id| match id {
            Cow::Borrowed(id) => Cow::Borrowed(id),
            Cow::Owned(id) => Cow::Owned(id),
        })
    }

    /// Returns an iterator over the program IDs and latest editions.
    pub fn program_ids_and_latest_editions(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramID<N>>, Cow<'_, u16>)> {
        self.storage.edition_map().iter_confirmed()
    }

    /// Returns an iterator over the programs, for all deployments.
    /// If a program has been upgraded, all instances of the program will be returned.
    pub fn programs(&self) -> impl '_ + Iterator<Item = Cow<'_, Program<N>>> {
        self.storage.program_map().values_confirmed().map(|program| match program {
            Cow::Borrowed(program) => Cow::Borrowed(program),
            Cow::Owned(program) => Cow::Owned(program),
        })
    }

    /// Returns an iterator over the programs and editions, for all deployments.
    pub fn programs_with_editions(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, ProgramIDEdition<N>>, Cow<'_, Program<N>>)> {
        self.storage.program_map().iter_confirmed()
    }

    /// Returns an iterator over the `((program ID, function name, edition), verifying key)`, for all deployments.
    pub fn verifying_keys(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramTriplet<N>>, Cow<'_, VerifyingKey<N>>)> {
        self.storage.verifying_key_map().iter_confirmed()
    }

    /// Returns an iterator over the `((program ID, function name, edition), certificate)`, for all deployments.
    pub fn certificates(&self) -> impl '_ + Iterator<Item = (Cow<'_, ProgramTriplet<N>>, Cow<'_, Certificate<N>>)> {
        self.storage.certificate_map().iter_confirmed()
    }
}

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns the number of amendments for the given `program ID` and `edition`.
    pub fn get_amendment_count(&self, program_id: &ProgramID<N>, edition: u16) -> Result<Option<u64>> {
        self.storage.get_amendment_count(program_id, edition)
    }

    /// Returns `true` if the given `transaction ID` is an amendment.
    pub fn is_amendment(&self, transaction_id: &N::TransactionID) -> Result<bool> {
        self.storage.is_amendment(transaction_id)
    }

    /// Returns the amendment info `(program ID, edition, amendment index)` for the given `transaction ID`.
    /// Returns `None` if the transaction is not an amendment.
    pub fn get_amendment_info(&self, transaction_id: &N::TransactionID) -> Result<Option<(ProgramID<N>, u16, u64)>> {
        self.storage.get_amendment_info(transaction_id)
    }

    /// Returns the verifying key for a specific amendment.
    pub fn get_verifying_key_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<VerifyingKey<N>>> {
        self.storage.get_verifying_key_for_amendment(program_id, function_name, edition, amendment_index)
    }

    /// Returns the certificate for a specific amendment.
    pub fn get_certificate_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Certificate<N>>> {
        self.storage.get_certificate_for_amendment(program_id, function_name, edition, amendment_index)
    }

    /// Returns the deployment for a specific amendment.
    /// This reconstructs the deployment using the amendment's verifying keys and certificates.
    pub fn get_deployment_for_amendment(
        &self,
        program_id: &ProgramID<N>,
        edition: u16,
        amendment_index: u64,
    ) -> Result<Option<Deployment<N>>> {
        self.storage.get_deployment_for_amendment(program_id, edition, amendment_index)
    }
}

type AmendmentKey<N> = (ProgramID<N>, u16, u64);
type AmendmentVKKey<N> = (ProgramID<N>, Identifier<N>, u16, u64);

impl<N: Network, D: DeploymentStorage<N>> DeploymentStore<N, D> {
    /// Returns an iterator over the amendment transaction IDs.
    pub fn amendment_transaction_ids(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentKey<N>>, Cow<'_, N::TransactionID>)> {
        self.storage.amendment_id_map().iter_confirmed()
    }

    /// Returns an iterator over the amendment verifying keys.
    pub fn amendment_verifying_keys(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentVKKey<N>>, Cow<'_, VerifyingKey<N>>)> {
        self.storage.amendment_verifying_key_map().iter_confirmed()
    }

    /// Returns an iterator over the amendment certificates.
    pub fn amendment_certificates(
        &self,
    ) -> impl '_ + Iterator<Item = (Cow<'_, AmendmentVKKey<N>>, Cow<'_, Certificate<N>>)> {
        self.storage.amendment_certificate_map().iter_confirmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransitionStore, helpers::memory::DeploymentMemory};
    use console::network::MainnetV0;

    #[test]
    fn test_get_credits_translation_verifying_key() -> Result<()> {
        let transition_store = TransitionStore::open(StorageMode::Test(None))?;
        let fee_store = FeeStore::open(transition_store)?;
        let deployment_store = DeploymentMemory::<MainnetV0>::open(fee_store)?;
        let credits_id = ProgramID::from_str("credits.aleo")?;
        let credits_record_name = Identifier::from_str("credits")?;

        let raw_verifying_key = MainnetV0::translation_credits_verifying_key();
        let num_variables = raw_verifying_key.circuit_info.num_public_and_private_variables as u64;
        let expected = VerifyingKey::new(raw_verifying_key.clone(), num_variables);

        assert_eq!(
            Some(expected.clone()),
            deployment_store.get_latest_verifying_key(&credits_id, &credits_record_name)?
        );
        assert_eq!(
            Some(expected.clone()),
            deployment_store.get_latest_verifying_key_with_edition(&credits_id, &credits_record_name, 0)?
        );
        assert_eq!(Some(expected), deployment_store.get_original_verifying_key(&credits_id, &credits_record_name, 0)?);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new deployment store.
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Sample the transactions.
        let transaction_0 = snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 0, false, true, rng);
        let transaction_1 = snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 1, false, false, rng);
        let transaction_2 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let transaction_3 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, false, false, rng);
        let transaction_4 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, false, true, rng);
        let transaction_5 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, true, true, rng);
        let transaction_6 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, true, false, rng);
        let transaction_7 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, true, true, rng);

        let transactions = vec![
            transaction_0,
            transaction_1,
            transaction_2,
            transaction_3,
            transaction_4,
            transaction_5,
            transaction_6,
            transaction_7,
        ];

        for transaction in transactions {
            let transaction_id = transaction.id();
            let program_id = *transaction.deployment().unwrap().program_id();
            let checksum = transaction.deployment().unwrap().program_checksum();
            let edition = transaction.deployment().unwrap().edition();

            // Ensure the deployment transaction does not exist.
            let candidate = deployment_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the deployment transaction.
            deployment_store.insert(&transaction).unwrap();

            // If the deployment has a checksum, then check that it exists in the checksum map.
            match checksum {
                Some(checksum) => {
                    let candidate = deployment_store.checksum_map().get_confirmed(&(program_id, edition)).unwrap();
                    assert_eq!(Some(checksum), candidate.map(|c| c.into_owned()));
                }
                None => {
                    let candidate = deployment_store.checksum_map().get_confirmed(&(program_id, edition)).unwrap();
                    assert_eq!(None, candidate);
                }
            }

            // Check that the transaction exists in the ID edition map
            let candidate = deployment_store.id_edition_map().get_confirmed(&transaction_id).unwrap();
            assert_eq!(Some(edition), candidate.map(|e| *e));

            // Retrieve the deployment transaction.
            let candidate = deployment_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(Some(transaction.clone()), candidate);

            // Retrieve the edition for the transaction and verify that it is matches.
            let actual = deployment_store.get_edition_for_transaction(&transaction_id).unwrap();
            assert_eq!(Some(edition), actual);

            // Retrieve the latest edition for the program ID and verify that it matches.
            let actual = deployment_store.get_latest_edition_for_program(&program_id).unwrap();
            assert_eq!(Some(edition), actual);

            // Retrieve the latest edition for the transaction ID and verify that it matches.
            let actual = deployment_store.get_edition_for_transaction(&transaction_id).unwrap();
            assert_eq!(Some(edition), actual);

            // Remove the deployment.
            deployment_store.remove(&transaction_id).unwrap();

            // Ensure the deployment transaction does not exist.
            let candidate = deployment_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // If the edition is zero, then check that the edition is not found.
            // Otherwise, check that the edition is decremented.
            if edition == 0 {
                let candidate = deployment_store.edition_map().get_confirmed(&program_id).unwrap();
                assert_eq!(None, candidate);
            } else {
                let candidate = deployment_store.edition_map().get_confirmed(&program_id).unwrap();
                assert_eq!(Some(edition.saturating_sub(1)), candidate.as_deref().copied());
            }

            // Ensure the edition is not found in the `IDEditionMap`.
            let candidate = deployment_store.id_edition_map().get_confirmed(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // Insert the deployment transaction again.
            deployment_store.insert(&transaction).unwrap();
        }
    }

    #[test]
    #[ignore]
    fn test_find_transaction_id() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new deployment store.
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Sample the transactions.
        let transaction_0 = snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 0, false, true, rng);
        let transaction_1 = snarkvm_ledger_test_helpers::sample_deployment_transaction(1, 1, false, false, rng);
        let transaction_2 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let transaction_3 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, false, false, rng);
        let transaction_4 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, false, true, rng);
        let transaction_5 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, true, true, rng);
        let transaction_6 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 1, true, false, rng);
        let transaction_7 = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 2, true, true, rng);

        let transactions = vec![
            transaction_0,
            transaction_1,
            transaction_2,
            transaction_3,
            transaction_4,
            transaction_5,
            transaction_6,
            transaction_7,
        ];

        for transaction in transactions {
            let transaction_id = transaction.id();
            let (program_id, edition) = match transaction {
                Transaction::Deploy(_, _, _, ref deployment, _) => (*deployment.program_id(), deployment.edition()),
                _ => panic!("Incorrect transaction type"),
            };
            let fee_id = *transaction.fee_transition().unwrap().id();

            // Ensure the deployment transaction does not exist.
            let candidate = deployment_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(None, candidate);

            // A helper to test the `find_*` methods.
            let test_find_methods = |program_exists: bool, transaction_exists: bool| {
                // Find the latest transaction ID from the program ID.
                let candidate_0 = deployment_store.find_latest_transaction_id_from_program_id(&program_id).unwrap();
                // Find the original transaction ID from the program ID and edition.
                let candidate_1 = deployment_store
                    .find_original_transaction_id_from_program_id_and_edition(&program_id, edition)
                    .unwrap();
                // Find the transaction ID from the transition ID.
                let candidate_2 = deployment_store.find_transaction_id_from_transition_id(&fee_id).unwrap();

                // If the program exists, then the latest transaction ID should be found.
                assert_eq!(program_exists, candidate_0.is_some());
                // If the transaction exists, then the transaction ID should be found.
                assert_eq!(transaction_exists, candidate_1.is_some());
                assert_eq!(candidate_1, candidate_2);
            };

            // If the edition is zero, then check that a transaction is not found.
            // Otherwise, check that the transaction is found.
            if edition == 0 {
                test_find_methods(false, false);
            } else {
                test_find_methods(true, false);
            }

            // Insert the deployment.
            deployment_store.insert(&transaction).unwrap();

            // Get the transaction again.
            let candidate = deployment_store.get_transaction(&transaction_id).unwrap();
            assert_eq!(Some(transaction.clone()), candidate);

            // Find the transaction ID.
            test_find_methods(true, true);

            // Remove the deployment.
            deployment_store.remove(&transaction_id).unwrap();

            // If the edition is zero, then check that a transaction is not found.
            // Otherwise, check that the transaction is found.
            if edition == 0 {
                test_find_methods(false, false);
            } else {
                test_find_methods(true, false);
            }

            // Insert the deployment again.
            deployment_store.insert(&transaction).unwrap();
        }
    }

    #[test]
    fn test_amendment_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new deployment store.
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // First, insert a V2 deployment (the original deployment that the amendment will target).
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_transaction_id = original_transaction.id();
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        deployment_store.insert(&original_transaction).unwrap();

        // Verify the original deployment was inserted.
        assert_eq!(Some(0), deployment_store.get_latest_edition_for_program(&original_program_id).unwrap());
        // No amendments yet, so count is None.
        assert_eq!(None, deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Verify the original is not an amendment.
        assert!(!deployment_store.is_amendment(&original_transaction_id).unwrap());

        // Now insert an amendment for the same program.
        // V3 is the amendment version (uses same program as V2).
        let amendment_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_id = amendment_transaction.id();
        let amendment_deployment = amendment_transaction.deployment().unwrap();
        assert_eq!(original_program_id, *amendment_deployment.program_id());

        // Insert the amendment.
        deployment_store.insert(&amendment_transaction).unwrap();

        // Verify the amendment was inserted.
        assert!(deployment_store.is_amendment(&amendment_id).unwrap());
        assert_eq!(Some((original_program_id, 0, 0)), deployment_store.get_amendment_info(&amendment_id).unwrap());
        assert_eq!(Some(1), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Verify we can retrieve the amendment deployment.
        let retrieved_deployment = deployment_store.get_deployment(&amendment_id).unwrap();
        assert_eq!(Some(amendment_deployment.clone()), retrieved_deployment);

        // Verify the amendment VKs are stored correctly.
        for (function_name, (vk, cert)) in amendment_deployment.verifying_keys() {
            let retrieved_vk =
                deployment_store.get_verifying_key_for_amendment(&original_program_id, function_name, 0, 0).unwrap();
            assert_eq!(Some(vk.clone()), retrieved_vk);
            let retrieved_cert =
                deployment_store.get_certificate_for_amendment(&original_program_id, function_name, 0, 0).unwrap();
            assert_eq!(Some(cert.clone()), retrieved_cert);
        }

        // Verify the latest VK returns the amendment's VK (not the original VK).
        for (function_name, (vk, _)) in amendment_deployment.verifying_keys() {
            let latest_vk = deployment_store.get_latest_verifying_key(&original_program_id, function_name).unwrap();
            assert_eq!(Some(vk.clone()), latest_vk);
        }

        // Verify the original deployment is still accessible.
        assert_eq!(Some(original_program_id), deployment_store.get_program_id(&original_transaction_id).unwrap());

        // Remove the amendment.
        deployment_store.remove(&amendment_id).unwrap();
        assert!(!deployment_store.is_amendment(&amendment_id).unwrap());
        // No amendments left, so count is None.
        assert_eq!(None, deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // The original deployment should still exist.
        assert_eq!(Some(original_program_id), deployment_store.get_program_id(&original_transaction_id).unwrap());
        assert_eq!(Some(0), deployment_store.get_latest_edition_for_program(&original_program_id).unwrap());

        // Remove the original deployment.
        deployment_store.remove(&original_transaction_id).unwrap();
        assert_eq!(None, deployment_store.get_latest_edition_for_program(&original_program_id).unwrap());
    }

    #[test]
    fn test_multiple_sequential_amendments() {
        let rng = &mut TestRng::default();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeStore::open(transition_store).unwrap();
        // Initialize a new deployment store.
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 deployment (the original deployment).
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        deployment_store.insert(&original_transaction).unwrap();

        // Insert multiple amendments sequentially (V3 is the amendment version).
        let amendment_1 = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_1_id = amendment_1.id();
        let amendment_1_deployment = amendment_1.deployment().unwrap();
        deployment_store.insert(&amendment_1).unwrap();

        // Verify first amendment.
        assert_eq!(Some(1), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());
        assert_eq!(Some((original_program_id, 0, 0)), deployment_store.get_amendment_info(&amendment_1_id).unwrap());

        // Insert second amendment.
        let amendment_2 = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, true, rng);
        let amendment_2_id = amendment_2.id();
        let amendment_2_deployment = amendment_2.deployment().unwrap();
        deployment_store.insert(&amendment_2).unwrap();

        // Verify second amendment.
        assert_eq!(Some(2), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());
        assert_eq!(Some((original_program_id, 0, 1)), deployment_store.get_amendment_info(&amendment_2_id).unwrap());

        // Verify the latest VK returns the second amendment's VK.
        for (function_name, (vk, _)) in amendment_2_deployment.verifying_keys() {
            let latest_vk = deployment_store.get_latest_verifying_key(&original_program_id, function_name).unwrap();
            assert_eq!(Some(vk.clone()), latest_vk);
        }

        // Verify we can still retrieve both amendments.
        assert_eq!(Some(amendment_1_deployment.clone()), deployment_store.get_deployment(&amendment_1_id).unwrap());
        assert_eq!(Some(amendment_2_deployment.clone()), deployment_store.get_deployment(&amendment_2_id).unwrap());

        // Remove amendments in LIFO order (latest first).
        deployment_store.remove(&amendment_2_id).unwrap();
        assert_eq!(Some(1), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // After removing amendment 2, the latest VK should be from amendment 1.
        for (function_name, (vk, _)) in amendment_1_deployment.verifying_keys() {
            let latest_vk = deployment_store.get_latest_verifying_key(&original_program_id, function_name).unwrap();
            assert_eq!(Some(vk.clone()), latest_vk);
        }

        // Remove the last amendment.
        deployment_store.remove(&amendment_1_id).unwrap();
        assert_eq!(None, deployment_store.get_amendment_count(&original_program_id, 0).unwrap());
    }

    #[test]
    fn test_get_latest_vk_with_amendments() {
        let rng = &mut TestRng::default();

        // Initialize stores.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        let fee_store = FeeStore::open(transition_store).unwrap();
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 original deployment.
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        let original_deployment = original_transaction.deployment().unwrap();
        deployment_store.insert(&original_transaction).unwrap();

        // Verify we can get the original VKs.
        for (function_name, (vk, _)) in original_deployment.verifying_keys() {
            let latest_vk = deployment_store.get_latest_verifying_key(&original_program_id, function_name).unwrap();
            assert_eq!(Some(vk.clone()), latest_vk, "original VK should be retrievable");
        }

        // Insert an amendment (V3 is the amendment version).
        let amendment_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_deployment = amendment_transaction.deployment().unwrap();
        deployment_store.insert(&amendment_transaction).unwrap();

        // Verify that get_latest_verifying_key now returns the amendment's VK (not the original's).
        for (function_name, (vk, _)) in amendment_deployment.verifying_keys() {
            let latest_vk = deployment_store.get_latest_verifying_key(&original_program_id, function_name).unwrap();
            assert_eq!(Some(vk.clone()), latest_vk, "Amendment VK should be returned as latest");
        }

        // Also verify we can still get the original VK using the original-specific method.
        for (function_name, (vk, _)) in original_deployment.verifying_keys() {
            let original_vk =
                deployment_store.get_original_verifying_key(&original_program_id, function_name, 0).unwrap();
            assert_eq!(Some(vk.clone()), original_vk, "original VK should still be retrievable");
        }

        // Also verify we can still get the original certificate using the original-specific method.
        for (function_name, (_, cert)) in original_deployment.verifying_keys() {
            let original_cert =
                deployment_store.get_original_certificate(&original_program_id, function_name, 0).unwrap();
            assert_eq!(Some(cert.clone()), original_cert, "original certificate should still be retrievable");
        }

        // Simulate a "reload" by creating a new store pointing to the same data.
        // Since we're using in-memory storage, we verify that the data structure is correct.
        // The key test here is that get_latest_verifying_key correctly accounts for amendments.
        let amendment_count = deployment_store.get_amendment_count(&original_program_id, 0).unwrap();
        assert_eq!(Some(1), amendment_count, "Amendment count should be 1");

        // Verify the amendment info is correct.
        let amendment_id = amendment_transaction.id();
        let info = deployment_store.get_amendment_info(&amendment_id).unwrap();
        assert_eq!(
            Some((original_program_id, 0, 0)),
            info,
            "Amendment info should be (program_id, edition=0, index=0)"
        );
    }

    #[test]
    fn test_cannot_remove_original_with_amendments() {
        let rng = &mut TestRng::default();

        // Initialize stores.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        let fee_store = FeeStore::open(transition_store).unwrap();
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 original deployment.
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_transaction_id = original_transaction.id();
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        deployment_store.insert(&original_transaction).unwrap();

        // Insert an amendment (V3 is the amendment version).
        let amendment_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_transaction_id = amendment_transaction.id();
        deployment_store.insert(&amendment_transaction).unwrap();

        // Verify amendment exists.
        assert_eq!(Some(1), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Attempt to remove original deployment while amendment exists - should FAIL.
        let result = deployment_store.remove(&original_transaction_id);
        assert!(result.is_err(), "Should not be able to remove original deployment with active amendments");
        assert!(
            result.unwrap_err().to_string().contains("amendment(s) must be removed first"),
            "Error message should mention amendments need to be removed"
        );

        // Verify original and amendment still exist.
        assert!(deployment_store.get_transaction(&original_transaction_id).unwrap().is_some());
        assert!(deployment_store.get_transaction(&amendment_transaction_id).unwrap().is_some());

        // Remove amendment first.
        deployment_store.remove(&amendment_transaction_id).unwrap();
        assert_eq!(None, deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Now removing original should succeed.
        deployment_store.remove(&original_transaction_id).unwrap();
        assert!(deployment_store.get_transaction(&original_transaction_id).unwrap().is_none());
    }

    #[test]
    fn test_cannot_remove_non_latest_amendment() {
        let rng = &mut TestRng::default();

        // Initialize stores.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        let fee_store = FeeStore::open(transition_store).unwrap();
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 original deployment.
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        deployment_store.insert(&original_transaction).unwrap();

        // Insert first amendment (index 0). V3 is the amendment version.
        let amendment_0 = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_0_id = amendment_0.id();
        deployment_store.insert(&amendment_0).unwrap();

        // Insert second amendment (index 1).
        let amendment_1 = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, true, rng);
        let amendment_1_id = amendment_1.id();
        deployment_store.insert(&amendment_1).unwrap();

        // Verify both amendments exist.
        assert_eq!(Some(2), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Attempt to remove amendment 0 (not latest) - should FAIL.
        let result = deployment_store.remove(&amendment_0_id);
        assert!(result.is_err(), "Should not be able to remove non-latest amendment");
        assert!(
            result.unwrap_err().to_string().contains("not the latest amendment"),
            "Error message should mention not latest amendment"
        );

        // Amendment 0 should still exist.
        assert!(deployment_store.get_transaction(&amendment_0_id).unwrap().is_some());

        // Remove amendment 1 (latest) - should succeed.
        deployment_store.remove(&amendment_1_id).unwrap();
        assert_eq!(Some(1), deployment_store.get_amendment_count(&original_program_id, 0).unwrap());

        // Now removing amendment 0 should succeed (it's now the latest).
        deployment_store.remove(&amendment_0_id).unwrap();
        assert_eq!(None, deployment_store.get_amendment_count(&original_program_id, 0).unwrap());
    }

    #[test]
    fn test_find_latest_transaction_id_with_amendments() {
        let rng = &mut TestRng::default();

        // Initialize stores.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        let fee_store = FeeStore::open(transition_store).unwrap();
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 original deployment.
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        let original_transaction_id = original_transaction.id();
        let original_program_id = *original_transaction.deployment().unwrap().program_id();
        deployment_store.insert(&original_transaction).unwrap();

        // Before any amendment, find_latest should return the original transaction ID.
        let latest = deployment_store.find_latest_transaction_id_from_program_id(&original_program_id).unwrap();
        assert_eq!(Some(original_transaction_id), latest, "Should return original when no amendments exist");

        // Also test the edition-specific variant.
        let latest_for_edition =
            deployment_store.find_latest_transaction_id_from_program_id_and_edition(&original_program_id, 0).unwrap();
        assert_eq!(Some(original_transaction_id), latest_for_edition);

        // Insert an amendment.
        let amendment = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 0, true, false, rng);
        let amendment_id = amendment.id();
        deployment_store.insert(&amendment).unwrap();

        // After amendment, find_latest should return the amendment transaction ID.
        let latest = deployment_store.find_latest_transaction_id_from_program_id(&original_program_id).unwrap();
        assert_eq!(Some(amendment_id), latest, "Should return amendment when one exists");

        // Edition-specific variant should also return the amendment.
        let latest_for_edition =
            deployment_store.find_latest_transaction_id_from_program_id_and_edition(&original_program_id, 0).unwrap();
        assert_eq!(Some(amendment_id), latest_for_edition);

        // The amendment-specific lookup should work.
        let amendment_tx = deployment_store
            .find_transaction_id_from_program_id_edition_and_amendment(&original_program_id, 0, 0)
            .unwrap();
        assert_eq!(Some(amendment_id), amendment_tx);

        // A non-existent amendment index should return None.
        let nonexistent = deployment_store
            .find_transaction_id_from_program_id_edition_and_amendment(&original_program_id, 0, 999)
            .unwrap();
        assert_eq!(None, nonexistent);

        // Remove the amendment and verify we get the original again.
        deployment_store.remove(&amendment_id).unwrap();
        let latest = deployment_store.find_latest_transaction_id_from_program_id(&original_program_id).unwrap();
        assert_eq!(Some(original_transaction_id), latest, "Should return original after amendment removed");
    }

    #[test]
    fn test_amendment_on_wrong_edition_fails() {
        let rng = &mut TestRng::default();

        // Initialize stores.
        let transition_store = TransitionStore::open(StorageMode::Test(None)).unwrap();
        let fee_store = FeeStore::open(transition_store).unwrap();
        let deployment_store = DeploymentMemory::open(fee_store).unwrap();

        // Insert a V2 deployment at edition 0.
        let original_transaction = snarkvm_ledger_test_helpers::sample_deployment_transaction(2, 0, false, true, rng);
        deployment_store.insert(&original_transaction).unwrap();

        // Attempt to insert a V3 amendment targeting edition 1 (which doesn't exist).
        let bad_amendment = snarkvm_ledger_test_helpers::sample_deployment_transaction(3, 1, true, false, rng);
        let result = deployment_store.insert(&bad_amendment);
        assert!(result.is_err(), "Amendment targeting non-latest edition should fail");
    }
}
