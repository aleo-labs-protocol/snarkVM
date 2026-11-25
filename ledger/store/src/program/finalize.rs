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
    helpers::{Map, MapRead, NestedMap, NestedMapRead},
    program::{CommitteeStorage, CommitteeStore},
};

use console::{
    network::prelude::*,
    program::{Identifier, Plaintext, ProgramID, Value},
    types::Field,
};
use snarkvm_ledger_block::RejectedReason;
use snarkvm_synthesizer_program::{FinalizeOperation, FinalizeStoreTrait};
use snarkvm_utilities::{StorageMode, locks::RwLock};

use anyhow::Result;
use core::marker::PhantomData;
use indexmap::IndexSet;

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

/// A block height encoded in big-endian byte order for lexicographic history keys.
pub type BlockHeight = [u8; 4];

/// One page of a mapping's entries, and the key to resume after if more keys follow.
pub type MappingPage<N> = (Vec<(Plaintext<N>, Value<N>)>, Option<Plaintext<N>>);

// Key 0 in the same storage metadata prefix holds the schema version.
pub(crate) const HISTORY_METADATA_KEY: u8 = 1;

const HISTORY_BASELINE_BATCH_SIZE: usize = 1024;
const HISTORY_BASELINE_BATCH_BYTES: u64 = 8 * 1024 * 1024;

/// TODO (howardwu): Remove this.
/// Returns the mapping ID for the given `program ID` and `mapping name`.
fn to_mapping_id<N: Network>(program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<Field<N>> {
    // Construct the preimage.
    let mut preimage = Vec::new();
    program_id.write_bits_le(&mut preimage);
    false.write_bits_le(&mut preimage); // Separator
    mapping_name.write_bits_le(&mut preimage);
    // Compute the mapping ID.
    N::hash_bhp1024(&preimage)
}

/// Returns the key ID for the given `program ID`, `mapping name`, and `key`.
fn to_key_id<N: Network>(
    program_id: &ProgramID<N>,
    mapping_name: &Identifier<N>,
    key: &Plaintext<N>,
) -> Result<Field<N>> {
    // Construct the preimage.
    let mut preimage = Vec::new();
    program_id.write_bits_le(&mut preimage);
    false.write_bits_le(&mut preimage); // Separator
    mapping_name.write_bits_le(&mut preimage);
    false.write_bits_le(&mut preimage); // Separator
    key.write_bits_le(&mut preimage);
    // Compute the key ID.
    N::hash_bhp1024(&preimage)
}

/// A trait for program state storage. Note: For the program logic, see `DeploymentStorage`.
///
/// We define the `key ID := Hash ( program ID || mapping name || Hash(key) )`
/// and the `value ID := Hash ( key ID || Hash(value) )`.
///
/// `FinalizeStorage` emulates the following data structure:
/// ```text
/// // (program_id => (mapping_name => (key => value)))
/// BTreeMap<ProgramID<N>, BTreeMap<Identifier<N>, BTreeMap<Key, Value>>>
/// ```
///
/// This trait is sealed. Only snarkVM implements it.
pub trait FinalizeStorage<N: Network>: crate::sealed::Sealed + 'static + Clone + Send + Sync {
    /// Whether a mapping reset in an atomic batch retains writes to previously absent keys.
    const RETAINS_PENDING_WRITES_ON_RESET: bool;

    /// The committee storage.
    type CommitteeStorage: CommitteeStorage<N>;
    /// The mapping of `program ID` to `[mapping name]`.
    type ProgramIDMap: for<'a> Map<'a, ProgramID<N>, IndexSet<Identifier<N>>>;
    /// The mapping of `(program ID, mapping name)` to `[(key, value)]`.
    type KeyValueMap: for<'a> NestedMap<'a, (ProgramID<N>, Identifier<N>), Plaintext<N>, Value<N>>;
    /// Inclusive indexed ranges `(program, start_height_be) -> end_height`.
    /// Each range starts with a baseline. A gap starts a new range.
    /// `u32::MAX` marks active archival coverage through the last indexed height in metadata.
    type ProgramHistoryMap: for<'a> Map<'a, (ProgramID<N>, BlockHeight), u32>;
    /// Mapping events `(program, range_start_be, mapping, height_be) -> exists`.
    /// `true` marks creation or reset; `false` marks removal. Range starts isolate gaps.
    type MappingHistoryMap: for<'a> Map<'a, (ProgramID<N>, BlockHeight, Identifier<N>, BlockHeight), bool>;
    /// Key versions `(program, range_start_be, mapping, key, height_be) -> value`.
    /// `None` marks deletion. Big-endian heights preserve numeric order for floor lookups.
    type KeyHistoryMap: for<'a> Map<'a, (ProgramID<N>, BlockHeight, Identifier<N>, Plaintext<N>, BlockHeight), Option<Value<N>>>;
    /// Key 1 in the storage metadata prefix maps to `(archival, selected programs, last indexed height)`.
    /// Archival mode stores an empty selected-program list.
    type HistoryMetadataMap: for<'a> Map<'a, u8, (bool, Vec<ProgramID<N>>, u32)>;
    /// The mapping of `transaction ID` to `rejection reason`.
    type RejectedReasonMap: for<'a> Map<'a, Field<N>, RejectedReason<N>>;

    /// Initializes the program state storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the committee storage.
    fn committee_store(&self) -> &CommitteeStore<N, Self::CommitteeStorage>;
    /// Returns the program ID map.
    fn program_id_map(&self) -> &Self::ProgramIDMap;
    /// Returns the key-value map.
    fn key_value_map(&self) -> &Self::KeyValueMap;
    /// Returns the program history map.
    fn program_history_map(&self) -> &Self::ProgramHistoryMap;
    /// Returns the mapping history map.
    fn mapping_history_map(&self) -> &Self::MappingHistoryMap;
    /// Returns the key history map.
    fn key_history_map(&self) -> &Self::KeyHistoryMap;
    /// Returns the recording metadata map.
    fn history_metadata_map(&self) -> &Self::HistoryMetadataMap;
    /// Returns the rejection reason map.
    fn rejected_reason_map(&self) -> &Self::RejectedReasonMap;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode;

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.committee_store().start_atomic();
        self.program_id_map().start_atomic();
        self.key_value_map().start_atomic();
        self.program_history_map().start_atomic();
        self.mapping_history_map().start_atomic();
        self.key_history_map().start_atomic();
        self.history_metadata_map().start_atomic();
        self.rejected_reason_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.committee_store().is_atomic_in_progress()
            || self.program_id_map().is_atomic_in_progress()
            || self.key_value_map().is_atomic_in_progress()
            || self.program_history_map().is_atomic_in_progress()
            || self.mapping_history_map().is_atomic_in_progress()
            || self.key_history_map().is_atomic_in_progress()
            || self.history_metadata_map().is_atomic_in_progress()
            || self.rejected_reason_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.committee_store().atomic_checkpoint();
        self.program_id_map().atomic_checkpoint();
        self.key_value_map().atomic_checkpoint();
        self.program_history_map().atomic_checkpoint();
        self.mapping_history_map().atomic_checkpoint();
        self.key_history_map().atomic_checkpoint();
        self.history_metadata_map().atomic_checkpoint();
        self.rejected_reason_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.committee_store().clear_latest_checkpoint();
        self.program_id_map().clear_latest_checkpoint();
        self.key_value_map().clear_latest_checkpoint();
        self.program_history_map().clear_latest_checkpoint();
        self.mapping_history_map().clear_latest_checkpoint();
        self.key_history_map().clear_latest_checkpoint();
        self.history_metadata_map().clear_latest_checkpoint();
        self.rejected_reason_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.committee_store().atomic_rewind();
        self.program_id_map().atomic_rewind();
        self.key_value_map().atomic_rewind();
        self.program_history_map().atomic_rewind();
        self.mapping_history_map().atomic_rewind();
        self.key_history_map().atomic_rewind();
        self.history_metadata_map().atomic_rewind();
        self.rejected_reason_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.committee_store().abort_atomic();
        self.program_id_map().abort_atomic();
        self.key_value_map().abort_atomic();
        self.program_history_map().abort_atomic();
        self.mapping_history_map().abort_atomic();
        self.key_history_map().abort_atomic();
        self.history_metadata_map().abort_atomic();
        self.rejected_reason_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.committee_store().finish_atomic()?;
        self.program_id_map().finish_atomic()?;
        self.key_value_map().finish_atomic()?;
        self.program_history_map().finish_atomic()?;
        self.mapping_history_map().finish_atomic()?;
        self.key_history_map().finish_atomic()?;
        self.history_metadata_map().finish_atomic()?;
        self.rejected_reason_map().finish_atomic()?;

        Ok(())
    }

    /// Initializes the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is already initialized, an error is returned.
    fn initialize_mapping(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<FinalizeOperation<N>> {
        // Retrieve the mapping names for the program ID. If the program ID does not exist, initialize the mapping names.
        let mut mapping_names =
            self.program_id_map().get_speculative(&program_id)?.map_or(Default::default(), |x| x.into_owned());

        // Ensure the mapping name does not already exist.
        if mapping_names.contains(&mapping_name) {
            bail!("Illegal operation: mapping name '{mapping_name}' already exists in storage - cannot re-initialize.")
        }

        // Insert the new mapping name.
        mapping_names.insert(mapping_name);

        atomic_batch_scope!(self, {
            // Update the program ID map with the new mapping name.
            self.program_id_map().insert(program_id, mapping_names)?;

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(FinalizeOperation::InitializeMapping(to_mapping_id(&program_id, &mapping_name)?))
    }

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` already exists, the method returns an error.
    fn insert_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot insert key-value.")
        }
        // Ensure the key-value does not already exist.
        if self.contains_key_speculative(program_id, mapping_name, &key)? {
            bail!(
                "Illegal operation: '{program_id}/{mapping_name}' key '{key}' already exists in storage - cannot insert key-value"
            );
        }

        // Compute the key ID.
        let key_id = to_key_id(&program_id, &mapping_name, &key)?;
        // Compute the value ID.
        let value_id = N::hash_bhp1024(&(key_id, N::hash_bhp1024(&value.to_bits_le())?).to_bits_le())?;

        atomic_batch_scope!(self, {
            // Update the key-value map with the new key-value.
            self.key_value_map().insert((program_id, mapping_name), key, value)?;

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(FinalizeOperation::InsertKeyValue(to_mapping_id(&program_id, &mapping_name)?, key_id, value_id))
    }

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` does not exist, the `(key, value)` pair is initialized.
    /// If the `key` already exists, the `value` is overwritten.
    fn update_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot update key-value.")
        }

        // Compute the key ID.
        let key_id = to_key_id(&program_id, &mapping_name, &key)?;
        // Compute the value ID.
        let value_id = N::hash_bhp1024(&(key_id, N::hash_bhp1024(&value.to_bits_le())?).to_bits_le())?;

        atomic_batch_scope!(self, {
            // Update the key-value map with the new key-value.
            self.key_value_map().insert((program_id, mapping_name), key, value)?;

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(FinalizeOperation::UpdateKeyValue(to_mapping_id(&program_id, &mapping_name)?, key_id, value_id))
    }

    /// Removes the key-value pair for the given `program ID`, `mapping name`, and `key` from storage.
    /// If the `key` does not exist, `None` is returned.
    fn remove_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<FinalizeOperation<N>>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot remove key-value.")
        }
        // Ensure the key-value entry exists.
        if !self.contains_key_speculative(program_id, mapping_name, key)? {
            return Ok(None);
        }

        // Compute the key ID.
        let key_id = to_key_id(&program_id, &mapping_name, key)?;

        atomic_batch_scope!(self, {
            // Update the key-value map with the new key.
            self.key_value_map().remove_key(&(program_id, mapping_name), key)?;

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(Some(FinalizeOperation::RemoveKeyValue(to_mapping_id(&program_id, &mapping_name)?, key_id)))
    }

    /// Replaces the mapping for the given `program ID` and `mapping name` from storage,
    /// with the given `key-value` pairs.
    fn replace_mapping(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        entries: Vec<(Plaintext<N>, Value<N>)>,
    ) -> Result<FinalizeOperation<N>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot replace mapping.")
        }

        atomic_batch_scope!(self, {
            // Remove the existing key-value entries.
            self.key_value_map().remove_map(&(program_id, mapping_name))?;

            // Insert the new key-value entries.
            for (key, value) in entries {
                // Insert the key-value entry.
                self.key_value_map().insert((program_id, mapping_name), key, value)?;
            }

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(FinalizeOperation::ReplaceMapping(to_mapping_id(&program_id, &mapping_name)?))
    }

    /// Removes the mapping for the given `program ID` and `mapping name` from storage,
    /// along with all associated key-value pairs in storage.
    fn remove_mapping(&self, program_id: ProgramID<N>, mapping_name: Identifier<N>) -> Result<FinalizeOperation<N>> {
        // Retrieve the mapping names.
        let Some(mut mapping_names) = self.program_id_map().get_speculative(&program_id)?.map(|x| x.into_owned())
        else {
            bail!("Illegal operation: program ID '{program_id}' is not initialized - cannot remove mapping.");
        };
        // Remove the mapping name.
        if !mapping_names.shift_remove(&mapping_name) {
            bail!("Illegal operation: mapping '{mapping_name}' does not exist in storage - cannot remove mapping.");
        }

        atomic_batch_scope!(self, {
            // Update the mapping names.
            self.program_id_map().insert(program_id, mapping_names)?;
            // Remove the mapping.
            self.key_value_map().remove_map(&(program_id, mapping_name))?;

            Ok(())
        })?;

        // Return the finalize operation.
        Ok(FinalizeOperation::RemoveMapping(to_mapping_id(&program_id, &mapping_name)?))
    }

    /// Removes the program for the given `program ID` from storage,
    /// along with all associated mappings and key-value pairs in storage.
    fn remove_program(&self, program_id: &ProgramID<N>) -> Result<()> {
        // Retrieve the mapping names.
        let Some(mapping_names) = self.program_id_map().get_speculative(program_id)? else {
            bail!("Illegal operation: program ID '{program_id}' is not initialized - cannot remove mapping.")
        };

        atomic_batch_scope!(self, {
            // Update the mapping names.
            self.program_id_map().remove(program_id)?;

            // Remove each mapping.
            for mapping_name in mapping_names.iter() {
                // Remove the mapping.
                self.key_value_map().remove_map(&(*program_id, *mapping_name))?;
            }
            Ok(())
        })
    }

    /// Returns `true` if the given `program ID` exist.
    fn contains_program_confirmed(&self, program_id: &ProgramID<N>) -> Result<bool> {
        self.program_id_map().contains_key_confirmed(program_id)
    }

    /// Returns `true` if the given `program ID` and `mapping name` exist.
    fn contains_mapping_confirmed(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool> {
        Ok(self.program_id_map().get_confirmed(program_id)?.is_some_and(|m| m.contains(mapping_name)))
    }

    /// Returns `true` if the given `program ID` and `mapping name` exist.
    fn contains_mapping_speculative(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool> {
        Ok(self.program_id_map().get_speculative(program_id)?.is_some_and(|m| m.contains(mapping_name)))
    }

    /// Returns `true` if the given `program ID`, `mapping name`, and `key` exist.
    fn contains_key_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<bool> {
        self.key_value_map().contains_key_confirmed(&(program_id, mapping_name), key)
    }

    /// Returns `true` if the given `program ID`, `mapping name`, and `key` exist.
    fn contains_key_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<bool> {
        self.key_value_map().contains_key_speculative(&(program_id, mapping_name), key)
    }

    /// Returns the confirmed mapping names for the given `program ID`.
    fn get_mapping_names_confirmed(&self, program_id: &ProgramID<N>) -> Result<Option<IndexSet<Identifier<N>>>> {
        Ok(self.program_id_map().get_confirmed(program_id)?.map(|names| names.into_owned()))
    }

    /// Returns the speculative mapping names for the given `program ID`.
    fn get_mapping_names_speculative(&self, program_id: &ProgramID<N>) -> Result<Option<IndexSet<Identifier<N>>>> {
        Ok(self.program_id_map().get_speculative(program_id)?.map(|names| names.into_owned()))
    }

    /// Returns the confirmed mapping entries for the given `program ID` and `mapping name`.
    fn get_mapping_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<Vec<(Plaintext<N>, Value<N>)>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_confirmed(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot get mapping (C).")
        }
        // Retrieve the key-values for the mapping.
        self.key_value_map().get_map_confirmed(&(program_id, mapping_name))
    }

    /// Returns the speculative mapping entries for the given `program ID` and `mapping name`.
    fn get_mapping_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<Vec<(Plaintext<N>, Value<N>)>> {
        // Ensure the mapping name exists.
        if !self.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Illegal operation: '{program_id}/{mapping_name}' is not initialized - cannot get mapping (S).")
        }
        // Retrieve the key-values for the mapping.
        self.key_value_map().get_map_speculative(&(program_id, mapping_name))
    }

    /// Returns the confirmed value for the given `program ID`, `mapping name`, and `key`.
    fn get_value_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>> {
        Ok(self.key_value_map().get_value_confirmed(&(program_id, mapping_name), key)?.map(|x| x.into_owned()))
    }

    /// Returns the speculative value for the given `program ID`, `mapping name`, and `key`.
    fn get_value_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>> {
        Ok(self.key_value_map().get_value_speculative(&(program_id, mapping_name), key)?.map(|x| x.into_owned()))
    }

    /// Returns the confirmed checksum of the finalize storage.
    fn get_checksum_confirmed(&self) -> Result<Field<N>> {
        // Compute all mapping checksums.
        let preimage: std::collections::BTreeMap<_, _> = self
            .key_value_map()
            .iter_confirmed()
            .map(|(m, k, v)| {
                let m = *m;
                let k = k.into_owned();
                let v = v.into_owned();

                let mut preimage = Vec::new();
                m.write_bits_le(&mut preimage);
                false.write_bits_le(&mut preimage); // Separator.
                k.write_bits_le(&mut preimage);
                false.write_bits_le(&mut preimage); // Separator.

                // Compute the mapping checksum as `Hash( m || k )`.
                let mapping_checksum = N::hash_bhp1024(&preimage)?;

                v.write_bits_le(&mut preimage);
                false.write_bits_le(&mut preimage); // Separator.

                // Compute the entry checksum as `Hash( m || k || v )`.
                let entry_checksum = N::hash_bhp1024(&preimage)?;
                // Return the mapping checksum and entry checksum.
                Ok::<_, Error>((mapping_checksum, entry_checksum.to_bits_le()))
            })
            .try_collect()?;
        // Compute the checksum as `Hash( all mapping checksums )`.
        N::hash_bhp1024(&preimage.into_values().flatten().collect::<Vec<_>>())
    }

    /// Returns the pending checksum of the finalize storage.
    fn get_checksum_pending(&self) -> Result<Field<N>> {
        // Compute all mapping checksums.
        let preimage: std::collections::BTreeMap<_, _> = self
            .key_value_map()
            .iter_pending()
            .map(|(m, k, v)| {
                let m = *m;

                let mut preimage = Vec::new();
                m.write_bits_le(&mut preimage);
                false.write_bits_le(&mut preimage); // Separator.
                if let Some(k) = k {
                    k.into_owned().write_bits_le(&mut preimage);
                }
                false.write_bits_le(&mut preimage); // Separator.

                // Compute the mapping checksum as `Hash( m || k )`.
                let mapping_checksum = N::hash_bhp1024(&preimage)?;

                if let Some(v) = v {
                    v.into_owned().write_bits_le(&mut preimage);
                }
                false.write_bits_le(&mut preimage); // Separator.

                // Compute the entry checksum as `Hash( m || k || v )`.
                let entry_checksum = N::hash_bhp1024(&preimage)?;
                // Return the mapping checksum and entry checksum.
                Ok::<_, Error>((mapping_checksum, entry_checksum.to_bits_le()))
            })
            .try_collect()?;
        // Compute the checksum as `Hash( all mapping checksums )`.
        N::hash_bhp1024(&preimage.into_values().flatten().collect::<Vec<_>>())
    }
}

/// The finalize store.
#[derive(Clone)]
pub struct FinalizeStore<N: Network, P: FinalizeStorage<N>> {
    /// The finalize storage.
    storage: P,
    /// PhantomData.
    _phantom: PhantomData<N>,
    /// Tracks the current block height.
    /// Updated by the VM at the start of each canonical finalize
    block_height: Arc<AtomicU32>,
    /// When set, canonical finalize writes credits.aleo history as JSON.
    record_history_json: Arc<AtomicBool>,
    /// Programs whose mapping writes are retained in the canonical finalize batch.
    history_programs: Arc<RwLock<Vec<ProgramID<N>>>>,
    /// Whether canonical finalize retains mapping history for every program.
    archival: Arc<AtomicBool>,
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Initializes the finalize store.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        Self::from(P::open(storage)?)
    }

    /// Initializes a finalize store from storage.
    pub fn from(storage: P) -> Result<Self> {
        // Return the finalize store.
        Ok(Self {
            storage,
            _phantom: PhantomData,
            block_height: Arc::new(AtomicU32::new(0)),
            record_history_json: Arc::new(AtomicBool::new(false)),
            history_programs: Arc::new(RwLock::new(Vec::new())),
            archival: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Enables or disables JSON history for later canonical finalizes.
    pub fn set_record_history_json(&self, enabled: bool) {
        self.record_history_json.store(enabled, Ordering::SeqCst);
    }

    /// Returns whether canonical finalize writes JSON history.
    pub fn record_history_json(&self) -> bool {
        self.record_history_json.load(Ordering::SeqCst)
    }

    /// Selects the programs whose mapping writes are retained as versioned history.
    pub fn set_history_programs(&self, programs: Vec<ProgramID<N>>) {
        *self.history_programs.write() = programs;
    }

    /// Returns the programs selected for mapping history.
    pub fn history_programs(&self) -> Vec<ProgramID<N>> {
        self.history_programs.read().clone()
    }

    /// Enables or disables mapping history for every program, including new deployments.
    pub fn set_archival(&self, enabled: bool) {
        self.archival.store(enabled, Ordering::SeqCst);
    }

    /// Configures program history recording and reports a warning and whether coverage shrinks.
    pub fn configure_history(&self, programs: Vec<ProgramID<N>>, archival: bool) -> Result<(Option<String>, bool)> {
        let selected: Vec<_> =
            if archival { Vec::new() } else { programs.into_iter().collect::<IndexSet<_>>().into_iter().collect() };
        let mut coverage_dropped = false;
        let warning = if let Some(metadata) =
            self.storage.history_metadata_map().get_confirmed(&HISTORY_METADATA_KEY)?
        {
            coverage_dropped =
                !archival && (metadata.0 || metadata.1.iter().any(|program| !selected.contains(program)));
            let changed = metadata.0 != archival
                || metadata.1.len() != selected.len()
                || !metadata.1.iter().all(|program| selected.contains(program));
            if changed {
                let old_mode = if metadata.0 {
                    "all programs".to_string()
                } else if metadata.1.is_empty() {
                    "off".to_string()
                } else {
                    format!(
                        "selected programs: {}",
                        metadata.1.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    )
                };
                let previous = if old_mode == "off" {
                    old_mode
                } else {
                    format!("{old_mode}; latest indexed block {}", metadata.2)
                };
                let new_mode = if archival {
                    "all programs".to_string()
                } else if selected.is_empty() {
                    "off".to_string()
                } else {
                    format!(
                        "selected programs: {}",
                        selected.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    )
                };
                Some(format!(
                    "Mapping history settings changed. Previous coverage: {previous}. New coverage: {new_mode}. Existing ranges remain available; missing blocks will not be backfilled."
                ))
            } else {
                None
            }
        } else if archival || !selected.is_empty() {
            Some("Mapping history recording enabled. Earlier blocks will not be backfilled.".to_string())
        } else {
            None
        };
        self.set_history_programs(selected);
        self.set_archival(archival);
        Ok((warning, coverage_dropped))
    }

    /// Copies confirmed state into history before the next block is imported.
    pub fn prepare_history_baseline(&self, height: u32) -> Result<()> {
        self.prepare_history_baseline_with_batch_size(height, HISTORY_BASELINE_BATCH_SIZE)
    }

    fn prepare_history_baseline_with_batch_size(&self, height: u32, batch_size: usize) -> Result<()> {
        ensure!(batch_size > 0, "History baseline batch size must be positive");
        ensure!(!self.is_atomic_in_progress(), "History baseline requires no active finalize batch");

        let archival = self.archival.load(Ordering::SeqCst);
        let selected = if archival { Vec::new() } else { self.history_programs() };
        let previous = self.storage.history_metadata_map().get_confirmed(&HISTORY_METADATA_KEY)?;
        if let Some(previous) = &previous {
            ensure!(height >= previous.2, "History cursor exceeds the current ledger height");
        }

        // An active archival range stops at the last indexed block when recording changes or skips blocks.
        if previous.as_ref().is_some_and(|previous| previous.0 && (!archival || previous.2 != height)) {
            let previous_end = previous.as_ref().map_or(0, |previous| previous.2);
            let active_ranges: Vec<_> = self
                .storage
                .program_history_map()
                .iter_confirmed()
                .filter(|(_, end)| *end.as_ref() == u32::MAX)
                .map(|(key, _)| key.into_owned())
                .collect();
            for chunk in active_ranges.chunks(batch_size) {
                self.start_atomic();
                let result = (|| {
                    for key in chunk {
                        self.storage.program_history_map().insert(*key, previous_end)?;
                    }
                    self.finish_atomic()
                })();
                if result.is_err() {
                    self.abort_atomic();
                }
                result?;
            }
        }

        let programs: IndexSet<_> = if archival {
            self.storage.program_id_map().keys_confirmed().map(|program| program.into_owned()).collect()
        } else {
            selected.iter().copied().collect()
        };
        let mut uncovered = IndexSet::with_capacity(programs.len());
        for program in &programs {
            if self.storage.program_id_map().get_confirmed(program)?.is_some()
                && self.get_program_history_range(program, height)?.is_none()
            {
                uncovered.insert(*program);
            }
        }

        if !uncovered.is_empty() {
            let version = height.to_be_bytes();
            self.start_atomic();
            let result = (|| {
                let mut queued = 0;
                let mut batch_bytes = 0u64;
                let mut baseline_maps = IndexSet::new();
                let mut expected_values = 0usize;
                for program in &uncovered {
                    if let Some(names) = self.storage.get_mapping_names_confirmed(program)? {
                        for mapping in names {
                            baseline_maps.insert((*program, mapping));
                            expected_values = expected_values
                                .checked_add(self.storage.key_value_map().len_map_confirmed(&(*program, mapping))?)
                                .ok_or_else(|| anyhow!("History baseline entry count overflow"))?;
                            let key = (*program, version, mapping, version);
                            let bytes = bincode::serialized_size(&key)? + bincode::serialized_size(&true)?;
                            if queued > 0
                                && (queued == batch_size
                                    || batch_bytes.saturating_add(bytes) > HISTORY_BASELINE_BATCH_BYTES)
                            {
                                self.finish_atomic()?;
                                self.start_atomic();
                                queued = 0;
                                batch_bytes = 0;
                            }
                            self.storage.mapping_history_map().insert(key, true)?;
                            queued += 1;
                            batch_bytes = batch_bytes.saturating_add(bytes);
                        }
                    }
                }
                let mut copied_values = 0usize;
                for (map, key, value) in self.storage.key_value_map().iter_confirmed() {
                    let (program, mapping) = *map;
                    if baseline_maps.contains(&(program, mapping)) {
                        let key = (program, version, mapping, key.into_owned(), version);
                        let value = Some(value.into_owned());
                        let bytes = bincode::serialized_size(&key)? + bincode::serialized_size(&value)?;
                        if queued > 0
                            && (queued == batch_size
                                || batch_bytes.saturating_add(bytes) > HISTORY_BASELINE_BATCH_BYTES)
                        {
                            self.finish_atomic()?;
                            self.start_atomic();
                            queued = 0;
                            batch_bytes = 0;
                        }
                        self.storage.key_history_map().insert(key, value)?;
                        copied_values += 1;
                        queued += 1;
                        batch_bytes = batch_bytes.saturating_add(bytes);
                    }
                }
                ensure!(
                    copied_values == expected_values,
                    "History baseline scan copied {copied_values} of {expected_values} expected values"
                );
                self.finish_atomic()
            })();
            if result.is_err() {
                self.abort_atomic();
            }
            result?;

            for chunk in uncovered.iter().copied().collect::<Vec<_>>().chunks(batch_size) {
                self.start_atomic();
                let result = (|| {
                    for program in chunk {
                        self.storage.program_history_map().insert((*program, version), height)?;
                    }
                    self.finish_atomic()
                })();
                if result.is_err() {
                    self.abort_atomic();
                }
                result?;
            }
        }

        let last_indexed =
            if archival || !selected.is_empty() { height } else { previous.as_ref().map_or(height, |x| x.2) };
        self.start_atomic();
        let result = (|| {
            self.storage.history_metadata_map().insert(HISTORY_METADATA_KEY, (archival, selected, last_indexed))?;
            self.finish_atomic()
        })();
        if result.is_err() {
            self.abort_atomic();
        }
        result?;

        if archival {
            let mut finite_ranges = Vec::new();
            for program in programs {
                if let Some((key, end)) =
                    self.storage.program_history_map().get_floor_confirmed(&(program, height.to_be_bytes()))?
                    && key.0 == program
                    && *end == height
                {
                    finite_ranges.push(key.into_owned());
                }
            }
            for chunk in finite_ranges.chunks(batch_size) {
                self.start_atomic();
                let result = (|| {
                    for key in chunk {
                        self.storage.program_history_map().insert(*key, u32::MAX)?;
                    }
                    self.finish_atomic()
                })();
                if result.is_err() {
                    self.abort_atomic();
                }
                result?;
            }
        }
        Ok(())
    }

    /// Queues program history in the current canonical finalize batch.
    pub fn record_program_history(&self, height: u32) -> Result<()> {
        let archival = self.archival.load(Ordering::SeqCst);
        let selected: Vec<_> = if archival {
            Vec::new()
        } else {
            self.history_programs().into_iter().collect::<IndexSet<_>>().into_iter().collect()
        };
        if !archival && selected.is_empty() {
            return Ok(());
        }
        let metadata = self.storage.history_metadata_map().get_confirmed(&HISTORY_METADATA_KEY)?;
        if (archival || !selected.is_empty())
            && let Some(metadata) = metadata.as_ref()
            && let Some(first_missing) = metadata.2.checked_add(1).filter(|next| *next < height)
        {
            tracing::warn!(
                "Mapping history gap: blocks {first_missing} through {} have no recorded history. New coverage starts at block {height}; missing blocks will not be backfilled.",
                height.saturating_sub(1)
            );
        }
        let continuing_archival = archival
            && metadata.as_ref().is_some_and(|metadata| metadata.0 && metadata.2.checked_add(1) == Some(height));
        let programs: IndexSet<_> = if archival {
            if continuing_archival {
                self.storage
                    .program_id_map()
                    .iter_pending()
                    .map(|(program, _)| program.into_owned())
                    .chain(self.storage.key_value_map().iter_pending().map(|(map, _, _)| map.0))
                    .collect()
            } else {
                self.storage
                    .program_id_map()
                    .keys_confirmed()
                    .map(|program| program.into_owned())
                    .chain(self.storage.program_id_map().iter_pending().map(|(program, _)| program.into_owned()))
                    .collect()
            }
        } else {
            selected.iter().copied().collect()
        };
        ensure!(self.is_atomic_in_progress(), "Program history requires an atomic finalize batch");

        if metadata.as_ref().is_some_and(|metadata| metadata.0 && !continuing_archival) {
            let previous_end = metadata.as_ref().map_or(0, |metadata| metadata.2);
            let active_ranges: Vec<_> = self
                .storage
                .program_history_map()
                .iter_confirmed()
                .filter(|(_, end)| *end.as_ref() == u32::MAX)
                .map(|(key, _)| key.into_owned())
                .collect();
            for key in active_ranges {
                self.storage.program_history_map().insert(key, previous_end)?;
            }
        }

        let version = height.to_be_bytes();
        let operations: Vec<_> = self
            .storage
            .key_value_map()
            .iter_pending()
            .filter(|(map, _, _)| programs.contains(&map.0))
            .map(|(map, key, value)| (*map, key.map(|key| key.into_owned()), value.map(|value| value.into_owned())))
            .collect();
        let mut resets = HashMap::new();
        for (index, (map, key, _)) in operations.iter().enumerate() {
            if key.is_none() {
                resets.insert(*map, index);
            }
        }

        let mut ranges = HashMap::with_capacity(programs.len());
        for program in programs {
            let previous = match height.checked_sub(1) {
                Some(previous) => self.get_program_history_range(&program, previous)?,
                None => None,
            };
            let (start, baseline) = match previous {
                Some((start, end)) => {
                    ensure!(end.checked_add(1) == Some(height), "Program history must advance in block order");
                    (start.to_be_bytes(), false)
                }
                None => (version, true),
            };
            ranges.insert(program, (start, baseline));

            if baseline {
                ensure!(
                    self.storage.program_id_map().get_confirmed(&program)?.is_none(),
                    "Program history for '{program}' requires a prepared baseline before block {height}"
                );
                if let Some(names) = self.storage.get_mapping_names_speculative(&program)? {
                    for mapping in names {
                        self.storage.mapping_history_map().insert((program, start, mapping, version), true)?;
                        for (key, value) in self.get_mapping_speculative(program, mapping)? {
                            self.storage
                                .key_history_map()
                                .insert((program, start, mapping, key, version), Some(value))?;
                        }
                    }
                }
            } else if self.storage.program_id_map().get_pending(&program).is_some()
                || resets.keys().any(|(id, _)| *id == program)
            {
                let before = self.storage.get_mapping_names_confirmed(&program)?.unwrap_or_default();
                let after = self.storage.get_mapping_names_speculative(&program)?.unwrap_or_default();
                for mapping in &before {
                    if !after.contains(mapping) {
                        self.storage.mapping_history_map().insert((program, start, *mapping, version), false)?;
                    }
                }
                for mapping in after {
                    if !before.contains(&mapping) || resets.contains_key(&(program, mapping)) {
                        self.storage.mapping_history_map().insert((program, start, mapping, version), true)?;
                    }
                }
            }
            let end = if archival && self.storage.program_id_map().get_speculative(&program)?.is_some() {
                u32::MAX
            } else {
                height
            };
            self.storage.program_history_map().insert((program, start), end)?;
        }

        for (index, ((program, mapping), key, value)) in operations.into_iter().enumerate() {
            let (start, baseline) = ranges[&program];
            let reset = resets.get(&(program, mapping));
            if baseline && (!P::RETAINS_PENDING_WRITES_ON_RESET || reset.is_none()) {
                continue;
            }
            if let Some(key) = key {
                if reset.is_some_and(|reset| index < *reset)
                    && (!P::RETAINS_PENDING_WRITES_ON_RESET
                        || self.storage.key_value_map().contains_key_confirmed(&(program, mapping), &key)?)
                {
                    continue;
                }
                self.storage.key_history_map().insert((program, start, mapping, key, version), value)?;
            }
        }
        let last_indexed = if archival || !selected.is_empty() {
            height
        } else {
            metadata.as_ref().map_or(height, |metadata| metadata.2)
        };
        self.storage.history_metadata_map().insert(HISTORY_METADATA_KEY, (archival, selected, last_indexed))?;
        Ok(())
    }

    /// Returns the contiguous indexed range containing `height`, if one exists.
    pub fn get_program_history_range(&self, program: &ProgramID<N>, height: u32) -> Result<Option<(u32, u32)>> {
        let Some((key, end)) =
            self.storage.program_history_map().get_floor_confirmed(&(*program, height.to_be_bytes()))?
        else {
            return Ok(None);
        };
        let (found, start) = key.into_owned();
        let end = if *end == u32::MAX {
            self.storage
                .history_metadata_map()
                .get_confirmed(&HISTORY_METADATA_KEY)?
                .ok_or_else(|| anyhow!("Missing archival history cursor"))?
                .2
        } else {
            *end
        };
        Ok((found == *program && height <= end).then_some((u32::from_be_bytes(start), end)))
    }

    /// Returns the confirmed indexed ranges for a program in start-height order.
    pub fn get_program_history_ranges(&self, program: &ProgramID<N>) -> Result<Vec<(u32, u32)>> {
        let keys = self.storage.program_history_map().get_keys_confirmed_with_prefix(program)?;
        let mut ranges = Vec::with_capacity(keys.len());
        for key in keys {
            if key.0 == *program {
                let end = self
                    .storage
                    .program_history_map()
                    .get_confirmed(&key)?
                    .ok_or_else(|| anyhow!("Missing program history range for '{program}'"))?;
                let end = if *end == u32::MAX {
                    self.storage
                        .history_metadata_map()
                        .get_confirmed(&HISTORY_METADATA_KEY)?
                        .ok_or_else(|| anyhow!("Missing archival history cursor"))?
                        .2
                } else {
                    *end
                };
                ranges.push((u32::from_be_bytes(key.1), end));
            }
        }
        ranges.sort_unstable_by_key(|(start, _)| *start);
        Ok(ranges)
    }

    /// Returns the most recent mapping creation, reset or removal within an indexed range.
    fn mapping_history_at_height(
        &self,
        program: ProgramID<N>,
        start: BlockHeight,
        mapping: Identifier<N>,
        height: u32,
    ) -> Result<Option<(u32, bool)>> {
        let Some((key, exists)) =
            self.storage.mapping_history_map().get_floor_confirmed(&(program, start, mapping, height.to_be_bytes()))?
        else {
            return Ok(None);
        };
        let (found_program, found_start, found_mapping, version) = key.into_owned();
        Ok((found_program == program && found_start == start && found_mapping == mapping)
            .then_some((u32::from_be_bytes(version), *exists)))
    }

    /// Returns whether a mapping exists at a covered historical height.
    pub fn contains_mapping_at_height(
        &self,
        program: ProgramID<N>,
        mapping: Identifier<N>,
        height: u32,
    ) -> Result<bool> {
        let Some((start, _)) = self.get_program_history_range(&program, height)? else {
            bail!("Program history for '{program}' is unavailable at block {height}");
        };
        Ok(self
            .mapping_history_at_height(program, start.to_be_bytes(), mapping, height)?
            .is_some_and(|(_, exists)| exists))
    }

    /// Reads the last key version at or before a covered height, including deletion markers.
    pub fn get_value_at_height(
        &self,
        program: ProgramID<N>,
        mapping: Identifier<N>,
        key: &Plaintext<N>,
        height: u32,
    ) -> Result<Option<Value<N>>> {
        let (start, _) = self
            .get_program_history_range(&program, height)?
            .ok_or_else(|| anyhow!("Program history for '{program}' is unavailable at block {height}"))?;
        let start = start.to_be_bytes();
        let Some((created, true)) = self.mapping_history_at_height(program, start, mapping, height)? else {
            return Ok(None);
        };
        let Some((stored_key, value)) = self.storage.key_history_map().get_floor_confirmed(&(
            program,
            start,
            mapping,
            key.clone(),
            height.to_be_bytes(),
        ))?
        else {
            return Ok(None);
        };
        let (found_program, found_start, found_mapping, found_key, version) = stored_key.into_owned();
        if found_program != program
            || found_start != start
            || found_mapping != mapping
            || found_key != *key
            || u32::from_be_bytes(version) < created
        {
            return Ok(None);
        }
        Ok(value.into_owned())
    }

    /// Returns one page of a mapping's entries at a covered height, and the key to resume after.
    ///
    /// The page visits at most `limit` keys that follow `after` in stored key order, which is the
    /// order of the serialized keys. A visited key with no value at `height` adds no entry, so a
    /// page can hold fewer than `limit` entries. The resume key is `None` when no key follows.
    pub fn get_mapping_at_height(
        &self,
        program: ProgramID<N>,
        mapping: Identifier<N>,
        height: u32,
        after: Option<&Plaintext<N>>,
        limit: usize,
    ) -> Result<MappingPage<N>> {
        ensure!(limit > 0, "A mapping history page must visit at least one key");
        let (start, _) = self
            .get_program_history_range(&program, height)?
            .ok_or_else(|| anyhow!("Program history for '{program}' is unavailable at block {height}"))?;
        let start = start.to_be_bytes();
        let Some((created, true)) = self.mapping_history_at_height(program, start, mapping, height)? else {
            return Ok((Vec::new(), None));
        };

        let key_history = self.storage.key_history_map();
        let mut entries = Vec::new();
        let mut last = after.cloned();
        let mut visited = 0usize;
        loop {
            // Seek past every version of the last key, or to the first key of the mapping.
            let next = match &last {
                Some(key) => {
                    key_history.get_ceiling_confirmed(&(program, start, mapping, key, u32::MAX.to_be_bytes()))?
                }
                None => key_history.get_ceiling_confirmed(&(program, start, mapping))?,
            };
            let Some((stored_key, _)) = next else {
                return Ok((entries, None));
            };
            let (found_program, found_start, found_mapping, key, first_version) = stored_key.into_owned();
            if found_program != program || found_start != start || found_mapping != mapping {
                return Ok((entries, None));
            }
            // A version at `u32::MAX` would make the seek return the same key again.
            ensure!(
                last.as_ref() != Some(&key),
                "Mapping history for '{program}/{mapping}' has a version at the maximum height"
            );
            if visited == limit {
                return Ok((entries, last));
            }
            visited += 1;

            // The first version of a key is its oldest, so a later first version means no value yet.
            let probe = (program, start, mapping, key, height.to_be_bytes());
            if u32::from_be_bytes(first_version) <= height
                && let Some((stored_key, value)) = key_history.get_floor_confirmed(&probe)?
            {
                let (found_program, found_start, found_mapping, found_key, version) = stored_key.into_owned();
                if found_program == program
                    && found_start == start
                    && found_mapping == mapping
                    && found_key == probe.3
                    && u32::from_be_bytes(version) >= created
                    && let Some(value) = value.into_owned()
                {
                    entries.push((found_key, value));
                }
            }
            last = Some(probe.3);
        }
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

    /// Returns the rejection reason map.
    pub fn rejected_reason_map(&self) -> &P::RejectedReasonMap {
        self.storage.rejected_reason_map()
    }

    /// Returns the current block height.
    pub fn block_height(&self) -> &AtomicU32 {
        &self.block_height
    }
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Returns the committee store.
    pub fn committee_store(&self) -> &CommitteeStore<N, P::CommitteeStorage> {
        self.storage.committee_store()
    }
}

impl<N: Network, P: FinalizeStorage<N>> snarkvm_synthesizer_program::sealed_execution::Sealed for FinalizeStore<N, P> {}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStoreTrait<N> for FinalizeStore<N, P> {
    /// Returns `true` if the given `program ID` and `mapping name` is confirmed to exist.
    fn contains_mapping_confirmed(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool> {
        self.storage.contains_mapping_confirmed(program_id, mapping_name)
    }

    /// Returns `true` if the given `program ID` and `mapping name` exist.
    fn contains_mapping_speculative(&self, program_id: &ProgramID<N>, mapping_name: &Identifier<N>) -> Result<bool> {
        self.storage.contains_mapping_speculative(program_id, mapping_name)
    }

    /// Returns `true` if the given `program ID`, `mapping name`, and `key` exist.
    fn contains_key_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<bool> {
        self.storage.contains_key_speculative(program_id, mapping_name, key)
    }

    /// Returns the speculative value for the given `program ID`, `mapping name`, and `key`.
    fn get_value_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>> {
        self.storage.get_value_speculative(program_id, mapping_name, key)
    }

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` already exists, the method returns an error.
    fn insert_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>> {
        self.storage.insert_key_value(program_id, mapping_name, key, value)
    }

    /// Stores the given `(key, value)` pair at the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is not initialized, an error is returned.
    /// If the `key` does not exist, the `(key, value)` pair is initialized.
    /// If the `key` already exists, the `value` is overwritten.
    fn update_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: Plaintext<N>,
        value: Value<N>,
    ) -> Result<FinalizeOperation<N>> {
        self.storage.update_key_value(program_id, mapping_name, key, value)
    }

    /// Removes the key-value pair for the given `program ID`, `mapping name`, and `key` from storage.
    fn remove_key_value(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<FinalizeOperation<N>>> {
        self.storage.remove_key_value(program_id, mapping_name, key)
    }
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Initializes the given `program ID` and `mapping name` in storage.
    /// If the `mapping name` is already initialized, an error is returned.
    pub fn initialize_mapping(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<FinalizeOperation<N>> {
        self.storage.initialize_mapping(program_id, mapping_name)
    }

    /// Replaces the mapping for the given `program ID` and `mapping name` from storage,
    /// with the given `key-value` pairs.
    pub fn replace_mapping(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        entries: Vec<(Plaintext<N>, Value<N>)>,
    ) -> Result<FinalizeOperation<N>> {
        self.storage.replace_mapping(program_id, mapping_name, entries)
    }

    /// Removes the mapping for the given `program ID` and `mapping name` from storage,
    /// along with all associated key-value pairs in storage.
    pub fn remove_mapping(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<FinalizeOperation<N>> {
        self.storage.remove_mapping(program_id, mapping_name)
    }

    /// Removes the program for the given `program ID` from storage,
    /// along with all associated mappings and key-value pairs in storage.
    pub fn remove_program(&self, program_id: &ProgramID<N>) -> Result<()> {
        self.storage.remove_program(program_id)
    }
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Returns `true` if the given `program ID` exist.
    pub fn contains_program_confirmed(&self, program_id: &ProgramID<N>) -> Result<bool> {
        self.storage.contains_program_confirmed(program_id)
    }

    /// Returns `true` if the given `program ID`, `mapping name`, and `key` exist.
    pub fn contains_key_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<bool> {
        self.storage.contains_key_confirmed(program_id, mapping_name, key)
    }
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Returns the confirmed mapping names for the given `program ID`.
    pub fn get_mapping_names_confirmed(&self, program_id: &ProgramID<N>) -> Result<Option<IndexSet<Identifier<N>>>> {
        self.storage.get_mapping_names_confirmed(program_id)
    }

    /// Returns the confirmed mapping entries for the given `program ID` and `mapping name`.
    pub fn get_mapping_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<Vec<(Plaintext<N>, Value<N>)>> {
        self.storage.get_mapping_confirmed(program_id, mapping_name)
    }

    /// Returns the speculative mapping entries for the given `program ID` and `mapping name`.
    pub fn get_mapping_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) -> Result<Vec<(Plaintext<N>, Value<N>)>> {
        self.storage.get_mapping_speculative(program_id, mapping_name)
    }

    /// Returns the confirmed value for the given `program ID`, `mapping name`, and `key`.
    pub fn get_value_confirmed(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>> {
        self.storage.get_value_confirmed(program_id, mapping_name, key)
    }

    /// Returns the speculative value for the given `program ID`, `mapping name`, and `key`.
    pub fn get_value_speculative(
        &self,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
        key: &Plaintext<N>,
    ) -> Result<Option<Value<N>>> {
        self.storage.get_value_speculative(program_id, mapping_name, key)
    }

    /// Returns the confirmed checksum of the finalize store.
    pub fn get_checksum_confirmed(&self) -> Result<Field<N>> {
        self.storage.get_checksum_confirmed()
    }
}

impl<N: Network, P: FinalizeStorage<N>> FinalizeStore<N, P> {
    /// Stores the rejection reason for the given transaction ID.
    pub fn insert_rejected_reason(&self, transaction_id: Field<N>, reason: RejectedReason<N>) -> Result<()> {
        let height = self.block_height.load(std::sync::atomic::Ordering::SeqCst);
        let consensus_version = N::CONSENSUS_VERSION(height)?;
        if consensus_version >= ConsensusVersion::V15 {
            self.storage.rejected_reason_map().insert(transaction_id, reason)
        } else {
            Ok(())
        }
    }

    /// Returns the rejection reason for the given transaction ID.
    pub fn get_rejected_reason(&self, transaction_id: &Field<N>) -> Result<Option<RejectedReason<N>>> {
        match self.storage.rejected_reason_map().get_speculative(transaction_id)? {
            Some(reason) => Ok(Some(reason.into_owned())),
            None => Ok(None),
        }
    }

    /// Returns `true` if a rejection reason exists for the given transaction ID.
    pub fn contains_rejected_reason(&self, transaction_id: &Field<N>) -> Result<bool> {
        self.storage.rejected_reason_map().contains_key_speculative(transaction_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::FinalizeMemory;
    use console::network::MainnetV0;
    use snarkvm_utilities::StorageMode;

    use console::{
        program::Literal,
        types::{U8, U64},
    };

    type CurrentNetwork = MainnetV0;

    /// Checks `initialize_mapping`, `insert_key_value`, `remove_key_value`, and `remove_mapping`.
    fn check_initialize_insert_remove<N: Network>(
        finalize_store: &FinalizeStore<N, FinalizeMemory<N>>,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) {
        // Prepare a key and value.
        let key = Plaintext::from_str("123456789field").unwrap();
        let value = Value::from_str("987654321u128").unwrap();

        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        // Now, initialize the mapping.
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID got initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name got initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key did not get initialized.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Insert a (key, value) pair.
        finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key got initialized.
        assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns Some(value).
        assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

        // Ensure removing the key succeeds.
        assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).unwrap().is_some());
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key got removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Ensure removing the mapping succeeds.
        finalize_store.remove_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key is still removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Ensure removing the program succeeds.
        finalize_store.remove_program(&program_id).unwrap();
        // Ensure the program ID is no longer initialized.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key is still removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
    }

    /// Checks `initialize_mapping`, `update_key_value`, `remove_key_value`, and `remove_mapping`.
    fn check_initialize_update_remove<N: Network>(
        finalize_store: &FinalizeStore<N, FinalizeMemory<N>>,
        program_id: ProgramID<N>,
        mapping_name: Identifier<N>,
    ) {
        // Prepare a key and value.
        let key = Plaintext::from_str("123456789field").unwrap();
        let value = Value::from_str("987654321u128").unwrap();

        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        // Now, initialize the mapping.
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID got initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name got initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key did not get initialized.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Update a (key, value) pair.
        finalize_store.update_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key got initialized.
        assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns Some(value).
        assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

        // Ensure calling `insert_key_value` with the same key and value fails.
        assert!(finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value.clone()).is_err());
        // Ensure the key is still initialized.
        assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns Some(value).
        assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

        // Ensure calling `update_key_value` with the same key and value succeeds.
        finalize_store.update_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
        // Ensure the key is still initialized.
        assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns Some(value).
        assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

        {
            // Prepare the same key and different value.
            let new_value = Value::from_str("123456789u128").unwrap();

            // Ensure calling `insert_key_value` with a different key and value fails.
            assert!(finalize_store.insert_key_value(program_id, mapping_name, key.clone(), new_value.clone()).is_err());
            // Ensure the key is still initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value still returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

            // Ensure calling `update_key_value` with a different key and value succeeds.
            finalize_store.update_key_value(program_id, mapping_name, key.clone(), new_value.clone()).unwrap();
            // Ensure the key is still initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(new_value).
            assert_eq!(
                new_value,
                finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap()
            );

            // Ensure calling `update_key_value` with the same key and original value succeeds.
            finalize_store.update_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
            // Ensure the key is still initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());
        }

        // Ensure removing the key succeeds.
        assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).unwrap().is_some());
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key got removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Ensure removing the mapping succeeds.
        finalize_store.remove_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key is still removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

        // Ensure removing the program succeeds.
        finalize_store.remove_program(&program_id).unwrap();
        // Ensure the program ID is no longer initialized.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is still no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure the key is still removed.
        assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        // Ensure the value still returns None.
        assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
    }

    #[test]
    fn test_initialize_insert_remove() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Check the operations.
        check_initialize_insert_remove(&finalize_store, program_id, mapping_name);
    }

    #[test]
    fn test_initialize_update_remove() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Check the operations.
        check_initialize_update_remove(&finalize_store, program_id, mapping_name);
    }

    #[test]
    fn test_remove_key_value() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        // Now, initialize the mapping.
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID got initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name got initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());

        // Attempt to remove a key-value pairs that do not exist.
        for item in 0..1000 {
            // Prepare the key.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

            // Remove the key-value pair.
            assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).unwrap().is_none());
            // Ensure the program ID is still initialized.
            assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name is still initialized.
            assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
        }

        // Insert the list of keys and values.
        for item in 0..1000 {
            // Prepare the key and value.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();
            let value = Value::from_str(&format!("{item}u64")).unwrap();
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

            // Insert the key and value.
            finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
            // Ensure the program ID is still initialized.
            assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name is still initialized.
            assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key got initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());
        }

        // Remove the list of keys and values.
        for item in 0..1000 {
            // Prepare the key and value.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();
            let value = Value::from_str(&format!("{item}u64")).unwrap();
            // Ensure the key is still initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());

            // Remove the key-value pair.
            assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).unwrap().is_some());
            // Ensure the program ID is still initialized.
            assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name is still initialized.
            assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key is no longer initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
        }
    }

    #[test]
    fn test_remove_mapping() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        // Now, initialize the mapping.
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID got initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name got initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());

        // Insert the list of keys and values.
        for item in 0..1000 {
            // Prepare the key and value.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();
            let value = Value::from_str(&format!("{item}u64")).unwrap();
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

            // Insert the key and value.
            finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
            // Ensure the program ID is still initialized.
            assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name is still initialized.
            assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key got initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());
        }

        // Remove the mapping.
        finalize_store.remove_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID is still initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());

        // Check the list of keys and values.
        for item in 0..1000 {
            // Prepare the key.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();

            // Ensure the key is no longer initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
        }
    }

    #[test]
    fn test_remove_program() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        // Now, initialize the mapping.
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        // Ensure the program ID got initialized.
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name got initialized.
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());

        // Insert the list of keys and values.
        for item in 0..1000 {
            // Prepare the key and value.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();
            let value = Value::from_str(&format!("{item}u64")).unwrap();
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());

            // Insert the key and value.
            finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value.clone()).unwrap();
            // Ensure the program ID is still initialized.
            assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name is still initialized.
            assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key got initialized.
            assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns Some(value).
            assert_eq!(value, finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap());
        }

        // Remove the program.
        finalize_store.remove_program(&program_id).unwrap();
        // Ensure the program ID is no longer initialized.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name is no longer initialized.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());

        // Check the list of keys and values.
        for item in 0..1000 {
            // Prepare the key.
            let key = Plaintext::from_str(&format!("{item}field")).unwrap();

            // Ensure the key is no longer initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
        }
    }

    #[test]
    fn test_must_initialize_first() {
        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
        let finalize_store = FinalizeStore::from(program_memory).unwrap();
        // Ensure the program ID does not exist.
        assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
        // Ensure the mapping name does not exist.
        assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        // Ensure removing an un-initialized mapping fails.
        assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());

        {
            // Ensure inserting a (key, value) before initializing the mapping fails.
            let key = Plaintext::from_str("123456789field").unwrap();
            let value = Value::from_str("987654321u128").unwrap();
            assert!(finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value).is_err());

            // Ensure the program ID did not get initialized.
            assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name did not get initialized.
            assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
            // Ensure removing an un-initialized key fails.
            assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).is_err());
            // Ensure removing an un-initialized mapping fails.
            assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());
        }
        {
            // Ensure updating a (key, value) before initializing the mapping fails.
            let key = Plaintext::from_str("987654321field").unwrap();
            let value = Value::from_str("123456789u128").unwrap();
            assert!(finalize_store.update_key_value(program_id, mapping_name, key.clone(), value).is_err());

            // Ensure the program ID did not get initialized.
            assert!(!finalize_store.contains_program_confirmed(&program_id).unwrap());
            // Ensure the mapping name did not get initialized.
            assert!(!finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
            // Ensure the key did not get initialized.
            assert!(!finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
            // Ensure the value returns None.
            assert!(finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().is_none());
            // Ensure removing an un-initialized key fails.
            assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).is_err());
            // Ensure removing an un-initialized mapping fails.
            assert!(finalize_store.remove_mapping(program_id, mapping_name).is_err());
        }

        // Ensure finalize storage still behaves correctly after the above operations.
        check_initialize_insert_remove(&finalize_store, program_id, mapping_name);
        check_initialize_update_remove(&finalize_store, program_id, mapping_name);
    }

    /// If you want to customize the DB size, run:
    /// ```ignore
    /// NUM_ITEMS=100000 cargo test test_finalize_timings -- --nocapture
    /// ```
    /// If you want to run the test with RocksDB, run:
    /// ```ignore
    /// NUM_ITEMS=100000 cargo test test_finalize_timings --features rocks -- --nocapture
    /// ```
    #[test]
    #[ignore]
    fn test_finalize_timings() {
        let rng = &mut TestRng::default();

        // Default to "100000" if the environment variable doesn't exist or is invalid.
        let num_items: u128 = std::env::var("NUM_ITEMS")
            .unwrap_or_else(|_| "100000".to_string())
            .parse()
            .expect("Failed to parse NUM_ITEMS as u128");

        // Initialize a program ID and mapping name.
        let program_id = ProgramID::<CurrentNetwork>::from_str("hello.aleo").unwrap();
        let mapping_name = Identifier::from_str("account").unwrap();

        // Initialize a new finalize store.
        #[cfg(not(feature = "rocks"))]
        let finalize_store = {
            let program_memory = FinalizeMemory::open(StorageMode::Test(None)).unwrap();
            FinalizeStore::from(program_memory).unwrap()
        };

        // Initialize a new finalize store.
        #[cfg(feature = "rocks")]
        let finalize_store = {
            let temp_dir = std::sync::Arc::new(tempfile::tempdir().expect("Failed to open temporary directory"));
            let program_rocksdb = crate::helpers::rocksdb::FinalizeDB::open(temp_dir).unwrap();
            FinalizeStore::from(program_rocksdb).unwrap()
        };

        // Now, initialize the mapping.
        let timer = std::time::Instant::now();
        finalize_store.initialize_mapping(program_id, mapping_name).unwrap();
        println!("FinalizeStore::initialize_mapping - {} μs", timer.elapsed().as_micros());

        // Prepare the key and value.
        let item: u64 = 100u64;
        let key = Plaintext::from(Literal::Field(Field::from_u64(item)));
        let value = Value::from(Literal::U64(U64::new(item)));

        // Insert the key and value.
        let timer = std::time::Instant::now();
        finalize_store.insert_key_value(program_id, mapping_name, key.clone(), value).unwrap();
        println!("FinalizeStore::insert_key_value - {} μs", timer.elapsed().as_micros());

        // Insert the list of keys and values.
        let mut elapsed = 0u128;
        // Start an atomic transaction.
        finalize_store.start_atomic();
        for i in 0..num_items {
            if i != 0 && i % 10_000 == 0 {
                // Finish the atomic transaction.
                if finalize_store.is_atomic_in_progress() {
                    finalize_store.finish_atomic().unwrap();
                }
                println!("FinalizeStore::insert_key_value - {} μs (average over {i} items)", elapsed / i);
                // Start a new atomic transaction.
                finalize_store.start_atomic();
            }

            // Prepare the key and value.
            let item: u64 = rng.random();
            let key = Plaintext::from(Literal::Field(Field::from_u64(item)));
            let value = Value::from(Literal::U64(U64::new(item)));

            // Insert the key and value.
            let timer = std::time::Instant::now();
            finalize_store.insert_key_value(program_id, mapping_name, key, value).unwrap();
            elapsed = elapsed.checked_add(timer.elapsed().as_micros()).unwrap();
        }
        // Finish the atomic transaction.
        if finalize_store.is_atomic_in_progress() {
            finalize_store.finish_atomic().unwrap();
        }
        println!("FinalizeStore::insert_key_value - {} μs (average over {num_items} items)", elapsed / num_items);

        // Retrieve the checksum.
        let timer = std::time::Instant::now();
        finalize_store.get_checksum_confirmed().unwrap();
        println!("FinalizeStore::get_checksum_confirmed - {} μs", timer.elapsed().as_micros());

        // Ensure the program ID is still initialized.
        let timer = std::time::Instant::now();
        assert!(finalize_store.contains_program_confirmed(&program_id).unwrap());
        println!("FinalizeStore::contains_program_confirmed - {} μs", timer.elapsed().as_micros());

        // Ensure the mapping name is still initialized.
        let timer = std::time::Instant::now();
        assert!(finalize_store.contains_mapping_confirmed(&program_id, &mapping_name).unwrap());
        println!("FinalizeStore::contains_mapping_confirmed - {} μs", timer.elapsed().as_micros());

        // Ensure the key got initialized.
        let timer = std::time::Instant::now();
        assert!(finalize_store.contains_key_confirmed(program_id, mapping_name, &key).unwrap());
        println!("FinalizeStore::contains_key_confirmed - {} μs", timer.elapsed().as_micros());

        // Retrieve the value.
        let timer = std::time::Instant::now();
        finalize_store.get_value_speculative(program_id, mapping_name, &key).unwrap().unwrap();
        println!("FinalizeStore::get_value_speculative - {} μs", timer.elapsed().as_micros());

        // Remove the key-value pair.
        let timer = std::time::Instant::now();
        assert!(finalize_store.remove_key_value(program_id, mapping_name, &key).unwrap().is_some());
        println!("FinalizeStore::remove_key_value - {} μs", timer.elapsed().as_micros());

        // Ensure removing the mapping succeeds.
        let timer = std::time::Instant::now();
        finalize_store.remove_mapping(program_id, mapping_name).unwrap();
        println!("FinalizeStore::remove_mapping - {} μs", timer.elapsed().as_micros());

        // Ensure removing the program succeeds.
        let timer = std::time::Instant::now();
        finalize_store.remove_program(&program_id).unwrap();
        println!("FinalizeStore::remove_program - {} μs", timer.elapsed().as_micros());
    }

    /// The number of blocks in each randomized program history test.
    const NUM_HISTORY_BLOCKS: u32 = 40;

    /// The confirmed entries of each mapping, or `None` for a mapping that does not exist.
    type MappingSnapshot = Vec<Option<Vec<(Plaintext<CurrentNetwork>, Value<CurrentNetwork>)>>>;

    /// Returns a new in-memory finalize store.
    fn sample_memory_finalize_store() -> FinalizeStore<CurrentNetwork, FinalizeMemory<CurrentNetwork>> {
        FinalizeStore::from(FinalizeMemory::open(StorageMode::Test(None)).unwrap()).unwrap()
    }

    /// Returns a new RocksDB finalize store.
    #[cfg(feature = "rocks")]
    fn sample_rocksdb_finalize_store()
    -> FinalizeStore<CurrentNetwork, crate::helpers::rocksdb::FinalizeDB<CurrentNetwork>> {
        FinalizeStore::from(crate::helpers::rocksdb::FinalizeDB::open(StorageMode::new_test(None)).unwrap()).unwrap()
    }

    /// Returns `(program, mapping)` pairs whose program IDs share a prefix and whose mapping names
    /// differ in encoded length, so that a floor lookup that crosses into a neighbouring entry fails.
    fn sample_history_mappings() -> Vec<(ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>)> {
        ["hello.aleo", "hello_world.aleo", "other.aleo"]
            .into_iter()
            .cartesian_product(["a", "ab", "b"])
            .map(|(program, mapping)| (ProgramID::from_str(program).unwrap(), Identifier::from_str(mapping).unwrap()))
            .collect()
    }

    /// Returns keys of different literal types, so that their encodings differ in length.
    fn sample_history_keys() -> Vec<Plaintext<CurrentNetwork>> {
        (0..4u8)
            .map(|i| Plaintext::from(Literal::U8(U8::new(i))))
            .chain((0..4u64).map(|i| Plaintext::from(Literal::U64(U64::new(i)))))
            .collect()
    }

    /// Returns the confirmed entries of each given mapping.
    fn snapshot_mappings<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        mappings: &[(ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>)],
    ) -> MappingSnapshot {
        mappings
            .iter()
            .map(|(program_id, mapping)| {
                let exists = finalize_store
                    .get_mapping_names_confirmed(program_id)
                    .unwrap()
                    .is_some_and(|names| names.contains(mapping));
                exists.then(|| finalize_store.get_mapping_confirmed(*program_id, *mapping).unwrap())
            })
            .collect()
    }

    /// Applies one random mapping operation. An operation that is illegal in the current state fails
    /// before it writes, and is ignored.
    fn apply_random_mapping_operation<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        mappings: &[(ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>)],
        keys: &[Plaintext<CurrentNetwork>],
        rng: &mut TestRng,
    ) -> (ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>, bool, bool) {
        let (program_id, mapping) = mappings[rng.random_range(0..mappings.len())];
        let key = keys[rng.random_range(0..keys.len())].clone();
        let value = Value::from(Literal::U64(U64::new(rng.random_range(0..1000))));
        let (result, resets_mapping) = match rng.random_range(0..11) {
            0..=1 => (finalize_store.initialize_mapping(program_id, mapping).map(drop), false),
            2..=5 => (finalize_store.update_key_value(program_id, mapping, key, value).map(drop), false),
            6..=7 => (finalize_store.remove_key_value(program_id, mapping, &key).map(drop), false),
            8..=9 => {
                let mut entries = Vec::with_capacity(keys.len());
                for key in keys {
                    if rng.random_range(0..2) == 0 {
                        entries.push((key.clone(), Value::from(Literal::U64(U64::new(rng.random_range(0..1000))))));
                    }
                }
                (finalize_store.replace_mapping(program_id, mapping, entries).map(drop), true)
            }
            _ => (finalize_store.remove_mapping(program_id, mapping).map(drop), true),
        };
        (program_id, mapping, resets_mapping, result.is_ok())
    }

    /// Finalizes one block of random mapping operations and records its history.
    /// About one in four operations is rewound, as finalize does for a rejected transaction.
    fn finalize_random_history_block<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        height: u32,
        mappings: &[(ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>)],
        keys: &[Plaintext<CurrentNetwork>],
        rng: &mut TestRng,
    ) {
        finalize_store.start_atomic();
        let mut touched_mappings = IndexSet::new();
        let mut reset_mappings = IndexSet::new();
        for _ in 0..rng.random_range(0..8) {
            finalize_store.atomic_checkpoint();
            let (program, mapping, reset, success) =
                apply_random_mapping_operation(finalize_store, mappings, keys, rng);
            if success
                && (reset_mappings.contains(&(program, mapping))
                    || (reset && touched_mappings.contains(&(program, mapping))))
            {
                finalize_store.atomic_rewind();
                continue;
            }
            match rng.random_range(0..4) {
                0 => finalize_store.atomic_rewind(),
                _ => {
                    finalize_store.clear_latest_checkpoint();
                    if success {
                        touched_mappings.insert((program, mapping));
                        if reset {
                            reset_mappings.insert((program, mapping));
                        }
                    }
                }
            }
        }
        finalize_store.record_program_history(height).unwrap();
        finalize_store.finish_atomic().unwrap();
    }

    /// Checks that each mapping of `program_id` at each height in `heights` matches the snapshot
    /// taken after that height, for every key in `keys`.
    fn check_history_matches_snapshots<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        program_id: ProgramID<CurrentNetwork>,
        heights: core::ops::RangeInclusive<u32>,
        mappings: &[(ProgramID<CurrentNetwork>, Identifier<CurrentNetwork>)],
        keys: &[Plaintext<CurrentNetwork>],
        snapshots: &HashMap<u32, MappingSnapshot>,
    ) {
        for height in heights {
            let snapshot = &snapshots[&height];
            for ((_, mapping), entries) in
                mappings.iter().zip_eq(snapshot).filter(|((program, _), _)| *program == program_id)
            {
                let exists = finalize_store.contains_mapping_at_height(program_id, *mapping, height).unwrap();
                assert_eq!(exists, entries.is_some(), "'{program_id}/{mapping}' existence at height {height}");
                for key in keys {
                    let expected = entries
                        .as_ref()
                        .and_then(|entries| entries.iter().find(|(entry_key, _)| entry_key == key))
                        .map(|(_, value)| value.clone());
                    let found = finalize_store.get_value_at_height(program_id, *mapping, key, height).unwrap();
                    assert_eq!(found, expected, "'{program_id}/{mapping}[{key}]' at height {height}");
                }
                let mut expected = entries.clone().unwrap_or_default();
                let mut found = collect_mapping_at_height(finalize_store, program_id, *mapping, height, 3);
                expected.sort_by_key(|(key, _)| key.to_string());
                found.sort_by_key(|(key, _)| key.to_string());
                assert_eq!(found, expected, "'{program_id}/{mapping}' at height {height}");
            }
        }
    }

    /// Reads a whole mapping at a height in pages of at most `limit` keys.
    fn collect_mapping_at_height<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        program_id: ProgramID<CurrentNetwork>,
        mapping: Identifier<CurrentNetwork>,
        height: u32,
        limit: usize,
    ) -> Vec<(Plaintext<CurrentNetwork>, Value<CurrentNetwork>)> {
        let mut entries = Vec::new();
        let mut after = None;
        loop {
            let (page, next) =
                finalize_store.get_mapping_at_height(program_id, mapping, height, after.as_ref(), limit).unwrap();
            assert!(page.len() <= limit);
            entries.extend(page);
            match next {
                Some(key) => after = Some(key),
                None => return entries,
            }
        }
    }

    fn check_mapping_at_height_pages<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
    ) -> Result<()> {
        let program_id = ProgramID::from_str("hello.aleo")?;
        // The second mapping name extends the first, so that a scan that leaves its mapping fails.
        let mapping = Identifier::from_str("records")?;
        let neighbour = Identifier::from_str("records_two")?;
        let keys = sample_history_keys();
        let value = |number: u64| Value::from(Literal::U64(U64::new(number)));
        finalize_store.configure_history(vec![program_id], false)?;

        // Block 0 inserts every key.
        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.initialize_mapping(program_id, neighbour)?;
        for (index, key) in keys.iter().enumerate() {
            finalize_store.insert_key_value(program_id, mapping, key.clone(), value(index as u64))?;
        }
        finalize_store.insert_key_value(program_id, neighbour, keys[0].clone(), value(100))?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        // Block 1 removes one key and updates another.
        finalize_store.start_atomic();
        finalize_store.remove_key_value(program_id, mapping, &keys[1])?;
        finalize_store.update_key_value(program_id, mapping, keys[2].clone(), value(20))?;
        finalize_store.record_program_history(1)?;
        finalize_store.finish_atomic()?;

        // Block 2 resets the mapping to one key.
        finalize_store.start_atomic();
        finalize_store.replace_mapping(program_id, mapping, vec![(keys[4].clone(), value(40))])?;
        finalize_store.record_program_history(2)?;
        finalize_store.finish_atomic()?;

        // Block 3 inserts a key that the reset removed.
        finalize_store.start_atomic();
        finalize_store.insert_key_value(program_id, mapping, keys[6].clone(), value(60))?;
        finalize_store.record_program_history(3)?;
        finalize_store.finish_atomic()?;

        let sorted = |mut entries: Vec<(Plaintext<CurrentNetwork>, Value<CurrentNetwork>)>| {
            entries.sort_by_key(|(key, _)| key.to_string());
            entries
        };
        let at_genesis: Vec<_> = keys.iter().cloned().zip((0..).map(value)).collect();
        let mut at_one = at_genesis.clone();
        at_one[2].1 = value(20);
        at_one.remove(1);

        // Every page size returns the same entries in the same order.
        let whole = collect_mapping_at_height(finalize_store, program_id, mapping, 0, usize::MAX);
        assert_eq!(sorted(whole.clone()), sorted(at_genesis));
        for limit in [1, 3, keys.len(), keys.len() + 1] {
            assert_eq!(collect_mapping_at_height(finalize_store, program_id, mapping, 0, limit), whole);
        }

        // A full page names the key to resume after, and the last page names none.
        let (page, next) = finalize_store.get_mapping_at_height(program_id, mapping, 0, None, 3)?;
        assert_eq!(page, whole[..3]);
        assert_eq!(next.as_ref(), Some(&whole[2].0));
        let (page, next) =
            finalize_store.get_mapping_at_height(program_id, mapping, 0, next.as_ref(), keys.len() - 3)?;
        assert_eq!(page, whole[3..]);
        assert_eq!(next, None);
        let last = &whole[whole.len() - 1].0;
        assert_eq!(finalize_store.get_mapping_at_height(program_id, mapping, 0, Some(last), 3)?, (Vec::new(), None));

        // Each height returns the entries that were confirmed after it.
        assert_eq!(sorted(collect_mapping_at_height(finalize_store, program_id, mapping, 1, 3)), sorted(at_one));
        assert_eq!(collect_mapping_at_height(finalize_store, program_id, mapping, 2, 3), vec![(
            keys[4].clone(),
            value(40)
        )]);
        assert_eq!(
            sorted(collect_mapping_at_height(finalize_store, program_id, mapping, 3, 1)),
            sorted(vec![(keys[4].clone(), value(40)), (keys[6].clone(), value(60))])
        );
        assert_eq!(collect_mapping_at_height(finalize_store, program_id, neighbour, 3, 3), vec![(
            keys[0].clone(),
            value(100)
        )]);

        // A mapping that does not exist has no entries.
        let missing = Identifier::from_str("missing")?;
        assert_eq!(finalize_store.get_mapping_at_height(program_id, missing, 3, None, 3)?, (Vec::new(), None));
        // A height without history and an empty page are errors.
        assert!(finalize_store.get_mapping_at_height(program_id, mapping, 4, None, 3).is_err());
        assert!(finalize_store.get_mapping_at_height(program_id, mapping, 3, None, 0).is_err());
        Ok(())
    }

    #[test]
    fn test_mapping_at_height_pages_memory() -> Result<()> {
        check_mapping_at_height_pages(&sample_memory_finalize_store())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_mapping_at_height_pages_rocksdb() -> Result<()> {
        check_mapping_at_height_pages(&sample_rocksdb_finalize_store())
    }

    /// Runs random mapping operations over many blocks, then checks every height of history against
    /// the state that was confirmed after that height.
    ///
    /// In selective mode, `hello.aleo` and `hello_world.aleo` are selected and `other.aleo` is not.
    /// In archival mode, each program is covered from the first block in which it exists.
    fn check_program_history_random<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
        archival: bool,
    ) {
        let rng = &mut TestRng::default();
        let mappings = sample_history_mappings();
        let keys = sample_history_keys();
        let programs: IndexSet<_> = mappings.iter().map(|(program_id, _)| *program_id).collect();

        match archival {
            true => finalize_store.set_archival(true),
            false => finalize_store.set_history_programs(programs.iter().take(2).copied().collect()),
        }

        let mut snapshots = HashMap::new();
        let mut first_seen = HashMap::new();
        for height in 0..NUM_HISTORY_BLOCKS {
            finalize_random_history_block(finalize_store, height, &mappings, &keys, rng);
            snapshots.insert(height, snapshot_mappings(finalize_store, &mappings));
            for program_id in &programs {
                if finalize_store.contains_program_confirmed(program_id).unwrap() {
                    first_seen.entry(*program_id).or_insert(height);
                }
            }
        }

        let last = NUM_HISTORY_BLOCKS - 1;
        for (index, program_id) in programs.iter().enumerate() {
            let start = match archival {
                true => first_seen.get(program_id).copied(),
                false => (index < 2).then_some(0),
            };
            assert_eq!(
                finalize_store.get_program_history_ranges(program_id).unwrap(),
                start.map(|start| vec![(start, last)]).unwrap_or_default(),
            );
            for height in 0..NUM_HISTORY_BLOCKS {
                let expected = start.filter(|start| *start <= height).map(|start| (start, last));
                assert_eq!(finalize_store.get_program_history_range(program_id, height).unwrap(), expected);
            }
            if let Some(start) = start {
                check_history_matches_snapshots(
                    finalize_store,
                    *program_id,
                    start..=last,
                    &mappings,
                    &keys,
                    &snapshots,
                );
            }
        }
    }

    #[test]
    fn test_program_history_selected_memory() {
        check_program_history_random(&sample_memory_finalize_store(), false);
    }

    #[test]
    fn test_program_history_archival_memory() {
        check_program_history_random(&sample_memory_finalize_store(), true);
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_program_history_selected_rocksdb() {
        check_program_history_random(&sample_rocksdb_finalize_store(), false);
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_program_history_archival_rocksdb() {
        check_program_history_random(&sample_rocksdb_finalize_store(), true);
    }

    fn check_chunked_history_baseline<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
    ) -> Result<()> {
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        let empty = Identifier::from_str("empty")?;
        let keys = sample_history_keys();
        let old = Value::from(Literal::U64(U64::new(10)));
        let new = Value::from(Literal::U64(U64::new(20)));

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.initialize_mapping(program_id, empty)?;
        for key in &keys {
            finalize_store.update_key_value(program_id, mapping, key.clone(), old.clone())?;
        }
        finalize_store.finish_atomic()?;

        let version = 5u32.to_be_bytes();
        finalize_store
            .storage
            .key_history_map()
            .insert((program_id, version, mapping, keys[0].clone(), version), Some(new.clone()))?;
        assert_eq!(finalize_store.get_program_history_range(&program_id, 5)?, None);

        finalize_store.configure_history(Vec::new(), true)?;
        finalize_store.prepare_history_baseline_with_batch_size(5, 2)?;
        finalize_store.prepare_history_baseline_with_batch_size(5, 2)?;
        assert_eq!(finalize_store.get_program_history_range(&program_id, 4)?, None);
        assert_eq!(finalize_store.get_program_history_range(&program_id, 5)?, Some((5, 5)));
        assert!(finalize_store.contains_mapping_at_height(program_id, empty, 5)?);
        for key in &keys {
            assert_eq!(finalize_store.get_value_at_height(program_id, mapping, key, 5)?, Some(old.clone()));
        }

        finalize_store.start_atomic();
        finalize_store.update_key_value(program_id, mapping, keys[0].clone(), new.clone())?;
        finalize_store.record_program_history(6)?;
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_value_at_height(program_id, mapping, &keys[0], 5)?, Some(old));
        assert_eq!(finalize_store.get_value_at_height(program_id, mapping, &keys[0], 6)?, Some(new));
        assert_eq!(finalize_store.get_program_history_ranges(&program_id)?, vec![(5, 6)]);
        Ok(())
    }

    #[test]
    fn test_chunked_history_baseline_memory() -> Result<()> {
        check_chunked_history_baseline(&sample_memory_finalize_store())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_chunked_history_baseline_rocksdb() -> Result<()> {
        check_chunked_history_baseline(&sample_rocksdb_finalize_store())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_history_baseline_retries_after_corrupt_value() -> Result<()> {
        use crate::helpers::rocksdb::{Database, MapID, ProgramMap, RocksDB};

        let finalize_store = sample_rocksdb_finalize_store();
        let before_program = ProgramID::from_str("aaaaa.aleo")?;
        let corrupt_program = ProgramID::from_str("mmmmm.aleo")?;
        let program_id = ProgramID::from_str("zzzzz.aleo")?;
        let mapping = Identifier::from_str("records")?;
        let key = Plaintext::from_str("1u8")?;
        let value = Value::from_str("7u64")?;
        finalize_store.initialize_mapping(before_program, mapping)?;
        finalize_store.insert_key_value(before_program, mapping, key.clone(), value.clone())?;
        finalize_store.initialize_mapping(corrupt_program, mapping)?;
        finalize_store.insert_key_value(corrupt_program, mapping, key.clone(), value.clone())?;
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.insert_key_value(program_id, mapping, key.clone(), value.clone())?;
        finalize_store.configure_history(vec![before_program, program_id], false)?;

        let database = RocksDB::open(CurrentNetwork::ID, finalize_store.storage.storage_mode().clone())?;
        let mut prefix = CurrentNetwork::ID.to_le_bytes().to_vec();
        prefix.extend_from_slice(&u16::from(MapID::Program(ProgramMap::KeyValueID)).to_le_bytes());
        let (raw_key, raw_value) =
            database.prefix_iterator(&prefix).nth(1).ok_or_else(|| anyhow::anyhow!("Missing test mapping entry"))??;
        database.put(&raw_key, [0xff])?;
        assert!(finalize_store.get_value_confirmed(corrupt_program, mapping, &key).is_err());
        assert_eq!(finalize_store.get_value_confirmed(program_id, mapping, &key)?, Some(value.clone()));

        assert!(finalize_store.prepare_history_baseline_with_batch_size(0, 1).is_err());
        assert_eq!(finalize_store.get_program_history_range(&before_program, 0)?, None);
        assert_eq!(finalize_store.get_program_history_range(&program_id, 0)?, None);

        database.put(&raw_key, raw_value)?;
        finalize_store.prepare_history_baseline_with_batch_size(0, 1)?;
        assert_eq!(finalize_store.get_value_at_height(before_program, mapping, &key, 0)?, Some(value.clone()));
        assert_eq!(finalize_store.get_value_at_height(program_id, mapping, &key, 0)?, Some(value));
        Ok(())
    }

    fn check_insert_then_reset_history<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
    ) -> Result<()> {
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        let recreated = Identifier::from_str("recreated")?;
        let key = Plaintext::from_str("1u8")?;
        let old_key = Plaintext::from_str("2u8")?;
        let after_key = Plaintext::from_str("3u8")?;
        let value = Value::from_str("7u64")?;
        finalize_store.configure_history(vec![program_id], false)?;

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.initialize_mapping(program_id, recreated)?;
        finalize_store.insert_key_value(program_id, mapping, old_key.clone(), Value::from_str("3u64")?)?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        finalize_store.insert_key_value(program_id, mapping, key.clone(), value.clone())?;
        finalize_store.update_key_value(program_id, mapping, old_key.clone(), Value::from_str("4u64")?)?;
        finalize_store.replace_mapping(program_id, mapping, Vec::new())?;
        finalize_store.insert_key_value(program_id, mapping, after_key.clone(), Value::from_str("8u64")?)?;
        finalize_store.insert_key_value(program_id, recreated, key.clone(), value)?;
        finalize_store.remove_mapping(program_id, recreated)?;
        finalize_store.initialize_mapping(program_id, recreated)?;
        finalize_store.record_program_history(1)?;
        finalize_store.finish_atomic()?;

        for (mapping, key) in [(mapping, &key), (mapping, &old_key), (mapping, &after_key), (recreated, &key)] {
            assert_eq!(
                finalize_store.get_value_at_height(program_id, mapping, key, 1)?,
                finalize_store.get_value_confirmed(program_id, mapping, key)?
            );
        }
        Ok(())
    }

    #[test]
    fn test_insert_then_reset_history_memory() -> Result<()> {
        check_insert_then_reset_history(&sample_memory_finalize_store())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_insert_then_reset_history_rocksdb() -> Result<()> {
        check_insert_then_reset_history(&sample_rocksdb_finalize_store())
    }

    fn check_new_program_reset_history<P: FinalizeStorage<CurrentNetwork>>(
        finalize_store: &FinalizeStore<CurrentNetwork, P>,
    ) -> Result<()> {
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        let key = Plaintext::from_str("1u8")?;
        finalize_store.configure_history(vec![program_id], false)?;

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.insert_key_value(program_id, mapping, key.clone(), Value::from_str("7u64")?)?;
        finalize_store.replace_mapping(program_id, mapping, Vec::new())?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        assert_eq!(
            finalize_store.get_value_at_height(program_id, mapping, &key, 0)?,
            finalize_store.get_value_confirmed(program_id, mapping, &key)?
        );
        Ok(())
    }

    #[test]
    fn test_new_program_reset_history_memory() -> Result<()> {
        check_new_program_reset_history(&sample_memory_finalize_store())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_new_program_reset_history_rocksdb() -> Result<()> {
        check_new_program_reset_history(&sample_rocksdb_finalize_store())
    }

    #[test]
    fn test_existing_state_requires_prepared_history_baseline() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.finish_atomic()?;

        finalize_store.configure_history(vec![program_id], false)?;
        finalize_store.start_atomic();
        assert!(finalize_store.record_program_history(1).is_err());
        finalize_store.abort_atomic();
        Ok(())
    }

    #[test]
    fn test_program_history_gap_starts_new_range() {
        let rng = &mut TestRng::default();
        let finalize_store = sample_memory_finalize_store();
        let mappings = sample_history_mappings();
        let keys = sample_history_keys();
        let program_id = mappings[0].0;

        // Record heights 0 to 9, skip heights 10 to 14, and record heights 15 to 24.
        let mut snapshots = HashMap::new();
        let mut resumed_start = 15;
        for height in 0..25 {
            let recorded = !(10..15).contains(&height);
            finalize_store
                .configure_history(if recorded { vec![program_id] } else { vec![] }, false)
                .expect("The test explicitly changes history coverage");
            if height == 15 {
                if finalize_store.contains_program_confirmed(&program_id).expect("The test reads confirmed state") {
                    resumed_start = 14;
                }
                finalize_store.prepare_history_baseline(14).expect("The test prepares existing state");
            }
            finalize_random_history_block(&finalize_store, height, &mappings, &keys, rng);
            snapshots.insert(height, snapshot_mappings(&finalize_store, &mappings));
        }

        assert_eq!(finalize_store.get_program_history_range(&program_id, 9).unwrap(), Some((0, 9)));
        assert_eq!(finalize_store.get_program_history_range(&program_id, 12).unwrap(), None);
        assert_eq!(finalize_store.get_program_history_range(&program_id, 15).unwrap(), Some((resumed_start, 24)));
        assert_eq!(finalize_store.get_program_history_ranges(&program_id).unwrap(), vec![(0, 9), (resumed_start, 24)]);
        assert!(finalize_store.contains_mapping_at_height(program_id, mappings[0].1, 12).is_err());
        assert!(finalize_store.get_value_at_height(program_id, mappings[0].1, &keys[0], 12).is_err());

        // The new range starts with a baseline of the state that existed when recording resumed.
        check_history_matches_snapshots(&finalize_store, program_id, 0..=9, &mappings, &keys, &snapshots);
        check_history_matches_snapshots(&finalize_store, program_id, resumed_start..=24, &mappings, &keys, &snapshots);
    }

    #[test]
    fn test_archival_untouched_program_has_no_range_write() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        finalize_store.set_archival(true);

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        finalize_store.record_program_history(1)?;
        assert!(finalize_store.storage.program_history_map().iter_pending().next().is_none());
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_program_history_range(&program_id, 1)?, Some((0, 1)));
        Ok(())
    }

    #[test]
    fn test_history_configuration_change_preserves_coverage() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        finalize_store.set_history_programs(vec![program_id]);
        finalize_store.start_atomic();
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        let reopened = FinalizeStore::from(finalize_store.storage.clone())?;
        let warning = reopened.configure_history(Vec::new(), false)?;
        assert!(warning.0.as_deref().is_some_and(|message| message.contains("New coverage: off")));
        assert!(warning.1);
        reopened.start_atomic();
        reopened.record_program_history(1)?;
        reopened.finish_atomic()?;
        assert_eq!(reopened.get_program_history_range(&program_id, 0)?, Some((0, 0)));
        assert_eq!(reopened.get_program_history_range(&program_id, 1)?, None);
        Ok(())
    }

    #[test]
    fn test_history_configuration_reports_coverage_drop() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let first = ProgramID::from_str("first.aleo")?;
        let second = ProgramID::from_str("second.aleo")?;
        assert!(!finalize_store.configure_history(vec![first], false)?.1);
        finalize_store.start_atomic();
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        assert!(!finalize_store.configure_history(vec![first, second], false)?.1);
        assert!(finalize_store.configure_history(vec![second], false)?.1);
        assert!(!finalize_store.configure_history(Vec::new(), true)?.1);
        finalize_store.start_atomic();
        finalize_store.record_program_history(1)?;
        finalize_store.finish_atomic()?;
        assert!(finalize_store.configure_history(vec![second], false)?.1);
        Ok(())
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_history_configuration_persists_rocksdb() -> Result<()> {
        let finalize_store = sample_rocksdb_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        finalize_store.configure_history(vec![program_id], false)?;
        finalize_store.start_atomic();
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        let reopened = FinalizeStore::from(finalize_store.storage.clone())?;
        let warning = reopened.configure_history(Vec::new(), false)?;
        assert!(warning.0.as_deref().is_some_and(|message| message.contains("New coverage: off")));
        assert!(warning.1);
        reopened.start_atomic();
        reopened.record_program_history(1)?;
        reopened.finish_atomic()?;
        reopened.configure_history(vec![program_id], false)?;
        reopened.start_atomic();
        reopened.record_program_history(2)?;
        reopened.finish_atomic()?;
        assert_eq!(reopened.get_program_history_ranges(&program_id)?, vec![(0, 0), (2, 2)]);
        assert_eq!(reopened.get_program_history_range(&program_id, 1)?, None);
        Ok(())
    }

    #[test]
    fn test_archival_mode_change_closes_and_restarts_coverage() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        finalize_store.configure_history(Vec::new(), true)?;

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        finalize_store.record_program_history(1)?;
        finalize_store.finish_atomic()?;

        finalize_store.configure_history(Vec::new(), false)?;
        finalize_store.start_atomic();
        finalize_store.record_program_history(2)?;
        assert!(finalize_store.storage.program_history_map().iter_pending().next().is_none());
        assert!(finalize_store.storage.history_metadata_map().iter_pending().next().is_none());
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_program_history_ranges(&program_id)?, vec![(0, 1)]);
        assert_eq!(finalize_store.get_program_history_range(&program_id, 2)?, None);

        finalize_store.configure_history(Vec::new(), true)?;
        finalize_store.prepare_history_baseline(2)?;
        finalize_store.start_atomic();
        finalize_store.record_program_history(3)?;
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_program_history_ranges(&program_id)?, vec![(0, 1), (2, 3)]);
        Ok(())
    }

    #[test]
    fn test_archival_removed_program_does_not_extend_coverage() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        finalize_store.set_archival(true);

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        finalize_store.remove_program(&program_id)?;
        finalize_store.record_program_history(1)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        finalize_store.record_program_history(2)?;
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_program_history_range(&program_id, 2)?, None);
        assert_eq!(finalize_store.get_program_history_ranges(&program_id)?, vec![(0, 1)]);
        Ok(())
    }

    #[test]
    fn test_archival_skipped_height_requires_baseline() -> Result<()> {
        let finalize_store = sample_memory_finalize_store();
        let program_id = ProgramID::from_str("hello.aleo")?;
        let mapping = Identifier::from_str("records")?;
        finalize_store.set_archival(true);

        finalize_store.start_atomic();
        finalize_store.initialize_mapping(program_id, mapping)?;
        finalize_store.record_program_history(0)?;
        finalize_store.finish_atomic()?;

        finalize_store.start_atomic();
        assert!(finalize_store.record_program_history(2).is_err());
        finalize_store.abort_atomic();
        finalize_store.prepare_history_baseline(1)?;
        finalize_store.start_atomic();
        finalize_store.record_program_history(2)?;
        finalize_store.finish_atomic()?;
        assert_eq!(finalize_store.get_program_history_ranges(&program_id)?, vec![(0, 0), (1, 2)]);
        assert_eq!(finalize_store.get_program_history_range(&program_id, 1)?, Some((1, 2)));
        Ok(())
    }

    #[test]
    fn test_program_history_disabled_records_nothing() {
        let rng = &mut TestRng::default();
        let finalize_store = sample_memory_finalize_store();
        let mappings = sample_history_mappings();
        let keys = sample_history_keys();

        for height in 0..10 {
            finalize_random_history_block(&finalize_store, height, &mappings, &keys, rng);
        }
        // Recording is skipped without an atomic batch when nothing is selected.
        finalize_store.record_program_history(10).unwrap();

        assert!(finalize_store.storage.program_history_map().iter_confirmed().next().is_none());
        assert!(finalize_store.storage.mapping_history_map().iter_confirmed().next().is_none());
        assert!(finalize_store.storage.key_history_map().iter_confirmed().next().is_none());
    }

    #[test]
    fn test_program_history_requires_atomic_batch() {
        let finalize_store = sample_memory_finalize_store();
        finalize_store.set_history_programs(vec![ProgramID::from_str("hello.aleo").unwrap()]);
        assert!(finalize_store.record_program_history(0).is_err());
    }
}
