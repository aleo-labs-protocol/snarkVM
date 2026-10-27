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
use console::{
    network::prelude::*,
    program::{Ciphertext, Plaintext},
    types::Field,
};
use snarkvm_ledger_block::Input;

use aleo_std_storage::StorageMode;
use anyhow::Result;
use std::borrow::Cow;

/// A trait for transition input storage.
pub trait InputStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transition ID` to `input IDs`.
    type IDMap: for<'a> Map<'a, N::TransitionID, Vec<Field<N>>>;
    /// The mapping of `input ID` to `transition ID`.
    type ReverseIDMap: for<'a> Map<'a, Field<N>, N::TransitionID>;
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    type ConstantMap: for<'a> Map<'a, Field<N>, Option<Plaintext<N>>>;
    /// The mapping of `plaintext hash` to `(optional) plaintext`.
    type PublicMap: for<'a> Map<'a, Field<N>, Option<Plaintext<N>>>;
    /// The mapping of `ciphertext hash` to `(optional) ciphertext`.
    type PrivateMap: for<'a> Map<'a, Field<N>, Option<Ciphertext<N>>>;
    /// The mapping of `serial number` to `tag`.
    type RecordMap: for<'a> Map<'a, Field<N>, Field<N>>;
    /// The mapping of `tag` to `serial number`.
    type RecordTagMap: for<'a> Map<'a, Field<N>, Field<N>>;
    /// The mapping of `external hash` to `()`. Note: This is **not** the record commitment.
    type ExternalRecordMap: for<'a> Map<'a, Field<N>, ()>;
    /// The mapping of `dynamic hash` to `()`. Note: This is **not** the record commitment.
    type DynamicRecordMap: for<'a> Map<'a, Field<N>, ()>;
    /// The mapping of `input ID` to `dynamic ID` for inputs with dynamic IDs.
    type DynamicIDMap: for<'a> Map<'a, Field<N>, Field<N>>;

    /// Initializes the transition input storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the ID map.
    fn id_map(&self) -> &Self::IDMap;
    /// Returns the reverse ID map.
    fn reverse_id_map(&self) -> &Self::ReverseIDMap;
    /// Returns the constant map.
    fn constant_map(&self) -> &Self::ConstantMap;
    /// Returns the public map.
    fn public_map(&self) -> &Self::PublicMap;
    /// Returns the private map.
    fn private_map(&self) -> &Self::PrivateMap;
    /// Returns the record map.
    fn record_map(&self) -> &Self::RecordMap;
    /// Returns the record tag map.
    fn record_tag_map(&self) -> &Self::RecordTagMap;
    /// Returns the external record map.
    fn external_record_map(&self) -> &Self::ExternalRecordMap;
    /// Returns the dynamic record map.
    fn dynamic_record_map(&self) -> &Self::DynamicRecordMap;
    /// Returns the dynamic ID map.
    fn dynamic_id_map(&self) -> &Self::DynamicIDMap;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode;

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.id_map().start_atomic();
        self.reverse_id_map().start_atomic();
        self.constant_map().start_atomic();
        self.public_map().start_atomic();
        self.private_map().start_atomic();
        self.record_map().start_atomic();
        self.record_tag_map().start_atomic();
        self.external_record_map().start_atomic();
        self.dynamic_record_map().start_atomic();
        self.dynamic_id_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.id_map().is_atomic_in_progress()
            || self.reverse_id_map().is_atomic_in_progress()
            || self.constant_map().is_atomic_in_progress()
            || self.public_map().is_atomic_in_progress()
            || self.private_map().is_atomic_in_progress()
            || self.record_map().is_atomic_in_progress()
            || self.record_tag_map().is_atomic_in_progress()
            || self.external_record_map().is_atomic_in_progress()
            || self.dynamic_record_map().is_atomic_in_progress()
            || self.dynamic_id_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.id_map().atomic_checkpoint();
        self.reverse_id_map().atomic_checkpoint();
        self.constant_map().atomic_checkpoint();
        self.public_map().atomic_checkpoint();
        self.private_map().atomic_checkpoint();
        self.record_map().atomic_checkpoint();
        self.record_tag_map().atomic_checkpoint();
        self.external_record_map().atomic_checkpoint();
        self.dynamic_record_map().atomic_checkpoint();
        self.dynamic_id_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.id_map().clear_latest_checkpoint();
        self.reverse_id_map().clear_latest_checkpoint();
        self.constant_map().clear_latest_checkpoint();
        self.public_map().clear_latest_checkpoint();
        self.private_map().clear_latest_checkpoint();
        self.record_map().clear_latest_checkpoint();
        self.record_tag_map().clear_latest_checkpoint();
        self.external_record_map().clear_latest_checkpoint();
        self.dynamic_record_map().clear_latest_checkpoint();
        self.dynamic_id_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.id_map().atomic_rewind();
        self.reverse_id_map().atomic_rewind();
        self.constant_map().atomic_rewind();
        self.public_map().atomic_rewind();
        self.private_map().atomic_rewind();
        self.record_map().atomic_rewind();
        self.record_tag_map().atomic_rewind();
        self.external_record_map().atomic_rewind();
        self.dynamic_record_map().atomic_rewind();
        self.dynamic_id_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.id_map().abort_atomic();
        self.reverse_id_map().abort_atomic();
        self.constant_map().abort_atomic();
        self.public_map().abort_atomic();
        self.private_map().abort_atomic();
        self.record_map().abort_atomic();
        self.record_tag_map().abort_atomic();
        self.external_record_map().abort_atomic();
        self.dynamic_record_map().abort_atomic();
        self.dynamic_id_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.id_map().finish_atomic()?;
        self.reverse_id_map().finish_atomic()?;
        self.constant_map().finish_atomic()?;
        self.public_map().finish_atomic()?;
        self.private_map().finish_atomic()?;
        self.record_map().finish_atomic()?;
        self.record_tag_map().finish_atomic()?;
        self.external_record_map().finish_atomic()?;
        self.dynamic_record_map().finish_atomic()?;
        self.dynamic_id_map().finish_atomic()
    }

    /// Stores the given `(transition ID, input)` pair into storage.
    fn insert(&self, transition_id: N::TransitionID, inputs: &[Input<N>]) -> Result<()> {
        atomic_batch_scope!(self, {
            // Store the input IDs.
            self.id_map().insert(transition_id, inputs.iter().map(Input::id).copied().collect())?;

            // Store the inputs.
            for input in inputs {
                // Store the reverse input ID.
                self.reverse_id_map().insert(*input.id(), transition_id)?;
                // Store the input.
                match input.clone() {
                    Input::Constant(input_id, constant) => self.constant_map().insert(input_id, constant)?,
                    Input::Public(input_id, public) => self.public_map().insert(input_id, public)?,
                    Input::Private(input_id, private) => self.private_map().insert(input_id, private)?,
                    Input::Record(serial_number, tag) => {
                        // Store the record tag.
                        self.record_tag_map().insert(tag, serial_number)?;
                        // Store the record.
                        self.record_map().insert(serial_number, tag)?
                    }
                    Input::ExternalRecord(input_id) => self.external_record_map().insert(input_id, ())?,
                    Input::DynamicRecord(input_id) => self.dynamic_record_map().insert(input_id, ())?,
                    Input::RecordWithDynamicID(serial_number, tag, dynamic_id) => {
                        // Store the record tag.
                        self.record_tag_map().insert(tag, serial_number)?;
                        // Store the record.
                        self.record_map().insert(serial_number, tag)?;
                        // Store the dynamic ID.
                        self.dynamic_id_map().insert(serial_number, dynamic_id)?;
                    }
                    Input::ExternalRecordWithDynamicID(input_id, dynamic_id) => {
                        self.external_record_map().insert(input_id, ())?;
                        // Store the dynamic ID.
                        self.dynamic_id_map().insert(input_id, dynamic_id)?;
                    }
                }
            }

            Ok(())
        })
    }

    /// Removes the input for the given `transition ID`.
    fn remove(&self, transition_id: &N::TransitionID) -> Result<()> {
        // Retrieve the input IDs.
        let input_ids: Vec<_> = match self.id_map().get_confirmed(transition_id)? {
            Some(Cow::Borrowed(ids)) => ids.to_vec(),
            Some(Cow::Owned(ids)) => ids.into_iter().collect(),
            None => return Ok(()),
        };

        atomic_batch_scope!(self, {
            // Remove the input IDs.
            self.id_map().remove(transition_id)?;

            // Remove the inputs.
            for input_id in input_ids {
                // Remove the reverse input ID.
                self.reverse_id_map().remove(&input_id)?;

                // If the input is a record, remove the record tag.
                if let Some(tag) = self.record_map().get_confirmed(&input_id)? {
                    self.record_tag_map().remove(&tag)?;
                }

                // Remove the input.
                self.constant_map().remove(&input_id)?;
                self.public_map().remove(&input_id)?;
                self.private_map().remove(&input_id)?;
                self.record_map().remove(&input_id)?;
                self.external_record_map().remove(&input_id)?;
                self.dynamic_record_map().remove(&input_id)?;
                self.dynamic_id_map().remove(&input_id)?;
            }

            Ok(())
        })
    }

    /// Returns the transition ID that contains the given `input ID`.
    fn find_transition_id(&self, input_id: &Field<N>) -> Result<Option<N::TransitionID>> {
        match self.reverse_id_map().get_confirmed(input_id)? {
            Some(Cow::Borrowed(transition_id)) => Ok(Some(*transition_id)),
            Some(Cow::Owned(transition_id)) => Ok(Some(transition_id)),
            None => Ok(None),
        }
    }

    /// Returns the input IDs for the given `transition ID`.
    fn get_ids(&self, transition_id: &N::TransitionID) -> Result<Vec<Field<N>>> {
        // Retrieve the input IDs.
        match self.id_map().get_confirmed(transition_id)? {
            Some(Cow::Borrowed(inputs)) => Ok(inputs.to_vec()),
            Some(Cow::Owned(inputs)) => Ok(inputs),
            None => Ok(vec![]),
        }
    }

    /// Returns the input for the given `transition ID`.
    fn get(&self, transition_id: &N::TransitionID) -> Result<Vec<Input<N>>> {
        // Constructs the input given the input ID and input value.
        macro_rules! into_input {
            (Input::Record($input_id:ident, $input:expr)) => {
                match $input {
                    Cow::Borrowed(tag) => Input::Record($input_id, *tag),
                    Cow::Owned(tag) => Input::Record($input_id, tag),
                }
            };
            (Input::$Variant:ident($input_id:ident, $input:expr)) => {
                match $input {
                    Cow::Borrowed(input) => Input::$Variant($input_id, input.clone()),
                    Cow::Owned(input) => Input::$Variant($input_id, input),
                }
            };
        }

        // A helper function to construct the input given the input ID.
        let construct_input = |input_id| {
            let constant = self.constant_map().get_confirmed(&input_id)?;
            let public = self.public_map().get_confirmed(&input_id)?;
            let private = self.private_map().get_confirmed(&input_id)?;
            let record = self.record_map().get_confirmed(&input_id)?;
            let external_record = self.external_record_map().get_confirmed(&input_id)?;
            let dynamic_record = self.dynamic_record_map().get_confirmed(&input_id)?;
            let dynamic_id = self.dynamic_id_map().get_confirmed(&input_id)?;

            // Retrieve the input.
            let input = match (constant, public, private, record, external_record, dynamic_record) {
                (Some(constant), None, None, None, None, None) => into_input!(Input::Constant(input_id, constant)),
                (None, Some(public), None, None, None, None) => into_input!(Input::Public(input_id, public)),
                (None, None, Some(private), None, None, None) => into_input!(Input::Private(input_id, private)),
                (None, None, None, Some(record), None, None) => {
                    match dynamic_id {
                        // If a dynamic ID is present, this is a RecordWithDynamicID.
                        Some(dynamic_id) => {
                            let tag = match record {
                                Cow::Borrowed(tag) => *tag,
                                Cow::Owned(tag) => tag,
                            };
                            let dynamic_id = match dynamic_id {
                                Cow::Borrowed(id) => *id,
                                Cow::Owned(id) => id,
                            };
                            Input::RecordWithDynamicID(input_id, tag, dynamic_id)
                        }
                        None => into_input!(Input::Record(input_id, record)),
                    }
                }
                (None, None, None, None, Some(_), None) => {
                    match dynamic_id {
                        // If a dynamic ID is present, this is an ExternalRecordWithDynamicID.
                        Some(dynamic_id) => {
                            let dynamic_id = match dynamic_id {
                                Cow::Borrowed(id) => *id,
                                Cow::Owned(id) => id,
                            };
                            Input::ExternalRecordWithDynamicID(input_id, dynamic_id)
                        }
                        None => Input::ExternalRecord(input_id),
                    }
                }
                (None, None, None, None, None, Some(_)) => Input::DynamicRecord(input_id),
                (None, None, None, None, None, None) => {
                    bail!("Missing input '{input_id}' in transition '{transition_id}'")
                }
                _ => bail!("Found multiple inputs for the input ID '{input_id}' in transition '{transition_id}'"),
            };

            Ok(input)
        };

        // Retrieve the input IDs.
        match self.id_map().get_confirmed(transition_id)? {
            Some(Cow::Borrowed(ids)) => ids.iter().map(|input_id| construct_input(*input_id)).collect(),
            Some(Cow::Owned(ids)) => ids.iter().map(|input_id| construct_input(*input_id)).collect(),
            None => Ok(vec![]),
        }
    }
}

/// The transition input store.
#[derive(Clone)]
pub struct InputStore<N: Network, I: InputStorage<N>> {
    /// The map of constant inputs.
    constant: I::ConstantMap,
    /// The map of public inputs.
    public: I::PublicMap,
    /// The map of private inputs.
    private: I::PrivateMap,
    /// The map of record inputs.
    record: I::RecordMap,
    /// The map of record tags.
    record_tag: I::RecordTagMap,
    /// The map of external record inputs.
    external_record: I::ExternalRecordMap,
    /// The map of dynamic record inputs.
    dynamic_record: I::DynamicRecordMap,
    /// The map of dynamic IDs for inputs with dynamic IDs.
    dynamic_id: I::DynamicIDMap,
    /// The input storage.
    storage: I,
}

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Initializes the transition input store.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        // Initialize a new transition input storage.
        let storage = I::open(storage)?;
        // Return the transition input store.
        Ok(Self {
            constant: storage.constant_map().clone(),
            public: storage.public_map().clone(),
            private: storage.private_map().clone(),
            record: storage.record_map().clone(),
            record_tag: storage.record_tag_map().clone(),
            external_record: storage.external_record_map().clone(),
            dynamic_record: storage.dynamic_record_map().clone(),
            dynamic_id: storage.dynamic_id_map().clone(),
            storage,
        })
    }

    /// Initializes a transition input store from storage.
    pub fn from(storage: I) -> Self {
        Self {
            constant: storage.constant_map().clone(),
            public: storage.public_map().clone(),
            private: storage.private_map().clone(),
            record: storage.record_map().clone(),
            record_tag: storage.record_tag_map().clone(),
            external_record: storage.external_record_map().clone(),
            dynamic_record: storage.dynamic_record_map().clone(),
            dynamic_id: storage.dynamic_id_map().clone(),
            storage,
        }
    }

    /// Stores the given `(transition ID, input)` pair into storage.
    pub fn insert(&self, transition_id: N::TransitionID, inputs: &[Input<N>]) -> Result<()> {
        self.storage.insert(transition_id, inputs)
    }

    /// Removes the input for the given `transition ID`.
    pub fn remove(&self, transition_id: &N::TransitionID) -> Result<()> {
        self.storage.remove(transition_id)
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

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Returns the input IDs for the given `transition ID`.
    pub fn get_input_ids(&self, transition_id: &N::TransitionID) -> Result<Vec<Field<N>>> {
        self.storage.get_ids(transition_id)
    }

    /// Returns the inputs for the given `transition ID`.
    pub fn get_inputs(&self, transition_id: &N::TransitionID) -> Result<Vec<Input<N>>> {
        self.storage.get(transition_id)
    }
}

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Returns the transition ID that contains the given `input ID`.
    pub fn find_transition_id(&self, input_id: &Field<N>) -> Result<Option<N::TransitionID>> {
        self.storage.find_transition_id(input_id)
    }
}

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Returns `true` if the given input ID exists.
    pub fn contains_input_id(&self, input_id: &Field<N>) -> Result<bool> {
        self.storage.reverse_id_map().contains_key_confirmed(input_id)
    }

    /// Returns `true` if the given serial number exists.
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> Result<bool> {
        self.record.contains_key_confirmed(serial_number)
    }

    /// Returns `true` if the given tag exists.
    pub fn contains_tag(&self, tag: &Field<N>) -> Result<bool> {
        self.record_tag.contains_key_confirmed(tag)
    }
}

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Returns an iterator over the input IDs, for all transition inputs.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.storage.reverse_id_map().keys_confirmed()
    }

    /// Returns an iterator over the constant input IDs, for all transition inputs that are constant.
    pub fn constant_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.constant.keys_confirmed()
    }

    /// Returns an iterator over the public input IDs, for all transition inputs that are public.
    pub fn public_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.public.keys_confirmed()
    }

    /// Returns an iterator over the private input IDs, for all transition inputs that are private.
    pub fn private_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.private.keys_confirmed()
    }

    /// Returns an iterator over the serial numbers, for all transition inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.record.keys_confirmed()
    }

    /// Returns an iterator over the external record input IDs, for all transition inputs that are external records.
    pub fn external_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.external_record.keys_confirmed()
    }

    /// Returns an iterator over the dynamic record input IDs, for all transition inputs that are dynamic records.
    pub fn dynamic_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.dynamic_record.keys_confirmed()
    }

    /// Returns an iterator over the dynamic IDs, for all transition inputs with dynamic IDs.
    pub fn input_dynamic_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.dynamic_id.values_confirmed()
    }
}

impl<N: Network, I: InputStorage<N>> InputStore<N, I> {
    /// Returns an iterator over the constant inputs, for all transitions.
    pub fn constant_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.constant.values_confirmed().flat_map(|input| match input {
            Cow::Borrowed(Some(input)) => Some(Cow::Borrowed(input)),
            Cow::Owned(Some(input)) => Some(Cow::Owned(input)),
            _ => None,
        })
    }

    /// Returns an iterator over the constant inputs, for all transitions.
    pub fn public_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.public.values_confirmed().flat_map(|input| match input {
            Cow::Borrowed(Some(input)) => Some(Cow::Borrowed(input)),
            Cow::Owned(Some(input)) => Some(Cow::Owned(input)),
            _ => None,
        })
    }

    /// Returns an iterator over the private inputs, for all transitions.
    pub fn private_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Ciphertext<N>>> {
        self.private.values_confirmed().flat_map(|input| match input {
            Cow::Borrowed(Some(input)) => Some(Cow::Borrowed(input)),
            Cow::Owned(Some(input)) => Some(Cow::Owned(input)),
            _ => None,
        })
    }

    /// Returns an iterator over the tags, for all transition inputs that are records.
    pub fn tags(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.record_tag.keys_confirmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::InputMemory;

    #[test]
    fn test_insert_get_remove() {
        // Sample the transition inputs.
        for (transition_id, input) in snarkvm_ledger_test_helpers::sample_inputs() {
            // Initialize a new input store.
            let input_store = InputMemory::open(StorageMode::Test(None)).unwrap();

            // Ensure the transition input does not exist.
            let candidate = input_store.get(&transition_id).unwrap();
            assert!(candidate.is_empty());

            // Insert the transition input.
            input_store.insert(transition_id, std::slice::from_ref(&input)).unwrap();

            // Retrieve the transition input.
            let candidate = input_store.get(&transition_id).unwrap();
            assert_eq!(vec![input.clone()], candidate);

            // Remove the transition input.
            input_store.remove(&transition_id).unwrap();

            // Retrieve the transition input.
            let candidate = input_store.get(&transition_id).unwrap();
            assert!(candidate.is_empty());
        }
    }

    #[test]
    fn test_find_transition_id() {
        // Sample the transition inputs.
        for (transition_id, input) in snarkvm_ledger_test_helpers::sample_inputs() {
            // Initialize a new input store.
            let input_store = InputMemory::open(StorageMode::Test(None)).unwrap();

            // Ensure the transition input does not exist.
            let candidate = input_store.get(&transition_id).unwrap();
            assert!(candidate.is_empty());

            // Ensure the transition ID is not found.
            let candidate = input_store.find_transition_id(input.id()).unwrap();
            assert!(candidate.is_none());

            // Insert the transition input.
            input_store.insert(transition_id, std::slice::from_ref(&input)).unwrap();

            // Find the transition ID.
            let candidate = input_store.find_transition_id(input.id()).unwrap();
            assert_eq!(Some(transition_id), candidate);

            // Remove the transition input.
            input_store.remove(&transition_id).unwrap();

            // Ensure the transition ID is not found.
            let candidate = input_store.find_transition_id(input.id()).unwrap();
            assert!(candidate.is_none());
        }
    }
}
