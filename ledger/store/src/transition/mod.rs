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

mod input;
pub use input::*;

mod output;
pub use output::*;

use crate::{
    atomic_batch_scope,
    helpers::{Map, MapRead},
};
use console::{
    network::prelude::*,
    program::{Ciphertext, Identifier, Plaintext, ProgramID, Record},
    types::{Field, Group},
};
use snarkvm_ledger_block::{Input, Output, Transition};

use aleo_std_storage::StorageMode;
use anyhow::Result;
use std::borrow::Cow;

/// A trait for transition storage.
pub trait TransitionStorage<N: Network>: Clone + Send + Sync {
    /// The transition program IDs and function names.
    type LocatorMap: for<'a> Map<'a, N::TransitionID, (ProgramID<N>, Identifier<N>)>;
    /// The transition inputs.
    type InputStorage: InputStorage<N>;
    /// The transition outputs.
    type OutputStorage: OutputStorage<N>;
    /// The transition public keys.
    type TPKMap: for<'a> Map<'a, N::TransitionID, Group<N>>;
    /// The mapping of `transition public key` to `transition ID`.
    type ReverseTPKMap: for<'a> Map<'a, Group<N>, N::TransitionID>;
    /// The transition commitments.
    type TCMMap: for<'a> Map<'a, N::TransitionID, Field<N>>;
    /// The mapping of `transition commitment` to `transition ID`.
    type ReverseTCMMap: for<'a> Map<'a, Field<N>, N::TransitionID>;
    /// The signer commitments.
    type SCMMap: for<'a> Map<'a, N::TransitionID, Field<N>>;

    /// Initializes the transition storage.
    fn open<S: Into<StorageMode>>(storage: S) -> Result<Self>;

    /// Returns the transition program IDs and function names.
    fn locator_map(&self) -> &Self::LocatorMap;
    /// Returns the transition input store.
    fn input_store(&self) -> &InputStore<N, Self::InputStorage>;
    /// Returns the transition output store.
    fn output_store(&self) -> &OutputStore<N, Self::OutputStorage>;
    /// Returns the transition public keys map.
    fn tpk_map(&self) -> &Self::TPKMap;
    /// Returns the reverse `tpk` map.
    fn reverse_tpk_map(&self) -> &Self::ReverseTPKMap;
    /// Returns the transition commitments map.
    fn tcm_map(&self) -> &Self::TCMMap;
    /// Returns the reverse `tcm` map.
    fn reverse_tcm_map(&self) -> &Self::ReverseTCMMap;
    /// Returns the signer commitments map.
    fn scm_map(&self) -> &Self::SCMMap;

    /// Returns the storage mode.
    fn storage_mode(&self) -> &StorageMode {
        debug_assert!(self.input_store().storage_mode() == self.output_store().storage_mode());
        self.input_store().storage_mode()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.locator_map().start_atomic();
        self.input_store().start_atomic();
        self.output_store().start_atomic();
        self.tpk_map().start_atomic();
        self.reverse_tpk_map().start_atomic();
        self.tcm_map().start_atomic();
        self.reverse_tcm_map().start_atomic();
        self.scm_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.locator_map().is_atomic_in_progress()
            || self.input_store().is_atomic_in_progress()
            || self.output_store().is_atomic_in_progress()
            || self.tpk_map().is_atomic_in_progress()
            || self.reverse_tpk_map().is_atomic_in_progress()
            || self.tcm_map().is_atomic_in_progress()
            || self.reverse_tcm_map().is_atomic_in_progress()
            || self.scm_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.locator_map().atomic_checkpoint();
        self.input_store().atomic_checkpoint();
        self.output_store().atomic_checkpoint();
        self.tpk_map().atomic_checkpoint();
        self.reverse_tpk_map().atomic_checkpoint();
        self.tcm_map().atomic_checkpoint();
        self.reverse_tcm_map().atomic_checkpoint();
        self.scm_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.locator_map().clear_latest_checkpoint();
        self.input_store().clear_latest_checkpoint();
        self.output_store().clear_latest_checkpoint();
        self.tpk_map().clear_latest_checkpoint();
        self.reverse_tpk_map().clear_latest_checkpoint();
        self.tcm_map().clear_latest_checkpoint();
        self.reverse_tcm_map().clear_latest_checkpoint();
        self.scm_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.locator_map().atomic_rewind();
        self.input_store().atomic_rewind();
        self.output_store().atomic_rewind();
        self.tpk_map().atomic_rewind();
        self.reverse_tpk_map().atomic_rewind();
        self.tcm_map().atomic_rewind();
        self.reverse_tcm_map().atomic_rewind();
        self.scm_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.locator_map().abort_atomic();
        self.input_store().abort_atomic();
        self.output_store().abort_atomic();
        self.tpk_map().abort_atomic();
        self.reverse_tpk_map().abort_atomic();
        self.tcm_map().abort_atomic();
        self.reverse_tcm_map().abort_atomic();
        self.scm_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.locator_map().finish_atomic()?;
        self.input_store().finish_atomic()?;
        self.output_store().finish_atomic()?;
        self.tpk_map().finish_atomic()?;
        self.reverse_tpk_map().finish_atomic()?;
        self.tcm_map().finish_atomic()?;
        self.reverse_tcm_map().finish_atomic()?;
        self.scm_map().finish_atomic()
    }

    /// Stores the given `transition` into storage.
    fn insert(&self, transition: &Transition<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            // Retrieve the transition ID.
            let transition_id = *transition.id();
            // Store the program ID and function name.
            self.locator_map().insert(transition_id, (*transition.program_id(), *transition.function_name()))?;
            // Store the inputs.
            self.input_store().insert(transition_id, transition.inputs())?;
            // Store the outputs.
            self.output_store().insert(transition_id, transition.outputs())?;
            // Store `tpk`.
            self.tpk_map().insert(transition_id, *transition.tpk())?;
            // Store the reverse `tpk` entry.
            self.reverse_tpk_map().insert(*transition.tpk(), transition_id)?;
            // Store `tcm`.
            self.tcm_map().insert(transition_id, *transition.tcm())?;
            // Store the reverse `tcm` entry.
            self.reverse_tcm_map().insert(*transition.tcm(), transition_id)?;
            // Store `scm`.
            self.scm_map().insert(transition_id, *transition.scm())?;
            Ok(())
        })
    }

    /// Removes the input for the given `transition ID`.
    fn remove(&self, transition_id: &N::TransitionID) -> Result<()> {
        // Retrieve the `tpk`.
        let Some(tpk) = self.tpk_map().get_confirmed(transition_id)?.map(|x| *x) else {
            return Ok(());
        };
        // Retrieve the `tcm`.
        let Some(tcm) = self.tcm_map().get_confirmed(transition_id)?.map(|x| *x) else {
            return Ok(());
        };

        atomic_batch_scope!(self, {
            // Remove the program ID and function name.
            self.locator_map().remove(transition_id)?;
            // Remove the inputs.
            self.input_store().remove(transition_id)?;
            // Remove the outputs.
            self.output_store().remove(transition_id)?;
            // Remove `tpk`.
            self.tpk_map().remove(transition_id)?;
            // Remove the reverse `tpk` entry.
            self.reverse_tpk_map().remove(&tpk)?;
            // Remove `tcm`.
            self.tcm_map().remove(transition_id)?;
            // Remove the reverse `tcm` entry.
            self.reverse_tcm_map().remove(&tcm)?;
            // Remove `scm`.
            self.scm_map().remove(transition_id)?;

            Ok(())
        })
    }

    /// Returns the transition for the given `transition ID`.
    fn get(&self, transition_id: &N::TransitionID) -> Result<Option<Transition<N>>> {
        // Retrieve the program ID and function name.
        let Some((program_id, function_name)) =
            self.locator_map().get_confirmed(transition_id)?.map(|x| x.into_owned())
        else {
            return Ok(None);
        };
        // Retrieve the inputs.
        let inputs = self.input_store().get_inputs(transition_id)?;
        // Retrieve the outputs.
        let outputs = self.output_store().get_outputs(transition_id)?;
        // Retrieve `tpk`.
        let tpk = self.tpk_map().get_confirmed(transition_id)?;
        // Retrieve `tcm`.
        let tcm = self.tcm_map().get_confirmed(transition_id)?;
        // Retrieve `scm`.
        let scm = self.scm_map().get_confirmed(transition_id)?;

        match (tpk, tcm, scm) {
            (Some(tpk), Some(tcm), Some(scm)) => Ok(Some(Transition::new_unchecked(
                *transition_id,
                program_id,
                function_name,
                inputs,
                outputs,
                tpk.into_owned(),
                tcm.into_owned(),
                scm.into_owned(),
            ))),
            _ => bail!("Transition '{transition_id}' is missing some data (possible corruption)"),
        }
    }
}

/// The transition store.
#[derive(Clone)]
pub struct TransitionStore<N: Network, T: TransitionStorage<N>> {
    /// The map of transition program IDs and function names.
    locator: T::LocatorMap,
    /// The map of transition inputs.
    inputs: InputStore<N, T::InputStorage>,
    /// The map of transition outputs.
    outputs: OutputStore<N, T::OutputStorage>,
    /// The map of transition public keys.
    tpk: T::TPKMap,
    /// The reverse `tpk` map.
    reverse_tpk: T::ReverseTPKMap,
    /// The map of transition commitments.
    tcm: T::TCMMap,
    /// The reverse `tcm` map.
    reverse_tcm: T::ReverseTCMMap,
    /// The map of signer commitments.
    scm: T::SCMMap,
    /// The transition storage.
    storage: T,
}

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /// Initializes the transition store.
    pub fn open<S: Into<StorageMode>>(storage: S) -> Result<Self> {
        // Initialize the transition storage.
        let storage = T::open(storage)?;
        // Return the transition store.
        Ok(Self {
            locator: storage.locator_map().clone(),
            inputs: (*storage.input_store()).clone(),
            outputs: (*storage.output_store()).clone(),
            tpk: storage.tpk_map().clone(),
            reverse_tpk: storage.reverse_tpk_map().clone(),
            tcm: storage.tcm_map().clone(),
            reverse_tcm: storage.reverse_tcm_map().clone(),
            scm: storage.scm_map().clone(),
            storage,
        })
    }

    /// Initializes a transition store from storage.
    pub fn from(storage: T) -> Self {
        Self {
            locator: storage.locator_map().clone(),
            inputs: (*storage.input_store()).clone(),
            outputs: (*storage.output_store()).clone(),
            tpk: storage.tpk_map().clone(),
            reverse_tpk: storage.reverse_tpk_map().clone(),
            tcm: storage.tcm_map().clone(),
            reverse_tcm: storage.reverse_tcm_map().clone(),
            scm: storage.scm_map().clone(),
            storage,
        }
    }

    /// Stores the given `transition` into storage.
    pub fn insert(&self, transition: &Transition<N>) -> Result<()> {
        self.storage.insert(transition)
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

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /// Returns the transition ID that contains the given `input ID` or `output ID`.
    pub fn find_transition_id(&self, id: &Field<N>) -> Result<N::TransitionID> {
        // Start by checking the output IDs (which is the more likely case).
        if let Some(transition_id) = self.outputs.find_transition_id(id)? {
            return Ok(transition_id);
        }
        // Then check the input IDs.
        if let Some(transition_id) = self.inputs.find_transition_id(id)? {
            return Ok(transition_id);
        }
        // Throw an error.
        bail!("Failed to find the transition ID for the given input or output ID '{id}'")
    }
}

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /// Returns the transition for the given `transition ID`.
    pub fn get_transition(&self, transition_id: &N::TransitionID) -> Result<Option<Transition<N>>> {
        self.storage.get(transition_id)
    }

    /// Returns the program ID for the given `transition ID`.
    pub fn get_program_id(&self, transition_id: &N::TransitionID) -> Result<Option<ProgramID<N>>> {
        Ok(self.locator.get_confirmed(transition_id)?.map(|locator| match locator {
            Cow::Borrowed((program_id, _)) => *program_id,
            Cow::Owned((program_id, _)) => program_id,
        }))
    }

    /// Returns the function name for the given `transition ID`.
    pub fn get_function_name(&self, transition_id: &N::TransitionID) -> Result<Option<Identifier<N>>> {
        Ok(self.locator.get_confirmed(transition_id)?.map(|locator| match locator {
            Cow::Borrowed((_, function_name)) => *function_name,
            Cow::Owned((_, function_name)) => function_name,
        }))
    }

    /// Returns the input IDs for the given `transition ID`.
    pub fn get_input_ids(&self, transition_id: &N::TransitionID) -> Result<Vec<Field<N>>> {
        self.inputs.get_input_ids(transition_id)
    }

    /// Returns the inputs for the given `transition ID`.
    pub fn get_inputs(&self, transition_id: &N::TransitionID) -> Result<Vec<Input<N>>> {
        self.inputs.get_inputs(transition_id)
    }

    /// Returns the output IDs for the given `transition ID`.
    pub fn get_output_ids(&self, transition_id: &N::TransitionID) -> Result<Vec<Field<N>>> {
        self.outputs.get_output_ids(transition_id)
    }

    /// Returns the outputs for the given `transition ID`.
    pub fn get_outputs(&self, transition_id: &N::TransitionID) -> Result<Vec<Output<N>>> {
        self.outputs.get_outputs(transition_id)
    }

    /// Returns the record for the given `commitment`.
    ///
    /// If the record exists, `Ok(Some(record))` is returned.
    /// If the record was purged, `Ok(None)` is returned.
    /// If the record does not exist, `Err(error)` is returned.
    pub fn get_record(&self, commitment: &Field<N>) -> Result<Option<Record<N, Ciphertext<N>>>> {
        self.outputs.get_record(commitment)
    }
}

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /// Returns `true` if the given transition ID exists.
    pub fn contains_transition_id(&self, transition_id: &N::TransitionID) -> Result<bool> {
        self.locator.contains_key_confirmed(transition_id)
    }

    /* Input */

    /// Returns `true` if the given input ID exists.
    pub fn contains_input_id(&self, input_id: &Field<N>) -> Result<bool> {
        self.inputs.contains_input_id(input_id)
    }

    /// Returns `true` if the given serial number exists.
    pub fn contains_serial_number(&self, serial_number: &Field<N>) -> Result<bool> {
        self.inputs.contains_serial_number(serial_number)
    }

    /// Returns `true` if the given tag exists.
    pub fn contains_tag(&self, tag: &Field<N>) -> Result<bool> {
        self.inputs.contains_tag(tag)
    }

    /* Output */

    /// Returns `true` if the given output ID exists.
    pub fn contains_output_id(&self, output_id: &Field<N>) -> Result<bool> {
        self.outputs.contains_output_id(output_id)
    }

    /// Returns `true` if the given commitment exists.
    pub fn contains_commitment(&self, commitment: &Field<N>) -> Result<bool> {
        self.outputs.contains_commitment(commitment)
    }

    /// Returns `true` if the given checksum exists.
    pub fn contains_checksum(&self, checksum: &Field<N>) -> bool {
        self.outputs.contains_checksum(checksum)
    }

    /// Returns `true` if the given nonce exists.
    pub fn contains_nonce(&self, nonce: &Group<N>) -> Result<bool> {
        self.outputs.contains_nonce(nonce)
    }

    /* Metadata */

    /// Returns `true` if the given transition public key exists.
    pub fn contains_tpk(&self, tpk: &Group<N>) -> Result<bool> {
        self.reverse_tpk.contains_key_confirmed(tpk)
    }

    /// Returns `true` if the given transition commitment exists.
    pub fn contains_tcm(&self, tcm: &Field<N>) -> Result<bool> {
        self.reverse_tcm.contains_key_confirmed(tcm)
    }
}

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /// Returns an iterator over the transition IDs, for all transitions.
    pub fn transition_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransitionID>> {
        self.tcm.keys_confirmed()
    }

    /* Input */

    /// Returns an iterator over the input IDs, for all transition inputs.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.input_ids()
    }

    /// Returns an iterator over the constant input IDs, for all transition inputs that are constant.
    pub fn constant_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.constant_input_ids()
    }

    /// Returns an iterator over the public input IDs, for all transition inputs that are public.
    pub fn public_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.public_input_ids()
    }

    /// Returns an iterator over the private input IDs, for all transition inputs that are private.
    pub fn private_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.private_input_ids()
    }

    /// Returns an iterator over the serial numbers, for all transition inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.serial_numbers()
    }

    /// Returns an iterator over the external record input IDs, for all transition inputs that are external records.
    pub fn external_input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.external_input_ids()
    }

    /* Output */

    /// Returns an iterator over the output IDs, for all transition outputs.
    pub fn output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.output_ids()
    }

    /// Returns an iterator over the constant output IDs, for all transition outputs that are constant.
    pub fn constant_output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.constant_output_ids()
    }

    /// Returns an iterator over the public output IDs, for all transition outputs that are public.
    pub fn public_output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.public_output_ids()
    }

    /// Returns an iterator over the private output IDs, for all transition outputs that are private.
    pub fn private_output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.private_output_ids()
    }

    /// Returns an iterator over the commitments, for all transition outputs that are records.
    pub fn commitments(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.commitments()
    }

    /// Returns an iterator over the external record output IDs, for all transition outputs that are external records.
    pub fn external_output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.external_output_ids()
    }
}

impl<N: Network, T: TransitionStorage<N>> TransitionStore<N, T> {
    /* Input */

    /// Returns an iterator over the constant inputs, for all transitions.
    pub fn constant_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.inputs.constant_inputs()
    }

    /// Returns an iterator over the constant inputs, for all transitions.
    pub fn public_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.inputs.public_inputs()
    }

    /// Returns an iterator over the private inputs, for all transitions.
    pub fn private_inputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Ciphertext<N>>> {
        self.inputs.private_inputs()
    }

    /// Returns an iterator over the tags, for all transition inputs that are records.
    pub fn tags(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.inputs.tags()
    }

    /* Output */

    /// Returns an iterator over the constant outputs, for all transitions.
    pub fn constant_outputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.outputs.constant_outputs()
    }

    /// Returns an iterator over the constant outputs, for all transitions.
    pub fn public_outputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Plaintext<N>>> {
        self.outputs.public_outputs()
    }

    /// Returns an iterator over the private outputs, for all transitions.
    pub fn private_outputs(&self) -> impl '_ + Iterator<Item = Cow<'_, Ciphertext<N>>> {
        self.outputs.private_outputs()
    }

    /// Returns an iterator over the checksums, for all transition outputs that are records.
    pub fn checksums(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.outputs.checksums()
    }

    /// Returns an iterator over the nonces, for all transition outputs that are records.
    pub fn nonces(&self) -> impl '_ + Iterator<Item = Cow<'_, Group<N>>> {
        self.outputs.nonces()
    }

    /// Returns an iterator over the `(commitment, record)` pairs, for all transition outputs that are records.
    #[allow(clippy::type_complexity)]
    pub fn records(&self) -> impl '_ + Iterator<Item = (Cow<'_, Field<N>>, Cow<'_, Record<N, Ciphertext<N>>>)> {
        self.outputs.records()
    }

    /* Metadata */

    /// Returns an iterator over the transition public keys, for all transitions.
    pub fn tpks(&self) -> impl '_ + Iterator<Item = Cow<'_, Group<N>>> {
        self.tpk.values_confirmed()
    }

    /// Returns an iterator over the transition commitments, for all transitions.
    pub fn tcms(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.tcm.values_confirmed()
    }

    /// Returns an iterator over the signer commitments, for all transitions.
    pub fn scms(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.scm.values_confirmed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::memory::TransitionMemory;

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the transactions.
        let transaction_0 = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        let transaction_1 = snarkvm_ledger_test_helpers::sample_execution_transaction_with_fee(false, rng, 0);
        let transactions = vec![transaction_0, transaction_1];

        for transaction in transactions {
            let transitions = transaction.transitions().cloned().collect::<Vec<_>>();

            // Ensure there is at least 2 transition.
            println!("\n\nNumber of transitions: {}\n", transitions.len());
            assert!(transitions.len() > 1, "\n\nNumber of transitions: {}\n", transitions.len());

            // Initialize a new transition store.
            let transition_store = TransitionMemory::open(StorageMode::Test(None)).unwrap();

            // Test each transition in isolation.
            for transition in transitions.iter() {
                // Retrieve the transition ID.
                let transition_id = *transition.id();

                // Ensure the transition does not exist.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(None, candidate);

                // Insert the transition.
                transition_store.insert(transition).unwrap();

                // Retrieve the transition.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(Some(transition.clone()), candidate);

                // Remove the transition.
                transition_store.remove(&transition_id).unwrap();

                // Retrieve the transition.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(None, candidate);
            }

            // Insert every transition.
            for transition in transitions.iter() {
                // Retrieve the transition ID.
                let transition_id = *transition.id();

                // Ensure the transition does not exist.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(None, candidate);

                // Insert the transition.
                transition_store.insert(transition).unwrap();

                // Ensure the transition exists.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(Some(transition.clone()), candidate);
            }

            // Get every transition (in reverse).
            for transition in transitions.iter().rev() {
                // Retrieve the transition ID.
                let transition_id = *transition.id();

                // Retrieve the transition.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(Some(transition.clone()), candidate);
            }

            // Remove every transition (in reverse).
            for transition in transitions.iter().rev() {
                // Retrieve the transition ID.
                let transition_id = *transition.id();

                // Remove the transition.
                transition_store.remove(&transition_id).unwrap();

                // Ensure the transition does not exist.
                let candidate = transition_store.get(&transition_id).unwrap();
                assert_eq!(None, candidate);
            }
        }
    }
}
