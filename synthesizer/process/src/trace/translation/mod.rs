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

mod assignment;
pub use assignment::{TranslationAssignment, compute_console_dynamic_or_external_record_id};

mod prepare;

#[cfg(test)]
mod tests;

use crate::Stack;

use circuit::{Inject, traits::ToGroup};

use console::{
    network::prelude::*,
    program::{DynamicRecord, Identifier, Plaintext, ProgramID, Record, U16, ValueType, compute_function_id},
    types::{Field, Group},
};
use snarkvm_ledger_block::{Input, Output, Transition};
use snarkvm_synthesizer_program::Function;
use snarkvm_synthesizer_snark::{ProvingKey, VerifyingKey};

use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct Translation<N: Network> {
    /// A map of caller `transition IDs` to a list of translation assignments, each paired with its proving key.
    /// Only contains entries for transitions that perform dynamic calls involving translation.
    translation_tasks: HashMap<N::TransitionID, Vec<(TranslationAssignment<N>, ProvingKey<N>)>>,
}

impl<N: Network> Translation<N> {
    /// Initializes a new `Translation` instance.
    pub fn new() -> Self {
        Self { translation_tasks: HashMap::new() }
    }

    /// Inserts the transition to build state for the translation task.
    pub fn insert_transition(
        &mut self,
        transition_id: N::TransitionID,
        translation_assignments: Vec<(TranslationAssignment<N>, ProvingKey<N>)>,
    ) -> Result<()> {
        self.translation_tasks.insert(transition_id, translation_assignments);

        Ok(())
    }

    /// Returns the verifier public inputs for the given call graph and transitions.
    pub fn prepare_verifier_inputs<'a, F>(
        transitions: impl ExactSizeIterator<Item = &'a Transition<N>>,
        // Used to retrieve record names
        transition_map: &HashMap<N::TransitionID, (&Transition<N>, Function<N>)>,
        get_verifying_key: &F,
    ) -> Result<Vec<(VerifyingKey<N>, Vec<Vec<N::Field>>)>>
    where
        F: Fn(&(ProgramID<N>, Identifier<N>)) -> Result<VerifyingKey<N>>,
    {
        let mut batch_verifier_inputs: HashMap<(ProgramID<N>, Identifier<N>), Vec<Vec<N::Field>>> = HashMap::new();

        let mut translation_index = 0;

        // Traversal order affects the translation count as well as the internal order of each batch input to proving/verification.
        // Order is irrelevant as long as it is consistent between the prover and verifier. (cf. Translation::prepare)
        for transition in transitions {
            let (_, callee_function_core) = transition_map
                .get(transition.id())
                .ok_or_else(|| anyhow!("Transition {} from execution not found transition map", transition.id()))?;
            let callee_function_id =
                compute_function_id(&U16::<N>::new(N::ID), transition.program_id(), transition.function_name())?;

            let callee_input_types = callee_function_core.input_types();
            let num_inputs = transition.inputs().len();
            ensure!(
                num_inputs == callee_input_types.len(),
                "The number of transition inputs ({num_inputs}) and callee input types ({}) do not match",
                callee_input_types.len()
            );

            // Prepare the input translation tasks.
            for (record_register_index, (input, callee_input_type)) in
                transition.inputs().iter().zip_eq(callee_input_types.iter()).enumerate()
            {
                // Only process inputs that have a dynamic ID.
                let Some(dynamic_id) = input.dynamic_id() else { continue };

                // Construct the translation count as a field element.
                let field_translation_index = *Field::<N>::from_u128(translation_index as u128);
                // Construct the record register index as a field element.
                let field_record_register_index = *Field::<N>::from_u128(record_register_index as u128);

                let field_is_to_static = N::Field::one();
                let field_function_id = *callee_function_id;
                let field_id_static = **input.id();
                let field_id_dynamic = **dynamic_id;

                match (input, callee_input_type) {
                    (Input::RecordWithDynamicID(..), ValueType::Record(record_name)) => {
                        let field_is_external_record = N::Field::zero();
                        // Index 0 is the Varuna constant-1 wire (required by every Varuna constraint system).
                        // The remaining 7 elements are the explicit public inputs injected by the translation circuit.
                        let verifier_inputs = vec![
                            N::Field::one(),
                            field_is_to_static,
                            field_is_external_record,
                            field_function_id,
                            field_translation_index,
                            field_record_register_index,
                            field_id_static,
                            field_id_dynamic,
                        ];
                        batch_verifier_inputs
                            .entry((*transition.program_id(), *record_name))
                            .or_default()
                            .push(verifier_inputs);
                        translation_index += 1;
                    }
                    (Input::ExternalRecordWithDynamicID(..), ValueType::ExternalRecord(record_locator)) => {
                        let field_is_external_record = N::Field::one();
                        let verifier_inputs = vec![
                            N::Field::one(),
                            field_is_to_static,
                            field_is_external_record,
                            field_function_id,
                            field_translation_index,
                            field_record_register_index,
                            field_id_static,
                            field_id_dynamic,
                        ];
                        batch_verifier_inputs
                            .entry((*record_locator.program_id(), *record_locator.resource()))
                            .or_default()
                            .push(verifier_inputs);
                        translation_index += 1;
                    }
                    _ => bail!(
                        "Unexpected input variant with dynamic_id in transition {} (index: {})",
                        transition.id(),
                        record_register_index
                    ),
                }
            }

            let callee_output_types = callee_function_core.output_types();
            ensure!(
                transition.outputs().len() == callee_output_types.len(),
                "The number of transition outputs ({}) and callee output types ({}) do not match",
                transition.outputs().len(),
                callee_output_types.len()
            );

            // Prepare the output translation tasks.
            for (record_register_index, (output, callee_output_type)) in
                transition.outputs().iter().zip_eq(callee_output_types.iter()).enumerate()
            {
                // Only process outputs that have a dynamic ID.
                let Some(dynamic_id) = output.dynamic_id() else { continue };

                // Construct the translation count as a field element.
                let field_translation_index = *Field::<N>::from_u128(translation_index as u128);
                // Construct the record register index as a field element.
                let field_record_register_index = *Field::<N>::from_u128((num_inputs + record_register_index) as u128);

                let field_is_to_static = N::Field::zero();
                let field_function_id = *callee_function_id;
                let field_id_static = **output.id();
                let field_id_dynamic = **dynamic_id;

                match (output, callee_output_type) {
                    (Output::RecordWithDynamicID(..), ValueType::Record(record_name)) => {
                        let field_is_external_record = N::Field::zero();
                        let verifier_inputs = vec![
                            N::Field::one(),
                            field_is_to_static,
                            field_is_external_record,
                            field_function_id,
                            field_translation_index,
                            field_record_register_index,
                            field_id_static,
                            field_id_dynamic,
                        ];
                        batch_verifier_inputs
                            .entry((*transition.program_id(), *record_name))
                            .or_default()
                            .push(verifier_inputs);
                        translation_index += 1;
                    }
                    (Output::ExternalRecordWithDynamicID(..), ValueType::ExternalRecord(record_locator)) => {
                        let field_is_external_record = N::Field::one();
                        let verifier_inputs = vec![
                            N::Field::one(),
                            field_is_to_static,
                            field_is_external_record,
                            field_function_id,
                            field_translation_index,
                            field_record_register_index,
                            field_id_static,
                            field_id_dynamic,
                        ];
                        batch_verifier_inputs
                            .entry((*record_locator.program_id(), *record_locator.resource()))
                            .or_default()
                            .push(verifier_inputs);
                        translation_index += 1;
                    }
                    _ => bail!(
                        "Unexpected output variant with dynamic_id in transition {} (index: {})",
                        transition.id(),
                        record_register_index
                    ),
                }
            }
        }

        let batch_with_verifying_keys = batch_verifier_inputs
            .into_iter()
            .map(|(key, inputs)| Ok((get_verifying_key(&key)?, inputs)))
            .collect::<Result<Vec<(VerifyingKey<N>, Vec<Vec<N::Field>>)>>>()?;

        Ok(batch_with_verifying_keys)
    }
}
