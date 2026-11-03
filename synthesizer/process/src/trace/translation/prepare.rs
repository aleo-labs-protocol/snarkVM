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

use crate::Process;

use super::*;

impl<N: Network> Translation<N> {
    /// Returns the translation assignments for the given transitions grouped by
    /// program ID and record name, each paired with its proving key.
    /// Each assignment is accompanied by its translation index (a sequential counter
    /// used as a public input for proof verification).
    pub fn prepare(
        &self,
        transitions: &[Transition<N>],
        call_graph: &HashMap<N::TransitionID, Vec<N::TransitionID>>,
    ) -> Result<Vec<(ProvingKey<N>, Vec<(TranslationAssignment<N>, u16)>)>> {
        // Initialize a map for the batched assignments, keyed by (program_id, record_name).
        // Each entry stores the proving key (taken from the first item in the group) and the assignments.
        let mut batched_assignments: HashMap<
            (ProgramID<N>, Identifier<N>),
            (ProvingKey<N>, Vec<(TranslationAssignment<N>, u16)>),
        > = HashMap::new();

        let mut translation_index: u16 = 0;

        // Traversal order affects the translation count as well as the internal order of each batch input to proving/verification.
        // Order is irrelevant as long as it is consistent between the prover and verifier. (cf. Translation::prepare_verifier_inputs).
        // Note that
        //  - The verifier iterates through the transitions (which are received in post-order exploration of the call graph)
        //    and explores the inputs and outputs of each of them
        //  - The prover's translation tasks (here, in `self`) are grouped under the *caller*'s transition ID
        //
        // In order to reconcile the two views, we make the prover iterate through the transitions as received (just like the
        // verifier does) and, upon detecting a translation, fetch the corresponding translation task using the ID of the transition's
        // caller. Since accumulation of prover translation tasks happens in order of dynamic calls within the transition; and in
        // input/output order or arguments for each such call, this results in consistency with the verifier's (i.e. post-order)
        // traversal order.
        //
        // At the end of the process, we verify that all translation tasks have been consumed. In order to avoid consuming or
        // modifying `self`, we keep a separate map to track the next unconsumed translation task for each (caller)
        // transition ID.
        let mut caller_id_to_next_task: HashMap<N::TransitionID, usize> =
            self.translation_tasks.keys().map(|transition_id| (*transition_id, 0)).collect();

        // Construct the reverse call graph to easily access the caller when the need for translation is detected.
        let reverse_call_graph = Process::<N>::reverse_call_graph(call_graph);

        // Closure that fetches the next translation task for the given caller and updates the next_task and translation_index
        // trackers. It is called while iterating through the (callee's) inputs and outputs.
        let mut consume_translation_task = |caller_id: N::TransitionID| -> Result<()> {
            let translation_tasks = self
                .translation_tasks
                .get(&caller_id)
                .ok_or_else(|| anyhow!("Translation tasks not found for (caller) transition ID {caller_id}"))?;

            // This unwrap is safe as caller_id_to_next_task is constructed using the keys of self.translation_tasks.
            let next_task = caller_id_to_next_task.get_mut(&caller_id).unwrap();

            let (assignment, proving_key) = translation_tasks.get(*next_task).ok_or_else(
                || anyhow!(
                    "Translation task not found for (caller) transition ID {}: queried task with index {} but only {} are available",
                    caller_id,
                    *next_task,
                    translation_tasks.len()
                )
            )?;

            // Update the pointer to read the next translation task next time.
            *next_task += 1;

            // Insert the assignment into the batch for this (program_id, record_name) group.
            // The proving key is the same `Arc` for all entries in a given group, so we take it from the first item.
            let (_, assignments) = batched_assignments
                .entry((assignment.program_id, assignment.record_name))
                // Note: `ProvingKey` is `Arc`-wrapped, so cloning is cheap (reference count bump).
                .or_insert_with(|| (proving_key.clone(), Vec::new()));

            assignments.push((assignment.clone(), translation_index));

            translation_index += 1;

            Ok(())
        };

        // Iterate through the transitions (consistent order with the verifier).
        // Note: Validation that a transition should be dynamic based on the call graph is done in
        // `verify_execution.rs::to_transition_verifier_inputs`, which checks that the parent instruction
        // is `CallDynamic` and validates that inputs/outputs use the correct `*WithDynamicID` variants
        // via the `to_caller_input().is_type()` and `to_caller_output().is_type()` checks.
        for transition in transitions {
            let transition_id = transition.id();

            // Input translation: detect inputs with dynamic IDs (RecordWithDynamicID, ExternalRecordWithDynamicID).
            for input in transition.inputs() {
                if input.dynamic_id().is_some() {
                    let caller_transition_id = reverse_call_graph
                        .get(transition_id)
                        .ok_or_else(|| anyhow!("Caller transition ID not found for transition ID {transition_id}"))?;
                    consume_translation_task(*caller_transition_id)?;
                }
            }

            // Output translation: detect outputs with dynamic IDs (RecordWithDynamicID, ExternalRecordWithDynamicID).
            for output in transition.outputs() {
                if output.dynamic_id().is_some() {
                    let caller_transition_id = reverse_call_graph
                        .get(transition_id)
                        .ok_or_else(|| anyhow!("Caller transition ID not found for transition ID {transition_id}"))?;
                    consume_translation_task(*caller_transition_id)?;
                }
            }
        }

        // Ensure all translation tasks have been consumed.
        for (transition_id, next_task) in caller_id_to_next_task.iter() {
            ensure!(
                // The unwrap is safe as caller_id_to_next_task is constructed using the keys of self.translation_tasks.
                *next_task == self.translation_tasks.get(transition_id).unwrap().len(),
                "Not all (caller) translation tasks have been consumed for transition ID {}: there are {}, but only {} have been consumed",
                transition_id,
                self.translation_tasks.get(transition_id).unwrap().len(),
                *next_task
            );
        }

        // Collect the batched assignments, discarding the (program_id, record_name) key.
        Ok(batched_assignments.into_values().collect())
    }

    /// Returns the translation assignments for the given transitions.
    // Note that the `Translation::prepare` is already async-compatible because it does not do any blocking operations.
    #[cfg(feature = "async")]
    pub async fn prepare_async(
        &self,
        transitions: &[Transition<N>],
        call_graph: &HashMap<N::TransitionID, Vec<N::TransitionID>>,
    ) -> Result<Vec<(ProvingKey<N>, Vec<(TranslationAssignment<N>, u16)>)>> {
        self.prepare(transitions, call_graph)
    }
}
