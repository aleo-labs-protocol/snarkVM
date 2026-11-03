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

mod call_metrics;
pub use call_metrics::*;

mod inclusion;
pub use inclusion::*;

mod translation;
pub use translation::*;

use circuit::Assignment;
use console::{
    network::prelude::*,
    program::{InputID, Locator},
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{Execution, Fee, Transition};
use snarkvm_ledger_query::QueryTrait;
use snarkvm_synthesizer_snark::{Proof, ProvingKey, VerifyingKey};

use std::{collections::HashMap, sync::OnceLock};

use crate::Authorization;

#[derive(Clone, Debug, Default)]
pub struct Trace<N: Network> {
    /// The list of transitions.
    transitions: Vec<Transition<N>>,
    /// A map of locators to (proving key, assignments) pairs.
    transition_tasks: HashMap<Locator<N>, (ProvingKey<N>, Vec<Assignment<N::Field>>)>,
    /// A tracker for all inclusion tasks.
    inclusion_tasks: Inclusion<N>,
    /// A tracker for all translation tasks.
    translation_tasks: Translation<N>,
    /// A list of call metrics.
    call_metrics: Vec<CallMetrics<N>>,
    /// A map of transition IDs to child transition IDs.
    call_graph: HashMap<N::TransitionID, Vec<N::TransitionID>>,

    /// A tracker for the inclusion assignments.
    inclusion_assignments: OnceLock<Vec<InclusionAssignmentWrapper<N>>>,
    /// A tracker for the translation assignments, each paired with its translation index.
    translation_assignments: OnceLock<Vec<(ProvingKey<N>, Vec<(TranslationAssignment<N>, u16)>)>>,
    /// A tracker for the global state root.
    global_state_root: OnceLock<N::StateRoot>,
}

impl<N: Network> Trace<N> {
    /// Initializes a new trace.
    pub fn new() -> Self {
        Self {
            transitions: Vec::new(),
            transition_tasks: HashMap::new(),
            inclusion_tasks: Inclusion::new(),
            translation_tasks: Translation::new(),
            call_metrics: Vec::new(),
            call_graph: HashMap::new(),
            inclusion_assignments: OnceLock::new(),
            translation_assignments: OnceLock::new(),
            global_state_root: OnceLock::new(),
        }
    }

    /// Returns the list of transitions.
    pub fn transitions(&self) -> &[Transition<N>] {
        &self.transitions
    }

    /// Returns the transition proving tasks (proving key + assignments), keyed by locator.
    pub fn transition_tasks(&self) -> &HashMap<Locator<N>, (ProvingKey<N>, Vec<Assignment<N::Field>>)> {
        &self.transition_tasks
    }

    /// Returns the call metrics.
    pub fn call_metrics(&self) -> &[CallMetrics<N>] {
        &self.call_metrics
    }

    /// Returns the call graph.
    pub fn call_graph(&self) -> &HashMap<N::TransitionID, Vec<N::TransitionID>> {
        &self.call_graph
    }
}

impl<N: Network> Trace<N> {
    /// Inserts the transition into the trace.
    pub fn insert_transition(
        &mut self,
        input_ids: &[InputID<N>],
        transition: &Transition<N>,
        (proving_key, assignment): (ProvingKey<N>, Assignment<N::Field>),
        translations: Vec<(TranslationAssignment<N>, ProvingKey<N>)>,
        metrics: CallMetrics<N>,
    ) -> Result<()> {
        // Ensure the inclusion assignments and global state root have not been set.
        ensure!(self.inclusion_assignments.get().is_none());
        ensure!(self.translation_assignments.get().is_none());
        ensure!(self.global_state_root.get().is_none());

        // Insert the transition into the inclusion and, if applicable, translation tasks.
        self.inclusion_tasks.insert_transition(input_ids, transition)?;
        if !translations.is_empty() {
            self.translation_tasks.insert_transition(*transition.id(), translations)?;
        }

        // Construct the locator.
        let locator = Locator::new(*transition.program_id(), *transition.function_name());
        // Insert the assignment (and proving key if the entry does not exist), for the specified locator.
        self.transition_tasks.entry(locator).or_insert((proving_key, vec![])).1.push(assignment);
        // Insert the transition into the list.
        self.transitions.push(transition.clone());
        // Insert the call metrics into the list.
        self.call_metrics.push(metrics);

        Ok(())
    }
}

impl<N: Network> Trace<N> {
    /// Returns `true` if the trace is for a fee transition.
    pub fn is_fee(&self) -> bool {
        self.is_fee_private() || self.is_fee_public()
    }

    /// Returns `true` if the trace is for a private fee transition.
    pub fn is_fee_private(&self) -> bool {
        // If there is 1 transition, check if the transition is a fee transition.
        self.transitions.len() == 1 && self.transitions[0].is_fee_private()
    }

    /// Returns `true` if the trace is for a public fee transition.
    pub fn is_fee_public(&self) -> bool {
        // If there is 1 transition, check if the transition is a fee transition.
        self.transitions.len() == 1 && self.transitions[0].is_fee_public()
    }

    /// Returns `true` if the trace is for an upgrade transition.
    pub fn is_upgrade(&self) -> bool {
        // If there is 1 transition, check if the transition is an upgrade transition.
        self.transitions.len() == 1 && self.transitions[0].is_upgrade()
    }
}

impl<N: Network> Trace<N> {
    /// Constructs the call graph.
    pub fn construct_call_graph(&mut self, process: &crate::Process<N>) -> Result<()> {
        let mut execution_stacks = indexmap::IndexMap::new();
        for transition in &self.transitions {
            execution_stacks.insert(*transition.program_id(), process.get_stack(transition.program_id())?);
        }
        self.call_graph = crate::Process::construct_call_graph(self.transitions.iter(), &execution_stacks)?;
        Ok(())
    }
}

impl<N: Network> Trace<N> {
    /// Returns the inclusion assignments, translation assignments, and global state root for the current transition(s).
    pub fn prepare(&mut self, query: &dyn QueryTrait<N>) -> Result<()> {
        // Compute the inclusion and translation assignments.
        let (inclusion_assignments, global_state_root) = self.inclusion_tasks.prepare(&self.transitions, query)?;
        let translation_assignments = self.translation_tasks.prepare(&self.transitions, &self.call_graph)?;

        // Store the inclusion assignments.
        self.inclusion_assignments
            .set(inclusion_assignments)
            .map_err(|_| anyhow!("Failed to set inclusion assignments"))?;

        // Store the translation assignments.
        self.translation_assignments
            .set(translation_assignments)
            .map_err(|_| anyhow!("Failed to set translation assignments"))?;

        // Store the global state root.
        self.global_state_root.set(global_state_root).map_err(|_| anyhow!("Failed to set global state root"))?;

        Ok(())
    }

    /// Returns the inclusion assignments, translation assignments, and global state root for the current transition(s).
    #[cfg(feature = "async")]
    pub async fn prepare_async(&mut self, query: &dyn QueryTrait<N>) -> Result<()> {
        // Compute the inclusion and translation assignments.
        let (inclusion_assignments, global_state_root) =
            self.inclusion_tasks.prepare_async(&self.transitions, query).await?;
        let translation_assignments = self.translation_tasks.prepare_async(&self.transitions, &self.call_graph).await?;

        // Store the inclusion assignments.
        self.inclusion_assignments
            .set(inclusion_assignments)
            .map_err(|_| anyhow!("Failed to set inclusion assignments"))?;

        // Store the translation assignments.
        self.translation_assignments
            .set(translation_assignments)
            .map_err(|_| anyhow!("Failed to set translation assignments"))?;

        // Store the global state root.
        self.global_state_root.set(global_state_root).map_err(|_| anyhow!("Failed to set global state root"))?;

        Ok(())
    }

    /// Returns a new execution with a proof, for the current inclusion assignments and global state root.
    pub fn prove_execution<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        locator: &str,
        varuna_version: VarunaVersion,
        rng: &mut R,
    ) -> Result<Execution<N>> {
        // Ensure this is not a fee.
        ensure!(!self.is_fee(), "The trace cannot call 'prove_execution' for a fee type");
        // Ensure there are no fee transitions.
        ensure!(
            self.transitions.iter().all(|transition| !(transition.is_fee_private() || transition.is_fee_public())),
            "The trace cannot prove execution for a fee, call 'prove_fee' instead"
        );
        // Retrieve the inclusion assignments.
        let inclusion_assignments =
            self.inclusion_assignments.get().ok_or_else(|| anyhow!("Inclusion assignments have not been set"))?;
        // Retrieve the global state root.
        let global_state_root =
            self.global_state_root.get().ok_or_else(|| anyhow!("Global state root has not been set"))?;
        // Retrieve the translation assignments.
        let translation_assignments =
            self.translation_assignments.get().ok_or_else(|| anyhow!("Translation assignments have not been set"))?;
        // Construct the proving tasks with enough capacity for the transition, translation, and inclusion tasks.
        let mut proving_tasks = Vec::with_capacity(self.transition_tasks.len() + translation_assignments.len() + 1);
        proving_tasks.extend(self.transition_tasks.values().cloned());

        // Compute the proof.
        let (global_state_root, proof) = Self::prove_batch::<A, R>(
            locator,
            varuna_version,
            proving_tasks,
            translation_assignments,
            inclusion_assignments,
            *global_state_root,
            rng,
        )?;
        // Return the execution.
        Execution::from(self.transitions.iter().cloned(), global_state_root, Some(proof))
    }

    /// Returns a new fee with a proof, for the current inclusion assignment and global state root.
    pub fn prove_fee<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        varuna_version: VarunaVersion,
        rng: &mut R,
    ) -> Result<Fee<N>> {
        // Ensure this is a fee.
        let is_fee_public = self.is_fee_public();
        let is_fee_private = self.is_fee_private();
        ensure!(is_fee_public || is_fee_private, "The trace cannot call 'prove_fee' for an execution type");
        // Retrieve the inclusion assignments.
        let inclusion_assignments =
            self.inclusion_assignments.get().ok_or_else(|| anyhow!("Inclusion assignments have not been set"))?;
        // Ensure the correct number of inclusion assignments are provided.
        match is_fee_public {
            true => ensure!(inclusion_assignments.is_empty(), "Expected 0 inclusion assignments for proving the fee"),
            false => ensure!(inclusion_assignments.len() == 1, "Expected 1 inclusion assignment for proving the fee"),
        }
        // Retrieve the global state root.
        let global_state_root =
            self.global_state_root.get().ok_or_else(|| anyhow!("Global state root has not been set"))?;
        // Retrieve the fee transition.
        let fee_transition = &self.transitions[0];
        // Construct the proving tasks with enough capacity for the transition tasks and optional inclusion.
        let mut proving_tasks = Vec::with_capacity(self.transition_tasks.len() + 1);
        proving_tasks.extend(self.transition_tasks.values().cloned());
        // Set the translation assignments to an empty vector, not applicable to fee transitions.
        let translation_assignments = vec![];
        // Compute the proof.
        let (global_state_root, proof) = Self::prove_batch::<A, R>(
            "credits.aleo/fee (private or public)",
            varuna_version,
            proving_tasks,
            &translation_assignments,
            inclusion_assignments,
            *global_state_root,
            rng,
        )?;
        // Return the fee.
        Ok(Fee::from_unchecked(fee_transition.clone(), global_state_root, Some(proof)))
    }

    /// Checks the proof for the execution.
    /// Note: This does *not* check that the global state root exists in the ledger.
    pub fn verify_execution_proof(
        locator: &str,
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        verifier_inputs: Vec<(VerifyingKey<N>, Vec<Vec<N::Field>>)>,
        execution: &Execution<N>,
    ) -> Result<()> {
        if cfg!(all(feature = "dev_skip_checks", feature = "test_consensus_heights")) {
            return Ok(());
        }
        // Retrieve the global state root.
        let global_state_root = execution.global_state_root();
        // Ensure the global state root is not zero.
        if global_state_root == N::StateRoot::default() {
            bail!("Inclusion expected the global state root in the execution to *not* be zero")
        }
        // Retrieve the proof.
        let Some(proof) = execution.proof() else { bail!("Expected the execution to contain a proof") };
        // Verify the execution proof.
        match Self::verify_batch(
            locator,
            varuna_version,
            inclusion_version,
            verifier_inputs,
            global_state_root,
            execution.transitions(),
            proof,
        ) {
            Ok(()) => Ok(()),
            Err(e) => bail!("Execution is invalid - {e}"),
        }
    }

    /// Checks the proof for the fee.
    /// Note: This does *not* check that the global state root exists in the ledger.
    pub fn verify_fee_proof(
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        verifier_inputs: (VerifyingKey<N>, Vec<Vec<N::Field>>),
        fee: &Fee<N>,
    ) -> Result<()> {
        if cfg!(all(feature = "dev_skip_checks", feature = "test_consensus_heights")) {
            return Ok(());
        }
        // Retrieve the global state root.
        let global_state_root = fee.global_state_root();
        // Ensure the global state root is not zero.
        if global_state_root == N::StateRoot::default() {
            bail!("Inclusion expected the global state root in the fee to *not* be zero")
        }
        // Retrieve the proof.
        let Some(proof) = fee.proof() else { bail!("Expected the fee to contain a proof") };
        // Verify the fee proof.
        match Self::verify_batch(
            "credits.aleo/fee (private or public)",
            varuna_version,
            inclusion_version,
            vec![verifier_inputs],
            global_state_root,
            [fee.transition()].into_iter(),
            proof,
        ) {
            Ok(()) => Ok(()),
            Err(e) => bail!("Fee is invalid - {e}"),
        }
    }
}

impl<N: Network> Trace<N> {
    /// Returns the global state root and proof for the given assignments.
    pub fn prove_batch<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        locator: &str,
        varuna_version: VarunaVersion,
        mut proving_tasks: Vec<(ProvingKey<N>, Vec<Assignment<N::Field>>)>,
        translation_assignments: &[(ProvingKey<N>, Vec<(TranslationAssignment<N>, u16)>)],
        inclusion_assignments: &[InclusionAssignmentWrapper<N>],
        global_state_root: N::StateRoot,
        rng: &mut R,
    ) -> Result<(N::StateRoot, Proof<N>)> {
        // Ensure the global state root is not zero.
        // Note: To protect user privacy, even when there are *no* inclusion assignments,
        // the user must provide a real global state root (which is checked in consensus).
        if global_state_root == N::StateRoot::default() {
            bail!("Inclusion expected the global state root in the execution to *not* be zero")
        }

        // Initialize a vector for the batch inclusion assignments.
        let mut batch_inclusions = Vec::with_capacity(inclusion_assignments.len());

        let mut inclusion_version = None;
        for assignment in inclusion_assignments.iter() {
            // Ensure the inclusion version is the same across iterations.
            match &mut inclusion_version {
                None => inclusion_version = Some(assignment),
                Some(expected) if std::mem::discriminant(expected) == std::mem::discriminant(&assignment) => {}
                Some(_) => bail!("Inclusion version expected to be the same across iterations."),
            }
            // Add the assignment to the assignments.
            let assignment = match assignment {
                InclusionAssignmentWrapper::V0(assignment_v0) => {
                    // Ensure the global state root is the same across iterations.
                    if global_state_root != assignment_v0.state_path.global_state_root() {
                        bail!("Inclusion expected the global state root to be the same across iterations")
                    }
                    assignment_v0.to_circuit_assignment::<A>()?
                }
                InclusionAssignmentWrapper::V1(assignment_v1) => {
                    // Ensure the global state root is the same across iterations.
                    if global_state_root != assignment_v1.state_path.global_state_root() {
                        bail!("Inclusion expected the global state root to be the same across iterations")
                    }
                    assignment_v1.to_circuit_assignment::<A>()?
                }
            };
            batch_inclusions.push(assignment);
        }

        if !batch_inclusions.is_empty() {
            // Fetch the inclusion proving key.
            #[cfg(not(feature = "wasm"))]
            let proving_key = match inclusion_version {
                Some(InclusionAssignmentWrapper::V0(..)) => ProvingKey::<N>::new(N::inclusion_v0_proving_key().clone()),
                Some(InclusionAssignmentWrapper::V1(..)) => ProvingKey::<N>::new(N::inclusion_proving_key().clone()),
                None => bail!("Invalid or missing inclusion version"),
            };
            #[cfg(feature = "wasm")]
            let proving_key = match inclusion_version {
                Some(InclusionAssignmentWrapper::V0(..)) => {
                    ProvingKey::<N>::new(N::inclusion_v0_proving_key(None).clone())
                }
                Some(InclusionAssignmentWrapper::V1(..)) => {
                    ProvingKey::<N>::new(N::inclusion_proving_key(None).clone())
                }
                None => bail!("Invalid or missing inclusion version"),
            };
            // Insert the inclusion proving key and assignments.
            proving_tasks.push((proving_key, batch_inclusions));
        }

        for (proving_key, assignments) in translation_assignments {
            let circuit_assignments = assignments
                .iter()
                .map(|(assignment, translation_index)| {
                    assignment.to_circuit_assignment::<A>(*translation_index, None, None, None)
                })
                .collect::<Result<Vec<Assignment<N::Field>>>>()?;
            // Note that the `ProvingKey` contains an `Arc` to the underlying proving key, so cloning is cheap.
            proving_tasks.push((proving_key.clone(), circuit_assignments));
        }

        // Ensure the number of instances does not exceed the limit.
        let num_instances: usize = proving_tasks.iter().map(|(_, assignments)| assignments.len()).sum();
        ensure!(
            num_instances <= N::MAX_BATCH_PROOF_INSTANCES,
            "Total proof instances ({}) exceed the maximum allowed ({})",
            num_instances,
            N::MAX_BATCH_PROOF_INSTANCES
        );

        // Compute the proof.
        let proof = ProvingKey::prove_batch(locator, varuna_version, &proving_tasks, rng)?;
        // Return the global state root and proof.
        Ok((global_state_root, proof))
    }

    /// Checks the proof for the given inputs.
    /// Note: This does *not* check that the global state root exists in the ledger.
    fn verify_batch<'a>(
        locator: &str,
        varuna_version: VarunaVersion,
        inclusion_version: InclusionVersion,
        mut verifier_inputs: Vec<(VerifyingKey<N>, Vec<Vec<N::Field>>)>,
        global_state_root: N::StateRoot,
        transitions: impl ExactSizeIterator<Item = &'a Transition<N>> + Clone,
        proof: &Proof<N>,
    ) -> Result<()> {
        // Construct the batch of inclusion verifier inputs.
        let batch_inclusion_inputs =
            Inclusion::prepare_verifier_inputs(global_state_root, inclusion_version, transitions.clone())?;

        let expected_incl = Authorization::number_of_input_records(transitions);
        let actual_incl = batch_inclusion_inputs.len();
        ensure!(
            actual_incl == expected_incl,
            "Unexpected number of inclusion inputs: {actual_incl} v.s. {expected_incl}"
        );

        // Insert the batch of inclusion verifier inputs to the verifier inputs.
        if !batch_inclusion_inputs.is_empty() {
            // Retrieve the inclusion verifying key depending on the inclusion version.
            let verifying_key = match inclusion_version {
                InclusionVersion::V0 => N::inclusion_v0_verifying_key().clone(),
                InclusionVersion::V1 => N::inclusion_verifying_key().clone(),
            };
            // Retrieve the number of public and private variables.
            // Note: This number does *NOT* include the number of constants. This is safe because
            // this program is never deployed, as it is a first-class citizen of the protocol.
            let num_variables = verifying_key.circuit_info.num_public_and_private_variables as u64;
            // Insert the inclusion verifier inputs.
            verifier_inputs.push((VerifyingKey::<N>::new(verifying_key, num_variables), batch_inclusion_inputs));
        }
        // Verify the proof.
        VerifyingKey::verify_batch(locator, varuna_version, verifier_inputs, proof)
            .map_err(|e| anyhow!("Failed to verify proof - {e}"))
    }
}
