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

mod prepare;

mod assignment_v0;
pub use assignment_v0::*;

mod assignment;
pub use assignment::*;

use crate::Stack;

use circuit::{
    U32,
    traits::{FromBits as _, FromField, ToBits as _},
};
use console::{
    network::prelude::*,
    program::{InputID, StatePath, TRANSACTION_DEPTH, TransactionLeaf, TransitionLeaf, TransitionPath},
    types::{Field, Group},
};
use snarkvm_ledger_block::{Transaction, Transition};
use snarkvm_ledger_query::QueryTrait;

use std::collections::{HashMap, VecDeque};

#[derive(Clone, Copy, Debug)]
pub enum InclusionVersion {
    V0,
    V1,
}

#[derive(Clone, Debug)]
pub enum InclusionAssignmentWrapper<N: Network> {
    V0(InclusionV0Assignment<N>),
    V1(InclusionAssignment<N>),
}

#[derive(Clone, Debug)]
struct InputTask<N: Network> {
    /// The commitment.
    commitment: Field<N>,
    /// The gamma value.
    gamma: Group<N>,
    /// The serial number.
    serial_number: Field<N>,
    /// Contains the local transaction leaf, local transition root, local transition tcm, local transition path,
    /// and local transition leaf, if this input is a record from a previous local transition.
    local: Option<(TransactionLeaf<N>, Field<N>, Field<N>, TransitionPath<N>, TransitionLeaf<N>)>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Inclusion<N: Network> {
    /// A map of `transition IDs` to a list of `input tasks`.
    input_tasks: HashMap<N::TransitionID, Vec<InputTask<N>>>,
    /// A map of `commitments` to `(local transaction leaf, local transition root, local transition tcm, local transition path, local transition leaf)` pairs.
    output_commitments:
        HashMap<Field<N>, (TransactionLeaf<N>, Field<N>, Field<N>, TransitionPath<N>, TransitionLeaf<N>)>,
}

impl<N: Network> Inclusion<N> {
    /// Initializes a new `Inclusion` instance.
    pub fn new() -> Self {
        Self { input_tasks: HashMap::new(), output_commitments: HashMap::new() }
    }

    /// Inserts the transition to build state for the inclusion task.
    pub fn insert_transition(&mut self, input_ids: &[InputID<N>], transition: &Transition<N>) -> Result<()> {
        // Ensure the transition inputs and input IDs are the same length.
        if input_ids.len() != transition.inputs().len() {
            bail!("Inclusion expected the same number of input IDs as transition inputs")
        }

        // Retrieve the transition index.
        let transition_index = u16::try_from(self.input_tasks.len())?;

        // Initialize the input tasks.
        let input_tasks = self.input_tasks.entry(*transition.id()).or_default();

        // Process the inputs.
        for input_id in input_ids {
            // Filter the inputs for records.
            if let InputID::Record(commitment, gamma, _, serial_number, _) = input_id {
                // Add the record to the input tasks.
                input_tasks.push(InputTask {
                    commitment: *commitment,
                    gamma: *gamma,
                    serial_number: *serial_number,
                    local: self.output_commitments.get(commitment).cloned(),
                });
            }
        }

        if !transition.outputs().is_empty() {
            // Compute the transaction leaf.
            let transaction_leaf = TransactionLeaf::new_execution(transition_index, **transition.id());
            // Compute the transition root.
            let transition_root = transition.to_root()?;
            // Fetch the tcm.
            let tcm = *transition.tcm();

            // Process the outputs.
            for (index, output) in transition.outputs().iter().enumerate() {
                // Filter the outputs for records.
                if let Some(commitment) = output.commitment() {
                    // Compute the output index.
                    let output_index = u8::try_from(input_ids.len().saturating_add(index))?;
                    // Compute the transition leaf.
                    let transition_leaf = output.to_transition_leaf(output_index);
                    // Compute the transition path.
                    let transition_path = transition.to_path(&transition_leaf)?;
                    // Add the record's local Merklization to the output commitments.
                    self.output_commitments.insert(
                        *commitment,
                        (transaction_leaf, transition_root, tcm, transition_path, transition_leaf),
                    );
                }
            }
        }

        Ok(())
    }
}

impl<N: Network> Inclusion<N> {
    /// Returns the verifier public inputs for the given global state root, inclusion version, and transitions.
    pub fn prepare_verifier_inputs<'a>(
        global_state_root: N::StateRoot,
        inclusion_version: InclusionVersion,
        transitions: impl ExactSizeIterator<Item = &'a Transition<N>>,
    ) -> Result<Vec<Vec<N::Field>>> {
        // Determine the number of transitions.
        let num_transitions = transitions.len();

        // Initialize an empty transaction tree.
        let mut transaction_tree = N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&[])?;
        // Initialize a vector for the batch verifier inputs.
        let mut batch_verifier_inputs = vec![];

        // Construct the batch verifier inputs.
        for (transition_index, transition) in transitions.enumerate() {
            // Retrieve the local state root.
            let local_state_root = *transaction_tree.root();
            // Determine the `is_record_block_height_reached` and `upgrade_block_height` flags.
            let (is_record_block_height_reached, upgrade_block_height) = match transition.is_credits() {
                // If the transition is `credits.aleo`, then determine if the call is to `upgrade`.
                // This checks against `INCLUSION_UPGRADE_HEIGHT + 1` because any records produced for
                // block `INCLUSION_UPGRADE_HEIGHT` would be using the old inclusion version.
                true => (!transition.is_upgrade(), N::INCLUSION_UPGRADE_HEIGHT()?.saturating_add(1)),
                // If the record is not `credits.aleo`, then perform a null enforcement.
                false => (true, 0),
            };

            // Iterate through the inputs.
            for input in transition.inputs() {
                // Filter the inputs for records.
                if let Some(serial_number) = input.serial_number() {
                    // Add the public inputs to the batch verifier inputs.
                    let mut verifier_inputs =
                        vec![N::Field::one(), **global_state_root, *local_state_root, **serial_number];
                    // Add the additional inputs depending on the inclusion version.
                    match inclusion_version {
                        InclusionVersion::V0 => {}
                        InclusionVersion::V1 => {
                            // This should be consistent with `Inclusion::prepare`
                            // Add the additional verifier inputs.
                            verifier_inputs.push(*Field::<N>::from_bits_le(&[is_record_block_height_reached])?);
                            verifier_inputs.push(*Field::<N>::from_u32(upgrade_block_height));
                        }
                    }
                    batch_verifier_inputs.push(verifier_inputs);
                }
            }

            // If this is not the last transition, append the transaction leaf to the transaction tree.
            if transition_index + 1 != num_transitions {
                // Construct the transaction leaf.
                let leaf = TransactionLeaf::new_execution(u16::try_from(transition_index)?, **transition.id());
                // Insert the leaf into the transaction tree.
                transaction_tree.append(&[leaf.to_bits_le()])?;
            }
        }

        // Ensure the global state root is not zero.
        if batch_verifier_inputs.is_empty() && *global_state_root == Field::zero() {
            bail!("Inclusion expected the global state root in the execution to *not* be zero")
        }

        Ok(batch_verifier_inputs)
    }
}
