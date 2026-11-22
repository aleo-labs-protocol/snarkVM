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

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::AleoV0;
    use console::{
        network::MainnetV0,
        program::{
            BLOCKS_DEPTH,
            BlockPath,
            Identifier,
            Plaintext,
            ProgramID,
            Record,
            state_path::test_helpers::sample_global_state_path,
        },
        types::{U32, U64},
    };
    use snarkvm_ledger_block::{Input, Output};

    type CurrentNetwork = MainnetV0;

    /// Returns `true` if the inclusion circuit accepts a record from block `height`, spent by `program`/`function`.
    fn accepts(program: &str, function: &str, height: u32, rng: &mut TestRng) -> Result<bool> {
        let commitment = Field::rand(rng);
        let gamma = Group::rand(rng);
        let serial_number =
            Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number_from_gamma(&gamma, commitment)?;

        // Move the block of a sampled state path to `height`. A tree of that many blocks is too large to build,
        // so the root is hashed up from random siblings, as `MerklePath::verify` does.
        let path = sample_global_state_path::<CurrentNetwork>(Some(commitment), rng)?;
        let leaf = path.block_hash().to_bits_le();
        let siblings = (0..BLOCKS_DEPTH).map(|_| Field::rand(rng)).collect::<Vec<_>>();
        let mut root = CurrentNetwork::hash_bhp1024(&[&[false], &leaf[..]].concat())?;
        for (level, sibling) in siblings.iter().enumerate() {
            let (left, right) = if (height >> level) & 1 == 0 { (root, *sibling) } else { (*sibling, root) };
            root = CurrentNetwork::hash_bhp512(&[vec![true], left.to_bits_le(), right.to_bits_le()].concat())?;
        }
        let block_path = BlockPath::<CurrentNetwork>::try_from((U64::new(height as u64), siblings))?;
        ensure!(CurrentNetwork::verify_merkle_path_bhp(&block_path, &root, &leaf), "Invalid block path");
        let state_path = StatePath::from(
            root.into(),
            block_path,
            path.block_hash(),
            path.previous_block_hash(),
            *path.header_root(),
            path.header_path().clone(),
            *path.header_leaf(),
            path.transactions_path().clone(),
            *path.transaction_id(),
            path.transaction_path().clone(),
            *path.transaction_leaf(),
            *path.transition_root(),
            *path.tcm(),
            path.transition_path().clone(),
            *path.transition_leaf(),
        );

        // `Transition::is_upgrade` requires two outputs.
        let transition = Transition::new_unchecked(
            Field::<CurrentNetwork>::rand(rng).into(),
            ProgramID::from_str(program)?,
            Identifier::from_str(function)?,
            vec![Input::Record(serial_number, Field::rand(rng))],
            vec![Output::Constant(Field::rand(rng), None), Output::Constant(Field::rand(rng), None)],
            Group::rand(rng),
            Field::rand(rng),
            Field::rand(rng),
        );
        let verifier_inputs = Inclusion::prepare_verifier_inputs(
            state_path.global_state_root(),
            InclusionVersion::V1,
            [transition].iter(),
        )?
        .remove(0);
        let [_, _, local_state_root, _, is_record_block_height_reached, upgrade_block_height] = verifier_inputs[..]
        else {
            bail!("Expected six verifier inputs");
        };
        let upgrade_block_height =
            *<U32<CurrentNetwork> as console::prelude::FromField>::from_field(&Field::new(upgrade_block_height))?;
        let assignment = InclusionAssignment::new(
            state_path,
            commitment,
            gamma,
            serial_number,
            is_record_block_height_reached.is_one(),
            upgrade_block_height,
            Field::<CurrentNetwork>::new(local_state_root).into(),
            true,
        )
        .to_circuit_assignment::<AleoV0>()?;

        // The circuit takes the verifier's public inputs.
        let public_inputs = assignment.public_inputs().iter().map(|variable| variable.value()).collect::<Vec<_>>();
        ensure!(public_inputs == verifier_inputs, "The circuit and the verifier take different public inputs");
        Ok(assignment.constraints().iter().all(|constraint| {
            let (a, b, c) = constraint.to_terms();
            a.value() * b.value() == c.value()
        }))
    }

    #[test]
    fn test_upgrade_height_boundary() -> Result<()> {
        let rng = &mut TestRng::default();
        // A `credits.aleo` record from the block at `INCLUSION_UPGRADE_HEIGHT` or below can only be spent by `upgrade`.
        let upgrade_height = CurrentNetwork::INCLUSION_UPGRADE_HEIGHT()?;
        for (height, needs_upgrade) in [(upgrade_height - 1, true), (upgrade_height, true), (upgrade_height + 1, false)]
        {
            assert_eq!(accepts("credits.aleo", "transfer_private", height, rng)?, !needs_upgrade, "height {height}");
            assert_eq!(accepts("credits.aleo", "upgrade", height, rng)?, needs_upgrade, "height {height}");
            // Other programs' records carry no height check.
            assert!(accepts("token.aleo", "transfer", height, rng)?, "height {height}");
        }
        Ok(())
    }
}
