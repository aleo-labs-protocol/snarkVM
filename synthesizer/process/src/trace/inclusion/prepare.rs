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

use super::*;

macro_rules! prepare_impl {
    ($self:ident, $transitions:ident, $query:ident, $current_state_root:ident, $current_block_height:ident, $get_state_paths_for_commitments:ident $(, $await:ident)?) => {{
        // Ensure the number of leaves is within the Merkle tree size.
        Transaction::<N>::check_execution_size($transitions.len())?;

        // Initialize an empty transaction tree.
        let mut transaction_tree = N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&[])?;
        // Initialize a vector for the assignments.
        let mut assignments = vec![];

        // Retrieve the current block height.
        let current_block_height = {
            $query.$current_block_height()
            $(.$await)?
        }?;

        // Determine which consensus version is being used.
        let consensus_version = N::CONSENSUS_VERSION(current_block_height)?;

        // Fetch all the record commitments for the transitions.
        let commitments: Vec<_> = $transitions
            .iter()
            .flat_map(|t| $self.input_tasks.get(t.id()).into_iter().flatten())
            .filter_map(|task| task.local.is_none().then_some(task.commitment))
            .collect();

        // Fetch all the state paths for the commitments.
        let mut state_paths: VecDeque<_> = $query.$get_state_paths_for_commitments(&commitments)
                                $(.$await)??.into();

        // Retrieve the global state root.
        let global_state_root = match state_paths.front() {
            Some(path) => path.global_state_root(),
            None => {
                $query.$current_state_root()
                $(.$await)?
            }?
        };

        // Ensure the global state root is not zero.
        if *global_state_root == Field::zero() {
            bail!("Inclusion expected the global state root in the execution to *not* be zero")
        }

        for (transition_index, transition) in $transitions.iter().enumerate() {
            // Construct the transaction leaf.
            let transaction_leaf = TransactionLeaf::new_execution(u16::try_from(transition_index)?, **transition.id());

            // Process the input tasks.
            match $self.input_tasks.get(transition.id()) {
                Some(tasks) => {
                    for task in tasks {
                        // Retrieve the local state root.
                        let local_state_root = (*transaction_tree.root()).into();

                        // Construct the state path.
                        let state_path = match &task.local {
                            Some((transaction_leaf, transition_root, tcm, transition_path, transition_leaf)) => {
                                // Compute the transaction path.
                                let transaction_path =
                                    transaction_tree.prove(transaction_leaf.index() as usize, &transaction_leaf.to_bits_le())?;
                                // Output the state path.
                                StatePath::new_local(
                                    global_state_root,
                                    local_state_root,
                                    transaction_path,
                                    *transaction_leaf,
                                    *transition_root,
                                    *tcm,
                                    transition_path.clone(),
                                    *transition_leaf,
                                )?
                            }
                            None => {
                                // Use the next state path from the batched state paths.
                                state_paths.pop_front()
                                    .ok_or(anyhow!("Missing state path for commitment {}", task.commitment))?
                            }
                        };

                        // Ensure the global state root is the same across iterations.
                        if global_state_root != state_path.global_state_root() {
                            bail!("Inclusion expected the global state root to be the same across iterations")
                        }

                        // Construct the assignment for the state path based on the consensus version
                        let assignment = if (ConsensusVersion::V1..=ConsensusVersion::V7).contains(&consensus_version) {
                            let assignment = InclusionV0Assignment::new(
                                state_path,
                                task.commitment,
                                task.gamma,
                                task.serial_number,
                                local_state_root,
                                task.local.is_none(), // Equivalent to 'is_global'
                            );

                            InclusionAssignmentWrapper::V0(assignment)
                        } else {
                            // Enforce the record block height based on the conditions:
                            //     1. If the function is an `upgrade` then check that the record block height is before the upgrade block height.
                            //     2. If the function is a `credits.aleo` and not an `upgrade` then check that the record height is after the upgrade block height.
                            //     3. If the function is neither, do not perform any height checks.

                            // Determine the `is_record_block_height_reached` and `upgrade_block_height` flags.
                            let (is_record_block_height_reached, upgrade_block_height) = match  transition.is_credits() {
                                // If the transition is `credits.aleo`, then determine if the call is to `upgrade`.
                                // This checks against `INCLUSION_UPGRADE_HEIGHT + 1` because any records produced for
                                // block `INCLUSION_UPGRADE_HEIGHT` would be using the old inclusion version.
                                true => (!transition.is_upgrade(), N::INCLUSION_UPGRADE_HEIGHT()?.saturating_add(1)),
                                // If the record is not `credits.aleo`, then perform a null enforcement.
                                false => (true, 0),
                            };

                            // This should be consistent with `Inclusion::prepare_verifier_inputs`
                            let assignment = InclusionAssignment::new(
                                state_path,
                                task.commitment,
                                task.gamma,
                                task.serial_number,
                                is_record_block_height_reached,
                                upgrade_block_height,
                                local_state_root,
                                task.local.is_none(), // Equivalent to 'is_global'
                            );

                            InclusionAssignmentWrapper::V1(assignment)
                        };

                        // Add the assignment to the assignments.
                        assignments.push(assignment);
                    }
                }
                None => bail!("Missing input tasks for transition {} in inclusion", transition.id()),
            }

            // Insert the leaf into the transaction tree.
            transaction_tree.append(&[transaction_leaf.to_bits_le()])?;
        }

        Ok((assignments, global_state_root))
    }};
}

impl<N: Network> Inclusion<N> {
    /// Returns the inclusion assignments for the given transitions.
    pub fn prepare(
        &self,
        transitions: &[Transition<N>],
        query: &dyn QueryTrait<N>,
    ) -> Result<(Vec<InclusionAssignmentWrapper<N>>, N::StateRoot)> {
        prepare_impl!(
            self,
            transitions,
            query,
            current_state_root,
            current_block_height,
            get_state_paths_for_commitments
        )
    }

    /// Returns the inclusion assignments for the given transitions.
    #[cfg(feature = "async")]
    pub async fn prepare_async(
        &self,
        transitions: &[Transition<N>],
        query: &dyn QueryTrait<N>,
    ) -> Result<(Vec<InclusionAssignmentWrapper<N>>, N::StateRoot)> {
        prepare_impl!(
            self,
            transitions,
            query,
            current_state_root_async,
            current_block_height_async,
            get_state_paths_for_commitments_async,
            await
        )
    }
}
