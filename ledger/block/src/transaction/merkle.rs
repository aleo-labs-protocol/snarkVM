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

impl<N: Network> Transaction<N> {
    /// The maximum number of transitions allowed in a transaction.
    pub const MAX_TRANSITIONS: usize = usize::pow(2, TRANSACTION_DEPTH as u32);

    /// Returns the transaction root, by computing the root for a Merkle tree of the transition IDs.
    pub fn to_root(&self) -> Result<Field<N>> {
        Ok(*self.to_tree()?.root())
    }

    /// Returns the Merkle leaf for the given ID of a function or transition in the transaction.
    pub fn to_leaf(&self, id: &Field<N>) -> Result<TransactionLeaf<N>> {
        match self {
            Self::Deploy(_, _, _, deployment, fee) => {
                // Check if the ID is the transition ID for the fee.
                if *id == **fee.id() {
                    // Return the transaction leaf.
                    return Ok(TransactionLeaf::new_fee(
                        u16::try_from(deployment.program().functions().len())?, // The last index.
                        *id,
                    ));
                }

                // Prepare the header for the function hash.
                // Note: This must match the header used by `deployment_tree_v1` and `deployment_tree_v2`.
                let header = match deployment.version() {
                    Ok(DeploymentVersion::V1) => deployment.program().id().to_bits_le(),
                    Ok(version @ (DeploymentVersion::V2 | DeploymentVersion::V3)) => {
                        let deployment_hash = N::hash_sha3_256(&to_bits_le!(deployment.to_bytes_le()?))?;
                        to_bits_le![version as u8, deployment_hash]
                    }
                    Err(e) => bail!("Malformed deployment - {e}"),
                };
                // Iterate through the functions in the deployment.
                for (index, function) in deployment.program().functions().values().enumerate() {
                    // Check if the function hash matches the given ID.
                    if *id == N::hash_bhp1024(&to_bits_le![header, function.to_bytes_le()?])? {
                        // Return the transaction leaf.
                        return Ok(TransactionLeaf::new_deployment(u16::try_from(index)?, *id));
                    }
                }
                // Error if the function hash was not found.
                bail!("Function hash not found in deployment transaction");
            }
            Self::Execute(_, _, execution, fee) => {
                // Check if the ID is the transition ID for the fee.
                if let Some(fee) = fee
                    && *id == **fee.id()
                {
                    // Return the transaction leaf.
                    return Ok(TransactionLeaf::new_execution(
                        u16::try_from(execution.len())?, // The last index.
                        *id,
                    ));
                }

                // Iterate through the transitions in the execution.
                for (index, transition) in execution.transitions().enumerate() {
                    // Check if the transition ID matches the given ID.
                    if *id == **transition.id() {
                        // Return the transaction leaf.
                        return Ok(TransactionLeaf::new_execution(u16::try_from(index)?, *id));
                    }
                }
                // Error if the transition ID was not found.
                bail!("Transition ID not found in execution transaction");
            }
            Self::Fee(_, fee) => {
                if *id == **fee.id() {
                    // Return the transaction leaf.
                    return Ok(TransactionLeaf::new_fee(0, **fee.id()));
                }
                // Error if the transition ID was not found.
                bail!("Transition ID not found in fee transaction");
            }
        }
    }

    /// Returns the Merkle path for the transaction leaf.
    pub fn to_path(&self, leaf: &TransactionLeaf<N>) -> Result<TransactionPath<N>> {
        // Compute the Merkle path.
        self.to_tree()?.prove(leaf.index() as usize, &leaf.to_bits_le())
    }

    /// The Merkle tree of transition IDs for the transaction.
    pub fn to_tree(&self) -> Result<TransactionTree<N>> {
        match self {
            // Compute the deployment tree.
            Transaction::Deploy(_, _, _, deployment, fee) => {
                Self::transaction_tree(Self::deployment_tree(deployment)?, Some(fee))
            }
            // Compute the execution tree.
            Transaction::Execute(_, _, execution, fee) => {
                Self::transaction_tree(Self::execution_tree(execution)?, fee.as_ref())
            }
            // Compute the fee tree.
            Transaction::Fee(_, fee) => Self::fee_tree(fee),
        }
    }
}

impl<N: Network> Transaction<N> {
    /// Returns the Merkle tree for the given transaction tree, fee index, and fee.
    pub fn transaction_tree(
        mut deployment_or_execution_tree: TransactionTree<N>,
        fee: Option<&Fee<N>>,
    ) -> Result<TransactionTree<N>> {
        // Retrieve the fee index, defined as the last index in the transaction tree.
        let fee_index = deployment_or_execution_tree.number_of_leaves();
        // Ensure the fee index is within the Merkle tree size.
        ensure!(
            fee_index <= N::MAX_FUNCTIONS,
            "The fee index ('{fee_index}') in the transaction tree must be at most {}",
            N::MAX_FUNCTIONS
        );
        // Ensure the fee index is within the Merkle tree size.
        ensure!(
            fee_index < Self::MAX_TRANSITIONS,
            "The fee index ('{fee_index}') in the transaction tree must be less than {}",
            Self::MAX_TRANSITIONS
        );

        // If a fee is provided, append the fee leaf to the transaction tree.
        if let Some(fee) = fee {
            // Construct the transaction leaf.
            let leaf = TransactionLeaf::new_fee(u16::try_from(fee_index)?, **fee.transition_id()).to_bits_le();
            // Append the fee leaf to the transaction tree.
            deployment_or_execution_tree.append(&[leaf])?;
        }
        // Return the transaction tree.
        Ok(deployment_or_execution_tree)
    }

    /// Returns the Merkle tree for the given deployment.
    pub fn deployment_tree(deployment: &Deployment<N>) -> Result<DeploymentTree<N>> {
        // Use the V1 or V2 deployment tree based on implicit deployment version.
        // Note: `ConsensusVersion::V9` requires the program checksum and program owner to be present, while prior versions require it to be absent.
        //   `Deployment::version` checks that this is the case.
        // Note: After `ConsensusVersion::V9`, the program checksum and owner are used in the header of the hash instead of the program ID.
        match deployment.version() {
            Ok(DeploymentVersion::V1) => Self::deployment_tree_v1(deployment),
            Ok(DeploymentVersion::V2) => Self::deployment_tree_v2(deployment),
            // Note: We use the same method for computing the deployment tree for V2 and V3.
            // This is safe because the tree root contains a hash of all bytes in the deployment and V3 is guaranteed to have no owner.
            Ok(DeploymentVersion::V3) => Self::deployment_tree_v2(deployment),
            Err(e) => bail!("Malformed deployment - {e}"),
        }
    }

    /// Returns the Merkle tree for the given execution.
    pub fn execution_tree(execution: &Execution<N>) -> Result<ExecutionTree<N>> {
        Self::transitions_tree(execution.transitions())
    }

    /// Returns the Merkle tree for the given transitions.
    pub fn transitions_tree<'a>(
        transitions: impl ExactSizeIterator<Item = &'a Transition<N>>,
    ) -> Result<ExecutionTree<N>> {
        // Retrieve the number of transitions.
        let num_transitions = transitions.len();
        // Ensure the number of leaves is within the Merkle tree size.
        Self::check_execution_size(num_transitions)?;
        // Prepare the leaves.
        let leaves = transitions.enumerate().map(|(index, transition)| {
            // Construct the transaction leaf.
            Ok::<_, Error>(TransactionLeaf::new_execution(u16::try_from(index)?, **transition.id()).to_bits_le())
        });
        // Compute the execution tree.
        N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&leaves.collect::<Result<Vec<_>, _>>()?)
    }

    /// Returns the Merkle tree for the given fee.
    pub fn fee_tree(fee: &Fee<N>) -> Result<TransactionTree<N>> {
        // Construct the transaction leaf.
        let leaf = TransactionLeaf::new_fee(0u16, **fee.transition_id()).to_bits_le();
        // Compute the execution tree.
        N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&[leaf])
    }

    /// Returns `true` if the deployment is within the size bounds.
    pub fn check_deployment_size(deployment: &Deployment<N>) -> Result<()> {
        // Retrieve the program.
        let program = deployment.program();
        // Retrieve the functions.
        let functions = program.functions();
        // Retrieve the function verifying keys.
        let function_verifying_keys = deployment.function_verifying_keys();
        // Retrieve the number of functions.
        let num_functions = functions.len();

        // Ensure the number of functions and function verifying keys match.
        ensure!(
            num_functions == function_verifying_keys.len(),
            "Number of functions ('{num_functions}') and function verifying keys ('{}') do not match",
            function_verifying_keys.len()
        );
        // Ensure there are functions.
        ensure!(num_functions != 0, "Deployment must contain at least one function");
        // Ensure the number of functions is within the allowed range.
        ensure!(
            num_functions <= N::MAX_FUNCTIONS,
            "Deployment must contain at most {} functions, found {num_functions}",
            N::MAX_FUNCTIONS,
        );

        // If translation verifying keys are present, ensure the count is within bounds.
        if let Some(translation_verifying_keys) = deployment.translation_verifying_keys() {
            let num_records = translation_verifying_keys.len();
            ensure!(
                num_records <= N::MAX_RECORDS,
                "Deployment must contain at most {} records, found {num_records}",
                N::MAX_RECORDS,
            );
        }

        // Ensure the number of function verifying keys fits in the transaction tree.
        // Note: Record verifying keys do not occupy transition leaves.
        ensure!(
            num_functions < Self::MAX_TRANSITIONS, // Note: Observe we hold back 1 for the fee.
            "Deployment must contain less than {} function verifying keys, found {num_functions}",
            Self::MAX_TRANSITIONS,
        );
        Ok(())
    }

    /// Returns `true` if the execution is within the size bounds.
    pub fn check_execution_size(num_transitions: usize) -> Result<()> {
        // Ensure there are transitions.
        ensure!(num_transitions > 0, "Execution must contain at least one transition");
        // Ensure the number of functions is within the allowed range.
        ensure!(
            num_transitions < Self::MAX_TRANSITIONS, // Note: Observe we hold back 1 for the fee.
            "Execution must contain less than {} transitions, found {num_transitions}",
            Self::MAX_TRANSITIONS,
        );
        Ok(())
    }
}

impl<N: Network> Transaction<N> {
    /// Returns the V1 deployment tree.
    pub fn deployment_tree_v1(deployment: &Deployment<N>) -> Result<DeploymentTree<N>> {
        // Ensure the number of leaves is within the Merkle tree size.
        Self::check_deployment_size(deployment)?;
        // Prepare the header for the hash.
        let header = deployment.program().id().to_bits_le();
        // Prepare the leaves.
        let leaves = deployment.program().functions().values().enumerate().map(|(index, function)| {
            // Construct the transaction leaf.
            Ok(TransactionLeaf::new_deployment(
                u16::try_from(index)?,
                N::hash_bhp1024(&to_bits_le![header, function.to_bytes_le()?])?,
            )
            .to_bits_le())
        });
        // Compute the deployment tree.
        N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&leaves.collect::<Result<Vec<_>>>()?)
    }

    /// Returns the V2 deployment tree.
    pub fn deployment_tree_v2(deployment: &Deployment<N>) -> Result<DeploymentTree<N>> {
        // Ensure the number of leaves is within the Merkle tree size.
        Self::check_deployment_size(deployment)?;
        // Compute a hash of the deployment bytes.
        let deployment_hash = N::hash_sha3_256(&to_bits_le!(deployment.to_bytes_le()?))?;
        // Prepare the header for the hash.
        let header = to_bits_le![deployment.version()? as u8, deployment_hash];
        // Prepare the leaves.
        let leaves = deployment.program().functions().values().enumerate().map(|(index, function)| {
            // Construct the transaction leaf.
            Ok(TransactionLeaf::new_deployment(
                u16::try_from(index)?,
                N::hash_bhp1024(&to_bits_le![header, function.to_bytes_le()?])?,
            )
            .to_bits_le())
        });
        // Compute the deployment tree.
        N::merkle_tree_bhp::<TRANSACTION_DEPTH>(&leaves.collect::<Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_transaction_depth_is_correct() {
        // We ensure 2^TRANSACTION_DEPTH == MAX_FUNCTIONS + 1.
        // The "1 extra" is for the fee transition.
        assert_eq!(
            2u32.checked_pow(TRANSACTION_DEPTH as u32).unwrap() as usize,
            Transaction::<CurrentNetwork>::MAX_TRANSITIONS
        );
        assert_eq!(
            CurrentNetwork::MAX_FUNCTIONS.checked_add(1).unwrap(),
            Transaction::<CurrentNetwork>::MAX_TRANSITIONS
        );
    }

    #[test]
    fn test_to_leaf_deployment_functions() -> Result<()> {
        let rng = &mut TestRng::default();

        for (version, has_translation_keys, is_fee_private) in
            [(1, false, true), (2, false, false), (2, true, true), (3, false, false)]
        {
            let transaction = crate::transaction::test_helpers::sample_deployment_transaction(
                version,
                Uniform::rand(rng),
                has_translation_keys,
                is_fee_private,
                rng,
            );
            let Transaction::Deploy(_, _, _, deployment, fee) = &transaction else {
                bail!("Expected a deployment transaction");
            };
            let root = transaction.to_root()?;

            let header = match version {
                1 => deployment.program().id().to_bits_le(),
                _ => to_bits_le![version, CurrentNetwork::hash_sha3_256(&to_bits_le!(deployment.to_bytes_le()?))?],
            };
            for (index, function) in deployment.program().functions().values().enumerate() {
                let id = CurrentNetwork::hash_bhp1024(&to_bits_le![header, function.to_bytes_le()?])?;
                let leaf = transaction.to_leaf(&id)?;
                assert_eq!(leaf, TransactionLeaf::new_deployment(u16::try_from(index)?, id));
                let path = transaction.to_path(&leaf)?;
                assert!(CurrentNetwork::verify_merkle_path_bhp(&path, &root, &leaf.to_bits_le()));

                // A function hash without the header is not a leaf.
                let headerless_id = CurrentNetwork::hash_bhp1024(&function.to_bytes_le()?.to_bits_le())?;
                assert!(matches!(
                    transaction.to_leaf(&headerless_id),
                    Err(e) if e.to_string().contains("Function hash not found")
                ));
            }

            let fee_leaf = transaction.to_leaf(&**fee.id())?;
            assert_eq!(
                fee_leaf,
                TransactionLeaf::new_fee(u16::try_from(deployment.program().functions().len())?, **fee.id())
            );
        }
        Ok(())
    }
}
