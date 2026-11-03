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

mod bytes;
mod serialize;
mod string;

use crate::{Transaction, rejected::Rejected};
use console::{network::prelude::*, program::FINALIZE_ID_DEPTH, types::Field};
use snarkvm_synthesizer_program::FinalizeOperation;

pub type NumFinalizeSize = u16;

/// The confirmed transaction.
#[derive(Clone, PartialEq, Eq)]
pub enum ConfirmedTransaction<N: Network> {
    /// The accepted deploy transaction is composed of `(index, deploy_transaction, finalize_operations)`.
    /// The finalize operations may contain operations from the executing the constructor and fee transition.
    AcceptedDeploy(u32, Transaction<N>, Vec<FinalizeOperation<N>>),
    /// The accepted execute transaction is composed of `(index, execute_transaction, finalize_operations)`.
    /// The finalize operations can contain operations from the executing the finalize scope and fee transition.
    AcceptedExecute(u32, Transaction<N>, Vec<FinalizeOperation<N>>),
    /// The rejected deploy transaction is composed of `(index, fee_transaction, rejected_deployment, finalize_operations)`.
    /// The finalize operations can contain operations from the fee transition.
    RejectedDeploy(u32, Transaction<N>, Rejected<N>, Vec<FinalizeOperation<N>>),
    /// The rejected execute transaction is composed of `(index, fee_transaction, rejected_execution, finalize_operations)`.
    /// The finalize operations can contain operations from the fee transition.
    RejectedExecute(u32, Transaction<N>, Rejected<N>, Vec<FinalizeOperation<N>>),
}

impl<N: Network> ConfirmedTransaction<N> {
    /// Returns a new instance of an accepted deploy transaction.
    pub fn accepted_deploy(
        index: u32,
        transaction: Transaction<N>,
        finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<Self> {
        // Retrieve the program and fee from the deployment transaction, and ensure the transaction is a deploy transaction.
        let (program, fee) = match &transaction {
            Transaction::Deploy(_, _, _, deployment, fee) => (deployment.program(), fee),
            Transaction::Execute(..) | Transaction::Fee(..) => {
                bail!("Transaction '{}' is not a deploy transaction", transaction.id())
            }
        };

        // Count the number of `InitializeMapping` and `*KeyValue` finalize operations.
        let (num_initialize_mappings, num_key_values) =
            finalize_operations.iter().try_fold((0, 0), |(init, key_value), operation| match operation {
                FinalizeOperation::InitializeMapping(..) => Ok((init + 1, key_value)),
                FinalizeOperation::InsertKeyValue(..) // At the time of writing, `InsertKeyValue` is only used in tests. However, it is added for completeness, as it is a valid operation.
                | FinalizeOperation::RemoveKeyValue(..)
                | FinalizeOperation::UpdateKeyValue(..) => Ok((init, key_value + 1)),
                op => {
                    bail!("Transaction '{}' (deploy) contains an invalid finalize operation ({op})", transaction.id())
                }
            })?;

        // Perform safety checks on the finalize operations.
        {
            // Ensure the number of finalize operations matches the number of 'InitializeMapping' and '*KeyValue' finalize operations.
            if num_initialize_mappings + num_key_values != finalize_operations.len() {
                bail!(
                    "Transaction '{}' (deploy) must contain '{}' operations",
                    transaction.id(),
                    finalize_operations.len()
                );
            }
            // Ensure the number of program mappings upper bounds the number of 'InitializeMapping' finalize operations.
            // The upper bound is due to the fact that some mappings may have been initialized in earlier deployments or upgrades.
            ensure!(
                num_initialize_mappings <= program.mappings().len(),
                "Transaction '{}' (deploy) must contain at most '{}' 'InitializeMapping' operations (found '{num_initialize_mappings}')",
                transaction.id(),
                program.mappings().len(),
            );
            // Ensure the number of fee finalize operations lower bounds the number of '*KeyValue' finalize operations.
            // The lower bound is due to the fact that constructors can issue '*KeyValue' operations as part of the deployment.
            ensure!(
                fee.num_finalize_operations() <= num_key_values,
                "Transaction '{}' (deploy) must contain at least {} '*KeyValue' operations (found '{num_key_values}')",
                transaction.id(),
                fee.num_finalize_operations()
            );
            // Ensure the number of fee finalize operations and the number of "write" operations in the constructor upper bounds the number of '*KeyValue' finalize operations.
            // This is an upper bound because a constructor may contain `branch.*` commands so that a subset of writes are executed.
            let num_constructor_writes = usize::from(program.constructor().map(|c| c.num_writes()).unwrap_or_default());
            ensure!(
                fee.num_finalize_operations().saturating_add(num_constructor_writes) >= num_key_values,
                "Transaction '{}' (deploy) must contain at most {} '*KeyValue' operations (found '{num_key_values}')",
                transaction.id(),
                fee.num_finalize_operations().saturating_add(num_constructor_writes)
            );
        }

        // Return the accepted deploy transaction.
        Ok(Self::AcceptedDeploy(index, transaction, finalize_operations))
    }

    /// Returns a new instance of an accepted execute transaction.
    pub fn accepted_execute(
        index: u32,
        transaction: Transaction<N>,
        finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<Self> {
        // Ensure the finalize operations contain the correct types.
        for operation in finalize_operations.iter() {
            // Ensure the finalize operation is an insert or update key-value operation.
            match operation {
                FinalizeOperation::InsertKeyValue(..)
                | FinalizeOperation::UpdateKeyValue(..)
                | FinalizeOperation::RemoveKeyValue(..) => (),
                FinalizeOperation::InitializeMapping(..)
                | FinalizeOperation::ReplaceMapping(..)
                | FinalizeOperation::RemoveMapping(..) => {
                    bail!("Transaction '{}' (execute) contains an invalid finalize operation type", transaction.id())
                }
            }
        }
        // Ensure the transaction is an execute transaction.
        match transaction.is_execute() {
            true => Ok(Self::AcceptedExecute(index, transaction, finalize_operations)),
            false => bail!("Transaction '{}' is not an execute transaction", transaction.id()),
        }
    }

    /// Returns a new instance of a rejected deploy transaction.
    pub fn rejected_deploy(
        index: u32,
        transaction: Transaction<N>,
        rejected: Rejected<N>,
        finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<Self> {
        // Ensure the rejected object is a deployment.
        ensure!(rejected.is_deployment(), "Rejected deployment is not a deployment");
        // Ensure the finalize operations contain the correct types.
        for operation in finalize_operations.iter() {
            // Ensure the finalize operation is an insert or update key-value operation.
            match operation {
                FinalizeOperation::InsertKeyValue(..)
                | FinalizeOperation::UpdateKeyValue(..)
                | FinalizeOperation::RemoveKeyValue(..) => (),
                FinalizeOperation::InitializeMapping(..)
                | FinalizeOperation::ReplaceMapping(..)
                | FinalizeOperation::RemoveMapping(..) => {
                    bail!("Transaction '{}' (fee) contains an invalid finalize operation type", transaction.id())
                }
            }
        }
        // Ensure the transaction is a fee transaction.
        match transaction.is_fee() {
            true => Ok(Self::RejectedDeploy(index, transaction, rejected, finalize_operations)),
            false => bail!("Transaction '{}' is not a fee transaction", transaction.id()),
        }
    }

    /// Returns a new instance of a rejected execute transaction.
    ///
    /// Arguments:
    /// - `index`: The index of the transaction within the block.
    /// - `transaction`: The associated fee transaction.
    /// - `rejected`: The rejected execute transaction.
    /// - `finalize_operations`: The finalize operations for the fee transaction.
    pub fn rejected_execute(
        index: u32,
        transaction: Transaction<N>,
        rejected: Rejected<N>,
        finalize_operations: Vec<FinalizeOperation<N>>,
    ) -> Result<Self> {
        // Ensure the rejected object is an execution.
        ensure!(rejected.is_execution(), "Rejected execution is not an execution");
        // Ensure the finalize operations contain the correct types.
        for operation in finalize_operations.iter() {
            // Ensure the finalize operation is an insert or update key-value operation.
            match operation {
                FinalizeOperation::InsertKeyValue(..)
                | FinalizeOperation::UpdateKeyValue(..)
                | FinalizeOperation::RemoveKeyValue(..) => (),
                FinalizeOperation::InitializeMapping(..)
                | FinalizeOperation::ReplaceMapping(..)
                | FinalizeOperation::RemoveMapping(..) => {
                    bail!("Transaction '{}' (fee) contains an invalid finalize operation type", transaction.id())
                }
            }
        }
        // Ensure the transaction is a fee transaction.
        match transaction.is_fee() {
            true => Ok(Self::RejectedExecute(index, transaction, rejected, finalize_operations)),
            false => bail!("Transaction '{}' is not a fee transaction", transaction.id()),
        }
    }
}

impl<N: Network> ConfirmedTransaction<N> {
    /// Returns 'true' if the confirmed transaction is accepted.
    pub const fn is_accepted(&self) -> bool {
        match self {
            Self::AcceptedDeploy(..) | Self::AcceptedExecute(..) => true,
            Self::RejectedDeploy(..) | Self::RejectedExecute(..) => false,
        }
    }

    /// Returns 'true' if the confirmed transaction is rejected.
    pub const fn is_rejected(&self) -> bool {
        !self.is_accepted()
    }

    /// Returns `true` if the confirmed transaction represents the given unconfirmed transaction ID.
    pub fn contains_unconfirmed_transaction_id(&self, unconfirmed_transaction_id: &N::TransactionID) -> bool {
        self.to_unconfirmed_transaction_id().is_ok_and(|id| &id == unconfirmed_transaction_id)
    }
}

impl<N: Network> ConfirmedTransaction<N> {
    /// Returns the confirmed transaction index.
    pub const fn index(&self) -> u32 {
        match self {
            Self::AcceptedDeploy(index, ..) => *index,
            Self::AcceptedExecute(index, ..) => *index,
            Self::RejectedDeploy(index, ..) => *index,
            Self::RejectedExecute(index, ..) => *index,
        }
    }

    /// Returns the human-readable variant of the confirmed transaction.
    pub const fn variant(&self) -> &str {
        match self {
            Self::AcceptedDeploy(..) => "accepted deploy",
            Self::AcceptedExecute(..) => "accepted execute",
            Self::RejectedDeploy(..) => "rejected deploy",
            Self::RejectedExecute(..) => "rejected execute",
        }
    }

    /// Returns the underlying transaction.
    ///
    /// For an accepted transaction, it is the original/unconfirmed transaction issued by the client.
    /// For a rejected transaction, it is the fee transaction, not the original transaction.
    pub const fn transaction(&self) -> &Transaction<N> {
        match self {
            Self::AcceptedDeploy(_, transaction, _) => transaction,
            Self::AcceptedExecute(_, transaction, _) => transaction,
            Self::RejectedDeploy(_, transaction, _, _) => transaction,
            Self::RejectedExecute(_, transaction, _, _) => transaction,
        }
    }

    /// Returns the transaction.
    pub fn into_transaction(self) -> Transaction<N> {
        match self {
            Self::AcceptedDeploy(_, transaction, _) => transaction,
            Self::AcceptedExecute(_, transaction, _) => transaction,
            Self::RejectedDeploy(_, transaction, _, _) => transaction,
            Self::RejectedExecute(_, transaction, _, _) => transaction,
        }
    }

    /// Returns the number of finalize operations.
    pub fn num_finalize(&self) -> usize {
        match self {
            Self::AcceptedDeploy(_, _, finalize) => finalize.len(),
            Self::AcceptedExecute(_, _, finalize) => finalize.len(),
            Self::RejectedDeploy(_, _, _, finalize) => finalize.len(),
            Self::RejectedExecute(_, _, _, finalize) => finalize.len(),
        }
    }

    /// Returns the finalize operations for the confirmed transaction.
    pub const fn finalize_operations(&self) -> &Vec<FinalizeOperation<N>> {
        match self {
            Self::AcceptedDeploy(_, _, finalize) => finalize,
            Self::AcceptedExecute(_, _, finalize) => finalize,
            Self::RejectedDeploy(_, _, _, finalize) => finalize,
            Self::RejectedExecute(_, _, _, finalize) => finalize,
        }
    }

    /// Returns the finalize ID, by computing the root of a (small) Merkle tree comprised of
    /// the ordered finalize operations for the transaction.
    pub fn to_finalize_id(&self) -> Result<Field<N>> {
        // Prepare the leaves.
        let leaves = self.finalize_operations().iter().map(ToBits::to_bits_le).collect::<Vec<_>>();
        // Compute the finalize ID.
        // Note: This call will ensure the number of finalize operations is within the size of the Merkle tree.
        Ok(*N::merkle_tree_bhp::<FINALIZE_ID_DEPTH>(&leaves)?.root())
    }

    /// Returns the rejected ID, if the confirmed transaction is rejected.
    pub fn to_rejected_id(&self) -> Result<Option<Field<N>>> {
        match self {
            ConfirmedTransaction::AcceptedDeploy(..) | ConfirmedTransaction::AcceptedExecute(..) => Ok(None),
            ConfirmedTransaction::RejectedDeploy(_, _, rejected, _) => Ok(Some(rejected.to_id()?)),
            ConfirmedTransaction::RejectedExecute(_, _, rejected, _) => Ok(Some(rejected.to_id()?)),
        }
    }

    /// Returns the rejected object, if the confirmed transaction is rejected.
    pub fn to_rejected(&self) -> Option<&Rejected<N>> {
        match self {
            ConfirmedTransaction::AcceptedDeploy(..) | ConfirmedTransaction::AcceptedExecute(..) => None,
            ConfirmedTransaction::RejectedDeploy(_, _, rejected, _) => Some(rejected),
            ConfirmedTransaction::RejectedExecute(_, _, rejected, _) => Some(rejected),
        }
    }

    /// Returns the unconfirmed transaction ID, which is defined as the transaction ID prior to confirmation.
    /// When a transaction is rejected, its fee transition is used to construct the confirmed transaction ID,
    /// changing the original transaction ID.
    pub fn to_unconfirmed_transaction_id(&self) -> Result<N::TransactionID> {
        match self {
            Self::AcceptedDeploy(_, transaction, _) => Ok(transaction.id()),
            Self::AcceptedExecute(_, transaction, _) => Ok(transaction.id()),
            Self::RejectedDeploy(_, fee_transaction, rejected, _)
            | Self::RejectedExecute(_, fee_transaction, rejected, _) => {
                Ok(rejected.to_unconfirmed_id(&fee_transaction.fee_transition())?.into())
            }
        }
    }

    /// Returns the unconfirmed transaction, which is defined as the transaction prior to confirmation.
    /// When a transaction is rejected, its fee transition is used to construct the confirmed transaction,
    /// changing the original transaction.
    pub fn to_unconfirmed_transaction(&self) -> Result<Transaction<N>> {
        match self {
            Self::AcceptedDeploy(_, transaction, _) => Ok(transaction.clone()),
            Self::AcceptedExecute(_, transaction, _) => Ok(transaction.clone()),
            Self::RejectedDeploy(_, fee_transaction, rejected, _) => Transaction::from_deployment(
                rejected
                    .program_owner()
                    .copied()
                    .ok_or_else(|| anyhow!("Missing program owner for rejected transaction"))?,
                rejected.deployment().cloned().ok_or_else(|| anyhow!("Missing deployment for rejected transaction"))?,
                fee_transaction.fee_transition().ok_or_else(|| anyhow!("Missing fee for rejected deployment"))?,
            ),
            Self::RejectedExecute(_, fee_transaction, rejected, _) => Transaction::from_execution(
                rejected.execution().cloned().ok_or_else(|| anyhow!("Missing execution for rejected transaction"))?,
                fee_transaction.fee_transition(),
            ),
        }
    }
}

impl<N: Network> Deref for ConfirmedTransaction<N> {
    type Target = Transaction<N>;

    /// Returns a reference to the valid transaction.
    fn deref(&self) -> &Self::Target {
        self.transaction()
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    /// Samples an accepted deploy transaction at the given index.
    pub(crate) fn sample_accepted_deploy(
        index: u32,
        version: u8,
        edition: u16,
        has_translation_keys: bool,
        is_fee_private: bool,
        rng: &mut TestRng,
    ) -> ConfirmedTransaction<CurrentNetwork> {
        // Sample a deploy transaction.
        let tx = crate::transaction::test_helpers::sample_deployment_transaction(
            version,
            edition,
            has_translation_keys,
            is_fee_private,
            rng,
        );

        // Construct the finalize operations based on if the fee is public or private.
        let finalize_operations = match is_fee_private {
            true => vec![FinalizeOperation::InitializeMapping(Uniform::rand(rng))],
            false => vec![
                FinalizeOperation::InitializeMapping(Uniform::rand(rng)),
                FinalizeOperation::UpdateKeyValue(Uniform::rand(rng), Uniform::rand(rng), Uniform::rand(rng)),
            ],
        };

        // Return the confirmed transaction.
        ConfirmedTransaction::accepted_deploy(index, tx, finalize_operations).unwrap()
    }

    /// Samples an accepted execute transaction at the given index.
    pub(crate) fn sample_accepted_execute(
        index: u32,
        is_fee_private: bool,
        rng: &mut TestRng,
    ) -> ConfirmedTransaction<CurrentNetwork> {
        // Sample an execute transaction.
        let tx = crate::transaction::test_helpers::sample_execution_transaction_with_fee(is_fee_private, rng, 0);
        // Return the confirmed transaction.
        ConfirmedTransaction::accepted_execute(index, tx, vec![]).unwrap()
    }

    /// Samples a rejected deploy transaction at the given index.
    pub(crate) fn sample_rejected_deploy(
        index: u32,
        version: u8,
        edition: u16,
        has_translation_keys: bool,
        is_fee_private: bool,
        rng: &mut TestRng,
    ) -> ConfirmedTransaction<CurrentNetwork> {
        // Sample a fee transaction.
        let fee_transaction = match is_fee_private {
            true => crate::transaction::test_helpers::sample_private_fee_transaction(rng),
            false => crate::transaction::test_helpers::sample_fee_public_transaction(rng),
        };

        // Extract the rejected deployment.
        let rejected = crate::rejected::test_helpers::sample_rejected_deployment(
            version,
            edition,
            has_translation_keys,
            is_fee_private,
            rng,
        );

        // Return the confirmed transaction.
        ConfirmedTransaction::rejected_deploy(index, fee_transaction, rejected, vec![]).unwrap()
    }

    /// Samples a rejected execute transaction at the given index.
    pub(crate) fn sample_rejected_execute(
        index: u32,
        is_fee_private: bool,
        rng: &mut TestRng,
    ) -> ConfirmedTransaction<CurrentNetwork> {
        // Sample a fee transaction.
        let fee_transaction = match is_fee_private {
            true => crate::transaction::test_helpers::sample_private_fee_transaction(rng),
            false => crate::transaction::test_helpers::sample_fee_public_transaction(rng),
        };

        // Extract the rejected execution.
        let rejected = crate::rejected::test_helpers::sample_rejected_execution(is_fee_private, rng);

        // Return the confirmed transaction.
        ConfirmedTransaction::rejected_execute(index, fee_transaction, rejected, vec![]).unwrap()
    }

    /// Sample a list of randomly confirmed transactions.
    pub(crate) fn sample_confirmed_transactions() -> Vec<ConfirmedTransaction<CurrentNetwork>> {
        let rng = &mut TestRng::default();

        vec![
            sample_accepted_deploy(0, 1, Uniform::rand(rng), false, true, rng),
            sample_accepted_deploy(0, 1, Uniform::rand(rng), false, true, rng),
            sample_accepted_deploy(0, 2, Uniform::rand(rng), false, true, rng),
            sample_accepted_deploy(0, 2, Uniform::rand(rng), true, true, rng),
            sample_accepted_execute(1, true, rng),
            sample_accepted_execute(1, false, rng),
            sample_rejected_deploy(2, 1, Uniform::rand(rng), false, true, rng),
            sample_rejected_deploy(2, 1, Uniform::rand(rng), false, true, rng),
            sample_rejected_deploy(2, 2, Uniform::rand(rng), false, true, rng),
            sample_rejected_deploy(2, 2, Uniform::rand(rng), true, true, rng),
            sample_rejected_execute(3, true, rng),
            sample_rejected_execute(3, true, rng),
            sample_rejected_execute(3, false, rng),
            sample_rejected_execute(3, false, rng),
            sample_accepted_execute(Uniform::rand(rng), true, rng),
            sample_accepted_execute(Uniform::rand(rng), false, rng),
            sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, Uniform::rand(rng), rng),
            sample_rejected_execute(Uniform::rand(rng), true, rng),
            sample_rejected_execute(Uniform::rand(rng), true, rng),
            sample_rejected_execute(Uniform::rand(rng), false, rng),
            sample_rejected_execute(Uniform::rand(rng), false, rng),
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transactions::confirmed::test_helpers;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_accepted_execute() {
        let rng = &mut TestRng::default();

        let index = Uniform::rand(rng);
        let tx = crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0);

        // Create an `AcceptedExecution` with valid `FinalizeOperation`s.
        let finalize_operations = vec![
            FinalizeOperation::InsertKeyValue(Uniform::rand(rng), Uniform::rand(rng), Uniform::rand(rng)),
            FinalizeOperation::UpdateKeyValue(Uniform::rand(rng), Uniform::rand(rng), Uniform::rand(rng)),
            FinalizeOperation::RemoveKeyValue(Uniform::rand(rng), Uniform::rand(rng)),
        ];
        let confirmed = ConfirmedTransaction::accepted_execute(index, tx.clone(), finalize_operations.clone()).unwrap();

        assert_eq!(confirmed.index(), index);
        assert_eq!(confirmed.transaction(), &tx);
        assert_eq!(confirmed.num_finalize(), finalize_operations.len());
        assert_eq!(confirmed.finalize_operations(), &finalize_operations);

        // Attempt to create an `AcceptedExecution` with invalid `FinalizeOperation`s.
        let finalize_operations = vec![FinalizeOperation::InitializeMapping(Uniform::rand(rng))];
        let confirmed = ConfirmedTransaction::accepted_execute(index, tx.clone(), finalize_operations);
        assert!(confirmed.is_err());

        let finalize_operations = vec![FinalizeOperation::RemoveMapping(Uniform::rand(rng))];
        let confirmed = ConfirmedTransaction::accepted_execute(index, tx, finalize_operations);
        assert!(confirmed.is_err());
    }

    #[test]
    fn test_contains_unconfirmed_transaction_id() {
        let rng = &mut TestRng::default();

        // A helper function to check that the unconfirmed transaction ID is correct.
        let check_contains_unconfirmed_transaction_id = |confirmed: ConfirmedTransaction<CurrentNetwork>| {
            let rng = &mut TestRng::default();
            let unconfirmed_transaction_id = confirmed.to_unconfirmed_transaction_id().unwrap();
            assert!(confirmed.contains_unconfirmed_transaction_id(&unconfirmed_transaction_id));
            assert!(!confirmed.contains_unconfirmed_transaction_id(&<CurrentNetwork as Network>::TransactionID::from(
                Field::rand(rng)
            )));
        };

        // Ensure that the unconfirmed transaction ID of an accepted deployment is equivalent to its confirmed transaction ID.
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, true, rng);
        check_contains_unconfirmed_transaction_id(accepted_deploy);
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, false, rng);
        check_contains_unconfirmed_transaction_id(accepted_deploy);
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, true, rng);
        check_contains_unconfirmed_transaction_id(accepted_deploy);
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, false, rng);
        check_contains_unconfirmed_transaction_id(accepted_deploy);

        // Ensure that the unconfirmed transaction ID of an accepted execute is equivalent to its confirmed transaction ID.
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), true, rng);
        check_contains_unconfirmed_transaction_id(accepted_execution);
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), false, rng);
        check_contains_unconfirmed_transaction_id(accepted_execution);

        // Ensure that the unconfirmed transaction ID of a rejected deployment is not equivalent to its confirmed transaction ID.
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, true, rng);
        check_contains_unconfirmed_transaction_id(rejected_deploy);
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, false, rng);
        check_contains_unconfirmed_transaction_id(rejected_deploy);
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, true, rng);
        check_contains_unconfirmed_transaction_id(rejected_deploy);
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, false, rng);
        check_contains_unconfirmed_transaction_id(rejected_deploy);

        // Ensure that the unconfirmed transaction ID of a rejected execute is not equivalent to its confirmed transaction ID.
        let rejected_execution = test_helpers::sample_rejected_execute(Uniform::rand(rng), true, rng);
        check_contains_unconfirmed_transaction_id(rejected_execution);
        let rejected_execution = test_helpers::sample_rejected_execute(Uniform::rand(rng), false, rng);
        check_contains_unconfirmed_transaction_id(rejected_execution);
    }

    #[test]
    fn test_unconfirmed_transaction_ids() {
        let rng = &mut TestRng::default();

        // Ensure that the unconfirmed transaction ID of an accepted deployment is equivalent to its confirmed transaction ID.
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, true, rng);
        assert_eq!(accepted_deploy.to_unconfirmed_transaction_id().unwrap(), accepted_deploy.id());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, false, rng);
        assert_eq!(accepted_deploy.to_unconfirmed_transaction_id().unwrap(), accepted_deploy.id());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, true, rng);
        assert_eq!(accepted_deploy.to_unconfirmed_transaction_id().unwrap(), accepted_deploy.id());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, false, rng);
        assert_eq!(accepted_deploy.to_unconfirmed_transaction_id().unwrap(), accepted_deploy.id());

        // Ensure that the unconfirmed transaction ID of an accepted execute is equivalent to its confirmed transaction ID.
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), true, rng);
        assert_eq!(accepted_execution.to_unconfirmed_transaction_id().unwrap(), accepted_execution.id());
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), false, rng);
        assert_eq!(accepted_execution.to_unconfirmed_transaction_id().unwrap(), accepted_execution.id());

        // Ensure that the unconfirmed transaction ID of a rejected deployment is not equivalent to its confirmed transaction ID.
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, true, rng);
        assert_ne!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), rejected_deploy.id());
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, false, rng);
        assert_ne!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), rejected_deploy.id());
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, true, rng);
        assert_ne!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), rejected_deploy.id());
        let rejected_deploy =
            test_helpers::sample_rejected_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, false, rng);
        assert_ne!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), rejected_deploy.id());

        // Ensure that the unconfirmed transaction ID of a rejected execute is not equivalent to its confirmed transaction ID.
        let rejected_execution = test_helpers::sample_rejected_execute(Uniform::rand(rng), true, rng);
        assert_ne!(rejected_execution.to_unconfirmed_transaction_id().unwrap(), rejected_execution.id());
        let rejected_execution = test_helpers::sample_rejected_execute(Uniform::rand(rng), false, rng);
        assert_ne!(rejected_execution.to_unconfirmed_transaction_id().unwrap(), rejected_execution.id());
    }

    #[test]
    fn test_unconfirmed_transactions() {
        let rng = &mut TestRng::default();

        // Ensure that the unconfirmed transaction of an accepted deployment is equivalent to its confirmed transaction.
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, true, rng);
        assert_eq!(&accepted_deploy.to_unconfirmed_transaction().unwrap(), accepted_deploy.transaction());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 1, Uniform::rand(rng), false, false, rng);
        assert_eq!(&accepted_deploy.to_unconfirmed_transaction().unwrap(), accepted_deploy.transaction());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, true, rng);
        assert_eq!(&accepted_deploy.to_unconfirmed_transaction().unwrap(), accepted_deploy.transaction());
        let accepted_deploy =
            test_helpers::sample_accepted_deploy(Uniform::rand(rng), 2, Uniform::rand(rng), false, false, rng);
        assert_eq!(&accepted_deploy.to_unconfirmed_transaction().unwrap(), accepted_deploy.transaction());

        // Ensure that the unconfirmed transaction of an accepted execute is equivalent to its confirmed transaction.
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), true, rng);
        assert_eq!(&accepted_execution.to_unconfirmed_transaction().unwrap(), accepted_execution.transaction());
        let accepted_execution = test_helpers::sample_accepted_execute(Uniform::rand(rng), false, rng);
        assert_eq!(&accepted_execution.to_unconfirmed_transaction().unwrap(), accepted_execution.transaction());

        // Ensure that the unconfirmed transaction of a rejected deployment is not equivalent to its confirmed transaction.
        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, true, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, false, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, true, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, false, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, true, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        let deployment_transaction =
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, false, rng);
        let rejected = Rejected::new_deployment(
            *deployment_transaction.owner().unwrap(),
            deployment_transaction.deployment().unwrap().clone(),
        );
        let fee = Transaction::from_fee(deployment_transaction.fee_transition().unwrap()).unwrap();
        let rejected_deploy = ConfirmedTransaction::rejected_deploy(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_deploy.to_unconfirmed_transaction_id().unwrap(), deployment_transaction.id());
        assert_eq!(rejected_deploy.to_unconfirmed_transaction().unwrap(), deployment_transaction);

        // Ensure that the unconfirmed transaction of a rejected execute is not equivalent to its confirmed transaction.
        let execution_transaction =
            crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0);
        let rejected = Rejected::new_execution(execution_transaction.execution().unwrap().clone());
        let fee = Transaction::from_fee(execution_transaction.fee_transition().unwrap()).unwrap();
        let rejected_execute =
            ConfirmedTransaction::rejected_execute(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_execute.to_unconfirmed_transaction_id().unwrap(), execution_transaction.id());
        assert_eq!(rejected_execute.to_unconfirmed_transaction().unwrap(), execution_transaction);

        let execution_transaction =
            crate::transaction::test_helpers::sample_execution_transaction_with_fee(false, rng, 0);
        let rejected = Rejected::new_execution(execution_transaction.execution().unwrap().clone());
        let fee = Transaction::from_fee(execution_transaction.fee_transition().unwrap()).unwrap();
        let rejected_execute =
            ConfirmedTransaction::rejected_execute(Uniform::rand(rng), fee, rejected, vec![]).unwrap();
        assert_eq!(rejected_execute.to_unconfirmed_transaction_id().unwrap(), execution_transaction.id());
        assert_eq!(rejected_execute.to_unconfirmed_transaction().unwrap(), execution_transaction);
    }
}
