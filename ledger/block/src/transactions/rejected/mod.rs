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

use super::*;

use crate::{Deployment, Execution, Fee};

/// A wrapper around the rejected deployment or execution.
#[derive(Clone, PartialEq, Eq)]
pub enum Rejected<N: Network> {
    Deployment(ProgramOwner<N>, Box<Deployment<N>>),
    Execution(Box<Execution<N>>),
}

impl<N: Network> Rejected<N> {
    /// Initializes a rejected deployment.
    pub fn new_deployment(program_owner: ProgramOwner<N>, deployment: Deployment<N>) -> Self {
        Self::Deployment(program_owner, Box::new(deployment))
    }

    /// Initializes a rejected execution.
    pub fn new_execution(execution: Execution<N>) -> Self {
        Self::Execution(Box::new(execution))
    }

    /// Returns true if the rejected transaction is a deployment.
    pub fn is_deployment(&self) -> bool {
        matches!(self, Self::Deployment(..))
    }

    /// Returns true if the rejected transaction is an execution.
    pub fn is_execution(&self) -> bool {
        matches!(self, Self::Execution(..))
    }

    /// Returns the program owner of the rejected deployment.
    pub fn program_owner(&self) -> Option<&ProgramOwner<N>> {
        match self {
            Self::Deployment(program_owner, ..) => Some(program_owner),
            Self::Execution(..) => None,
        }
    }

    /// Returns the rejected deployment.
    pub fn deployment(&self) -> Option<&Deployment<N>> {
        match self {
            Self::Deployment(_, deployment) => Some(deployment),
            Self::Execution(..) => None,
        }
    }

    /// Returns the rejected execution.
    pub fn execution(&self) -> Option<&Execution<N>> {
        match self {
            Self::Deployment(..) => None,
            Self::Execution(execution) => Some(execution),
        }
    }

    /// Returns the rejected ID.
    pub fn to_id(&self) -> Result<Field<N>> {
        match self {
            Self::Deployment(_, deployment) => deployment.to_deployment_id(),
            Self::Execution(execution) => execution.to_execution_id(),
        }
    }

    /// Returns the unconfirmed transaction ID, which is defined as the transaction ID prior to confirmation.
    /// When a transaction is rejected, its fee transition is used to construct the confirmed transaction ID,
    /// changing the original transaction ID.
    pub fn to_unconfirmed_id(&self, fee: &Option<Fee<N>>) -> Result<Field<N>> {
        // Compute the deployment or execution tree.
        let tree = match self {
            Self::Deployment(_, deployment) => Transaction::deployment_tree(deployment)?,
            Self::Execution(execution) => Transaction::execution_tree(execution)?,
        };
        // Construct the transaction tree and return the unconfirmed transaction ID.
        Ok(*Transaction::transaction_tree(tree, fee.as_ref())?.root())
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use console::{account::PrivateKey, network::MainnetV0};

    type CurrentNetwork = MainnetV0;

    /// Samples a rejected deployment.
    pub(crate) fn sample_rejected_deployment(
        version: u8,
        edition: u16,
        has_translation_keys: bool,
        is_fee_private: bool,
        rng: &mut TestRng,
    ) -> Rejected<CurrentNetwork> {
        // Sample a deploy transaction.
        let deployment = match crate::transaction::test_helpers::sample_deployment_transaction(
            version,
            edition,
            has_translation_keys,
            is_fee_private,
            rng,
        ) {
            Transaction::Deploy(_, _, _, deployment, _) => (*deployment).clone(),
            _ => unreachable!(),
        };

        // Sample a new program owner.
        let private_key = PrivateKey::new(rng).unwrap();
        let deployment_id = deployment.to_deployment_id().unwrap();
        let program_owner = ProgramOwner::new(&private_key, deployment_id, rng).unwrap();

        // Return the rejected deployment.
        Rejected::new_deployment(program_owner, deployment)
    }

    /// Samples a rejected execution.
    pub(crate) fn sample_rejected_execution(is_fee_private: bool, rng: &mut TestRng) -> Rejected<CurrentNetwork> {
        // Sample an execute transaction.
        let execution =
            match crate::transaction::test_helpers::sample_execution_transaction_with_fee(is_fee_private, rng, 0) {
                Transaction::Execute(_, _, execution, _) => execution,
                _ => unreachable!(),
            };

        // Return the rejected execution.
        Rejected::new_execution(*execution)
    }

    /// Sample a list of randomly rejected transactions.
    pub(crate) fn sample_rejected_transactions() -> Vec<Rejected<CurrentNetwork>> {
        let rng = &mut TestRng::default();

        let mut txs = Vec::new();

        // Sample the deployments.
        for version in 1..=2 {
            for edition in 0..=1 {
                for has_translation_keys in [true, false] {
                    // version 1 didn't support translation keys
                    if version == 1 && has_translation_keys {
                        continue;
                    }
                    // version 2 expects edition 1
                    if version == 2 && edition == 0 {
                        continue;
                    }
                    for is_fee_private in [true, false] {
                        let tx =
                            sample_rejected_deployment(version, edition, has_translation_keys, is_fee_private, rng);
                        txs.push(tx);
                    }
                }
            }
        }

        // Sample the executions.
        for is_fee_private in [true, false] {
            let tx = sample_rejected_execution(is_fee_private, rng);
            txs.push(tx);
        }

        txs
    }
}
