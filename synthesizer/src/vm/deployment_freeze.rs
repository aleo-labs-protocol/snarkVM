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

//! The VM side of the deployment freeze. See `snarkvm_synthesizer_process::deployment_freeze`.

use super::*;

use snarkvm_synthesizer_process::{
    deployment_freeze::{
        FreezeWindow,
        deployment_freeze_program,
        is_deployment_freeze_activation_height,
        read_deployment_freeze,
    },
    frozen_deployment_minimum_cost,
};

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns the committed freeze window that applies to the block at `block_height`, or `None`
    /// if the freeze rule is not enforced at that height or no freeze has been set.
    ///
    /// The value is read from committed finalize state, so it ignores writes made earlier in the
    /// block being built or checked. Callers read it once per block and pass it on.
    pub fn deployment_freeze(&self, block_height: u32) -> Result<Option<FreezeWindow>> {
        read_deployment_freeze(self.finalize_store(), block_height)
    }

    /// Returns `true` if every deployment in the block at `block_height` is frozen (the consensus rule).
    pub fn deployments_frozen_at(&self, block_height: u32) -> Result<bool> {
        Ok(self.deployment_freeze(block_height)?.is_some_and(|freeze| freeze.is_frozen_at(block_height)))
    }

    /// Returns the freeze window if node policy should turn deployments away for the block at
    /// `next_height`, the block after a tip the caller has already read. This is not consensus: it
    /// applies from the block after a freeze passes, through `FREEZE_DELAY`, until `end`.
    pub fn deployment_freeze_policy_at(&self, next_height: u32) -> Result<Option<FreezeWindow>> {
        Ok(self.deployment_freeze(next_height)?.filter(|freeze| freeze.is_policy_active_at(next_height)))
    }

    /// In the first block of the deployment freeze version, initializes the mappings of the built-in
    /// freeze program, and returns the finalize operations, which go into the block's finalize root.
    /// In any other block, does nothing.
    ///
    /// The mappings are created here rather than when the VM starts, as `credits.aleo`'s are,
    /// because before the freeze version a node must behave as one without the program: a dynamic
    /// `get` or `contains` on a mapping that does not exist fails.
    pub(crate) fn initialize_deployment_freeze_mappings(
        store: &FinalizeStore<N, C::FinalizeStorage>,
        state: FinalizeGlobalState,
    ) -> Result<Vec<FinalizeOperation<N>>> {
        if !is_deployment_freeze_activation_height::<N>(state.block_height()) {
            return Ok(Vec::new());
        }
        let program = deployment_freeze_program::<N>()?;
        program.mappings().values().map(|mapping| store.initialize_mapping(*program.id(), *mapping.name())).collect()
    }

    /// Performs the cheap checks on a frozen deployment, none of which touch its program,
    /// circuits or verifying keys beyond their recorded sizes. On failure, the deployment is aborted.
    ///
    /// This runs from `should_abort_transaction`, so the block builder (in `prepare_for_speculate`
    /// and in `atomic_speculate`) and the block checker (in `atomic_speculate`) run the same checks.
    /// The fee proof is checked separately: in `prepare_for_speculate` when building, and in
    /// `check_transactions` (as the fee of a rejected deployment) when checking.
    pub(crate) fn check_frozen_deployment_cheap(
        &self,
        transaction: &Transaction<N>,
        consensus_version: ConsensusVersion,
    ) -> Result<()> {
        let Transaction::Deploy(id, deployment_id, owner, deployment, fee) = transaction else {
            bail!("Transaction '{}' is not a deployment", transaction.id());
        };

        // Deployment version: version 2 or later. A version 1 deployment ID does not cover the
        // verifying keys, so the fee would not be bound to them.
        ensure!(
            deployment.version()? != DeploymentVersion::V1,
            "Frozen deployment '{id}' must be deployment version 2 or later"
        );

        // The fee names this deployment. The fee proof itself is checked separately.
        ensure!(
            fee.deployment_or_execution_id()? == *deployment_id,
            "The fee of frozen deployment '{id}' is not bound to its deployment ID"
        );

        // Size: the transaction is within `MAX_TRANSACTION_SIZE`.
        let max_transaction_size = consensus_config_value_by_version!(N, MAX_TRANSACTION_SIZE, consensus_version)
            .ok_or(anyhow!("Failed to fetch maximum transaction size"))?;
        Self::ensure_transaction_size(transaction, max_transaction_size)?;

        // The owner signature and the program owner. The block checker reconstructs the deployment
        // with `Transaction::from_deployment`, which checks both, so the builder must check them too.
        ensure!(owner.verify(*deployment_id), "Invalid owner signature for frozen deployment '{id}'");
        if let Some(program_owner) = deployment.program_owner() {
            ensure!(program_owner == owner.address(), "Frozen deployment '{id}' has a mismatched program owner");
        }

        // The fee amount: at least the frozen minimum (storage, synthesis and namespace terms).
        let minimum_cost = frozen_deployment_minimum_cost(deployment)?;
        let base_fee = *fee.base_amount()?;
        ensure!(
            base_fee >= minimum_cost,
            "Frozen deployment '{id}' has an insufficient base fee - has {base_fee}, requires {minimum_cost} microcredits"
        );
        Ok(())
    }

    /// Verifies the fee of a frozen deployment, and the transaction's uniqueness in the ledger.
    /// Unlike `check_transaction`, this never builds the deployment's stack and never verifies the deployment.
    ///
    /// The uniqueness of the fee transition's elements against the ledger and the block is checked
    /// in `should_abort_transaction`.
    pub(crate) fn check_frozen_deployment_fee(&self, transaction: &Transaction<N>) -> Result<()> {
        let Transaction::Deploy(id, deployment_id, _, _, fee) = transaction else {
            bail!("Transaction '{}' is not a deployment", transaction.id());
        };
        // Ensure the transaction ID is unique.
        if self.block_store().contains_transaction_id(id)? {
            bail!("Transaction '{id}' already exists in the ledger")
        }
        // Verify the fee proof, bound to the deployment ID. This is the same check as for any fee.
        self.check_fee_internal(fee, *deployment_id, false)
    }
}
