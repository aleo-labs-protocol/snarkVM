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

use crate::{Input, Output, Transition};
use console::{
    network::prelude::*,
    program::{Argument, Literal, Plaintext},
    types::{Address, Field, U64},
};
use snarkvm_synthesizer_snark::Proof;

#[derive(Clone, PartialEq, Eq)]
pub struct Fee<N: Network> {
    /// The transition.
    transition: Transition<N>,
    /// The global state root.
    global_state_root: N::StateRoot,
    /// The proof.
    proof: Option<Proof<N>>,
}

impl<N: Network> Fee<N> {
    /// Initializes a new `Fee` instance with the given transition, global state root, and proof.
    pub fn from(transition: Transition<N>, global_state_root: N::StateRoot, proof: Option<Proof<N>>) -> Result<Self> {
        // Ensure the transition is correct for a fee function.
        match transition.is_fee_private() || transition.is_fee_public() {
            true => Ok(Self::from_unchecked(transition, global_state_root, proof)),
            false => bail!("Invalid fee transition locator"),
        }
    }

    /// Initializes a new `Fee` instance with the given transition, global state root, and proof.
    pub const fn from_unchecked(
        transition: Transition<N>,
        global_state_root: N::StateRoot,
        proof: Option<Proof<N>>,
    ) -> Self {
        Self { transition, global_state_root, proof }
    }
}

impl<N: Network> Fee<N> {
    /// Returns `true` if this is a `fee_private` transition.
    #[inline]
    pub fn is_fee_private(&self) -> bool {
        self.transition.is_fee_private()
    }

    /// Returns `true` if this is a `fee_public` transition.
    #[inline]
    pub fn is_fee_public(&self) -> bool {
        self.transition.is_fee_public()
    }
}

impl<N: Network> Fee<N> {
    /// Returns 'true' if the fee amount is zero.
    pub fn is_zero(&self) -> Result<bool> {
        self.amount().map(|amount| amount.is_zero())
    }

    /// Returns the payer, if the fee is public.
    pub fn payer(&self) -> Option<Address<N>> {
        // Retrieve the payer.
        match self.transition.outputs().last() {
            Some(Output::Future(_, Some(future))) => match future.arguments().first() {
                Some(Argument::Plaintext(Plaintext::Literal(Literal::Address(address), _))) => Some(*address),
                _ => None,
            },
            _ => None,
        }
    }

    /// Returns the amount (in microcredits).
    pub fn amount(&self) -> Result<U64<N>> {
        // Retrieve the base fee amount.
        let base_fee_amount = self.base_amount()?;
        // Retrieve the priority fee amount.
        let priority_fee_amount = self.priority_amount()?;
        // Return the amount.
        // Note: Use of saturating add is safe, as the sum cannot exceed a u64.
        Ok(U64::new(base_fee_amount.saturating_add(*priority_fee_amount)))
    }

    /// Returns the base amount (in microcredits).
    pub fn base_amount(&self) -> Result<U64<N>> {
        // Determine the indexes for the base fee.
        // Note: Checking whether the `output` is a `Record` or `Future` is a faster way to determine if the fee is private or public respectively.
        let base_fee_index: usize = match self.transition.outputs().last() {
            Some(output) => match output {
                Output::Record(..) => 1,
                Output::Future(..) => 0,
                _ => bail!("Unexpected output in fee transition"),
            },
            None => bail!("Missing output in fee transition"),
        };
        // Retrieve the base fee (in microcredits) as a plaintext value.
        match self.transition.inputs().get(base_fee_index) {
            Some(Input::Public(_, Some(Plaintext::Literal(Literal::U64(microcredits), _)))) => Ok(*microcredits),
            _ => bail!("Failed to retrieve the base fee (in microcredits) from the fee transition"),
        }
    }

    /// Returns the base amount (in microcredits).
    pub fn priority_amount(&self) -> Result<U64<N>> {
        // Determine the indexes for the priority fee.
        // Note: Checking whether the `output` is a `Record` or `Future` is a faster way to determine if the fee is private or public respectively.
        let priority_fee_index: usize = match self.transition.outputs().last() {
            Some(output) => match output {
                Output::Record(..) => 2,
                Output::Future(..) => 1,
                _ => bail!("Unexpected output in fee transition"),
            },
            None => bail!("Missing output in fee transition"),
        };
        // Retrieve the priority fee (in microcredits) as a plaintext value.
        match self.transition.inputs().get(priority_fee_index) {
            Some(Input::Public(_, Some(Plaintext::Literal(Literal::U64(microcredits), _)))) => Ok(*microcredits),
            _ => bail!("Failed to retrieve the priority fee (in microcredits) from the fee transition"),
        }
    }

    /// Returns the deployment or execution ID.
    pub fn deployment_or_execution_id(&self) -> Result<Field<N>> {
        // Determine the input index for the deployment or execution ID.
        // Note: Checking whether the `output` is a `Record` or `Future` is a faster way to determine if the fee is private or public respectively.
        let input_index = match self.transition.outputs().last() {
            Some(output) => match output {
                Output::Record(..) => 3,
                Output::Future(..) => 2,
                _ => bail!("Unexpected output in fee transition"),
            },
            None => bail!("Missing output in fee transition"),
        };
        // Retrieve the deployment or execution ID as a plaintext value.
        match self.transition.inputs().get(input_index) {
            Some(Input::Public(_, Some(Plaintext::Literal(Literal::Field(id), _)))) => Ok(*id),
            _ => bail!("Failed to retrieve the deployment or execution ID from the fee transition"),
        }
    }

    /// Returns the number of finalize operations.
    pub fn num_finalize_operations(&self) -> usize {
        // These values are empirically determined for performance.
        match self.is_fee_public() {
            true => 1,
            false => 0,
        }
    }

    /// Returns the transition ID.
    pub fn transition_id(&self) -> &N::TransitionID {
        self.transition.id()
    }

    /// Returns the transition.
    pub const fn transition(&self) -> &Transition<N> {
        &self.transition
    }

    /// Returns the transition, consuming self in the process.
    pub fn into_transition(self) -> Transition<N> {
        self.transition
    }

    /// Returns the global state root.
    pub const fn global_state_root(&self) -> N::StateRoot {
        self.global_state_root
    }

    /// Returns the proof.
    pub const fn proof(&self) -> Option<&Proof<N>> {
        self.proof.as_ref()
    }
}

impl<N: Network> Deref for Fee<N> {
    type Target = Transition<N>;

    fn deref(&self) -> &Self::Target {
        &self.transition
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use console::types::Field;
    use snarkvm_algorithms::snark::varuna::VarunaVersion;
    use snarkvm_ledger_query::Query;
    use snarkvm_ledger_store::{BlockStore, StorageMode, helpers::memory::BlockMemory};
    use snarkvm_synthesizer_process::Process;

    use std::sync::OnceLock;

    type CurrentNetwork = console::network::MainnetV0;
    type CurrentAleo = snarkvm_circuit::network::AleoV0;

    /// Samples a random hardcoded private fee.
    pub fn sample_fee_private_hardcoded(rng: &mut TestRng) -> Fee<CurrentNetwork> {
        static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Sample a deployment or execution ID.
                let deployment_or_execution_id = Field::rand(rng);
                // Sample a fee.
                sample_fee_private(deployment_or_execution_id, rng)
            })
            .clone()
    }

    /// Samples a random private fee.
    pub fn sample_fee_private(
        deployment_or_execution_id: Field<CurrentNetwork>,
        rng: &mut TestRng,
    ) -> Fee<CurrentNetwork> {
        // Sample the genesis block, transaction, and private key.
        let (block, transaction, private_key) = crate::test_helpers::sample_genesis_block_and_components(rng);
        // Retrieve a credits record.
        let credits = transaction.records().next().unwrap().1.clone();
        // Decrypt the record.
        let credits = credits.decrypt(&private_key.try_into().unwrap()).unwrap();
        // Sample a base fee in microcredits.
        let base_fee_in_microcredits = 10_000_000;
        // Sample a priority fee in microcredits.
        let priority_fee_in_microcredits = 1_000;

        // Initialize the process.
        let process = Process::load().unwrap();
        // Authorize the fee.
        let authorization = process
            .authorize_fee_private::<CurrentAleo, _>(
                &private_key,
                credits,
                base_fee_in_microcredits,
                priority_fee_in_microcredits,
                deployment_or_execution_id,
                rng,
            )
            .unwrap();

        // Construct the fee trace.
        let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block into the block store.
        // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
        block_store.insert(&FromStr::from_str(&block.to_string()).unwrap()).unwrap();

        // Prepare the assignments.
        trace.prepare(&Query::from(block_store)).unwrap();
        // Compute the proof and construct the fee.
        let fee = trace.prove_fee::<CurrentAleo, _>(VarunaVersion::V1, rng).unwrap();

        // Convert the fee.
        // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
        Fee::from_str(&fee.to_string()).unwrap()
    }

    /// Samples a random hardcoded public fee.
    pub fn sample_fee_public_hardcoded(rng: &mut TestRng) -> Fee<CurrentNetwork> {
        static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Sample a deployment or execution ID.
                let deployment_or_execution_id = Field::rand(rng);
                // Sample a fee.
                sample_fee_public(deployment_or_execution_id, rng)
            })
            .clone()
    }

    /// Samples a random public fee.
    pub fn sample_fee_public(
        deployment_or_execution_id: Field<CurrentNetwork>,
        rng: &mut TestRng,
    ) -> Fee<CurrentNetwork> {
        // Sample the genesis block and private key.
        let (block, _, private_key) = crate::test_helpers::sample_genesis_block_and_components(rng);
        // Set the base fee amount.
        let base_fee = 10_000_000;
        // Set the priority fee amount.
        let priority_fee = 1_000;

        // Initialize the process.
        let process = Process::load().unwrap();
        // Authorize the fee.
        let authorization = process
            .authorize_fee_public::<CurrentAleo, _>(
                &private_key,
                base_fee,
                priority_fee,
                deployment_or_execution_id,
                rng,
            )
            .unwrap();
        // Construct the fee trace.
        let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Insert the block into the block store.
        // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
        block_store.insert(&FromStr::from_str(&block.to_string()).unwrap()).unwrap();

        // Prepare the assignments.
        trace.prepare(&Query::from(block_store)).unwrap();
        // Compute the proof and construct the fee.
        let fee = trace.prove_fee::<CurrentAleo, _>(VarunaVersion::V1, rng).unwrap();

        // Convert the fee.
        // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
        Fee::from_str(&fee.to_string()).unwrap()
    }
}
