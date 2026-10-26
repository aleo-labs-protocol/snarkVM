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

mod helpers;
pub use helpers::*;

mod authorize;
mod deploy;
mod execute;
mod finalize;
mod verify;

#[cfg(test)]
mod tests;

use crate::{Command, Restrictions, Stack, cast_mut_ref, cast_ref, convert, process};
use console::{
    account::{Address, PrivateKey},
    network::prelude::*,
    program::{
        Argument,
        FINALIZE_ID_DEPTH,
        Identifier,
        Literal,
        Locator,
        Plaintext,
        ProgramID,
        ProgramOwner,
        Record,
        Response,
        Value,
    },
    types::{Field, Group, U8, U64},
};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_block::{
    Block,
    ConfirmedTransaction,
    Deployment,
    DeploymentVersion,
    Execution,
    Fee,
    Header,
    Output,
    Ratifications,
    Ratify,
    Rejected,
    RejectedReason,
    Solutions,
    Transaction,
    Transactions,
};
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal_data::Data;
use snarkvm_ledger_puzzle::Puzzle;
use snarkvm_ledger_query::{Query, QueryTrait};
use snarkvm_ledger_store::{
    BlockStore,
    ConsensusStorage,
    ConsensusStore,
    FinalizeMode,
    FinalizeStore,
    TransactionStore,
    TransitionStore,
    atomic_finalize,
};
use snarkvm_synthesizer_process::{
    Authorization,
    InclusionVersion,
    Process,
    Trace,
    deploy_compute_cost_in_microcredits,
    deployment_cost,
    execute_compute_cost_in_microcredits,
    execution_cost,
    transaction_compute_spend_in_microcredits,
};
use snarkvm_synthesizer_program::{
    FinalizeCore,
    FinalizeGlobalState,
    FinalizeOperation,
    FinalizeStoreTrait,
    Program,
    StackTrait as _,
};
use snarkvm_utilities::try_vm_runtime;

use aleo_std::prelude::{finish, lap, timer};
use anyhow::Context;
use indexmap::{IndexMap, IndexSet};
use itertools::Either;
#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
use lru::LruCache;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use rand::{SeedableRng, rngs::StdRng};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::{Arc, OnceLock, mpsc},
    thread,
};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

// The key for the partially-verified transactions cache.
// The key is a tuple of the transaction ID and a list of `(program checksum, edition, amendment count, consensus version)` for each transition.
// This is because program upgrades, amendments and consensus version changes can change verification behavior.
pub type TransactionCacheKey<N> = (<N as Network>::TransactionID, Vec<([U8<N>; 32], u16, u64, ConsensusVersion)>);

#[derive(Clone)]
pub struct VM<N: Network, C: ConsensusStorage<N>> {
    /// The process.
    process: Arc<Process<N>>,
    /// The puzzle.
    puzzle: Puzzle<N>,
    /// The VM store.
    store: ConsensusStore<N, C>,
    /// A cache containing the list of recent partially-verified transactions.
    partially_verified_transactions: Arc<RwLock<LruCache<TransactionCacheKey<N>, N::TransmissionChecksum>>>,
    /// The restrictions list.
    restrictions: Restrictions<N>,
    /// The list of rejection reasons for pending confirmed transactions.
    /// TODO: it would be cleaner if these are passed along as an argument to `add_next_block`, but this requires a bigger refactor.
    pending_rejected_reasons: Arc<RwLock<HashMap<N::TransactionID, RejectedReason<N>>>>,
    /// A sender to the channel for operations that must be performed sequentially.
    sequential_ops_tx: Option<Arc<SequentialOperationQueue<N>>>,
    /// The identity of the thread which processes operations sequentially.
    sequential_ops_thread_id: Arc<OnceLock<thread::ThreadId>>,
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Initializes the VM from storage.
    #[inline]
    pub fn from(store: ConsensusStore<N, C>) -> Result<Self> {
        // Initialize the store for 'credits.aleo'.
        let credits = Program::<N>::credits()?;
        for mapping in credits.mappings().values() {
            // Ensure that all mappings are initialized.
            if !store.finalize_store().contains_mapping_confirmed(credits.id(), mapping.name())? {
                // Initialize the mappings for 'credits.aleo'.
                store.finalize_store().initialize_mapping(*credits.id(), *mapping.name())?;
            }
        }

        // Retrieve the transaction store.
        let transaction_store = store.transaction_store();
        // Retrieve the block store.
        let block_store = store.block_store();

        #[cfg(not(any(test, feature = "test")))]
        let process = {
            // Determine the latest block height.
            let latest_block_height = block_store.current_block_height();
            // Determine the consensus version.
            let consensus_version = N::CONSENSUS_VERSION(latest_block_height)?; // TODO (raychu86): Record Commitment - Select the proper consensus version.
            // Initialize a new process based on the consensus version.
            if (ConsensusVersion::V1..=ConsensusVersion::V7).contains(&consensus_version) {
                Process::load_v0()?
            } else {
                Process::load()?
            }
        };
        #[cfg(any(test, feature = "test"))]
        // Initialize a new process.
        let process = Process::load()?;

        // Retrieve the list of deployment transaction IDs and their associated block heights.
        let deployment_ids = transaction_store.deployment_transaction_ids().collect::<Vec<_>>();
        let mut deployment_ids = cfg_into_iter!(deployment_ids)
            .map(|transaction_id| {
                // Retrieve the block hash for the deployment transaction ID.
                let Some(hash) = block_store.find_block_hash(&transaction_id)? else {
                    bail!("Deployment transaction '{transaction_id}' is not found in storage.")
                };
                // Retrieve the height.
                let Some(height) = block_store.get_block_height(&hash)? else {
                    bail!("Block height for deployment transaction '{transaction_id}' is not found in storage.")
                };
                // Get the corresponding block's transactions.
                let Some(transactions) = block_store.get_block_transactions(&hash)? else {
                    bail!("Transactions for deployment transaction '{hash}' is not found in storage.")
                };
                // Find the index of the deployment transaction ID in the block's transactions.
                let Some(index) = transactions.index_of(transaction_id.deref()) else {
                    bail!("Transaction for deployment transaction '{transaction_id}' is not found in storage.")
                };
                Ok((transaction_id, (height, index)))
            })
            .collect::<Result<Vec<_>>>()?;
        // Sort the deployment transaction IDs by their block heights.
        deployment_ids.sort_unstable_by_key(|(_, h)| *h);

        // Load the deployments in order of their block heights.
        const PARALLELIZATION_FACTOR: usize = 256;
        for (i, chunk) in deployment_ids.chunks(PARALLELIZATION_FACTOR).enumerate() {
            debug!(
                "Loading deployments {}-{} (of {})...",
                i * PARALLELIZATION_FACTOR,
                ((i + 1) * PARALLELIZATION_FACTOR).min(deployment_ids.len()),
                deployment_ids.len()
            );
            // Load the deployments.
            let deployments = cfg_iter!(chunk)
                .map(|(transaction_id, _)| {
                    // Retrieve the deployment from the transaction ID.
                    match transaction_store.get_deployment(transaction_id)? {
                        Some(deployment) => Ok(deployment),
                        None => bail!("Deployment transaction '{transaction_id}' is not found in storage."),
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            // Add the deployments to the process.
            // Note: This iterator must be serial, to ensure deployments are loaded in the order of their dependencies.
            deployments.iter().try_for_each(|deployment| process.load_deployment(deployment))?;
        }

        // Construct the VM object.
        let mut vm = Self {
            process: Arc::new(process),
            puzzle: Self::new_puzzle()?,
            store,
            partially_verified_transactions: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(Transactions::<N>::MAX_TRANSACTIONS).unwrap(),
            ))),
            restrictions: Restrictions::load()?,
            sequential_ops_tx: Default::default(),
            pending_rejected_reasons: Default::default(),
            sequential_ops_thread_id: Default::default(),
        };

        // Spawn a thread for sequential operations.
        let (sequential_ops_tx, sequential_ops_rx) = mpsc::channel();
        let sequential_ops_thread = vm.start_sequential_queue(sequential_ops_rx);

        // Populate the fields related to the sequential operations.
        let _ = vm.sequential_ops_thread_id.set(sequential_ops_thread.thread().id());
        vm.sequential_ops_tx = Some(Arc::new(SequentialOperationQueue {
            sender: Some(sequential_ops_tx),
            thread: Some(sequential_ops_thread),
        }));

        // Return the new VM.
        Ok(vm)
    }

    /// Returns `true` if a program with the given program ID exists.
    #[inline]
    pub fn contains_program(&self, program_id: &ProgramID<N>) -> bool {
        self.process.contains_program(program_id)
    }

    /// Returns the process.
    #[inline]
    pub fn process(&self) -> &Arc<Process<N>> {
        &self.process
    }

    /// Returns the puzzle.
    #[inline]
    pub const fn puzzle(&self) -> &Puzzle<N> {
        &self.puzzle
    }

    /// Returns the partially-verified transactions.
    #[inline]
    pub fn partially_verified_transactions(
        &self,
    ) -> Arc<RwLock<LruCache<TransactionCacheKey<N>, N::TransmissionChecksum>>> {
        self.partially_verified_transactions.clone()
    }

    /// Returns the restrictions.
    #[inline]
    pub const fn restrictions(&self) -> &Restrictions<N> {
        &self.restrictions
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns the finalize store.
    #[inline]
    pub fn finalize_store(&self) -> &FinalizeStore<N, C::FinalizeStorage> {
        self.store.finalize_store()
    }

    /// Returns the block store.
    #[inline]
    pub fn block_store(&self) -> &BlockStore<N, C::BlockStorage> {
        self.store.block_store()
    }

    /// Returns the transaction store.
    #[inline]
    pub fn transaction_store(&self) -> &TransactionStore<N, C::TransactionStorage> {
        self.store.transaction_store()
    }

    /// Returns the transition store.
    #[inline]
    pub fn transition_store(&self) -> &TransitionStore<N, C::TransitionStorage> {
        self.store.transition_store()
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns a new instance of the puzzle.
    pub fn new_puzzle() -> Result<Puzzle<N>> {
        // Initialize a new instance of the puzzle.
        macro_rules! logic {
            ($network:path, $aleo:path) => {{
                let puzzle = Puzzle::new::<snarkvm_ledger_puzzle_epoch::SynthesisPuzzle<$network, $aleo>>();
                Ok(cast_ref!(puzzle as Puzzle<N>).clone())
            }};
        }
        // Initialize the puzzle.
        convert!(logic)
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns a new genesis block for a beacon chain with the default size (four validators).
    pub fn genesis_beacon<R: Rng + CryptoRng>(&self, private_key: &PrivateKey<N>, rng: &mut R) -> Result<Block<N>> {
        self.genesis_beacon_with_size(private_key, 4, rng)
    }

    /// Returns a new genesis block for a beacon chain.
    pub fn genesis_beacon_with_size<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        num_validators: usize,
        rng: &mut R,
    ) -> Result<Block<N>> {
        ensure!(num_validators >= 4, "Need at least four validators");

        let mut private_keys = vec![*private_key];
        for _ in 1..num_validators {
            private_keys.push(PrivateKey::new(rng)?);
        }

        // Construct the committee members.
        let mut members = IndexMap::with_capacity(num_validators);
        for key in &private_keys {
            let addr = Address::try_from(key)?;
            members.insert(addr, (snarkvm_ledger_committee::MIN_VALIDATOR_STAKE, true, 0u8));
        }

        // Construct the committee.
        let committee = Committee::<N>::new_genesis(members)?;

        // Compute the remaining supply.
        let remaining_supply = N::STARTING_SUPPLY
            .checked_sub(snarkvm_ledger_committee::MIN_VALIDATOR_STAKE * (num_validators as u64))
            .with_context(|| "Not enough starting supply for this many validators")?;

        // Construct the public balances.
        let mut public_balances = IndexMap::with_capacity(4);
        for key in &private_keys {
            let addr = Address::try_from(key)?;
            public_balances.insert(addr, remaining_supply / num_validators as u64);
        }

        // Construct the bonded balances.
        let bonded_balances = committee
            .members()
            .iter()
            .map(|(address, (amount, _, _))| (*address, (*address, *address, *amount)))
            .collect();

        // Return the genesis block.
        self.genesis_quorum(private_key, committee, public_balances, bonded_balances, rng)
    }

    /// Returns a new genesis block for a quorum chain.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn genesis_quorum<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        committee: Committee<N>,
        public_balances: IndexMap<Address<N>, u64>,
        bonded_balances: IndexMap<Address<N>, (Address<N>, Address<N>, u64)>,
        rng: &mut R,
    ) -> Result<Block<N>> {
        // Retrieve the total bonded balance.
        let total_bonded_amount = bonded_balances
            .values()
            .try_fold(0u64, |acc, (_, _, x)| acc.checked_add(*x).ok_or(anyhow!("Invalid bonded amount")))?;
        // Compute the account supply.
        let account_supply = public_balances
            .values()
            .try_fold(0u64, |acc, x| acc.checked_add(*x).ok_or(anyhow!("Invalid account supply")))?;
        // Compute the total supply.
        let total_supply =
            total_bonded_amount.checked_add(account_supply).ok_or_else(|| anyhow!("Invalid total supply"))?;
        // Ensure the total supply matches.
        ensure!(
            total_supply == N::STARTING_SUPPLY,
            "Invalid total supply. Found {total_supply}, expected {}",
            N::STARTING_SUPPLY
        );

        // Prepare the caller.
        let caller = Address::try_from(private_key)?;
        // Prepare the locator.
        let locator = ("credits.aleo", "transfer_public_to_private");
        // Prepare the amount for each call to the function.
        let amount = public_balances
            .get(&caller)
            .ok_or_else(|| anyhow!("Missing public balance for {caller}"))?
            .saturating_div(Block::<N>::NUM_GENESIS_TRANSACTIONS.saturating_mul(2) as u64);
        // Prepare the function inputs.
        let inputs = [caller.to_string(), format!("{amount}_u64")];

        // Prepare the ratifications.
        let ratifications =
            vec![Ratify::Genesis(Box::new(committee), Box::new(public_balances), Box::new(bonded_balances))];
        // Prepare the solutions.
        let solutions = Solutions::<N>::from(None); // The genesis block does not require solutions.
        // Prepare the aborted solution IDs.
        let aborted_solution_ids = vec![];
        // Prepare the transactions.
        let transactions = (0..Block::<N>::NUM_GENESIS_TRANSACTIONS)
            .map(|_| self.execute(private_key, locator, inputs.iter(), None, 0, None, rng))
            .collect::<Result<Vec<_>, _>>()?;

        // Construct the finalize state.
        let state = FinalizeGlobalState::new_genesis::<N>()?;
        // Speculate on the ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) =
            self.speculate(state, 0, None, ratifications, &solutions, transactions.iter(), rng)?;
        ensure!(
            aborted_transaction_ids.is_empty(),
            "Failed to initialize a genesis block - found aborted transaction IDs"
        );

        // Prepare the block header.
        let header = Header::genesis(&ratifications, &transactions, ratified_finalize_operations)?;
        // Prepare the previous block hash.
        let previous_hash = N::BlockHash::default();

        // Construct the block.
        let block = Block::new_beacon(
            private_key,
            previous_hash,
            header,
            ratifications,
            solutions,
            aborted_solution_ids,
            transactions,
            aborted_transaction_ids,
            rng,
        )?;
        // Ensure the block is valid genesis block.
        match block.is_genesis()? {
            true => Ok(block),
            false => bail!("Failed to initialize a genesis block"),
        }
    }

    /// Adds the given block into the VM.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    #[inline]
    pub fn add_next_block(&self, block: &Block<N>) -> Result<()> {
        let sequential_op = SequentialOperation::AddNextBlock(block.clone());
        let Some(SequentialOperationResult::AddNextBlock(ret)) = self.run_sequential_operation(sequential_op) else {
            bail!("Already shutting down");
        };

        ret
    }

    /// Adds the given block into the VM.
    ///
    /// # Note
    /// This must only be called from the sequential operation thread.
    ///
    /// # Panics
    /// This function panics if not called from the sequential operation thread.
    #[inline]
    pub(crate) fn add_next_block_inner(&self, block: Block<N>) -> Result<()> {
        self.ensure_sequential_processing();

        // Determine if the block timestamp should be included.
        let block_timestamp = (block.height() >= N::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
            .then_some(block.timestamp());
        // Determine the block spend and synthesis limits.
        let (block_spend_limit, block_synthesis_limit) = if let Authority::Quorum(subdag) = block.authority() {
            (subdag.spend_limit(block.height()), subdag.synthesis_limit(block.height()))
        } else {
            Authority::<N>::beacon_limits(block.height())
        };
        // Construct the finalize state.
        let state = FinalizeGlobalState::new::<N>(
            block.round(),
            block.height(),
            block_timestamp,
            block.cumulative_weight(),
            block.cumulative_proof_target(),
            block.previous_hash(),
            block_spend_limit,
            block_synthesis_limit,
        )?;

        // Pause the atomic writes, so that both the insertion and finalization belong to a single batch.
        #[cfg(feature = "rocks")]
        self.block_store().pause_atomic_writes()?;

        // First, insert the block.
        if let Err(insert_error) = self.block_store().insert(&block) {
            if cfg!(feature = "rocks") {
                // Clear all pending atomic operations so that unpausing the atomic writes
                // doesn't execute any of the queued storage operations.
                self.block_store().abort_atomic();
                // Disable the atomic batch override.
                // Note: This call is guaranteed to succeed (without error), because `DISCARD_BATCH == true`.
                self.block_store().unpause_atomic_writes::<true>()?;
            }

            return Err(insert_error);
        };

        // Next, finalize the transactions.
        match self.finalize(state, block.ratifications(), block.solutions(), block.transactions()) {
            Ok(_ratified_finalize_operations) => {
                // If the block advances to `ConsensusVersion::V8`, updated the VKs used for the credits program.
                if N::CONSENSUS_HEIGHT(ConsensusVersion::V8).unwrap_or_default() == block.height() {
                    self.process.lock().update_credits_verifying_keys()?;
                }
                // Unpause the atomic writes, executing the ones queued from block insertion and finalization.
                #[cfg(feature = "rocks")]
                self.block_store().unpause_atomic_writes::<false>()?;
                // If the block advances to a new consensus version, clear the partial verification cache.
                if N::CONSENSUS_VERSION_HEIGHTS().iter().rev().any(|(_, height)| {
                    if block.height() < *height {
                        // If the block height is less than the consensus version height, break early.
                        return false;
                    }
                    height == &block.height()
                }) {
                    self.partially_verified_transactions().write().clear();
                }
                Ok(())
            }
            Err(finalize_error) => {
                if cfg!(feature = "rocks") {
                    // Clear all pending atomic operations so that unpausing the atomic writes
                    // doesn't execute any of the queued storage operations.
                    self.block_store().abort_atomic();
                    self.finalize_store().abort_atomic();
                    // Disable the atomic batch override.
                    // Note: This call is guaranteed to succeed (without error), because `DISCARD_BATCH == true`.
                    self.block_store().unpause_atomic_writes::<true>()?;
                    // Rollback the Merkle tree.
                    self.block_store().remove_last_n_from_tree_only(1).inspect_err(|_| {
                        // Log the finalize error.
                        error!("Failed to finalize block {} - {finalize_error}", block.height());
                    })?;
                } else {
                    // Rollback the block.
                    self.block_store().remove_last_n(1).inspect_err(|_| {
                        // Log the finalize error.
                        error!("Failed to finalize block {} - {finalize_error}", block.height());
                    })?;
                }
                // Return the finalize error.
                Err(finalize_error)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use circuit::AleoV0;
    use console::{
        account::{Address, ComputeKey, GraphKey, ViewKey},
        network::MainnetV0,
        program::{DynamicRecord, Entry, InputID, Request, Signature, Value, ValueType, compute_function_id},
        types::{Field, Scalar, U16},
    };
    use snarkvm_ledger_block::{Block, Header, Input, Metadata, Transition};
    use snarkvm_ledger_test_helpers::{large_transaction_program, small_transaction_program};
    use snarkvm_synthesizer_process::{execution_cost_for_authorization, execution_cost_for_call};
    use snarkvm_synthesizer_program::Program;

    use aleo_std::StorageMode;
    use indexmap::IndexMap;
    use serde_json::json;
    use snarkvm_synthesizer_snark::{Proof, VerifyingKey};
    use std::sync::OnceLock;

    pub(crate) type CurrentNetwork = MainnetV0;
    pub(crate) type CurrentAleo = AleoV0;

    #[cfg(not(feature = "rocks"))]
    pub(crate) type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
    #[cfg(feature = "rocks")]
    pub(crate) type LedgerType = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

    /// Samples a new finalize state.
    pub(crate) fn sample_finalize_state(block_height: u32) -> FinalizeGlobalState {
        FinalizeGlobalState::from(block_height as u64, block_height, None, [0u8; 32], None, None)
    }

    pub(crate) fn sample_vm() -> VM<CurrentNetwork, LedgerType> {
        // Initialize a new VM.
        VM::from(ConsensusStore::open(StorageMode::new_test(None)).unwrap()).unwrap()
    }

    #[cfg(feature = "test")]
    pub(crate) fn sample_vm_at_height(height: u32, rng: &mut TestRng) -> VM<CurrentNetwork, LedgerType> {
        // Initialize the VM with a genesis block.
        let mut vm = sample_vm_with_genesis_block(rng);
        // Get the genesis private key.
        let genesis_private_key = sample_genesis_private_key(rng);
        // Advance the VM to the given height.
        advance_vm_to_height(&mut vm, genesis_private_key, height, rng);
        // Return the VM.
        vm
    }

    #[cfg(feature = "test")]
    pub(crate) fn advance_vm_to_height(
        vm: &mut VM<CurrentNetwork, LedgerType>,
        genesis_private_key: PrivateKey<CurrentNetwork>,
        height: u32,
        rng: &mut TestRng,
    ) {
        // Advance the VM to the given height.
        for _ in vm.block_store().current_block_height()..height {
            let block = sample_next_block(vm, &genesis_private_key, &[], rng).unwrap();
            vm.add_next_block(&block).unwrap();
        }
    }

    pub(crate) fn sample_genesis_private_key(rng: &mut TestRng) -> PrivateKey<CurrentNetwork> {
        static INSTANCE: OnceLock<PrivateKey<CurrentNetwork>> = OnceLock::new();
        *INSTANCE.get_or_init(|| {
            // Initialize a new caller.
            PrivateKey::<CurrentNetwork>::new(rng).unwrap()
        })
    }

    pub(crate) fn sample_genesis_block(rng: &mut TestRng) -> Block<CurrentNetwork> {
        static INSTANCE: OnceLock<Block<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize the VM.
                let vm = crate::vm::test_helpers::sample_vm();
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                // Return the block.
                vm.genesis_beacon(&caller_private_key, rng).unwrap()
            })
            .clone()
    }

    pub(crate) fn sample_vm_with_genesis_block(rng: &mut TestRng) -> VM<CurrentNetwork, LedgerType> {
        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();
        // Return the VM.
        vm
    }

    pub(crate) fn sample_program() -> Program<CurrentNetwork> {
        static INSTANCE: OnceLock<Program<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new program.
                Program::<CurrentNetwork>::from_str(
                    r"
program testing.aleo;

struct message:
    amount as u128;

mapping account:
    key as address.public;
    value as u64.public;

record token:
    owner as address.private;
    amount as u64.private;

function initialize:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function compute:
    input r0 as message.private;
    input r1 as message.public;
    input r2 as message.private;
    input r3 as token.record;
    add r0.amount r1.amount into r4;
    cast r3.owner r3.amount into r5 as token.record;
    output r4 as u128.public;
    output r5 as token.record;",
                )
                .unwrap()
            })
            .clone()
    }

    pub(crate) fn sample_deployment_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceLock<Transaction<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize the program.
                let program = sample_program();

                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Prepare the fee.
                let credits = Some(records.values().next().unwrap().decrypt(&caller_view_key).unwrap());

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Deploy.
                let transaction = vm.deploy(&caller_private_key, &program, credits, 10, None, rng).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_without_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceLock<Transaction<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Select a record to spend.
                let record = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs =
                    [Value::<CurrentNetwork>::Record(record), Value::<CurrentNetwork>::from_str("1u64").unwrap()]
                        .into_iter();

                // Authorize.
                let authorization = vm.authorize(&caller_private_key, "credits.aleo", "split", inputs, rng).unwrap();
                assert_eq!(authorization.len(), 1);

                // Construct the execute transaction.
                let transaction = vm.execute_authorization(authorization, None, None, rng).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_with_private_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceLock<Transaction<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
                let address = Address::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Select a record to spend.
                let record = Some(records.values().next().unwrap().decrypt(&caller_view_key).unwrap());

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs = [
                    Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str("1u64").unwrap(),
                ]
                .into_iter();

                // Execute.
                let transaction = vm
                    .execute(&caller_private_key, ("credits.aleo", "transfer_public"), inputs, record, 0, None, rng)
                    .unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_with_public_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceLock<Transaction<CurrentNetwork>> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let address = Address::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs = [
                    Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str("1u64").unwrap(),
                ]
                .into_iter();

                // Execute.
                let transaction_without_fee = vm
                    .execute(&caller_private_key, ("credits.aleo", "transfer_public"), inputs, None, 0, None, rng)
                    .unwrap();
                let execution = transaction_without_fee.execution().unwrap().clone();

                // Authorize the fee.
                let authorization = vm
                    .authorize_fee_public(
                        &caller_private_key,
                        10_000_000,
                        100,
                        execution.to_execution_id().unwrap(),
                        rng,
                    )
                    .unwrap();
                // Compute the fee.
                let fee = vm.execute_fee_authorization(authorization, None, rng).unwrap();

                // Construct the transaction.
                let transaction = Transaction::from_execution(execution, Some(fee)).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub fn sample_next_block<R: Rng + CryptoRng>(
        vm: &VM<MainnetV0, LedgerType>,
        private_key: &PrivateKey<MainnetV0>,
        transactions: &[Transaction<MainnetV0>],
        rng: &mut R,
    ) -> Result<Block<MainnetV0>> {
        // Get the most recent block.
        let block_hash = vm.block_store().get_block_hash(vm.block_store().max_height().unwrap()).unwrap().unwrap();
        let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();

        // Create the finalize state for the next block height.
        let next_block_height = previous_block.height() + 1;
        let time_since_last_block = MainnetV0::BLOCK_TIME as i64;
        let next_block_timestamp = previous_block.timestamp().saturating_add(time_since_last_block);
        let next_timestamp = (next_block_height
            >= MainnetV0::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
        .then_some(next_block_timestamp);
        let finalize_state = FinalizeGlobalState::from(
            next_block_height as u64,
            next_block_height,
            next_timestamp,
            [0u8; 32],
            None,
            None,
        );

        // Speculate on the ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) = vm.speculate(
            finalize_state,
            time_since_last_block,
            Some(0u64),
            vec![],
            &None.into(),
            transactions.iter(),
            rng,
        )?;

        // Construct the metadata associated with the block.
        let metadata = Metadata::new(
            MainnetV0::ID,
            previous_block.round() + 1,
            previous_block.height() + 1,
            0,
            0,
            MainnetV0::GENESIS_COINBASE_TARGET,
            MainnetV0::GENESIS_PROOF_TARGET,
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            previous_block.timestamp().saturating_add(time_since_last_block),
        )?;

        // Construct the new block header.
        let header = Header::from(
            vm.block_store().current_state_root(),
            transactions.to_transactions_root().unwrap(),
            transactions.to_finalize_root(ratified_finalize_operations).unwrap(),
            ratifications.to_ratifications_root().unwrap(),
            Field::zero(),
            Field::zero(),
            metadata,
        )?;

        // Construct the new block.
        Block::new_beacon(
            private_key,
            previous_block.hash(),
            header,
            ratifications,
            None.into(),
            vec![],
            transactions,
            aborted_transaction_ids,
            rng,
        )
    }

    // Populates and signs a mocked request (e.g. one produced by Request::sample), reusing its
    // identifying data while recomputing tvk, tcm, scm, the input IDs, and the signature so that the
    // resulting request is well-formed and verifies. The corrected input values are supplied
    // explicitly via `inputs`; they must be correct for the resulting request to be valid. Note that
    // the request's program, function name and signer must also be correct.
    //
    // Unlike Request::sign, the transition view key tvk is provided externally rather than being
    // derived from the transition randomness r.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn populate_request_and_sign<N: Network, R: Rng + CryptoRng>(
        request: &Request<N>,
        private_key: &PrivateKey<N>,
        input_types: &[ValueType<N>],
        inputs: &[Value<N>],
        tvk: Field<N>,
        root_tvk: Option<Field<N>>,
        is_root: bool,
        program_checksum: Option<Field<N>>,
        rng: &mut R,
    ) -> Result<Request<N>> {
        // Reuse the mocked request's identifying data.
        let program_id = *request.program_id();
        let function_name = *request.function_name();
        let is_dynamic = request.is_dynamic();

        // Ensure the number of inputs matches the number of input types.
        if input_types.len() != inputs.len() {
            bail!(
                "'{program_id}/{function_name}' expects {} inputs, but {} were provided.",
                input_types.len(),
                inputs.len()
            )
        }

        let sk_sig = private_key.sk_sig();
        let compute_key = ComputeKey::try_from(private_key)?;
        let pk_sig = compute_key.pk_sig();
        let pr_sig = compute_key.pr_sig();
        let view_key = ViewKey::try_from((private_key, &compute_key))?;
        let sk_tag = GraphKey::try_from(view_key)?.sk_tag();

        let signer = Address::try_from(compute_key)?;
        ensure!(signer == *request.signer(), "The private key does not correspond to the mocked request's signer");

        // Sample a random nonce.
        let nonce = Field::<N>::rand(rng);
        // Compute `r` as `HashToScalar(sk_sig || nonce)`.
        // Unlike in the usual Request::sign method, this r is unrelated to the tvk.
        let r = N::hash_to_scalar_psd4(&[N::serial_number_domain(), sk_sig.to_field()?, nonce])?;
        // Compute `g_r` as `r * G`. Note: this is the transition public key `tpk`.
        let g_r = N::g_scalar_multiply(&r);

        // Compute the transition commitment `tcm` as `Hash(tvk)`.
        let tcm = N::hash_psd2(&[tvk])?;
        // Compute the signer commitment `scm` as `Hash(signer || root_tvk)`.
        let root_tvk = root_tvk.unwrap_or(tvk);
        let scm = N::hash_psd2(&[(*signer).to_x_coordinate(), root_tvk])?;
        // Compute 'is_root' as a field element.
        let is_root = if is_root { Field::<N>::one() } else { Field::<N>::zero() };

        // Retrieve the network ID.
        let network_id = U16::new(N::ID);
        // Compute the function ID.
        let function_id = compute_function_id(&network_id, &program_id, &function_name)?;

        // Construct the hash input as `(r * G, pk_sig, pr_sig, signer, [tvk, tcm, function ID, is_root, program checksum?, input IDs])`.
        let mut message = Vec::with_capacity(9 + 2 * inputs.len());
        message.extend([g_r, pk_sig, pr_sig, *signer].map(|point| point.to_x_coordinate()));
        message.extend([tvk, tcm, function_id, is_root]);
        // Add the program checksum to the hash input if it was provided.
        if let Some(program_checksum) = program_checksum {
            message.push(program_checksum);
        }

        // Initialize a vector to store the input IDs.
        let mut input_ids = Vec::with_capacity(inputs.len());

        // Compute the input IDs from the (already prepared) inputs.
        for (index, (input, input_type)) in inputs.iter().zip_eq(input_types).enumerate() {
            // Convert index to u16.
            let index = u16::try_from(index).map_err(|_| anyhow!("Input index exceeds u16"))?;

            match input_type {
                // A constant input is hashed (using `tcm`) to a field element.
                ValueType::Constant(..) => {
                    let input_id = InputID::constant(function_id, input, tcm, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A public input is hashed (using `tcm`) to a field element.
                ValueType::Public(..) => {
                    let input_id = InputID::public(function_id, input, tcm, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A private input is encrypted (using `tvk`) and hashed to a field element.
                ValueType::Private(..) => {
                    let input_id = InputID::private(function_id, input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A record input is computed to its serial number.
                ValueType::Record(record_name) => {
                    // Compute the input ID (commitment, gamma, record view key, serial number, tag).
                    let input_id =
                        InputID::record(&program_id, record_name, input, &signer, &view_key, &sk_sig, sk_tag)?;
                    // Extract the commitment, gamma, and tag for the message.
                    let (commitment, gamma, tag) = match &input_id {
                        InputID::Record(c, g, _, _, t) => (*c, *g, *t),
                        // InputID::record always returns the Record variant.
                        _ => unreachable!(),
                    };
                    // Compute the generator `H` as `HashToGroup(commitment)`.
                    let h = N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])?;
                    // Compute `h_r` as `r * H`.
                    let h_r = h * r;
                    // Add (`H`, `r * H`, `gamma`, `tag`) to the preimage.
                    message.extend([h, h_r, gamma].iter().map(|point| point.to_x_coordinate()));
                    message.push(tag);
                    input_ids.push(input_id);
                }
                // An external record input is hashed (using `tvk`) to a field element.
                ValueType::ExternalRecord(..) => {
                    let input_id = InputID::external_record(function_id, input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A future is not a valid input.
                ValueType::Future(..) => bail!("A future is not a valid input"),
                // A dynamic record input is hashed (using `tvk`) to a field element.
                ValueType::DynamicRecord => {
                    let input_id = InputID::dynamic_record(function_id, input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A dynamic future is not a valid input.
                ValueType::DynamicFuture => bail!("A dynamic future is not a valid input"),
            }
        }

        // Compute `challenge` as `HashToScalar(r * G, pk_sig, pr_sig, signer, [tvk, tcm, function ID, is_root, program checksum?, input IDs])`.
        let challenge = N::hash_to_scalar_psd8(&message)?;
        // Compute `response` as `r - challenge * sk_sig`.
        let response = r - challenge * sk_sig;

        // Construct the populated and signed request via the public tuple constructor.
        Ok(Request::from((
            signer,
            network_id,
            program_id,
            function_name,
            input_ids,
            inputs.to_vec(),
            Signature::from((challenge, response, compute_key)),
            sk_tag,
            tvk,
            tcm,
            scm,
            is_dynamic,
        )))
    }

    // Resolves the correct value of a record-bearing input slot of a reauthorized request.
    //
    // The mocked authorization derives intermediate records (those produced within the call tree) using
    // mocked transition view keys, so their nonces (and thus commitments, serial numbers, and input
    // IDs) do not match the execution. This function recovers the correct value by selecting, among the
    // candidate records, the one whose recomputed input ID matches the corresponding transition input.
    //
    // The candidates are the mocked value (correct for records derived purely from the root inputs,
    // since translation is tvk-independent) followed by the records decrypted from the execution's
    // outputs (correct for records produced within the call tree, since every such record is emitted as
    // a static record output by its birth transition).
    #[allow(clippy::too_many_arguments)]
    fn resolve_record_input(
        mock_value: &Value<CurrentNetwork>,
        value_type: &ValueType<CurrentNetwork>,
        target_id: &Field<CurrentNetwork>,
        output_records: &[Record<CurrentNetwork, Plaintext<CurrentNetwork>>],
        program_id: &ProgramID<CurrentNetwork>,
        function_id: Field<CurrentNetwork>,
        signer: &Address<CurrentNetwork>,
        view_key: &ViewKey<CurrentNetwork>,
        sk_sig: &Scalar<CurrentNetwork>,
        sk_tag: Field<CurrentNetwork>,
        tvk: Field<CurrentNetwork>,
        index: u16,
    ) -> Result<Value<CurrentNetwork>> {
        // Computes the transition-level input ID that the given candidate value would yield, returning
        // `None` if the candidate's shape is incompatible with the input type. For a record input, the
        // transition stores the serial number, so that is extracted; for external and dynamic record
        // inputs, the transition stores the input ID hash directly.
        let candidate_id = |value: &Value<CurrentNetwork>| -> Option<Field<CurrentNetwork>> {
            match value_type {
                ValueType::Record(record_name) => {
                    match InputID::record(program_id, record_name, value, signer, view_key, sk_sig, sk_tag) {
                        Ok(InputID::Record(_, _, _, serial_number, _)) => Some(serial_number),
                        _ => None,
                    }
                }
                ValueType::ExternalRecord(..) => {
                    InputID::external_record(function_id, value, tvk, index).ok().map(|id| *id.id())
                }
                ValueType::DynamicRecord => {
                    InputID::dynamic_record(function_id, value, tvk, index).ok().map(|id| *id.id())
                }
                _ => None,
            }
        };

        // First, try the mocked value, which is correct for records derived purely from the root inputs.
        if candidate_id(mock_value) == Some(*target_id) {
            return Ok(mock_value.clone());
        }
        // Otherwise, search the records decrypted from the execution's outputs.
        for record in output_records {
            let value = match value_type {
                ValueType::Record(..) | ValueType::ExternalRecord(..) => Value::Record(record.clone()),
                ValueType::DynamicRecord => Value::DynamicRecord(DynamicRecord::from_record(record)?),
                _ => continue,
            };
            if candidate_id(&value) == Some(*target_id) {
                return Ok(value);
            }
        }
        bail!("Could not resolve the value of record input {index} for '{program_id}'")
    }

    // Reconstructs an authorization for the given execution, extracting suitable requests and calling
    // authorize_requests. More specifically, this function:
    // - recovers each transition's actual tvk from its tpk and the signer's view key,
    // - samples a mocked authorization for the same root call via sample_authorization
    //   In particular, the requests in the authoriztion have correct program IDs, function names and
    //   input values (not IDs), but their tvk, tcm and signatures are mocked.
    // - corrects the input values of records produced within the call tree, whose mocked nonces do not
    //   match the execution, by decrypting the corresponding records from the execution's outputs,
    // - populates each mocked request with the correct data derived from its recovered tvk (tcm, input
    //   IDs and signature) via populate_request_and_sign
    // - passes the populated requests to authorize_requests
    pub(crate) fn reauthorize_from_execution(
        vm: &VM<CurrentNetwork, LedgerType>,
        execution: &Execution<CurrentNetwork>,
        root_inputs: &[Value<CurrentNetwork>],
        private_key: &PrivateKey<CurrentNetwork>,
        rng: &mut TestRng,
    ) -> Authorization<CurrentNetwork> {
        // Derive the signer's view key, address, and signing material.
        let view_key = ViewKey::try_from(private_key).unwrap();
        let signer = view_key.to_address();
        let sk_sig = private_key.sk_sig();
        let sk_tag = GraphKey::try_from(view_key).unwrap().sk_tag();

        // Decrypt every record emitted as a (static) record output of the execution. These provide the
        // correct values for records produced within the call tree, whose nonces depend on the
        // producing transition's tvk and so do not match the mocked authorization.
        let output_records: Vec<Record<CurrentNetwork, Plaintext<CurrentNetwork>>> = execution
            .transitions()
            .flat_map(|transition| transition.outputs())
            .filter_map(|output| match output {
                Output::Record(_, _, Some(record), _) | Output::RecordWithDynamicID(_, _, Some(record), _, _) => {
                    record.decrypt(&view_key).ok()
                }
                _ => None,
            })
            .collect();

        // Recover the transition view keys (tvks) from the transitions' tpks, in post-order (the order
        // in which the transitions appear in the execution).
        let recovered_tvks: Vec<Field<CurrentNetwork>> =
            execution.transitions().map(|transition| (*transition.tpk() * *view_key).to_x_coordinate()).collect();
        // The root call is the last transition (post-order), and its tvk is the root tvk.
        let root_transition = execution.transitions().last().unwrap();
        let root_tvk = *recovered_tvks.last().unwrap();

        // Sample a mocked authorization for the same root call.
        let root_stack = vm.process().get_stack(*root_transition.program_id()).unwrap();
        let sampled = root_stack
            .sample_authorization::<CurrentAleo, _>(
                signer,
                *root_transition.program_id(),
                *root_transition.function_name(),
                root_inputs.iter(),
                rng,
            )
            .unwrap();

        // The mocked transitions are in the same post-order as the execution's transitions, so map each
        // mocked transition's tcm to the recovered tvk and execution transition by position. Each mocked
        // request is then matched to its tvk and transition via its (mocked) tcm.
        let tcm_to_tvk: HashMap<Field<CurrentNetwork>, Field<CurrentNetwork>> = sampled
            .transitions()
            .values()
            .zip_eq(recovered_tvks.iter().copied())
            .map(|(transition, tvk)| (*transition.tcm(), tvk))
            .collect();
        let tcm_to_transition: HashMap<Field<CurrentNetwork>, &Transition<CurrentNetwork>> = sampled
            .transitions()
            .values()
            .zip_eq(execution.transitions())
            .map(|(mock, real)| (*mock.tcm(), real))
            .collect();

        // Populate each mocked request with the correct data derived from its recovered tvk.
        let populated_requests: Vec<Request<CurrentNetwork>> = sampled
            .to_vec_deque()
            .into_iter()
            .map(|request| {
                // Recover this request's tvk and execution transition via its (mocked) tcm.
                let tvk = *tcm_to_tvk.get(request.tcm()).expect("every mocked request has a matching transition");
                let transition = *tcm_to_transition.get(request.tcm()).expect("every mocked request has a transition");
                // Look up the callee program's stack, function input types, and program checksum.
                let stack = vm.process().get_stack(*request.program_id()).unwrap();
                let input_types = stack.get_function(request.function_name()).unwrap().input_types();
                let program_checksum = match stack.program().contains_constructor() {
                    true => Some(stack.program_checksum_as_field().unwrap()),
                    false => None,
                };
                // The root request is the one whose tvk matches the root tvk.
                let is_root = tvk == root_tvk;
                // Compute the function ID used to recompute external and dynamic record input IDs.
                let function_id =
                    compute_function_id(&U16::new(CurrentNetwork::ID), request.program_id(), request.function_name())
                        .unwrap();
                // Correct the value of each record-bearing input, leaving other inputs untouched.
                let corrected_inputs: Vec<Value<CurrentNetwork>> = request
                    .inputs()
                    .iter()
                    .zip_eq(input_types.iter())
                    .enumerate()
                    .map(|(index, (mock_value, value_type))| match value_type {
                        ValueType::Record(..) | ValueType::ExternalRecord(..) | ValueType::DynamicRecord => {
                            let target_id = transition.inputs()[index].id();
                            resolve_record_input(
                                mock_value,
                                value_type,
                                target_id,
                                &output_records,
                                request.program_id(),
                                function_id,
                                &signer,
                                &view_key,
                                &sk_sig,
                                sk_tag,
                                tvk,
                                u16::try_from(index).unwrap(),
                            )
                            .unwrap()
                        }
                        _ => mock_value.clone(),
                    })
                    .collect();
                // Populate and sign the request.
                populate_request_and_sign(
                    &request,
                    private_key,
                    &input_types,
                    &corrected_inputs,
                    tvk,
                    Some(root_tvk),
                    is_root,
                    program_checksum,
                    rng,
                )
                .unwrap()
            })
            .collect();

        // Authorize from the populated requests.
        root_stack.authorize_requests::<CurrentAleo, _>(populated_requests, rng).unwrap()
    }

    // Adds the given transactions to a new block and asserts all of them were accepted,
    // additionally checking that the cost estimations based on the Authorization and the call
    // target an inputs are correct. The latter check is done if and only if the `inputs` parameter
    // is provided, which should not be done for deployments. Furthermore, if that is the case, it
    // is checked that authorize_requests recovers a consistent authorization when provided with the
    // same requests.
    pub(crate) fn add_and_test_with_costs(
        vm: &VM<CurrentNetwork, LedgerType>,
        caller_private_key: &PrivateKey<CurrentNetwork>,
        inputs: Option<&[&[Value<CurrentNetwork>]]>,
        transactions: &[Transaction<CurrentNetwork>],
        rng: &mut TestRng,
    ) {
        // Check the transactions.
        let transactions: Vec<_> = transactions
            .iter()
            .map(|tx_0| {
                // Serialize and deserialize the transaction to ensure consistency.
                let tx_bytes_0 = tx_0.to_bytes_le().unwrap();
                let tx_1 = Transaction::<CurrentNetwork>::from_bytes_le(&tx_bytes_0).unwrap();
                assert_eq!(tx_0, &tx_1);
                assert_eq!(tx_bytes_0, tx_1.to_bytes_le().unwrap());
                // Stringify and parse the transaction to ensure consistency.
                let tx_1_string = tx_1.to_string();
                let tx = Transaction::<CurrentNetwork>::from_str(&tx_1_string).unwrap();
                assert_eq!(tx_0, &tx);
                assert_eq!(tx_1_string, tx.to_string());
                // Check the transaction.
                vm.check_transaction(&tx, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
                tx
            })
            .collect();
        // Sample the next block.
        let block = sample_next_block(vm, caller_private_key, &transactions, rng).unwrap();
        // Assert all transactions were accepted.
        assert_eq!(block.transactions().num_accepted(), transactions.len());
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);

        // Add the next block to the VM.
        vm.add_next_block(&block).unwrap();

        // Check the cost estimation is correct:
        if let Some(inputs) = inputs {
            for (transaction, inputs) in transactions.iter().zip_eq(inputs) {
                if let Some(execution) = transaction.execution() {
                    let actual_cost = execution_cost(vm.process(), execution, ConsensusVersion::V14).unwrap();
                    let authorization =
                        Authorization::from_unchecked((vec![], execution.transitions().cloned().collect()));
                    let estimated_cost_authorization =
                        execution_cost_for_authorization(vm.process(), &authorization, ConsensusVersion::V14).unwrap();
                    assert_eq!(actual_cost, estimated_cost_authorization);

                    let root_transition = execution.transitions().last().unwrap();
                    let estimated_cost_request = execution_cost_for_call::<CurrentAleo, _>(
                        vm.process(),
                        Address::try_from(caller_private_key).unwrap(),
                        *root_transition.program_id(),
                        *root_transition.function_name(),
                        inputs.iter(),
                        ConsensusVersion::V14,
                        rng,
                    )
                    .unwrap();
                    assert_eq!(actual_cost, estimated_cost_request);

                    // Reconstruct an authorization from the execution using authorize_requests
                    let reauthorization = reauthorize_from_execution(vm, execution, inputs, caller_private_key, rng);
                    let reauthorized_transitions = reauthorization.transitions();

                    // Test consistency between the transitions in the original execution and the new reauthorization.
                    // All values can be compared directly except for tpk.
                    for (original, (tid, reauthorized)) in
                        execution.transitions().zip_eq(reauthorized_transitions.iter())
                    {
                        assert_eq!(original.id(), tid);
                        assert_eq!(original.id(), reauthorized.id());
                        assert_eq!(original.program_id(), reauthorized.program_id());
                        assert_eq!(original.function_name(), reauthorized.function_name());
                        assert_eq!(original.tcm(), reauthorized.tcm());
                        assert_eq!(original.scm(), reauthorized.scm());
                        assert_eq!(original.inputs(), reauthorized.inputs());
                        assert_eq!(original.outputs(), reauthorized.outputs());
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_multiple_deployments_and_multiple_executions() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Fetch the unspent records.
        let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);

        // Select a record to spend.
        let record = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Split once.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(record), Value::from_str("1000000000u64").unwrap()].iter(), // 1000 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let first_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let second_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
        vm.add_next_block(&block).unwrap();

        // Split again.
        let mut transactions = Vec::new();
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(first_record), Value::from_str("100000000u64").unwrap()].iter(), // 100 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let first_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let third_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        transactions.push(transaction);
        // Split again.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(second_record), Value::from_str("100000000u64").unwrap()].iter(), // 100 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let second_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let fourth_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        transactions.push(transaction);
        // Add the split transactions to a block and update the VM.
        let fee_block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
        vm.add_next_block(&fee_block).unwrap();

        // Deploy the programs.
        let first_program = r"
program test_program_1.aleo;
mapping map_0:
    key as field.public;
    value as field.public;
function init:
    async init into r0;
    output r0 as test_program_1.aleo/init.future;
finalize init:
    set 0field into map_0[0field];
function getter:
    async getter into r0;
    output r0 as test_program_1.aleo/getter.future;
finalize getter:
    get map_0[0field] into r0;
        ";
        let second_program = r"
program test_program_2.aleo;
mapping map_0:
    key as field.public;
    value as field.public;
function init:
    async init into r0;
    output r0 as test_program_2.aleo/init.future;
finalize init:
    set 0field into map_0[0field];
function getter:
    async getter into r0;
    output r0 as test_program_2.aleo/getter.future;
finalize getter:
    get map_0[0field] into r0;
        ";
        let first_deployment = vm
            .deploy(&caller_private_key, &Program::from_str(first_program).unwrap(), Some(first_record), 1, None, rng)
            .unwrap();
        let second_deployment = vm
            .deploy(&caller_private_key, &Program::from_str(second_program).unwrap(), Some(second_record), 1, None, rng)
            .unwrap();
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, &[first_deployment, second_deployment], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Execute the programs.
        let first_execution = vm
            .execute(
                &caller_private_key,
                ("test_program_1.aleo", "init"),
                Vec::<Value<MainnetV0>>::new().iter(),
                Some(third_record),
                1,
                None,
                rng,
            )
            .unwrap();
        let second_execution = vm
            .execute(
                &caller_private_key,
                ("test_program_2.aleo", "init"),
                Vec::<Value<MainnetV0>>::new().iter(),
                Some(fourth_record),
                1,
                None,
                rng,
            )
            .unwrap();
        let execution_block =
            sample_next_block(&vm, &caller_private_key, &[first_execution, second_execution], rng).unwrap();
        vm.add_next_block(&execution_block).unwrap();
    }

    #[test]
    #[ignore]
    fn test_load_deployments_with_imports() {
        // NOTE: This seed was chosen for the CI's RNG to ensure that the test passes.
        let rng = &mut TestRng::fixed(123456789);

        // Initialize a new caller.
        let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        // Initialize the genesis block.
        let genesis = vm.genesis_beacon(&caller_private_key, rng).unwrap();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Fetch the unspent records.
        let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<Vec<(_, _)>>();
        trace!("Unspent Records:\n{:#?}", records);
        let record_0 = records[0].1.decrypt(&caller_view_key).unwrap();
        let record_1 = records[1].1.decrypt(&caller_view_key).unwrap();
        let record_2 = records[2].1.decrypt(&caller_view_key).unwrap();
        let record_3 = records[3].1.decrypt(&caller_view_key).unwrap();

        // Create the deployment for the first program.
        let program_1 = r"
program first_program.aleo;

function c:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_1 = vm
            .deploy(&caller_private_key, &Program::from_str(program_1).unwrap(), Some(record_0), 0, None, rng)
            .unwrap();

        // Deploy the first program.
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, std::slice::from_ref(&deployment_1), rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Create the deployment for the second program.
        let program_2 = r"
import first_program.aleo;

program second_program.aleo;

function b:
    input r0 as u8.private;
    input r1 as u8.private;
    call first_program.aleo/c r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_2 = vm
            .deploy(&caller_private_key, &Program::from_str(program_2).unwrap(), Some(record_1), 0, None, rng)
            .unwrap();

        // Deploy the second program.
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, std::slice::from_ref(&deployment_2), rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Create the deployment for the third program.
        let program_3 = r"
import second_program.aleo;

program third_program.aleo;

function a:
    input r0 as u8.private;
    input r1 as u8.private;
    call second_program.aleo/b r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_3 = vm
            .deploy(&caller_private_key, &Program::from_str(program_3).unwrap(), Some(record_2), 0, None, rng)
            .unwrap();

        // Create the deployment for the fourth program.
        let program_4 = r"
import second_program.aleo;
import first_program.aleo;

program fourth_program.aleo;

function a:
    input r0 as u8.private;
    input r1 as u8.private;
    call second_program.aleo/b r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_4 = vm
            .deploy(&caller_private_key, &Program::from_str(program_4).unwrap(), Some(record_3), 0, None, rng)
            .unwrap();

        // Deploy the third and fourth program together.
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, &[deployment_3.clone(), deployment_4.clone()], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Enforce that the VM can load properly with the imports.
        assert!(VM::from(vm.store.clone()).is_ok());
    }

    #[test]
    fn test_multiple_external_calls() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
        let address = Address::try_from(&caller_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Fetch the unspent records.
        let records =
            genesis.transitions().cloned().flat_map(Transition::into_records).take(3).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);
        let record_0 = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();
        let record_1 = records.values().nth(1).unwrap().decrypt(&caller_view_key).unwrap();
        let record_2 = records.values().nth(2).unwrap().decrypt(&caller_view_key).unwrap();

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the program.
        let program = Program::from_str(
            r"
import credits.aleo;

program test_multiple_external_calls.aleo;

function multitransfer:
    input r0 as credits.aleo/credits.record;
    input r1 as address.private;
    input r2 as u64.private;
    call credits.aleo/transfer_private r0 r1 r2 into r3 r4;
    call credits.aleo/transfer_private r4 r1 r2 into r5 r6;
    output r4 as credits.aleo/credits.record;
    output r5 as credits.aleo/credits.record;
    output r6 as credits.aleo/credits.record;
    ",
        )
        .unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, Some(record_0), 1, None, rng).unwrap();
        vm.add_next_block(&sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap()).unwrap();

        // Execute the programs.
        let inputs = [
            Value::<MainnetV0>::Record(record_1),
            Value::<MainnetV0>::from_str(&address.to_string()).unwrap(),
            Value::<MainnetV0>::from_str("10u64").unwrap(),
        ];
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_multiple_external_calls.aleo", "multitransfer"),
                inputs.into_iter(),
                Some(record_2),
                1,
                None,
                rng,
            )
            .unwrap();
        vm.add_next_block(&sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap()).unwrap();
    }

    #[test]
    fn test_nested_deployment_with_assert() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program child_program.aleo;

function check:
    input r0 as field.private;
    assert.eq r0 123456789123456789123456789123456789123456789123456789field;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("child_program.aleo").unwrap()));

        // Deploy the program that calls the program from the previous layer.
        let program = Program::from_str(
            r"
import child_program.aleo;

program parent_program.aleo;

function check:
    input r0 as field.private;
    call child_program.aleo/check r0;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("parent_program.aleo").unwrap()));
    }

    #[test]
    #[ignore]
    fn test_deployment_with_external_records() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the program.
        let program = Program::from_str(
            r"
import credits.aleo;
program test_program.aleo;

function transfer:
    input r0 as credits.aleo/credits.record;
    input r1 as u64.private;
    input r2 as u64.private;
    input r3 as [address; 10u32].private;
    call credits.aleo/transfer_private r0 r3[0u32] r1 into r4 r5;
    call credits.aleo/transfer_private r5 r3[0u32] r2 into r6 r7;
",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("test_program.aleo").unwrap()));
    }

    #[test]
    fn test_internal_fee_calls_are_invalid() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);
        let view_key = ViewKey::try_from(&private_key).unwrap();

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Fetch the unspent records.
        let records =
            genesis.transitions().cloned().flat_map(Transition::into_records).take(3).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);
        let record_0 = records.values().next().unwrap().decrypt(&view_key).unwrap();

        // Deploy the program.
        let program = Program::from_str(
            r"
import credits.aleo;
program test_program.aleo;

function call_fee_public:
    input r0 as u64.private;
    input r1 as u64.private;
    input r2 as field.private;
    call credits.aleo/fee_public r0 r1 r2 into r3;
    async call_fee_public r3 into r4;
    output r4 as test_program.aleo/call_fee_public.future;

finalize call_fee_public:
    input r0 as credits.aleo/fee_public.future;
    await r0;

function call_fee_private:
    input r0 as credits.aleo/credits.record;
    input r1 as u64.private;
    input r2 as u64.private;
    input r3 as field.private;
    call credits.aleo/fee_private r0 r1 r2 r3 into r4;
    output r4 as credits.aleo/credits.record;
",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Execute the programs.
        let internal_base_fee_amount: u64 = rng.random_range(1..1000);
        let internal_priority_fee_amount: u64 = rng.random_range(1..1000);

        // Ensure that the transaction that calls `fee_public` internally cannot be generated.
        let inputs = [
            Value::<MainnetV0>::from_str(&format!("{internal_base_fee_amount}u64")).unwrap(),
            Value::<MainnetV0>::from_str(&format!("{internal_priority_fee_amount}u64")).unwrap(),
            Value::<MainnetV0>::from_str("1field").unwrap(),
        ];
        assert!(
            vm.execute(&private_key, ("test_program.aleo", "call_fee_public"), inputs.into_iter(), None, 0, None, rng)
                .is_err()
        );

        // Ensure that the transaction that calls `fee_private` internally cannot be generated.
        let inputs = [
            Value::<MainnetV0>::Record(record_0),
            Value::<MainnetV0>::from_str(&format!("{internal_base_fee_amount}u64")).unwrap(),
            Value::<MainnetV0>::from_str(&format!("{internal_priority_fee_amount}u64")).unwrap(),
            Value::<MainnetV0>::from_str("1field").unwrap(),
        ];
        assert!(
            vm.execute(&private_key, ("test_program.aleo", "call_fee_private"), inputs.into_iter(), None, 0, None, rng)
                .is_err()
        );
    }

    #[test]
    #[cfg(feature = "memory-intensive")]
    #[ignore = "memory-intensive"]
    fn test_deployment_synthesis_overload() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program synthesis_overload.aleo;

function do:
    input r0 as [[u128; 32u32]; 2u32].private;
    hash.sha3_256 r0 into r1 as field;
    hash.sha3_256 r0 into r2 as field;
    output r2 as field.public;",
        )
        .unwrap();

        // Create the deployment transaction.
        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Verify the deployment transaction. It should fail because there are too many constraints.
        assert!(vm.check_transaction(&deployment, None, rng).is_err());
    }

    #[test]
    fn test_deployment_num_constant_overload() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program synthesis_num_constants.aleo;
function do:
    cast 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 into r0 as [u32; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [[u32; 32u32]; 32u32];
    cast r1 r1 r1 r1 r1 into r2 as [[[u32; 32u32]; 32u32]; 5u32];
    cast r1 r1 r1 r1 r1 into r3 as [[[u32; 32u32]; 32u32]; 5u32];
    hash.bhp1024 r2 into r4 as u32;
    hash.bhp1024 r3 into r5 as u32;
    output r4 as u32.private;
function do2:
    cast 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 0u32 into r0 as [u32; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [[u32; 32u32]; 32u32];
    cast r1 r1 r1 r1 r1 into r2 as [[[u32; 32u32]; 32u32]; 5u32];
    hash.bhp1024 r2 into r3 as u32;
    output r3 as u32.private;",
        )
            .unwrap();

        // Create the deployment transaction.
        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Verify the deployment transaction. It should fail because there are too many constants.
        let check_tx_res = vm.check_transaction(&deployment, None, rng);
        assert!(check_tx_res.is_err());
    }

    #[test]
    fn test_deployment_synthesis_overreport() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program synthesis_overreport.aleo;

function do:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
        )
        .unwrap();

        // Create the deployment transaction.
        let transaction = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Destructure the deployment transaction.
        let Transaction::Deploy(_, _, program_owner, deployment, fee) = transaction else {
            panic!("Expected a deployment transaction");
        };

        // Increase the number of constraints in the verifying keys.
        let mut vks_with_overreport = Vec::with_capacity(deployment.verifying_keys().len());
        for (id, (vk, cert)) in deployment.verifying_keys() {
            let mut vk_deref = vk.deref().clone();
            vk_deref.circuit_info.num_constraints += 1;
            let vk = VerifyingKey::new(Arc::new(vk_deref), vk.num_variables());
            vks_with_overreport.push((*id, (vk, cert.clone())));
        }

        // Each additional constraint costs 25 microcredits, so we need to increase the fee by 25 microcredits.
        let required_fee = *fee.base_amount().unwrap() + 25;
        // Authorize a new fee.
        let fee_authorization = vm
            .authorize_fee_public(&private_key, required_fee, 0, deployment.as_ref().to_deployment_id().unwrap(), rng)
            .unwrap();
        // Compute the fee.
        let fee = vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();

        // Create a new deployment transaction with the overreported verifying keys.
        let adjusted_deployment = Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            vks_with_overreport,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap();
        let adjusted_transaction = Transaction::from_deployment(program_owner, adjusted_deployment, fee).unwrap();

        // Verify the deployment transaction. It should error when certificate checking for constraint count mismatch.
        let res = vm.check_transaction(&adjusted_transaction, None, rng);
        assert!(res.is_err());
    }

    #[test]
    fn test_deployment_synthesis_underreport() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);
        let address = Address::try_from(&private_key).unwrap();

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program synthesis_underreport.aleo;

function do:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
        )
        .unwrap();

        // Create the deployment transaction.
        let transaction = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Destructure the deployment transaction.
        let Transaction::Deploy(txid, _, program_owner, deployment, fee) = transaction else {
            panic!("Expected a deployment transaction");
        };

        // Decrease the number of constraints in the verifying keys.
        let mut vks_with_underreport = Vec::with_capacity(deployment.verifying_keys().len());
        for (id, (vk, cert)) in deployment.verifying_keys() {
            let mut vk_deref = vk.deref().clone();
            vk_deref.circuit_info.num_constraints -= 2;
            let vk = VerifyingKey::new(Arc::new(vk_deref), vk.num_variables());
            vks_with_underreport.push((*id, (vk, cert.clone())));
        }

        // Create a new deployment transaction with the underreported verifying keys.
        let adjusted_deployment = Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            vks_with_underreport,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap();
        let deployment_id = adjusted_deployment.to_deployment_id().unwrap();
        let adjusted_transaction =
            Transaction::Deploy(txid, deployment_id, program_owner, Box::new(adjusted_deployment), fee);

        // Verify the deployment transaction. It should error when enforcing the first constraint over the vk limit.
        let result = vm.check_transaction(&adjusted_transaction, None, rng);
        assert!(result.is_err());

        // Create a standard transaction
        // Prepare the inputs.
        let inputs = [
            Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str("1u64").unwrap(),
        ]
        .into_iter();

        // Execute.
        let transaction =
            vm.execute(&private_key, ("credits.aleo", "transfer_public"), inputs, None, 0, None, rng).unwrap();

        // Check that the deployment transaction will be aborted if injected into a block.
        let block = sample_next_block(&vm, &private_key, &[transaction, adjusted_transaction.clone()], rng).unwrap();

        // Check that the block aborts the deployment transaction.
        assert_eq!(block.aborted_transaction_ids(), &vec![adjusted_transaction.id()]);

        // Update the VM.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_deployment_variable_underreport() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);
        let address = Address::try_from(&private_key).unwrap();

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program synthesis_underreport.aleo;
function do:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
        )
        .unwrap();

        // Create the deployment transaction.
        let transaction = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Destructure the deployment transaction.
        let Transaction::Deploy(txid, _, program_owner, deployment, fee) = transaction else {
            panic!("Expected a deployment transaction");
        };

        // Decrease the number of reported variables in the verifying keys.
        let mut vks_with_underreport = Vec::with_capacity(deployment.verifying_keys().len());
        for (id, (vk, cert)) in deployment.verifying_keys() {
            let vk = VerifyingKey::new(Arc::new(vk.deref().clone()), vk.num_variables() - 2);
            vks_with_underreport.push((*id, (vk.clone(), cert.clone())));
        }

        // Create a new deployment transaction with the underreported verifying keys.
        let adjusted_deployment = Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            vks_with_underreport,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap();
        let deployment_id = adjusted_deployment.to_deployment_id().unwrap();
        let adjusted_transaction =
            Transaction::Deploy(txid, deployment_id, program_owner, Box::new(adjusted_deployment), fee);

        // Verify the deployment transaction. It should error when synthesizing the first variable over the vk limit.
        let result = vm.check_transaction(&adjusted_transaction, None, rng);
        assert!(result.is_err());

        // Create a standard transaction
        // Prepare the inputs.
        let inputs = [
            Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str("1u64").unwrap(),
        ]
        .into_iter();

        // Execute.
        let transaction =
            vm.execute(&private_key, ("credits.aleo", "transfer_public"), inputs, None, 0, None, rng).unwrap();

        // Check that the deployment transaction will be aborted if injected into a block.
        let block = sample_next_block(&vm, &private_key, &[transaction, adjusted_transaction.clone()], rng).unwrap();

        // Check that the block aborts the deployment transaction.
        assert_eq!(block.aborted_transaction_ids(), &vec![adjusted_transaction.id()]);

        // Update the VM.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_transfer_public_from_user() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize a recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check the balance of the caller.
        let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_894_112, "Update me if the initial balance changes.");

        // Transfer credits from the caller to the recipient.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public"),
                [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_843_051, "Update me if the initial balance changes.");

        // Check the balance of the recipient.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 1, "Update me if the test amount changes.");
    }

    #[test]
    fn test_transfer_public_as_signer_from_user() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize a recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check the balance of the caller.
        let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_894_112, "Update me if the initial balance changes.");

        // Transfer credits from the caller to the recipient.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public_as_signer"),
                [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_843_031, "Update me if the initial balance changes.");

        // Check the balance of the recipient.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 1, "Update me if the test amount changes.");
    }

    #[test]
    fn transfer_public_from_program() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize a recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check the balance of the caller.
        let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_894_112, "Update me if the initial balance changes.");

        // Initialize a wrapper program, importing `credits.aleo` and calling `transfer_public`.
        let program = Program::from_str(
            r"
import credits.aleo;
program credits_wrapper.aleo;

function transfer_public:
    input r0 as address.public;
    input r1 as u64.public;
    call credits.aleo/transfer_public r0 r1 into r2;
    async transfer_public r2 into r3;
    output r3 as credits_wrapper.aleo/transfer_public.future;

finalize transfer_public:
    input r0 as credits.aleo/transfer_public.future;
    await r0;
        ",
        )
        .unwrap();

        // Get the address of the wrapper program.
        let wrapper_program_id = ProgramID::from_str("credits_wrapper.aleo").unwrap();
        let wrapper_program_address = wrapper_program_id.to_address().unwrap();

        // Deploy the wrapper program.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

        // Add the deployment to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Transfer credits from the caller to the `credits_wrapper` program.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public"),
                [Value::from_str(&format!("{wrapper_program_address}")).unwrap(), Value::from_str("1u64").unwrap()]
                    .iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_996_914_676, "Update me if the initial balance changes.");

        // Check the balance of the `credits_wrapper` program.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(wrapper_program_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 1, "Update me if the test amount changes.");

        // Transfer credits from the `credits_wrapper` program to the recipient.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits_wrapper.aleo", "transfer_public"),
                [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_996_862_151, "Update me if the initial balance changes.");

        // Check the balance of the `credits_wrapper` program.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(wrapper_program_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 0);

        // Check the balance of the recipient.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 1, "Update me if the test amount changes.");
    }

    #[test]
    fn transfer_public_as_signer_from_program() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize a recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check the balance of the caller.
        let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_894_112, "Update me if the initial balance changes.");

        // Initialize a wrapper program, importing `credits.aleo` and calling `transfer_public`.
        let program = Program::from_str(
            r"
import credits.aleo;
program credits_wrapper.aleo;

function transfer_public_as_signer:
    input r0 as address.public;
    input r1 as u64.public;
    call credits.aleo/transfer_public_as_signer r0 r1 into r2;
    async transfer_public_as_signer r2 into r3;
    output r3 as credits_wrapper.aleo/transfer_public_as_signer.future;

finalize transfer_public_as_signer:
    input r0 as credits.aleo/transfer_public_as_signer.future;
    await r0;
        ",
        )
        .unwrap();

        // Get the address of the wrapper program.
        let wrapper_program_id = ProgramID::from_str("credits_wrapper.aleo").unwrap();
        let wrapper_program_address = wrapper_program_id.to_address().unwrap();

        // Deploy the wrapper program.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

        // Add the deployment to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Transfer credits from the signer using `credits_wrapper` program.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits_wrapper.aleo", "transfer_public_as_signer"),
                [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_996_821_661, "Update me if the initial balance changes.");

        // Check the `credits_wrapper` program does not have any balance.
        let balance = vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(wrapper_program_address)),
            )
            .unwrap();
        assert!(balance.is_none());

        // Check the balance of the recipient.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 1, "Update me if the test amount changes.");
    }

    #[test]
    fn test_transfer_public_to_private_from_program() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_address = Address::try_from(&caller_private_key).unwrap();

        // Initialize a recipient.
        let recipient_private_key = PrivateKey::new(rng).unwrap();
        let recipient_address = Address::try_from(&recipient_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Check the balance of the caller.
        let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
        let account_mapping_name = Identifier::from_str("account").unwrap();
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_999_894_112, "Update me if the initial balance changes.");

        // Check that the recipient does not have a public balance.
        let balance = vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap();
        assert!(balance.is_none());

        // Initialize a wrapper program, importing `credits.aleo` and calling `transfer_public_as_signer` then `transfer_public_to_private`.
        let program = Program::from_str(
            r"
import credits.aleo;

program credits_wrapper.aleo;

function transfer_public_to_private:
    input r0 as address.private;
    input r1 as u64.public;
    call credits.aleo/transfer_public_as_signer credits_wrapper.aleo r1 into r2;
    call credits.aleo/transfer_public_to_private r0 r1 into r3 r4;
    async transfer_public_to_private r2 r4 into r5;
    output r3 as credits.aleo/credits.record;
    output r5 as credits_wrapper.aleo/transfer_public_to_private.future;

finalize transfer_public_to_private:
    input r0 as credits.aleo/transfer_public_as_signer.future;
    input r1 as credits.aleo/transfer_public_to_private.future;
    contains credits.aleo/account[credits_wrapper.aleo] into r2;
    assert.eq r2 false;
    await r0;
    get credits.aleo/account[credits_wrapper.aleo] into r3;
    assert.eq r3 r0[2u32];
    await r1;
        ",
        )
        .unwrap();

        // Get the address of the wrapper program.
        let wrapper_program_id = ProgramID::from_str("credits_wrapper.aleo").unwrap();

        // Deploy the wrapper program.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

        // Add the deployment to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 182_499_995_767_962, "Update me if the initial balance changes.");

        // Call the wrapper program to transfer credits from the caller to the recipient.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits_wrapper.aleo", "transfer_public_to_private"),
                [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, std::slice::from_ref(&transaction), rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Check the balance of the caller.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(caller_address)),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };

        assert_eq!(balance, 182_499_995_667_116, "Update me if the initial balance changes.");

        // Check that the `credits_wrapper` program has a balance of 0.
        let balance = match vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(wrapper_program_id.to_address().unwrap())),
            )
            .unwrap()
        {
            Some(Value::Plaintext(Plaintext::Literal(Literal::U64(balance), _))) => *balance,
            _ => panic!("Expected a valid balance"),
        };
        assert_eq!(balance, 0);

        // Check that the recipient does not have a public balance.
        let balance = vm
            .finalize_store()
            .get_value_confirmed(
                credits_program_id,
                account_mapping_name,
                &Plaintext::from(Literal::Address(recipient_address)),
            )
            .unwrap();
        assert!(balance.is_none());

        // Get the output record from the transaction and check that it is well-formed.
        let records = transaction.records().collect_vec();
        assert_eq!(records.len(), 1);
        let (commitment, record) = records[0];
        let record = record.decrypt(&ViewKey::try_from(&recipient_private_key).unwrap()).unwrap();
        assert_eq!(**record.owner(), recipient_address);
        let data = record.data();
        assert_eq!(data.len(), 1);
        match data.get(&Identifier::from_str("microcredits").unwrap()) {
            Some(Entry::<CurrentNetwork, _>::Private(Plaintext::Literal(Literal::U64(value), _))) => {
                assert_eq!(**value, 1)
            }
            _ => panic!("Incorrect record."),
        }

        // Check that the record exists in the VM.
        assert!(vm.transition_store().get_record(commitment).unwrap().is_some());

        // Check that the serial number of the record does not exist in the VM.
        assert!(
            !vm.transition_store()
                .contains_serial_number(
                    &Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(
                        recipient_private_key,
                        *commitment
                    )
                    .unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn test_modify_transaction_output() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Initialize a new private key.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Call `transfer_public_to_private`.
        let inputs = [
            Value::from_str(&format!("{}", Address::try_from(&private_key).unwrap())).unwrap(),
            Value::from_str("1u64").unwrap(),
        ];
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public_to_private"),
                inputs.iter(),
                None,
                0u64,
                None,
                rng,
            )
            .unwrap();

        // Check that the transaction is valid.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Check that the transaction is as expected.
        let transaction_string = transaction.to_string();
        // Parse the transaction string as a JSON map.
        let transaction: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&transaction_string).unwrap();
        // Get the execution.
        let execution = transaction.get("execution").unwrap();
        // Get the `transfer_public_to_private` transition.
        let transition = execution.get("transitions").unwrap().as_array().unwrap().first().unwrap();
        // Check that the transition is as expected.
        assert_eq!(transition.get("program").unwrap(), "credits.aleo");
        assert_eq!(transition.get("function").unwrap(), "transfer_public_to_private");
        // Get the transition outputs.
        let outputs = transition.get("outputs").unwrap().as_array().unwrap();
        // For any output that is a future, modify it to an external record.
        let new_outputs = outputs
            .iter()
            .map(|output| {
                if output.get("type").unwrap() == "future" {
                    let id = output.get("id").unwrap().as_str().unwrap();
                    json!({
                        "type": "external_record",
                        "id": id
                    })
                } else {
                    output.clone()
                }
            })
            .collect::<Vec<_>>();

        // Compute the new transition ID.
        let inputs = transition
            .get("inputs")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Input::from_str(&string).unwrap()
            })
            .collect::<Vec<_>>();
        let outputs = new_outputs
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Output::from_str(&string).unwrap()
            })
            .collect();
        let tpk = Group::from_str(transition.get("tpk").unwrap().as_str().unwrap()).unwrap();
        let tcm = Field::from_str(transition.get("tcm").unwrap().as_str().unwrap()).unwrap();
        let scm = Field::from_str(transition.get("scm").unwrap().as_str().unwrap()).unwrap();
        let transition = Transition::<CurrentNetwork>::new(
            ProgramID::from_str("credits.aleo").unwrap(),
            Identifier::from_str("transfer_public_to_private").unwrap(),
            inputs,
            outputs,
            tpk,
            tcm,
            scm,
        )
        .unwrap();

        // Construct the new transaction.
        let mut new_transitions = vec![transition];
        new_transitions.extend(execution.get("transitions").unwrap().as_array().unwrap().iter().skip(1).map(|value| {
            let string = serde_json::to_string(value).unwrap();
            Transition::from_str(&string).unwrap()
        }));
        let global_state_root = <CurrentNetwork as Network>::StateRoot::from_str(
            execution.get("global_state_root").unwrap().as_str().unwrap(),
        )
        .unwrap();
        let proof = Proof::<CurrentNetwork>::from_str(execution.get("proof").unwrap().as_str().unwrap()).unwrap();
        let new_execution = Execution::from(new_transitions.into_iter(), global_state_root, Some(proof)).unwrap();
        let authorization = vm
            .authorize_fee_public(&caller_private_key, 10_000_000, 0, new_execution.to_execution_id().unwrap(), rng)
            .unwrap();
        let fee = vm.execute_fee_authorization(authorization, None, rng).unwrap();
        let new_transaction = Transaction::from_execution(new_execution, Some(fee)).unwrap();

        // Verify the new transaction.
        assert!(vm.check_transaction(&new_transaction, None, rng).is_err());
    }

    #[test]
    fn test_modify_fee() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Initialize a new private key.
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Call `transfer_public_to_private`.
        let inputs = [
            Value::from_str(&format!("{}", Address::try_from(&private_key).unwrap())).unwrap(),
            Value::from_str("1u64").unwrap(),
        ];
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public_to_private"),
                inputs.iter(),
                None,
                0u64,
                None,
                rng,
            )
            .unwrap();

        // Check that the transaction is valid.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Check that the transaction is as expected.
        let transaction_string = transaction.to_string();
        // Parse the transaction string as a JSON map.
        let transaction: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&transaction_string).unwrap();
        // Get the execution.
        let execution: Execution<CurrentNetwork> =
            serde_json::from_value(transaction.get("execution").unwrap().clone()).unwrap();

        // Get the fee.
        let fee = transaction.get("fee").unwrap().as_object().unwrap();
        // Get the transition
        let transition = fee.get("transition").unwrap().as_object().unwrap();
        // Check that the transition is as expected.
        assert_eq!(transition.get("program").unwrap(), "credits.aleo");
        assert_eq!(transition.get("function").unwrap(), "fee_public");
        // Get the transition outputs.
        let outputs = transition.get("outputs").unwrap().as_array().unwrap();
        // For any output that is a future, modify it to an external record.
        let new_outputs = outputs
            .iter()
            .map(|output| {
                if output.get("type").unwrap() == "future" {
                    let id = output.get("id").unwrap().as_str().unwrap();
                    json!({
                        "type": "external_record",
                        "id": id
                    })
                } else {
                    output.clone()
                }
            })
            .collect::<Vec<_>>();

        // Compute the new transition ID.
        let inputs = transition
            .get("inputs")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Input::from_str(&string).unwrap()
            })
            .collect::<Vec<_>>();
        let outputs = new_outputs
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Output::from_str(&string).unwrap()
            })
            .collect();
        let tpk = Group::from_str(transition.get("tpk").unwrap().as_str().unwrap()).unwrap();
        let tcm = Field::from_str(transition.get("tcm").unwrap().as_str().unwrap()).unwrap();
        let scm = Field::from_str(transition.get("scm").unwrap().as_str().unwrap()).unwrap();
        // Construct the new transition.
        let transition = Transition::<CurrentNetwork>::new(
            ProgramID::from_str("credits.aleo").unwrap(),
            Identifier::from_str("fee_public").unwrap(),
            inputs,
            outputs,
            tpk,
            tcm,
            scm,
        )
        .unwrap();
        // Get the state root.
        let global_state_root =
            <CurrentNetwork as Network>::StateRoot::from_str(fee.get("global_state_root").unwrap().as_str().unwrap())
                .unwrap();
        // Get the proof.
        let proof = Proof::<CurrentNetwork>::from_str(fee.get("proof").unwrap().as_str().unwrap()).unwrap();
        // Construct the new fee.
        let fee = Fee::from(transition, global_state_root, Some(proof)).unwrap();

        // Construct the new transaction.
        let new_transaction = Transaction::from_execution(execution, Some(fee)).unwrap();

        // Verify the new transaction.
        assert!(vm.check_transaction(&new_transaction, None, rng).is_err());
    }

    #[test]
    fn test_modify_input_and_output() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the test program.
        let program = Program::from_str(
            r"
program basic_math.aleo;

function add_thrice:
    input r0 as u64.public;
    input r1 as u64.private;
    add r0 r1 into r2;
    add r2 r1 into r3;
    add r3 r1 into r4;
    output r2 as u64.constant;
    output r3 as u64.public;
    output r4 as u64.private;
        ",
        )
        .unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        vm.add_next_block(&block).unwrap();

        // Call the test program.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("basic_math.aleo", "add_thrice"),
                [Value::from_str("1u64").unwrap(), Value::from_str("2u64").unwrap()].iter(),
                None,
                0u64,
                None,
                rng,
            )
            .unwrap();

        // Check that the transaction is valid.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Get the transaction string.
        let transaction_string = transaction.to_string();
        // Parse the transaction string as a JSON map.
        let transaction: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&transaction_string).unwrap();
        // Get the execution.
        let execution = transaction.get("execution").unwrap();
        // Get the `add_twice` transition.
        let transition = execution.get("transitions").unwrap().as_array().unwrap().first().unwrap();
        // Get the transition inputs.
        let inputs = transition.get("inputs").unwrap().as_array().unwrap();
        // For any input, modify it to an external record.
        let new_inputs = inputs
            .iter()
            .map(|input| {
                let id = input.get("id").unwrap().as_str().unwrap();
                json!({
                    "type": "external_record",
                    "id": id
                })
            })
            .collect::<Vec<_>>();
        // Get the transition outputs.
        let outputs = transition.get("outputs").unwrap().as_array().unwrap();
        // For any output, modify it to an external record.
        let new_outputs = outputs
            .iter()
            .map(|output| {
                let id = output.get("id").unwrap().as_str().unwrap();
                json!({
                    "type": "external_record",
                    "id": id
                })
            })
            .collect::<Vec<_>>();

        // Compute the new transition ID.
        let inputs = new_inputs
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Input::from_str(&string).unwrap()
            })
            .collect::<Vec<_>>();
        let outputs = new_outputs
            .iter()
            .map(|value| {
                let string = serde_json::to_string(value).unwrap();
                Output::from_str(&string).unwrap()
            })
            .collect();
        let tpk = Group::from_str(transition.get("tpk").unwrap().as_str().unwrap()).unwrap();
        let tcm = Field::from_str(transition.get("tcm").unwrap().as_str().unwrap()).unwrap();
        let scm = Field::from_str(transition.get("scm").unwrap().as_str().unwrap()).unwrap();

        // Construct the new transition.
        let transition = Transition::<CurrentNetwork>::new(
            ProgramID::from_str("basic_math.aleo").unwrap(),
            Identifier::from_str("add_thrice").unwrap(),
            inputs,
            outputs,
            tpk,
            tcm,
            scm,
        )
        .unwrap();

        // Construct the new transaction.
        let mut new_transitions = vec![transition];
        new_transitions.extend(execution.get("transitions").unwrap().as_array().unwrap().iter().skip(1).map(|value| {
            let string = serde_json::to_string(value).unwrap();
            Transition::from_str(&string).unwrap()
        }));
        let global_state_root = <CurrentNetwork as Network>::StateRoot::from_str(
            execution.get("global_state_root").unwrap().as_str().unwrap(),
        )
        .unwrap();
        let proof = Proof::<CurrentNetwork>::from_str(execution.get("proof").unwrap().as_str().unwrap()).unwrap();
        let new_execution = Execution::from(new_transitions.into_iter(), global_state_root, Some(proof)).unwrap();
        let authorization = vm
            .authorize_fee_public(&caller_private_key, 10_000_000, 0, new_execution.to_execution_id().unwrap(), rng)
            .unwrap();
        let fee = vm.execute_fee_authorization(authorization, None, rng).unwrap();
        let new_transaction = Transaction::from_execution(new_execution, Some(fee)).unwrap();

        // Verify the new transaction.
        assert!(vm.check_transaction(&new_transaction, None, rng).is_err());
    }

    #[test]
    fn test_large_transaction_is_aborted() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();

        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy a program that produces small transactions.
        let program = small_transaction_program();

        // Deploy the program.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

        // Add the deployment to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Deploy a program that produces large transactions.
        let program = large_transaction_program();

        // Deploy the program.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

        // Add the deployment to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Call the program to produce the small transaction.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("testing_small.aleo", "small_transaction"),
                Vec::<Value<CurrentNetwork>>::new().iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify the transaction.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Check that the transaction was accepted.
        assert_eq!(block.transactions().num_accepted(), 1);

        // Update the VM.
        vm.add_next_block(&block).unwrap();

        // Call the program to produce a large transaction.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("testing_large.aleo", "large_transaction"),
                Vec::<Value<CurrentNetwork>>::new().iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Verify that the transaction is invalid.
        assert!(vm.check_transaction(&transaction, None, rng).is_err());

        // Add the transaction to a block and update the VM.
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();

        // Check that the transaction was aborted.
        assert_eq!(block.aborted_transaction_ids().len(), 1);

        // Update the VM.
        vm.add_next_block(&block).unwrap();
    }

    #[test]
    fn test_vm_puzzle() {
        // Attention: This test is used to ensure that the VM has performed downcasting correctly for
        // the puzzle, and that the underlying traits in the puzzle are working correctly. Please
        // *do not delete* this test as it is a critical safety check for the integrity of the
        // instantiation of the puzzle in the VM.

        let rng = &mut TestRng::default();

        // Initialize the VM.
        let vm = sample_vm();

        // Ensure this call succeeds.
        vm.puzzle.prove(rng.random(), rng.random(), rng.random(), None).unwrap();
    }

    #[test]
    fn test_multi_transition_authorization_deserialization() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let child_program_1 = Program::from_str(
            r"
program child_program_1.aleo;

function check:
    input r0 as field.private;
    assert.eq r0 123456789123456789123456789123456789123456789123456789field;
        ",
        )
        .unwrap();

        let child_program_2 = Program::from_str(
            r"
program child_program_2.aleo;

function check:
    input r0 as field.private;
    assert.eq r0 123456789123456789123456789123456789123456789123456789field;
        ",
        )
        .unwrap();

        // Deploy the child programs and add them to a block
        let deployment_1 = vm.deploy(&private_key, &child_program_1, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment_1, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment_1], rng).unwrap()).unwrap();

        let deployment_2 = vm.deploy(&private_key, &child_program_2, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment_2, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment_2], rng).unwrap()).unwrap();

        // Check that child programs are deployed
        assert!(vm.contains_program(&ProgramID::from_str("child_program_1.aleo").unwrap()));
        assert!(vm.contains_program(&ProgramID::from_str("child_program_2.aleo").unwrap()));

        // Deploy the program that calls the program from the previous layer.
        let parent_program = Program::from_str(
            r"
import child_program_1.aleo;
import child_program_2.aleo;

program parent_program.aleo;

function check:
    input r0 as field.private;
    call child_program_1.aleo/check r0;
    call child_program_2.aleo/check r0;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &parent_program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("parent_program.aleo").unwrap()));

        // Deploy the program that calls the program from the previous layer.
        let grandparent_program = Program::from_str(
            r"
import parent_program.aleo;

program grandparent_program.aleo;

function check:
    input r0 as field.private;
    call parent_program.aleo/check r0;
    call parent_program.aleo/check r0;
    call parent_program.aleo/check r0;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &grandparent_program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("grandparent_program.aleo").unwrap()));

        // Initialize the process.
        let process = Process::<CurrentNetwork>::load().unwrap();

        // Load the child and parent program
        process.lock().add_program(&child_program_1).unwrap();
        process.lock().add_program(&child_program_2).unwrap();
        process.lock().add_program(&parent_program).unwrap();
        process.lock().add_program(&grandparent_program).unwrap();

        // Specify the function name on the parent program
        let function_name = Identifier::<CurrentNetwork>::from_str("check").unwrap();

        // Generate a random Field for input
        let input =
            Value::<CurrentNetwork>::from_str("123456789123456789123456789123456789123456789123456789field").unwrap();

        // Generate the authorization that will contain multiple transitions
        let authorization = process
            .authorize::<CurrentAleo, _>(&private_key, grandparent_program.id(), &function_name, [input].iter(), rng)
            .unwrap();

        // Assert the Authorization has more than 1 transitions
        assert!(authorization.transitions().len() > 1);

        // Serialize the Authorization into a String
        let authorization_serialized = authorization.to_string();

        // Attempt to deserialize the Authorization from String
        let deserialization_result = Authorization::<CurrentNetwork>::from_str(&authorization_serialized);

        // Assert that the deserialization result is Ok
        assert!(deserialization_result.is_ok());
    }

    #[cfg(feature = "rocks")]
    #[test]
    fn test_atomic_unpause_on_error() {
        let rng = &mut TestRng::default();

        // Initialize a genesis private key..
        let genesis_private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize a VM and sample 2 blocks using it.
        let vm = sample_vm();
        vm.add_next_block(&genesis).unwrap();
        let block1 = sample_next_block(&vm, &genesis_private_key, &[], rng).unwrap();
        vm.add_next_block(&block1).unwrap();
        let block2 = sample_next_block(&vm, &genesis_private_key, &[], rng).unwrap();

        // Create a new, rocks-based VM shadowing the 1st one.
        let vm = sample_vm();
        vm.add_next_block(&genesis).unwrap();
        // This time, however, try to insert the 2nd block first, which fails due to height.
        assert!(vm.add_next_block(&block2).is_err());

        // It should still be possible to insert the 1st block afterwards.
        vm.add_next_block(&block1).unwrap();
    }

    #[test]
    fn test_dependent_deployments_in_same_block() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        vm.add_next_block(&genesis).unwrap();

        // Fund two accounts to pay for the deployment.
        // This has to be done because only one deployment can be made per fee-paying address per block.
        let private_key_1 = PrivateKey::new(rng).unwrap();
        let private_key_2 = PrivateKey::new(rng).unwrap();
        let address_1 = Address::try_from(&private_key_1).unwrap();
        let address_2 = Address::try_from(&private_key_2).unwrap();

        let tx_1 = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public"),
                [Value::from_str(&format!("{address_1}")).unwrap(), Value::from_str("100000000u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let tx_2 = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public"),
                [Value::from_str(&format!("{address_2}")).unwrap(), Value::from_str("100000000u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        let block = sample_next_block(&vm, &caller_private_key, &[tx_1, tx_2], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 2);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();

        // Deploy two programs that depend on each other.
        let program_1 = Program::from_str(
            r"
program child_program.aleo;

function adder:
    input r0 as u64.public;
    input r1 as u64.public;
    add r0 r1 into r2;
    output r2 as u64.public;
        ",
        )
        .unwrap();

        let program_2 = Program::from_str(
            r"
import child_program.aleo;

program parent_program.aleo;

function adder:
    input r0 as u64.public;
    input r1 as u64.public;
    call child_program.aleo/adder r0 r1 into r2;
    output r2 as u64.public;
        ",
        )
        .unwrap();

        // Initialize an "off-chain" VM to generate the deployments.
        let off_chain_vm = sample_vm();
        off_chain_vm.add_next_block(&genesis).unwrap();
        off_chain_vm.add_next_block(&block).unwrap();
        // Deploy the first program.
        let deployment_1 = off_chain_vm.deploy(&private_key_1, &program_1, None, 0, None, rng).unwrap();
        // Check that the account has enough to pay for the deployment.
        assert_eq!(*deployment_1.fee_amount().unwrap(), 2483025);
        // Add the first program to the off-chain VM.
        off_chain_vm.process().lock().add_program(&program_1).unwrap();
        // Deploy the second program.
        let deployment_2 = off_chain_vm.deploy(&private_key_2, &program_2, None, 0, None, rng).unwrap();
        // Check that the account has enough to pay for the deployment.
        assert_eq!(*deployment_2.fee_amount().unwrap(), 2659575);
        // Drop the off-chain VM.
        drop(off_chain_vm);

        let block = sample_next_block(&vm, &caller_private_key, &[deployment_1, deployment_2], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 1);
        vm.add_next_block(&block).unwrap();

        // Check that only `child_program.aleo` is in the VM.
        assert!(vm.process().contains_program(&ProgramID::from_str("child_program.aleo").unwrap()));
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_versioned_keyword_restrictions() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the VM at a specific height.
        // We subtract by 7 to deploy the 7 invalid programs.
        let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V6).unwrap() - 7, rng);

        // Define the invalid program bodies.
        let invalid_program_bodies = [
            "function constructor:",
            "function dummy:\nclosure constructor: input r0 as u8; assert.eq r0 0u8;",
            "function dummy:\nmapping constructor: key as boolean.public; value as boolean.public;",
            "function dummy:\nrecord constructor: owner as address.private;",
            "function dummy:\nrecord foo: owner as address.public; constructor as address.public;",
            "function dummy:\nstruct constructor: foo as address;",
            "function dummy:\nstruct foo: constructor as address;",
        ];

        println!("Current height: {}", vm.block_store().current_block_height());

        // Deploy a test program for each of the invalid program bodies.
        // They should all be accepted by the VM, because the restriction is not yet in place.
        for (i, body) in invalid_program_bodies.iter().enumerate() {
            println!("Deploying 'valid' test program {i}: {body}");
            let program = Program::from_str(&format!("program test_valid_{i}.aleo;\n{body}")).unwrap();
            let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
            let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
            assert_eq!(block.transactions().num_accepted(), 1);
            assert_eq!(block.transactions().num_rejected(), 0);
            assert_eq!(block.aborted_transaction_ids().len(), 0);
            vm.add_next_block(&block).unwrap();
        }

        println!("Current height: {}", vm.block_store().current_block_height());

        // Deploy a test program for each of the invalid program bodies.
        // Verify that `check_transaction` fails for each of them.
        for (i, body) in invalid_program_bodies.iter().enumerate() {
            println!("Deploying 'invalid' test program {i}: {body}");
            let program = Program::from_str(&format!("program test_invalid_{i}.aleo;\n{body}")).unwrap();
            let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
            if let Err(e) = vm.check_transaction(&deployment, None, rng) {
                println!("Error: {e}");
            } else {
                panic!("Expected an error, but the deployment was accepted.")
            }
        }

        // Attempt to deploy a program with the name `constructor`.
        // Verify that `check_transaction` fails.
        let program = Program::from_str(r"program constructor.aleo; function dummy:").unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        if let Err(e) = vm.check_transaction(&deployment, None, rng) {
            println!("Error: {e}");
        } else {
            panic!("Expected an error, but the deployment was accepted.")
        }
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_deploy_and_execute_in_same_block_fails() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        vm.add_next_block(&genesis).unwrap();

        // Deploy and execute a program in the same block.
        let program = Program::from_str(
            r"
program adder_program.aleo;
function adder:
    input r0 as u64.public;
    input r1 as u64.public;
    add r0 r1 into r2;
    output r2 as u64.public;
        ",
        )
        .unwrap();

        // Initialize an "off-chain" VM to generate the deployment and execution.
        let off_chain_vm = sample_vm();
        off_chain_vm.add_next_block(&genesis).unwrap();
        // Deploy the program.
        let deployment = off_chain_vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        // Check that the account has enough to pay for the deployment.
        assert_eq!(*deployment.fee_amount().unwrap(), 2483025);
        // Add the program to the off-chain VM.
        off_chain_vm.process().lock().add_program(&program).unwrap();
        // Execute the program.
        let transaction = off_chain_vm
            .execute(
                &caller_private_key,
                ("adder_program.aleo", "adder"),
                [Value::from_str("1u64").unwrap(), Value::from_str("2u64").unwrap()].iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        // Verify the transaction.
        off_chain_vm.check_transaction(&transaction, None, rng).unwrap();
        // Check that the account has enough to pay for the execution.
        assert_eq!(*transaction.fee_amount().unwrap(), 1283);
        // Drop the off-chain VM.
        drop(off_chain_vm);

        let block = sample_next_block(&vm, &caller_private_key, &[deployment, transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 1);
        vm.add_next_block(&block).unwrap();

        // Check that the program was deployed.
        assert!(vm.process().contains_program(&ProgramID::from_str("adder_program.aleo").unwrap()));
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_deploy_string() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

        // Initialize the VM at consensus version 11.
        let vm = crate::vm::test_helpers::sample_vm_at_height(
            CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V11).unwrap(),
            rng,
        );

        // Deploy and execute a program in the same block.
        let program = |i: u32| {
            Program::from_str(&format!(
                r#"
program strings_{i}.aleo;

mapping foo:
    key as string.public;
    value as string.public;

mapping test:
    key as string.public;
    value as [boolean; 1u32].public;

function dummy:
    input r0 as string.public;
    input r1 as string.private;
    input r2 as string.private;
    assert.eq "hello_friend" "hello_friend";
    assert.neq r1 r2;
    async dummy r0 r1 r2 into r3;
    hash.bhp256 "hello" into r4 as address;
    output r3 as strings_{i}.aleo/dummy.future;

finalize dummy:
    input r0 as string.public;
    input r1 as string.public;
    input r2 as string.public;
    assert.eq "hello_friend" "hello_friend";
    assert.neq r1 r2;
    get.or_use foo[r1] r0 into r3;
    set r2 into foo[r1];
    set "test" into foo[r2];
    set r2 into foo[r2];
    get foo[r1] into r4;
    assert.neq r3 r4;
    assert.eq r2 r4;
    assert.neq r0 r4;
    get.or_use foo[r1] "hello" into r5;

function dummy_with_array:
    input r0 as [string; 3u32].public;
    input r1 as [string; 4u32].private;
    async dummy_with_array r0 r1 "test" into r2;
    output r2 as strings_{i}.aleo/dummy_with_array.future;

finalize dummy_with_array:
    input r0 as [string; 3u32].public;
    input r1 as [string; 4u32].public;
    input r2 as string.public;
    set r2 into foo[r2];

constructor:
    assert.eq true true;
        "#
            ))
            .unwrap()
        };

        // Deploy the program.
        let _deployment = vm.deploy(&caller_private_key, &program(0), None, 0, None, rng).unwrap();
        // Check the deployment.
        // NOTE: this will only consistently pass if string sampling is updated.
        // vm.check_transaction(&deployment, None, rng).unwrap();

        // let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        // assert_eq!(block.transactions().num_accepted(), 1);
        // assert_eq!(block.transactions().num_rejected(), 0);
        // assert_eq!(block.aborted_transaction_ids().len(), 0);
        // vm.add_next_block(&block).unwrap();

        // // Check that the program was deployed.
        // assert!(vm.process().contains_program(&ProgramID::from_str("strings_0.aleo").unwrap()));

        // let hello_literal = Literal::String(StringType::new("hello"));
        // let hello_friend_literal = Literal::String(StringType::new("hello_friend"));
        // let hello_friends_literal = Literal::String(StringType::new("hello_friends"));

        // // Execution test 1
        // let hello_friend_1 = Value::from(hello_friend_literal.clone());
        // let hello_friend_2 = Value::from(hello_friend_literal.clone());
        // let hello_friends = Value::from(hello_friends_literal.clone());

        // // Execute the program.
        // let transaction = vm
        //     .execute(
        //         &caller_private_key,
        //         ("strings_0.aleo", "dummy"),
        //         [hello_friend_1, hello_friend_2, hello_friends].iter(),
        //         None,
        //         0,
        //         None,
        //         rng,
        //     )
        //     .unwrap();
        // // Verify the transaction.
        // vm.check_transaction(&transaction, None, rng).unwrap();

        // let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
        // assert_eq!(block.transactions().num_accepted(), 1);
        // assert_eq!(block.transactions().num_rejected(), 0);
        // assert_eq!(block.aborted_transaction_ids().len(), 0);
        // vm.add_next_block(&block).unwrap();

        // // Execution test 2: change the public type
        // let hello = Value::from(hello_literal.clone());
        // let hello_friend = Value::from(hello_friend_literal.clone());
        // let hello_friends = Value::from(hello_friends_literal.clone());

        // // Execute the program.
        // let transaction = vm.execute(
        //     &caller_private_key,
        //     ("strings_0.aleo", "dummy"),
        //     [hello, hello_friend, hello_friends].iter(),
        //     None,
        //     0,
        //     None,
        //     rng,
        // );
        // assert!(transaction.is_err());

        // // Execution test 3: change the private type
        // let hello_friend_1 = Value::from(hello_friend_literal.clone());
        // let hello_friend_2 = Value::from(hello_friend_literal.clone());
        // let hello = Value::from(hello_literal.clone());

        // // Execute the program.
        // let transaction = vm.execute(
        //     &caller_private_key,
        //     ("strings_0.aleo", "dummy"),
        //     [hello_friend_1, hello_friend_2, hello].iter(),
        //     None,
        //     0,
        //     None,
        //     rng,
        // );
        // assert!(transaction.is_err());

        // // Deploy another program.
        // let deployment = vm.deploy(&caller_private_key, &program(1), None, 0, None, rng).unwrap();
        // // Check the deployment.
        // assert!(vm.check_transaction(&deployment, None, rng).is_err());

        // let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        // assert_eq!(block.transactions().num_accepted(), 0);
        // assert_eq!(block.transactions().num_rejected(), 0);
        // assert_eq!(block.aborted_transaction_ids().len(), 1);
        // vm.add_next_block(&block).unwrap();

        // // Check that the program was notdeployed.
        // assert!(!vm.process().contains_program(&ProgramID::from_str("strings_1.aleo").unwrap()));
    }
}
