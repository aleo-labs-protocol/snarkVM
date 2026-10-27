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

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]

extern crate snarkvm_console as console;

#[macro_use]
extern crate tracing;

pub use snarkvm_ledger_authority as authority;
pub use snarkvm_ledger_block as block;
pub use snarkvm_ledger_committee as committee;
pub use snarkvm_ledger_narwhal as narwhal;
pub use snarkvm_ledger_puzzle as puzzle;
pub use snarkvm_ledger_query as query;
pub use snarkvm_ledger_store as store;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

mod error;
pub use error::*;

mod helpers;
pub use helpers::*;

pub use crate::block::*;

mod check_next_block;
pub use check_next_block::{CheckBlockError, PendingBlock};

mod advance;
mod check_transaction_basic;
mod contains;
mod find;
mod get;
mod is_solution_limit_reached;
mod iterators;

#[cfg(test)]
mod tests;

use console::{
    account::{Address, GraphKey, PrivateKey, ViewKey},
    network::prelude::*,
    program::{Ciphertext, Entry, Identifier, Literal, Plaintext, ProgramID, Record, StatePath, Value},
    types::{Field, Group},
};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_committee::Committee;
use snarkvm_ledger_narwhal::{BatchCertificate, Subdag, Transmission, TransmissionID};
use snarkvm_ledger_puzzle::{Puzzle, PuzzleSolutions, Solution, SolutionID};
use snarkvm_ledger_query::QueryTrait;
use snarkvm_ledger_store::{ConsensusStorage, ConsensusStore};
use snarkvm_synthesizer::{
    program::{FinalizeGlobalState, Program},
    vm::VM,
};

use aleo_std::{
    StorageMode,
    prelude::{finish, lap, timer},
};
use anyhow::{Context, Result};
use cfg_if::cfg_if;
use core::ops::Range;
use indexmap::IndexMap;
#[cfg(feature = "locktick")]
use locktick::parking_lot::{Mutex, RwLock};
use lru::LruCache;
#[cfg(not(feature = "locktick"))]
use parking_lot::{Mutex, RwLock};
use rand::prelude::IteratorRandom;
use std::{borrow::Cow, collections::HashSet, sync::Arc};
use time::OffsetDateTime;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

pub type RecordMap<N> = IndexMap<Field<N>, Record<N, Plaintext<N>>>;

/// The capacity of the LRU cache holding the recently queried committees.
const COMMITTEE_CACHE_SIZE: usize = 16;

/// Options describing the deterministic dev committee to install on a [`Ledger`].
///
/// Installs an override that is returned by [`Ledger::get_committee_for_round`]
/// and [`Ledger::get_committee_lookback_for_round`] for any round at or after
/// the resolved start round.
///
/// This is used by devnet deployments that hot-swap the on-chain mainnet
/// committee with a deterministic dev committee on top of a mainnet snapshot.
/// Without it, validators that fall behind enough to enter `BlockSync` (and
/// therefore go through `check_block_subdag_quorum`) would look up the mainnet
/// committee at the lookback round and reject the dev-signed certificates.
#[cfg(feature = "dev-committee")]
#[derive(Clone, Copy, Debug)]
pub struct DevCommitteeOptions {
    /// The round the committee was swapped.
    /// If none is set, the latest round in the ledger is chosen.
    pub start_round: Option<u64>,
    /// Number of members in the dev committee.
    pub dev_num_validators: u16,
    /// Seed used to deterministically derive the dev committee's keys.
    ///
    /// Every node in a devnet deployment must use the same value, or their
    /// committees won't match. Callers can pass a project-wide constant such
    /// as `snarkos_utilities::DEVELOPMENT_MODE_RNG_SEED`.
    pub seed: u64,
}

/// Deterministically builds the dev committee from the given parameters.
///
/// Every member is given equal stake (`MIN_VALIDATOR_STAKE`). Two callers that
/// pass the same `(start_round, dev_num_validators, seed)` get bitwise-
/// identical committees.
#[cfg(feature = "dev-committee")]
pub fn build_dev_committee<N: Network>(start_round: u64, dev_num_validators: u16, seed: u64) -> Result<Committee<N>> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaChaRng::seed_from_u64(seed);
    let dev_keys = (0..dev_num_validators).map(|_| PrivateKey::<N>::new(&mut rng)).collect::<Result<Vec<_>>>()?;
    let members = dev_keys
        .iter()
        .map(Address::<N>::try_from)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|address| (address, (snarkvm_ledger_committee::MIN_VALIDATOR_STAKE, true, 0)))
        .collect::<IndexMap<_, _>>();
    Committee::new(start_round, members)
}

#[derive(Copy, Clone, Debug)]
pub enum RecordsFilter<N: Network> {
    /// Returns all records associated with the account.
    All,
    /// Returns only records associated with the account that are **spent** with the graph key.
    Spent,
    /// Returns only records associated with the account that are **not spent** with the graph key.
    Unspent,
    /// Returns all records associated with the account that are **spent** with the given private key.
    SlowSpent(PrivateKey<N>),
    /// Returns all records associated with the account that are **not spent** with the given private key.
    SlowUnspent(PrivateKey<N>),
}

/// State of the entire chain.
///
/// All stored state is held in the `VM`, while Ledger holds the `VM` and relevant cache data.
///
/// The constructor is [`Ledger::load`],
/// which loads the ledger from storage,
/// or initializes it with the genesis block if the storage is empty
#[derive(Clone)]
pub struct Ledger<N: Network, C: ConsensusStorage<N>>(Arc<InnerLedger<N, C>>);

impl<N: Network, C: ConsensusStorage<N>> Deref for Ledger<N, C> {
    type Target = InnerLedger<N, C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[doc(hidden)]
pub struct InnerLedger<N: Network, C: ConsensusStorage<N>> {
    /// The VM state.
    vm: VM<N, C>,
    /// The genesis block.
    genesis_block: Block<N>,

    /// The current epoch hash.
    current_epoch_hash: RwLock<Option<N::BlockHash>>,

    /// The committee resulting from all the on-chain staking activity.
    ///
    /// This includes any bonding and unbonding transactions in the latest block.
    /// The starting point, in the genesis block, is the genesis committee.
    /// If the latest block has round `R`, `current_committee` is
    /// the committee bonded for rounds `R+1`, `R+2`, and perhaps others
    /// (unless a block at round `R+2` changes the committee).
    /// Note that this committee is not active (i.e. in charge of running consensus)
    /// until round `R + 1 + L`, where `L` is the lookback round distance.
    ///
    /// This committee is always well-defined
    /// (in particular, it is the genesis committee when the `Ledger` is empty, or only has the genesis block).
    /// So the `Option` should always be `Some`,
    /// but there are cases in which it is `None`,
    /// probably only temporarily when loading/initializing the ledger,
    current_committee: RwLock<Option<Committee<N>>>,

    /// The latest block that was added to the ledger.
    ///
    /// This lock is also to ensure *atomicity* of calls to `[Ledger::advance`], i.e., to guarantee that
    /// there cannot be multiple concurrent ledger advancements and that ledger state cannot be read while advancement happens.
    current_block: RwLock<Block<N>>,

    /// The recent committees of interest paired with their applicable rounds.
    ///
    /// Each entry consisting of a round `R` and a committee `C`,
    /// says that `C` is the bonded committee at round `R`,
    /// i.e. resulting from all the bonding and unbonding transactions before `R`.
    /// If `L` is the lookback round distance, `C` is the active committee at round `R + L`
    /// (i.e. the committee in charge of running consensus at round `R + L`).
    committee_cache: Mutex<LruCache<u64, Committee<N>>>,
    /// The cache that holds the provers and the number of solutions they have submitted for the current epoch.
    epoch_provers_cache: Arc<RwLock<IndexMap<Address<N>, u32>>>,

    /// Optional dev committee, returned for any round `>= committee.starting_round()`.
    ///
    /// See [`DevCommitteeOptions`] for details. This is only consulted by the
    /// round-based committee lookups; the height-based lookups and the
    /// on-chain `current_committee` continue to read from the finalize store.
    #[cfg(feature = "dev-committee")]
    dev_committee: Option<Committee<N>>,
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Loads the ledger from storage.
    pub fn load(genesis_block: Block<N>, storage_mode: StorageMode) -> Result<Self> {
        let timer = timer!("Ledger::load");

        // Retrieve the genesis hash.
        let genesis_hash = genesis_block.hash();
        // Initialize the ledger.
        let ledger = Self::load_unchecked(genesis_block, storage_mode)?;

        // Ensure the ledger contains the correct genesis block.
        if !ledger.contains_block_hash(&genesis_hash)? {
            bail!("Incorrect genesis block (run 'snarkos clean' and try again)")
        }

        // Spot check the integrity of `NUM_BLOCKS` random blocks upon bootup.
        const NUM_BLOCKS: usize = 10;
        // Retrieve the latest height.
        let latest_height = ledger.current_block.read().height();
        debug_assert_eq!(latest_height, ledger.vm.block_store().max_height().unwrap(), "Mismatch in latest height");
        // Sample random block heights.
        let block_heights: Vec<u32> =
            (0..=latest_height).sample(&mut rand::rng(), (latest_height as usize).min(NUM_BLOCKS));
        cfg_into_iter!(block_heights).try_for_each(|height| {
            ledger.get_block(height)?;
            Ok::<_, Error>(())
        })?;
        lap!(timer, "Check existence of {NUM_BLOCKS} random blocks");

        finish!(timer);
        Ok(ledger)
    }

    /// Loads the ledger from storage, without performing integrity checks.
    pub fn load_unchecked(genesis_block: Block<N>, storage_mode: StorageMode) -> Result<Self> {
        cfg_if! {
            if #[cfg(feature="dev-committee")] {
                Self::load_unchecked_inner(genesis_block, storage_mode, None)
            } else {
                Self::load_unchecked_inner(genesis_block, storage_mode)
            }
        }
    }

    /// Like [`Self::load`], but installs a dev committee override that is
    /// returned by [`Self::get_committee_for_round`] and
    /// [`Self::get_committee_lookback_for_round`] for any round at or after
    /// `dev_committee.start_round`. See [`DevCommitteeOptions`].
    #[cfg(feature = "dev-committee")]
    pub fn load_with_dev_committee(
        genesis_block: Block<N>,
        storage_mode: StorageMode,
        dev_committee_opts: DevCommitteeOptions,
    ) -> Result<Self> {
        let timer = timer!("Ledger::load_with_dev_committee");

        // Retrieve the genesis hash.
        let genesis_hash = genesis_block.hash();
        // Initialize the ledger.
        let ledger = Self::load_unchecked_with_dev_committee(genesis_block, storage_mode, dev_committee_opts)?;

        // Ensure the ledger contains the correct genesis block.
        if !ledger.contains_block_hash(&genesis_hash)? {
            bail!("Incorrect genesis block (run 'snarkos clean' and try again)")
        }

        // Spot check the integrity of `NUM_BLOCKS` random blocks upon bootup.
        const NUM_BLOCKS: usize = 10;
        let latest_height = ledger.current_block.read().height();
        debug_assert_eq!(latest_height, ledger.vm.block_store().max_height().unwrap(), "Mismatch in latest height");
        let block_heights: Vec<u32> =
            (0..=latest_height).sample(&mut rand::rng(), (latest_height as usize).min(NUM_BLOCKS));
        cfg_into_iter!(block_heights).try_for_each(|height| {
            ledger.get_block(height)?;
            Ok::<_, Error>(())
        })?;
        lap!(timer, "Check existence of {NUM_BLOCKS} random blocks");

        finish!(timer);
        Ok(ledger)
    }

    /// Like [`Self::load_unchecked`], but installs a dev committee override.
    #[cfg(feature = "dev-committee")]
    pub fn load_unchecked_with_dev_committee(
        genesis_block: Block<N>,
        storage_mode: StorageMode,
        dev_committee_opts: DevCommitteeOptions,
    ) -> Result<Self> {
        Self::load_unchecked_inner(genesis_block, storage_mode, Some(dev_committee_opts))
    }

    fn load_unchecked_inner(
        genesis_block: Block<N>,
        storage_mode: StorageMode,
        #[cfg(feature = "dev-committee")] dev_committee_opts: Option<DevCommitteeOptions>,
    ) -> Result<Self> {
        let timer = timer!("Ledger::load_unchecked");

        info!("Loading the ledger from storage...");
        // Initialize the consensus store.
        let store = match ConsensusStore::<N, C>::open(storage_mode) {
            Ok(store) => store,
            Err(e) => bail!("Failed to load ledger (run 'snarkos clean' and try again)\n\n{e}\n"),
        };
        lap!(timer, "Load consensus store");

        // Initialize a new VM.
        let vm = VM::from(store)?;
        lap!(timer, "Initialize a new VM");

        // Retrieve the current committee.
        let current_committee = vm.finalize_store().committee_store().current_committee().ok();
        // Create a committee cache.
        let committee_cache = Mutex::new(LruCache::new(COMMITTEE_CACHE_SIZE.try_into().unwrap()));

        // If a dev committee override was requested, resolve its start round
        // (defaulting to the round of the latest block in storage, or the
        // genesis round when storage is empty) and build the committee now,
        // before the `InnerLedger` is constructed.
        #[cfg(feature = "dev-committee")]
        let dev_committee = match dev_committee_opts {
            Some(opts) => {
                let start_round = if let Some(round) = opts.start_round {
                    round
                } else {
                    match vm.block_store().max_height() {
                        Some(h) => {
                            let hash = vm
                                .block_store()
                                .get_block_hash(h)?
                                .ok_or_else(|| anyhow!("Missing block hash at height {h}"))?;
                            let block = vm
                                .block_store()
                                .get_block(&hash)?
                                .ok_or_else(|| anyhow!("Missing block at height {h}"))?;
                            block.round()
                        }
                        None => genesis_block.round(),
                    }
                };

                Some(build_dev_committee::<N>(start_round, opts.dev_num_validators, opts.seed)?)
            }
            None => None,
        };

        // Initialize the ledger.
        let ledger = Self(Arc::new(InnerLedger {
            vm,
            genesis_block: genesis_block.clone(),
            current_epoch_hash: Default::default(),
            current_committee: RwLock::new(current_committee),
            current_block: RwLock::new(genesis_block.clone()),
            committee_cache,
            epoch_provers_cache: Default::default(),
            #[cfg(feature = "dev-committee")]
            dev_committee,
        }));

        // Attempt to obtain the maximum height from the storage.
        let max_stored_height = ledger.vm.block_store().max_height();

        // If the block store is empty, add the genesis block.
        let latest_height = if let Some(max_height) = max_stored_height {
            max_height
        } else {
            ledger.advance_to_next_block(&genesis_block)?;
            0
        };
        lap!(timer, "Initialize genesis");

        // Ensure that the greatest stored height matches that of the block tree.
        let tree_derived_block_height = ledger.vm().block_store().current_block_height();
        ensure!(
            latest_height == tree_derived_block_height,
            "The stored height ({latest_height}) is different than the one in \
            the block tree ({tree_derived_block_height}); please ensure that \
            the cached block tree is valid or delete the 'block_tree' file from \
            the ledger folder"
        );

        // Verify that the root of the cached block tree matches the one in the storage.
        let tree_root = <N::StateRoot>::from(ledger.vm().block_store().get_block_tree_root());
        // Height 0 stores `Field::one()` as its state root.
        #[cfg(feature = "dev_genesis_state_root")]
        let tree_root = if latest_height == 0 { Field::<N>::one().into() } else { tree_root };
        let state_root = ledger
            .vm()
            .block_store()
            .get_state_root(latest_height)?
            .ok_or_else(|| anyhow!("Missing state root in the storage"))?;
        ensure!(
            tree_root == state_root,
            "The stored state root is different than the one in the block tree;
            please ensure that the cached block tree is valid or delete the \
            'block_tree' file from the ledger folder"
        );

        // Fetch the latest block.
        let block = ledger
            .get_block(latest_height)
            .with_context(|| format!("Failed to load block {latest_height} from the ledger"))?;

        // Set the current block.
        *ledger.current_block.write() = block;
        // Set the current committee (and ensures the latest committee exists).
        *ledger.current_committee.write() = Some(ledger.latest_committee()?);
        // Set the current epoch hash.
        *ledger.current_epoch_hash.write() = Some(ledger.get_epoch_hash(latest_height)?);
        // Set the epoch prover cache.
        *ledger.epoch_provers_cache.write() = ledger.load_epoch_provers();

        finish!(timer, "Initialize ledger");
        Ok(ledger)
    }
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns the installed dev committee, if any.
    ///
    /// The committee is determined at load time by
    /// [`Ledger::load_with_dev_committee`] (or its `unchecked` variant) and is
    /// immutable thereafter.
    #[cfg(feature = "dev-committee")]
    pub fn dev_committee(&self) -> Option<&Committee<N>> {
        self.dev_committee.as_ref()
    }

    /// Creates a rocksdb checkpoint in the specified directory, which needs to not exist at the
    /// moment of calling. The checkpoints are based on hard links, which means they can both be
    /// incremental (i.e. they aren't full physical copies), and used as full rollback points
    /// (a checkpoint can be used to completely replace the original ledger).
    #[cfg(feature = "rocks")]
    pub fn backup_database<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        self.vm.block_store().backup_database(path).map_err(|err| anyhow!(err))
    }

    #[cfg(feature = "rocks")]
    pub fn cache_block_tree(&self) -> Result<()> {
        self.vm.block_store().cache_block_tree()
    }

    /// Loads the provers and the number of solutions they have submitted for the current epoch.
    pub fn load_epoch_provers(&self) -> IndexMap<Address<N>, u32> {
        // Fetch the current block height.
        let current_block_height = self.vm().block_store().current_block_height();

        // Determine the first block to start checking.
        // Note that the epoch boundary (where current_block_height % N::NUM_BLOCKS_PER_EPOCH == 0) can contain solutions
        // for the previous epoch X. The subsequent block is the first block to contain solutions for the current epoch X+1.
        let next_block_height = current_block_height.saturating_add(1);
        let start = next_block_height.saturating_sub(current_block_height % N::NUM_BLOCKS_PER_EPOCH);

        // If the epoch contains no blocks that have solutions for the epoch.
        if start > current_block_height {
            return IndexMap::new();
        }

        // Collect the addresses of the solutions submitted in the current epoch.
        let existing_epoch_blocks: Vec<_> = (start..=current_block_height).collect();
        let solution_addresses = cfg_iter!(existing_epoch_blocks)
            .flat_map(|height| match self.get_solutions(*height).as_deref() {
                Ok(Some(solutions)) => solutions.iter().map(|(_, s)| s.address()).collect::<Vec<_>>(),
                _ => vec![],
            })
            .collect::<Vec<_>>();

        // Count the number of occurrences of each address in the epoch blocks.
        let mut epoch_provers = IndexMap::new();
        for address in solution_addresses {
            epoch_provers.entry(address).and_modify(|e| *e += 1).or_insert(1);
        }
        epoch_provers
    }

    /// Returns the VM.
    pub fn vm(&self) -> &VM<N, C> {
        &self.vm
    }

    /// Returns the puzzle.
    pub fn puzzle(&self) -> &Puzzle<N> {
        self.vm.puzzle()
    }

    /// Returns the size of the block cache (or `None` if the block cache is not enabled).
    pub fn block_cache_size(&self) -> Option<u32> {
        self.vm.block_store().cache_size()
    }

    /// Returns the provers and the number of solutions they have submitted for the current epoch.
    pub fn epoch_provers(&self) -> Arc<RwLock<IndexMap<Address<N>, u32>>> {
        self.epoch_provers_cache.clone()
    }

    /// Returns the latest committee,
    /// i.e. the committee resulting from all the on-chain staking activity.
    pub fn latest_committee(&self) -> Result<Committee<N>> {
        match self.current_committee.read().as_ref() {
            Some(committee) => Ok(committee.clone()),
            None => self.vm.finalize_store().committee_store().current_committee(),
        }
    }

    /// Returns the latest state root.
    pub fn latest_state_root(&self) -> N::StateRoot {
        self.vm.block_store().current_state_root()
    }

    /// Returns the latest epoch number.
    pub fn latest_epoch_number(&self) -> u32 {
        self.current_block.read().height() / N::NUM_BLOCKS_PER_EPOCH
    }

    /// Returns the latest epoch hash.
    pub fn latest_epoch_hash(&self) -> Result<N::BlockHash> {
        match self.current_epoch_hash.read().as_ref() {
            Some(epoch_hash) => Ok(*epoch_hash),
            None => self.get_epoch_hash(self.latest_height()),
        }
    }

    /// Returns the latest block.
    pub fn latest_block(&self) -> Block<N> {
        self.current_block.read().clone()
    }

    /// Returns the latest round number.
    pub fn latest_round(&self) -> u64 {
        self.current_block.read().round()
    }

    /// Returns the latest block height.
    pub fn latest_height(&self) -> u32 {
        self.current_block.read().height()
    }

    /// Returns the latest block hash.
    pub fn latest_hash(&self) -> N::BlockHash {
        self.current_block.read().hash()
    }

    /// Returns the latest block header.
    pub fn latest_header(&self) -> Header<N> {
        *self.current_block.read().header()
    }

    /// Returns the latest block cumulative weight.
    pub fn latest_cumulative_weight(&self) -> u128 {
        self.current_block.read().cumulative_weight()
    }

    /// Returns the latest block cumulative proof target.
    pub fn latest_cumulative_proof_target(&self) -> u128 {
        self.current_block.read().cumulative_proof_target()
    }

    /// Returns the latest block solutions root.
    pub fn latest_solutions_root(&self) -> Field<N> {
        self.current_block.read().header().solutions_root()
    }

    /// Returns the latest block coinbase target.
    pub fn latest_coinbase_target(&self) -> u64 {
        self.current_block.read().coinbase_target()
    }

    /// Returns the latest block proof target.
    pub fn latest_proof_target(&self) -> u64 {
        self.current_block.read().proof_target()
    }

    /// Returns the last coinbase target.
    pub fn last_coinbase_target(&self) -> u64 {
        self.current_block.read().last_coinbase_target()
    }

    /// Returns the last coinbase timestamp.
    pub fn last_coinbase_timestamp(&self) -> i64 {
        self.current_block.read().last_coinbase_timestamp()
    }

    /// Returns the latest block timestamp.
    pub fn latest_timestamp(&self) -> i64 {
        self.current_block.read().timestamp()
    }

    /// Returns the latest block transactions.
    pub fn latest_transactions(&self) -> Transactions<N> {
        self.current_block.read().transactions().clone()
    }
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns the unspent `credits.aleo` records.
    pub fn find_unspent_credits_records(&self, view_key: &ViewKey<N>) -> Result<RecordMap<N>> {
        let microcredits = Identifier::from_str("microcredits")?;
        Ok(self
            .find_records(view_key, RecordsFilter::Unspent)?
            .filter(|(_, record)| {
                // TODO (raychu86): Find cleaner approach and check that the record is associated with the `credits.aleo` program
                match record.data().get(&microcredits) {
                    Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                    _ => false,
                }
            })
            .collect::<IndexMap<_, _>>())
    }

    /// Creates a deploy transaction.
    ///
    /// The `priority_fee_in_microcredits` is an additional fee **on top** of the deployment fee.
    pub fn create_deploy<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        program: &Program<N>,
        priority_fee_in_microcredits: u64,
        query: Option<&dyn QueryTrait<N>>,
        rng: &mut R,
    ) -> Result<Transaction<N>, CreateDeployError> {
        // Fetch the unspent records.
        let records = self.find_unspent_credits_records(&ViewKey::try_from(private_key)?)?;
        if records.len().is_zero() {
            return Err(anyhow!("The Aleo account has no records to spend.").into());
        }
        let mut records = records.values();

        // Prepare the fee record.
        let fee_record = Some(records.next().unwrap().clone());

        // Create a new deploy transaction.
        Ok(self.vm.deploy(private_key, program, fee_record, priority_fee_in_microcredits, query, rng)?)
    }

    /// Creates a transfer transaction.
    ///
    /// The `priority_fee_in_microcredits` is an additional fee **on top** of the execution fee.
    pub fn create_transfer<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        to: Address<N>,
        amount_in_microcredits: u64,
        priority_fee_in_microcredits: u64,
        query: Option<&dyn QueryTrait<N>>,
        rng: &mut R,
    ) -> Result<Transaction<N>, CreateTransferError> {
        // Fetch the unspent records.
        let records = self.find_unspent_credits_records(&ViewKey::try_from(private_key)?)?;
        if records.len() < 2 {
            return Err(anyhow!("The Aleo account does not have enough records to spend.").into());
        }
        let mut records = records.values();

        // Prepare the inputs.
        let inputs = [
            Value::Record(records.next().unwrap().clone()),
            Value::from_str(&format!("{to}"))?,
            Value::from_str(&format!("{amount_in_microcredits}u64"))?,
        ];

        // Prepare the fee.
        let fee_record = Some(records.next().unwrap().clone());

        // Create a new execute transaction.
        Ok(self.vm.execute(
            private_key,
            ("credits.aleo", "transfer_private"),
            inputs.iter(),
            fee_record,
            priority_fee_in_microcredits,
            query,
            rng,
        )?)
    }
}

#[cfg(feature = "rocks")]
impl<N: Network, C: ConsensusStorage<N>> Drop for InnerLedger<N, C> {
    fn drop(&mut self) {
        // Cache the block tree in order to speed up the next startup; this operation
        // is guaranteed to conclude as long as the destructors are allowed to run
        // (a clean shutdown, panic = "unwind", an explicit call to `drop`, etc.).
        // At the moment this code is executed, the Ledger is guaranteed to be owned
        // exclusively by this method, so no other activity may interrupt it.
        if let Err(e) = self.vm.block_store().cache_block_tree() {
            error!("Couldn't cache the block tree: {e}");
        }
    }
}

pub mod prelude {
    pub use crate::{Ledger, authority, block, block::*, committee, helpers::*, narwhal, puzzle, query, store};
}
