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

use crate::{
    Block,
    Ledger,
    Transaction,
    Transmission,
    TransmissionID,
    narwhal::{BatchCertificate, BatchHeader, Subdag},
    puzzle::Solution,
    store::{ConsensusStore, helpers::memory::ConsensusMemory},
};
use snarkvm_console::{
    account::{Address, PrivateKey},
    network::MainnetV0,
    prelude::*,
};
use snarkvm_synthesizer::vm::VM;

use aleo_std::StorageMode;

use anyhow::{Context, Result};
use indexmap::{IndexMap, IndexSet};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;

pub type CurrentNetwork = MainnetV0;

#[cfg(not(feature = "rocks"))]
pub type LedgerType<N> = snarkvm_ledger_store::helpers::memory::ConsensusMemory<N>;
#[cfg(feature = "rocks")]
pub type LedgerType<N> = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<N>;

/// Helper to build chains with custom structures for testing.
pub struct TestChainBuilder<N: Network> {
    /// The keys of all validators.
    private_keys: Vec<PrivateKey<N>>,
    /// The underlying ledger.
    ledger: Ledger<N, ConsensusMemory<N>>,
    /// The round containing the leader certificate for the most recent block we generated.
    last_block_round: u64,
    /// The batch certificates of the last round we generated.
    round_to_certificates: HashMap<u64, IndexMap<usize, BatchCertificate<N>>>,
    /// The batch certificate of the last leader (if any).
    previous_leader_certificate: Option<BatchCertificate<N>>,
    /// The last round for each committee member where they created a batch.
    /// Invariant: for any validator i, last_batch[i] <= last_committed_batch[i]
    last_batch_round: HashMap<usize, u64>,
    /// The last batch of a validator that was included in a block.
    last_committed_batch_round: HashMap<usize, u64>,
    /// The start of the test chain.
    genesis_block: Block<N>,
}

/// Additional options you can pass to the builder when generating a set of blocks.
#[derive(Clone)]
pub struct GenerateBlocksOptions<N: Network> {
    /// Do not include votes to the previous leader certificate
    pub skip_votes: bool,
    /// Do not generate certificates for the specific node indices (to simulate a partition).
    pub skip_nodes: Vec<usize>,
    /// A flag indicating that a number of initial "placeholder blocks" should be baked
    /// wthout transactions in order to skip to the latest version of consensus.
    pub skip_to_current_version: bool,
    /// The number of validators.
    pub num_validators: usize,
    /// Preloaded transactions to populate the blocks with.
    pub transactions: Vec<Transaction<N>>,
    /// When set, [`TestChainBuilder::generate_blocks_with_opts`] assigns quorum block timestamps as
    /// `start`, `start + 1`, … instead of wall-clock time so chains match across processes.
    pub deterministic_block_timestamp_start: Option<i64>,
}

impl<N: Network> Default for GenerateBlocksOptions<N> {
    fn default() -> Self {
        Self {
            skip_votes: false,
            skip_nodes: Default::default(),
            skip_to_current_version: false,
            num_validators: 0,
            transactions: Default::default(),
            deterministic_block_timestamp_start: None,
        }
    }
}

/// Additional options you can pass to the builder when generating a single block.
/// Note: As of now, all certificates for this block will have the given timestamp and contain listed transmissions.
#[derive(Clone)]
pub struct GenerateBlockOptions<N: Network> {
    /// Do not include votes to the previous leader certificate
    pub skip_votes: bool,
    /// Do not generate certificates for the specific node indices (to simulate a partition).
    pub skip_nodes: Vec<usize>,
    /// The timestamp for this block.
    pub timestamp: i64,
    /// The transmissions to be included in the block.
    pub solutions: Vec<Solution<N>>,
    pub transactions: Vec<Transaction<N>>,
}

impl<N: Network> Default for GenerateBlockOptions<N> {
    fn default() -> Self {
        Self {
            skip_votes: false,
            skip_nodes: Default::default(),
            transactions: Default::default(),
            solutions: Default::default(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}

impl<N: Network> TestChainBuilder<N> {
    /// Generate a new committee and genesis block.
    pub fn initialize_components(committee_size: usize, rng: &mut TestRng) -> Result<(Vec<PrivateKey<N>>, Block<N>)> {
        // Sample the genesis private key.
        let private_key = PrivateKey::<N>::new(rng)?;

        // Initialize the store.
        let store = ConsensusStore::<_, ConsensusMemory<_>>::open(StorageMode::new_test(None))
            .with_context(|| "Failed to initialize consensus store")?;
        // Create a genesis block with a seeded RNG to reproduce the same genesis private keys.
        let seed: u64 = rng.random();
        trace!("Using seed {seed} and key {} for genesis RNG", private_key);
        let genesis_rng = &mut TestRng::from_seed(seed);
        let genesis_block = VM::from(store).unwrap().genesis_beacon(&private_key, genesis_rng)?;

        // Extract the private keys from the genesis committee by using the same RNG to sample private keys.
        let genesis_rng = &mut TestRng::from_seed(seed);
        let private_keys = (0..committee_size).map(|_| PrivateKey::new(genesis_rng).unwrap()).collect();

        trace!(
            "Generated genesis block ({}) and private keys for all {committee_size} committee members",
            genesis_block.hash()
        );

        Ok((private_keys, genesis_block))
    }

    /// Initialize the builder with the default quorum size.
    pub fn new(rng: &mut TestRng) -> Result<Self> {
        Self::new_with_quorum_size(4, rng)
    }

    /// Initialize the builder with the specified quorum size.
    pub fn new_with_quorum_size(num_validators: usize, rng: &mut TestRng) -> Result<Self> {
        let (private_keys, genesis) = Self::initialize_components(num_validators, rng)?;
        Self::from_components(private_keys, genesis)
    }

    /// Initialize the builder with the specified genesis block..
    /// Note: this function mirrors the way the private keys are sampled in snarkOS `fn parse_genesis`.
    pub fn new_with_quorum_size_and_genesis_block(num_validators: usize, genesis_path: String) -> Result<Self> {
        // Attempts to load the genesis block file.
        let buffer = std::fs::read(genesis_path)?;
        // Return the genesis block.
        let genesis = Block::from_bytes_le(&buffer)?;
        /// The development mode RNG seed.
        pub const DEVELOPMENT_MODE_RNG_SEED: u64 = 1234567890u64;
        // Initialize the (fixed) RNG.
        let mut rng = ChaChaRng::seed_from_u64(DEVELOPMENT_MODE_RNG_SEED);
        // Initialize the development private keys.
        let private_keys = (0..num_validators).map(|_| PrivateKey::new(&mut rng).unwrap()).collect();
        // Initialize the builder with the specified committee and genesis block.
        Self::from_components(private_keys, genesis)
    }

    /// Initialize the builder with the specified committee and genesis block
    pub fn from_components(private_keys: Vec<PrivateKey<N>>, genesis_block: Block<N>) -> Result<Self> {
        // Initialize the ledger with the genesis block.
        let ledger = Ledger::<N, ConsensusMemory<N>>::load(genesis_block.clone(), StorageMode::new_test(None))
            .with_context(|| "Failed to set up ledger for test chain")?;

        ensure!(ledger.genesis_block == genesis_block);

        Self::from_genesis(private_keys, genesis_block)
    }

    /// Initialize the builder with the specified committee and gensis block
    pub fn from_genesis(private_keys: Vec<PrivateKey<N>>, genesis_block: Block<N>) -> Result<Self> {
        // Initialize the ledger with the genesis block.
        let ledger = Ledger::<N, ConsensusMemory<N>>::load(genesis_block.clone(), StorageMode::new_test(None))
            .with_context(|| "Failed to set up ledger for test chain")?;

        Ok(Self {
            private_keys,
            ledger,
            genesis_block,
            last_batch_round: Default::default(),
            last_committed_batch_round: Default::default(),
            last_block_round: 0,
            round_to_certificates: Default::default(),
            previous_leader_certificate: Default::default(),
        })
    }

    /// Create multiple blocks, with fully-connected DAGs.
    pub fn generate_blocks(&mut self, num_blocks: usize, rng: &mut TestRng) -> Result<Vec<Block<N>>> {
        let num_validators = self.private_keys.len();

        self.generate_blocks_with_opts(num_blocks, GenerateBlocksOptions { num_validators, ..Default::default() }, rng)
    }

    /// Create multiple blocks, with additional parameters.
    ///
    /// # Panics
    /// This function panics if called from an async context.
    pub fn generate_blocks_with_opts(
        &mut self,
        num_blocks: usize,
        mut options: GenerateBlocksOptions<N>,
        rng: &mut TestRng,
    ) -> Result<Vec<Block<N>>> {
        assert!(num_blocks > 0, "Need to build at least one block");

        let mut result = vec![];
        let mut deterministic_ts = options.deterministic_block_timestamp_start;

        let mut next_block_timestamp = || -> i64 {
            match deterministic_ts {
                Some(t) => {
                    deterministic_ts = Some(t.saturating_add(1));
                    t
                }
                None => OffsetDateTime::now_utc().unix_timestamp(),
            }
        };

        // If configured, skip enough blocks to reach the current consensus version.
        if options.skip_to_current_version {
            let (version, target_height) = TEST_CONSENSUS_VERSION_HEIGHTS.last().unwrap();
            let mut current_height = self.ledger.latest_height();

            let diff = target_height.saturating_sub(current_height);

            if diff > 0 {
                println!("Skipping {diff} blocks to reach {version}");

                while current_height < *target_height && result.len() < num_blocks {
                    let options = GenerateBlockOptions {
                        skip_votes: options.skip_votes,
                        skip_nodes: options.skip_nodes.clone(),
                        timestamp: next_block_timestamp(),
                        ..Default::default()
                    };

                    let block = self.generate_block_with_opts(options, rng)?;
                    current_height = block.height();
                    result.push(block);
                }

                println!("Advanced to the current consensus version at height {target_height}");
            } else {
                debug!("Already at the current consensus version. No blocks to skip.");
            }
        }

        while result.len() < num_blocks {
            let num_txs = (BatchHeader::<N>::MAX_TRANSMISSIONS_PER_BATCH * options.num_validators)
                .min(options.transactions.len());

            let options = GenerateBlockOptions {
                skip_votes: options.skip_votes,
                skip_nodes: options.skip_nodes.clone(),
                transactions: options.transactions.drain(..num_txs).collect(),
                timestamp: next_block_timestamp(),
                ..Default::default()
            };

            let block = self.generate_block_with_opts(options, rng)?;
            result.push(block);
        }

        Ok(result)
    }

    /// Create a new block, with a fully-connected DAG.
    ///
    /// This will "fill in" any gaps left in earlier rounds from non participating nodes.
    pub fn generate_block(&mut self, rng: &mut TestRng) -> Result<Block<N>> {
        self.generate_block_with_opts(GenerateBlockOptions::default(), rng)
    }

    /// Returns a read-only handle to the ledger under construction.
    pub fn ledger(&self) -> &Ledger<N, ConsensusMemory<N>> {
        &self.ledger
    }

    /// Builds the Narwhal subdag and transmission map for the next quorum block, updating internal
    /// Narwhal bookkeeping as if the block were committed, but **without** calling
    /// [`Ledger::prepare_advance_to_next_quorum_block`] or advancing the ledger.
    ///
    /// Pair with [`Ledger::prepare_advance_to_next_quorum_block`] and
    /// [`Self::apply_prepared_quorum_block`] to benchmark preparation separately from advancement.
    #[allow(clippy::type_complexity)]
    pub fn build_quorum_subdag_and_transmissions_for_next_block(
        &mut self,
        options: GenerateBlockOptions<N>,
        rng: &mut TestRng,
    ) -> Result<(Subdag<N>, IndexMap<TransmissionID<N>, Transmission<N>>, BatchCertificate<N>)> {
        assert!(
            options.skip_nodes.len() * 3 < self.private_keys.len(),
            "Cannot mark more than f nodes as unavailable/skipped"
        );

        let next_block_round = self.last_block_round + 2;
        let mut cert_count = 0;

        // SubDAGs can be at most GC rounds long.
        // Batches from genesis round cannot be included in any block that isn't genesis
        let mut round = next_block_round.checked_sub(BatchHeader::<N>::MAX_GC_ROUNDS as u64).unwrap_or(1).max(1);

        let mut transmissions = IndexMap::default();

        for txn in options.transactions {
            let txn_id = txn.id();
            let transmission = Transmission::from(txn);
            let transmission_id = TransmissionID::Transaction(txn_id, transmission.to_checksum().unwrap().unwrap());

            transmissions.insert(transmission_id, transmission);
        }

        for solution in options.solutions {
            let transmission = Transmission::from(solution);
            let transmission_id = TransmissionID::Solution(solution.id(), transmission.to_checksum().unwrap().unwrap());

            transmissions.insert(transmission_id, transmission);
        }

        // =======================================
        // Create certificates for the new block.
        // =======================================
        loop {
            let mut created_anchor = false;

            let previous_certificate_ids = if round == 1 {
                IndexSet::default()
            } else {
                self.round_to_certificates
                    .get(&(round - 1))
                    .unwrap()
                    .iter()
                    .filter_map(|(_, cert)| {
                        // If votes are skipped, remove previous leader cert from the set.
                        let skip = if let Some(leader) = &self.previous_leader_certificate {
                            options.skip_votes && leader.id() == cert.id()
                        } else {
                            false
                        };

                        if skip { None } else { Some(cert.id()) }
                    })
                    .collect()
            };

            let committee = self.ledger.get_committee_lookback_for_round(round).unwrap().unwrap_or_else(|| {
                panic!("No committee for round {round}");
            });

            for (key1_idx, private_key_1) in self.private_keys.iter().enumerate() {
                if options.skip_nodes.contains(&key1_idx) {
                    continue;
                }
                // Don't recreate batches that already exist.
                if self.last_batch_round.get(&key1_idx).unwrap_or(&0) >= &round {
                    continue;
                }

                let transmission_ids: IndexSet<_> = transmissions
                    .keys()
                    .skip(key1_idx * BatchHeader::<N>::MAX_TRANSMISSIONS_PER_BATCH)
                    .take(BatchHeader::<N>::MAX_TRANSMISSIONS_PER_BATCH)
                    .copied()
                    .collect();

                let batch_header = BatchHeader::new(
                    private_key_1,
                    round,
                    options.timestamp,
                    committee.id(),
                    transmission_ids.clone(),
                    previous_certificate_ids.clone(),
                    rng,
                )
                .unwrap();

                // Add signatures for the batch header.
                let signatures = self
                    .private_keys
                    .iter()
                    .enumerate()
                    .filter(|&(key2_idx, _)| key1_idx != key2_idx)
                    .map(|(_, private_key_2)| private_key_2.sign(&[batch_header.batch_id()], rng).unwrap())
                    .collect();

                // Update the round at which this validator last created a batch.
                self.last_batch_round.insert(key1_idx, round);

                // Insert certificate into the round_to_certificates mapping.
                self.round_to_certificates
                    .entry(round)
                    .or_default()
                    .insert(key1_idx, BatchCertificate::from(batch_header, signatures).unwrap());

                cert_count += 1;

                // Check if this batch was an anchor.
                if round.is_multiple_of(2) {
                    let leader = committee.get_leader(round).unwrap();
                    if leader == Address::try_from(private_key_1).unwrap() {
                        created_anchor = true;
                    }
                }
            }

            // Anchor was confirmed by more than a third of the validators.
            if created_anchor && round.is_multiple_of(2) && self.last_block_round < round {
                self.last_block_round = round;
                break;
            }

            round += 1;
        }

        // ==============================================================
        // Build a subdag from the new certificates and create the block.
        // ==============================================================
        let commit_round = round;

        let leader_committee = self.ledger.get_committee_lookback_for_round(round).unwrap().unwrap();
        let leader = leader_committee.get_leader(commit_round).unwrap();
        let (leader_idx, leader_certificate) =
            self.round_to_certificates.get(&commit_round).unwrap().iter().find(|(_, c)| c.author() == leader).unwrap();
        let leader_idx = *leader_idx;
        let leader_certificate = leader_certificate.clone();

        // Construct the subdag for the new block.
        let mut subdag_map = BTreeMap::new();

        // Figure out what the earliest round for the subDAG could be.
        let start_round = if commit_round < BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 {
            1
        } else {
            commit_round - BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS as u64 + 2
        };

        for round in start_round..commit_round {
            let mut to_insert = IndexSet::new();
            for idx in 0..self.private_keys.len() {
                // Some of the batches we in previous rounds might not be new,
                // and already included in a previous block.
                let cround = self.last_committed_batch_round.entry(idx).or_default();
                // Batch already included in another block
                if *cround >= round {
                    continue;
                }

                if let Some(cert) = self.round_to_certificates.entry(round).or_default().get(&idx) {
                    to_insert.insert(cert.clone());
                    *cround = round;
                }
            }
            if !to_insert.is_empty() {
                subdag_map.insert(round, to_insert);
            }
        }

        // Add the leader certificate.
        // (special case, because it is the only cert included from the commit round)
        subdag_map.insert(commit_round, [leader_certificate.clone()].into());
        self.last_committed_batch_round.insert(leader_idx, commit_round);

        trace!("Generated {cert_count} certificates for the next block");

        // Validate the subDAG before reconstructing the canonical certificate order.
        let subdag = Subdag::from(subdag_map).unwrap();
        // Reconstruct the canonical certificate order.
        let ordered_subdag = crate::narwhal::subdag::test_helpers::order_subdag_with_dfs(&subdag);
        let subdag = Subdag::from(ordered_subdag).unwrap();

        Ok((subdag, transmissions, leader_certificate))
    }

    /// Advances the builder ledger after [`Ledger::prepare_advance_to_next_quorum_block`], and
    /// updates Narwhal leader bookkeeping. Call with the same `leader_certificate` returned from
    /// [`Self::build_quorum_subdag_and_transmissions_for_next_block`] for this block.
    pub fn apply_prepared_quorum_block(
        &mut self,
        block: &Block<N>,
        leader_certificate: BatchCertificate<N>,
    ) -> Result<()> {
        self.ledger
            .advance_to_next_block(block)
            .with_context(|| "Failed to (internally) advance to generated block")?;
        self.previous_leader_certificate = Some(leader_certificate);
        Ok(())
    }

    /// Same as `generate_block` but with additional options/parameters.
    pub fn generate_block_with_opts(
        &mut self,
        options: GenerateBlockOptions<N>,
        rng: &mut TestRng,
    ) -> Result<Block<N>> {
        let (subdag, transmissions, leader_certificate) =
            self.build_quorum_subdag_and_transmissions_for_next_block(options, rng)?;

        let block = self.ledger.prepare_advance_to_next_quorum_block(subdag, transmissions, rng)?;

        // Skip to increase performance.
        //self.ledger.check_next_block(&block, rng).with_context(|| "Failed to (internally) check generated block")?;

        trace!("Generated new block {} at height {}", block.hash(), block.height());

        self.apply_prepared_quorum_block(&block, leader_certificate)?;

        trace!("Updated internal ledger to height {}", block.height());
        Ok(block)
    }

    /// Return the genesis block associated with the test chain
    pub fn genesis_block(&self) -> &Block<N> {
        &self.genesis_block
    }

    /// Returns the private keys of the genesis committee of this test chain
    pub fn private_keys(&self) -> &[PrivateKey<N>] {
        &self.private_keys
    }

    /// Returns the private keys of the genesis committee of this test chain
    pub fn validator_key(&self, index: usize) -> &PrivateKey<N> {
        &self.private_keys[index]
    }

    /// Returns the address of the specified validator.
    pub fn validator_address(&self, index: usize) -> Address<N> {
        Address::try_from(*self.validator_key(index)).unwrap()
    }

    /// Create a test ledger with this builder's genesis block.
    pub fn instantiate_ledger(&self) -> Ledger<N, LedgerType<N>> {
        Ledger::load(self.genesis_block().clone(), StorageMode::new_test(None)).unwrap()
    }
}
