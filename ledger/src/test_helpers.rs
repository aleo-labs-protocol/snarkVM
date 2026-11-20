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

pub mod chain_builder;
pub use chain_builder::TestChainBuilder;

use crate::{
    Block,
    Ledger,
    Transaction,
    Transmission,
    TransmissionID,
    authority::Authority,
    narwhal::{BatchCertificate, BatchHeader, Subdag, subdag::test_helpers::order_subdag_with_dfs},
    puzzle::Solution,
};
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::MainnetV0,
    prelude::*,
};
use snarkvm_ledger_store::{ConsensusStorage, StorageMode};

use snarkvm_circuit::AleoV0;
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::vm::VM;

use indexmap::{IndexMap, IndexSet};
use std::{collections::BTreeMap, sync::OnceLock};
use time::OffsetDateTime;

pub use snarkvm_ledger_test_helpers::*;

pub type CurrentNetwork = MainnetV0;
pub type CurrentAleo = AleoV0;

#[cfg(not(feature = "rocks"))]
pub type CurrentLedger = Ledger<CurrentNetwork, snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>>;
#[cfg(feature = "rocks")]
pub type CurrentLedger = Ledger<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>>;

#[cfg(not(feature = "rocks"))]
pub type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
#[cfg(feature = "rocks")]
pub type LedgerType = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

#[cfg(not(feature = "rocks"))]
pub type CurrentConsensusStore =
    ConsensusStore<CurrentNetwork, snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>>;
#[cfg(feature = "rocks")]
pub type CurrentConsensusStore =
    ConsensusStore<CurrentNetwork, snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>>;

#[cfg(not(feature = "rocks"))]
pub type CurrentConsensusStorage = snarkvm_ledger_store::helpers::memory::ConsensusMemory<CurrentNetwork>;
#[cfg(feature = "rocks")]
pub type CurrentConsensusStorage = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<CurrentNetwork>;

pub struct TestEnv {
    pub ledger: CurrentLedger,
    pub private_key: PrivateKey<CurrentNetwork>,
    /// The keys of the genesis committee, starting with `private_key`.
    pub validators: Vec<PrivateKey<CurrentNetwork>>,
    pub view_key: ViewKey<CurrentNetwork>,
    pub address: Address<CurrentNetwork>,
}

/// Returns a new ledger on the genesis block of the genesis fixture, and the genesis private key.
///
/// Every call returns the same genesis private key and genesis block.
/// The test environment does not depend on `_rng`, and `_rng` is not advanced.
pub fn sample_test_env(_rng: &mut (impl Rng + CryptoRng)) -> TestEnv {
    let (validators, genesis) = sample_genesis_committee();
    let private_key = validators[0];
    let view_key = ViewKey::try_from(private_key).unwrap();
    let address = Address::try_from(private_key).unwrap();
    // Sample the ledger.
    let ledger = load_ledger(genesis);
    // Return the test environment.
    TestEnv { ledger, private_key, validators, view_key, address }
}

/// Returns the next block on `ledger`: a quorum block whose subdag the committee members among `validators` certify.
///
/// The leader certificate of the block holds the transmissions, so the block keeps their order.
pub fn prepare_quorum_block<N: Network, C: ConsensusStorage<N>>(
    ledger: &Ledger<N, C>,
    validators: &[PrivateKey<N>],
    solutions: Vec<Solution<N>>,
    transactions: Vec<Transaction<N>>,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Block<N>> {
    let keys = validators.iter().map(|key| Ok((Address::try_from(key)?, key))).collect::<Result<IndexMap<_, _>>>()?;
    let checksum = |transmission: &Transmission<N>| {
        transmission.to_checksum()?.ok_or_else(|| anyhow!("A transmission object has no checksum"))
    };
    let mut transmissions = IndexMap::new();
    for transaction in transactions {
        let id = transaction.id();
        let transmission = Transmission::from(transaction);
        transmissions.insert(TransmissionID::Transaction(id, checksum(&transmission)?), transmission);
    }
    for solution in solutions {
        let transmission = Transmission::from(solution);
        transmissions.insert(TransmissionID::Solution(solution.id(), checksum(&transmission)?), transmission);
    }

    // The subdag spans the round of the previous leader certificate up to the next anchor round.
    // The previous block holds that certificate, and the certificates it links to.
    let latest_block = ledger.latest_block();
    let (first_round, mut previous_ids, previous_leader) = match latest_block.authority() {
        Authority::Beacon(_) => {
            ensure!(latest_block.height() == 0, "A quorum block cannot follow a beacon block after genesis");
            (1, IndexSet::new(), None)
        }
        Authority::Quorum(subdag) => {
            let leader = subdag.leader_certificate();
            let ids = subdag.get(&(leader.round() - 1)).into_iter().flatten().map(BatchCertificate::id).collect();
            (leader.round(), ids, Some((leader.author(), leader.id())))
        }
    };
    let anchor_round = latest_block.round() + 2;
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();

    let mut rounds = BTreeMap::new();
    for round in first_round..=anchor_round {
        let committee = ledger
            .get_committee_lookback_for_round(round)?
            .ok_or_else(|| anyhow!("No committee lookback for round {round}"))?;
        let authors = match round == anchor_round {
            true => vec![committee.get_leader(round)?],
            false => committee
                .members()
                .keys()
                .copied()
                .filter(|author| previous_leader.is_none_or(|(leader, _)| leader != *author || round != first_round))
                .collect(),
        };
        let mut certificates = IndexSet::new();
        for author in authors {
            let key = keys.get(&author).ok_or_else(|| anyhow!("No key for committee member {author}"))?;
            let transmission_ids = match round == anchor_round {
                true => transmissions.keys().copied().collect(),
                false => IndexSet::new(),
            };
            let header =
                BatchHeader::new(key, round, timestamp, committee.id(), transmission_ids, previous_ids.clone(), rng)?;
            let signatures = keys
                .iter()
                .filter(|(address, _)| **address != author && committee.is_committee_member(**address))
                .map(|(_, key)| key.sign(&[header.batch_id()], rng))
                .collect::<Result<_>>()?;
            certificates.insert(BatchCertificate::from(header, signatures)?);
        }
        previous_ids = certificates.iter().map(BatchCertificate::id).collect();
        if round == first_round {
            previous_ids.extend(previous_leader.map(|(_, id)| id));
        }
        rounds.insert(round, certificates);
    }

    let subdag = Subdag::from(order_subdag_with_dfs(&rounds))?;
    ledger.prepare_advance_to_next_quorum_block(subdag, transmissions, rng).map_err(|error| error.into_anyhow())
}

/// Returns a new ledger on a new genesis block, which `private_key` signs.
pub fn sample_ledger(private_key: PrivateKey<CurrentNetwork>, rng: &mut (impl Rng + CryptoRng)) -> CurrentLedger {
    // Initialize the store.
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();
    // Initialize the ledger.
    load_ledger(genesis)
}

/// Returns a new ledger on `genesis`.
fn load_ledger(genesis: Block<CurrentNetwork>) -> CurrentLedger {
    // Initialize the ledger with the genesis block.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    // Ensure the genesis block is correct.
    assert_eq!(genesis, ledger.get_block(0).unwrap());
    // Return the ledger.
    ledger
}

/// The seed of the RNG that builds the genesis fixture.
const GENESIS_FIXTURE_SEED: u64 = 1_779_120_457;

/// Returns the genesis private key and the genesis block that it signs.
///
/// The test processes of one binary share the fixture through a file beside the binary.
fn genesis_fixture() -> &'static (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    static INSTANCE: OnceLock<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> = OnceLock::new();
    INSTANCE
        .get_or_init(|| load_or_build_genesis_fixture("ledger-genesis", GENESIS_FIXTURE_SEED, build_genesis_fixture))
}

/// Returns the private keys of the four validators in the committee of the genesis fixture, and the genesis block.
///
/// The first key is the genesis private key. `VM::genesis_beacon` samples the other three keys
/// from the RNG that sampled the genesis private key.
pub fn sample_genesis_committee() -> (Vec<PrivateKey<CurrentNetwork>>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(GENESIS_FIXTURE_SEED);
    let private_keys = (0..4).map(|_| PrivateKey::new(rng).expect("Failed to sample a private key")).collect();
    (private_keys, genesis_fixture().1.clone())
}

/// Builds the genesis fixture from an RNG with the given seed.
fn build_genesis_fixture(seed: u64) -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(seed);
    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample the genesis private key");
    // The genesis block does not depend on the storage of the VM that builds it.
    let store = ConsensusStore::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::open(StorageMode::new_test(None))
        .expect("Failed to open the consensus store");
    let vm = VM::from(store).expect("Failed to initialize the VM");
    // Create a genesis block.
    let block = vm.genesis_beacon(&private_key, rng).expect("Failed to build the genesis block");
    (private_key, block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_test_env_does_not_advance_rng() {
        let rng = &mut TestRng::fixed(1);
        let TestEnv { ledger, private_key, .. } = sample_test_env(rng);
        assert_eq!(rng.random::<u64>(), TestRng::fixed(1).random::<u64>());
        // The test environment holds the genesis fixture.
        let (fixture_private_key, fixture_block) = genesis_fixture();
        assert_eq!(private_key, *fixture_private_key);
        assert_eq!(ledger.get_block(0).expect("Failed to get the genesis block"), *fixture_block);
    }

    #[test]
    fn test_sample_genesis_committee_holds_the_committee_keys() {
        let (private_keys, genesis) = sample_genesis_committee();
        assert_eq!(private_keys[0], genesis_fixture().0);

        let committee = match genesis.ratifications().iter().next() {
            Some(crate::Ratify::Genesis(committee, ..)) => committee,
            _ => panic!("Expected a genesis ratification"),
        };
        let addresses = private_keys
            .iter()
            .map(|private_key| Address::try_from(private_key).expect("Failed to derive an address"))
            .collect::<Vec<_>>();
        assert_eq!(addresses, committee.members().keys().copied().collect::<Vec<_>>());
    }
}
