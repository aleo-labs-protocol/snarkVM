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

use crate::{Block, Ledger};
use aleo_std::StorageMode;
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::MainnetV0,
    prelude::*,
};

use snarkvm_circuit::AleoV0;
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::vm::VM;

use std::sync::OnceLock;

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
    pub view_key: ViewKey<CurrentNetwork>,
    pub address: Address<CurrentNetwork>,
}

/// Returns a new ledger on the genesis block of the genesis fixture, and the genesis private key.
///
/// Every call returns the same genesis private key and genesis block.
/// The test environment does not depend on `_rng`, and `_rng` is not advanced.
pub fn sample_test_env(_rng: &mut (impl Rng + CryptoRng)) -> TestEnv {
    let (private_key, genesis) = genesis_fixture();
    let view_key = ViewKey::try_from(private_key).unwrap();
    let address = Address::try_from(private_key).unwrap();
    // Sample the ledger.
    let ledger = load_ledger(genesis.clone());
    // Return the test environment.
    TestEnv { ledger, private_key: *private_key, view_key, address }
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
    INSTANCE.get_or_init(|| load_or_build_genesis_fixture("ledger-genesis", build_genesis_fixture))
}

/// Builds the genesis fixture from an RNG with a fixed seed.
fn build_genesis_fixture() -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(GENESIS_FIXTURE_SEED);
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
}
