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

use crate::Ledger;
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::MainnetV0,
    prelude::*,
};
use snarkvm_ledger_store::StorageMode;

use snarkvm_circuit::AleoV0;
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer::vm::VM;

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

pub fn sample_test_env(rng: &mut (impl Rng + CryptoRng)) -> TestEnv {
    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let view_key = ViewKey::try_from(&private_key).unwrap();
    let address = Address::try_from(&private_key).unwrap();
    // Sample the ledger.
    let ledger = sample_ledger(private_key, rng);
    // Return the test environment.
    TestEnv { ledger, private_key, view_key, address }
}

pub fn sample_ledger(private_key: PrivateKey<CurrentNetwork>, rng: &mut (impl Rng + CryptoRng)) -> CurrentLedger {
    // Initialize the store.
    let store = CurrentConsensusStore::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();
    // Initialize the ledger with the genesis block.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    // Ensure the genesis block is correct.
    assert_eq!(genesis, ledger.get_block(0).unwrap());
    // Return the ledger.
    ledger
}
