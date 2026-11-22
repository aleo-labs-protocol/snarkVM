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

use snarkvm_console::{
    account::*,
    network::{ConsensusVersion, MainnetV0, Network, varuna_version_from_consensus},
    program::{Plaintext, Record, Value},
};
use snarkvm_ledger::Ledger;
use snarkvm_ledger_block::Transition;
use snarkvm_ledger_store::{ConsensusStore, StorageMode};
use snarkvm_synthesizer::VM;

#[cfg(not(feature = "rocks"))]
type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<MainnetV0>;
#[cfg(feature = "rocks")]
type LedgerType = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<MainnetV0>;

/// The consensus version every benchmark here runs at.
///
/// **This is load-bearing, not cosmetic.** `VM::execute_authorization` and `VM::check_transaction`
/// read the consensus version out of the current block height and derive the Varuna version from
/// it. A chain that has only just been created is at `ConsensusVersion::V1`, so it proves and
/// verifies with Varuna V1, which the network no longer runs.
///
/// Under `dev-network`, which these benchmarks require, each version from V2 onward lasts
/// one block, so only the latest version stays put across the blocks the setup needs.
fn bench_consensus_version() -> ConsensusVersion {
    ConsensusVersion::latest()
}

/// Mints a private credits record at the current consensus version, and returns it.
///
/// The genesis records cannot be used for this. They are created under `ConsensusVersion::V1`, which
/// makes them record **Version 0**, and from `ConsensusVersion::V8` onward the credits circuit
/// expects **Version 1** -- see `verify_execution`'s output-record check, and the note in
/// `Stack::deploy` that circuit synthesis changed incompatibly at V8. Feeding a Version 0 record to
/// a V8+ circuit produces an assignment that does not satisfy the constraints, which then surfaces a
/// long way from its cause: as a non-zero remainder when Varuna divides by the vanishing polynomial.
///
/// `transfer_public_to_private` takes no private input, only the beacon's public balance, so it is
/// the way to obtain a spendable record at a version the genesis records predate.
fn mint_private_record<R: Rng + CryptoRng>(
    ledger: &Ledger<MainnetV0, LedgerType>,
    private_key: &PrivateKey<MainnetV0>,
    rng: &mut R,
) -> Record<MainnetV0, Plaintext<MainnetV0>> {
    let address = Address::try_from(private_key).unwrap();
    let inputs = [
        Value::<MainnetV0>::from_str(&address.to_string()).unwrap(),
        Value::<MainnetV0>::from_str("100000000u64").unwrap(),
    ];

    let transaction = ledger
        .vm()
        .execute(private_key, ("credits.aleo", "transfer_public_to_private"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();

    // The record has to be in a block before it can be spent: the transfer that spends it needs an
    // inclusion proof against a committed state root.
    let block = ledger
        .prepare_advance_to_next_beacon_block(private_key, vec![], vec![], vec![transaction.clone()], rng)
        .unwrap();
    ledger.advance_to_next_block(&block).unwrap();

    let view_key = ViewKey::try_from(private_key).unwrap();
    transaction
        .transitions()
        .cloned()
        .flat_map(Transition::into_records)
        .map(|(_, record)| record.decrypt(&view_key).unwrap())
        .next()
        .expect("transfer_public_to_private must output a record")
}

#[allow(clippy::type_complexity)]
pub fn initialize_vm<R: Rng + CryptoRng>(
    private_key: &PrivateKey<MainnetV0>,
    rng: &mut R,
) -> (Ledger<MainnetV0, LedgerType>, Vec<Record<MainnetV0, Plaintext<MainnetV0>>>) {
    // Initialize the genesis block.
    let vm = VM::<MainnetV0, LedgerType>::from(ConsensusStore::open(StorageMode::new_test(None)).unwrap()).unwrap();
    let genesis = vm.genesis_beacon(private_key, rng).unwrap();

    // Initialize the ledger with the genesis block.
    let ledger = Ledger::<MainnetV0, LedgerType>::load(genesis, StorageMode::new_test(None)).unwrap();

    // Advance to the benchmark's consensus version. These blocks are empty, so none of this costs
    // any proving.
    let target = MainnetV0::CONSENSUS_HEIGHT(bench_consensus_version()).unwrap();
    while ledger.latest_height() < target {
        let block = ledger.prepare_advance_to_next_beacon_block(private_key, vec![], vec![], vec![], rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();
    }

    // The genesis records are the wrong record version to spend here; see `mint_private_record`.
    let records = vec![mint_private_record(&ledger, private_key, rng)];

    // Fail loudly rather than silently benchmarking a prover or verifier the network does not run.
    let height = ledger.latest_height();
    let consensus_version = MainnetV0::CONSENSUS_VERSION(height).unwrap();
    assert_eq!(consensus_version, bench_consensus_version(), "height {height} is {consensus_version:?}");
    eprintln!(
        "{}: height {height}, {consensus_version:?}, Varuna {:?}",
        env!("CARGO_CRATE_NAME"),
        varuna_version_from_consensus(consensus_version)
    );

    (ledger, records)
}
