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

//! The cost of verifying a `credits.aleo/transfer_public` execution, with a public and with a
//! private fee, at the latest consensus version, which verifies with Varuna V3 and Inclusion V1.
//!
//! `VM::check_transaction` records every transaction it accepts in
//! `VM::partially_verified_transactions`, and skips both proof verifications for a transaction it
//! finds there. A benchmark that checks the same transaction repeatedly therefore measures one real
//! verification followed by cache hits. Every benchmark here that calls `check_transaction` clears
//! that cache first; `uncleared cache` is the control showing what a cache hit costs.

#![allow(clippy::type_complexity)]

#[macro_use]
extern crate criterion;

use snarkvm_console::{
    account::*,
    network::{ConsensusVersion, MainnetV0, Network, varuna_version_from_consensus},
    program::{Plaintext, Record, Value},
};
use snarkvm_ledger::Ledger;
use snarkvm_ledger_block::{Transaction, Transition};
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer::VM;

use aleo_std::StorageMode;
use criterion::{Criterion, Throughput};
use rayon::prelude::*;

type LedgerType = snarkvm_ledger_store::helpers::memory::ConsensusMemory<MainnetV0>;

/// The consensus version every transaction here is built and verified at.
///
/// Under `test_consensus_heights` each version from V2 onward lasts one block, so only the latest
/// version is stable across the several blocks this setup needs.
fn bench_consensus_version() -> ConsensusVersion {
    ConsensusVersion::latest()
}

/// Fixed RNG seed so benchmark inputs are reproducible across runs.
const BENCH_RNG_SEED: u64 = 0x5EED_F00D_0DD5_BA11;

const BASE_FEE: u64 = 300_000;
const PRIORITY_FEE: u64 = 1_000;

/// Builds a ledger at `bench_consensus_version()` and returns it with a private credits record that
/// is spendable there.
///
/// The genesis records cannot be used: they are record Version 0, and from `ConsensusVersion::V8`
/// onward `fee_private` must output a Version 1 record.
fn initialize_ledger<R: Rng + CryptoRng>(
    private_key: &PrivateKey<MainnetV0>,
    rng: &mut R,
) -> (Ledger<MainnetV0, LedgerType>, Record<MainnetV0, Plaintext<MainnetV0>>) {
    let vm = VM::<MainnetV0, LedgerType>::from(ConsensusStore::open(StorageMode::new_test(None)).unwrap()).unwrap();
    let genesis = vm.genesis_beacon(private_key, rng).unwrap();
    let ledger = Ledger::<MainnetV0, LedgerType>::load(genesis, StorageMode::new_test(None)).unwrap();

    let target = MainnetV0::CONSENSUS_HEIGHT(bench_consensus_version()).unwrap();
    while ledger.latest_height() < target {
        let block = ledger.prepare_advance_to_next_beacon_block(private_key, vec![], vec![], vec![], rng).unwrap();
        ledger.advance_to_next_block(&block).unwrap();
    }

    // `transfer_public_to_private` spends only the public balance genesis funds, so it can mint a
    // record at the current version.
    let address = Address::try_from(private_key).unwrap();
    let inputs = [
        Value::<MainnetV0>::from_str(&address.to_string()).unwrap(),
        Value::<MainnetV0>::from_str("100000000u64").unwrap(),
    ];
    let transaction = ledger
        .vm()
        .execute(private_key, ("credits.aleo", "transfer_public_to_private"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let block = ledger
        .prepare_advance_to_next_beacon_block(private_key, vec![], vec![], vec![transaction.clone()], rng)
        .unwrap();
    ledger.advance_to_next_block(&block).unwrap();

    let view_key = ViewKey::try_from(private_key).unwrap();
    let record = transaction
        .transitions()
        .cloned()
        .flat_map(Transition::into_records)
        .map(|(_, record)| record.decrypt(&view_key).unwrap())
        .next()
        .expect("transfer_public_to_private must output a record");

    let height = ledger.latest_height();
    let consensus_version = MainnetV0::CONSENSUS_VERSION(height).unwrap();
    let varuna_version = varuna_version_from_consensus(consensus_version);
    assert_eq!(consensus_version, bench_consensus_version(), "height {height} is {consensus_version:?}");
    assert_eq!(format!("{varuna_version:?}"), "V3", "{consensus_version:?} verifies with Varuna {varuna_version:?}");
    assert!(height >= MainnetV0::INCLUSION_UPGRADE_HEIGHT().unwrap());
    eprintln!("verify_transaction: height {height}, {consensus_version:?}, Varuna {varuna_version:?}");

    (ledger, record)
}

/// Proves a `transfer_public` of 1 microcredit to `private_key`'s own address, paid with a public
/// fee when `fee_record` is `None` and with that record otherwise.
fn transfer_public<R: Rng + CryptoRng>(
    vm: &VM<MainnetV0, LedgerType>,
    private_key: &PrivateKey<MainnetV0>,
    fee_record: Option<&Record<MainnetV0, Plaintext<MainnetV0>>>,
    rng: &mut R,
) -> Transaction<MainnetV0> {
    let address = Address::try_from(private_key).unwrap();
    let inputs =
        [Value::<MainnetV0>::from_str(&address.to_string()).unwrap(), Value::<MainnetV0>::from_str("1u64").unwrap()];
    let authorization = vm.authorize(private_key, "credits.aleo", "transfer_public", inputs, rng).unwrap();
    let execution_id = authorization.to_execution_id().unwrap();
    let fee_authorization = match fee_record {
        None => vm.authorize_fee_public(private_key, BASE_FEE, PRIORITY_FEE, execution_id, rng).unwrap(),
        Some(record) => {
            vm.authorize_fee_private(private_key, record.clone(), BASE_FEE, PRIORITY_FEE, execution_id, rng).unwrap()
        }
    };
    vm.execute_authorization(authorization, Some(fee_authorization), None, rng).unwrap()
}

fn verify(c: &mut Criterion) {
    let rng = &mut TestRng::fixed(BENCH_RNG_SEED);
    let private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();
    let (ledger, record) = initialize_ledger(&private_key, rng);
    let vm = ledger.vm();

    // Distinct transactions for the throughput benchmarks, one per thread rayon will use. Several
    // spend the same fee record, which `check_transaction` permits: it rejects only serial numbers
    // already in the ledger.
    let batch_size = rayon::current_num_threads();
    let public_fee_txs: Vec<_> = (0..batch_size).map(|_| transfer_public(vm, &private_key, None, rng)).collect();
    let private_fee_txs: Vec<_> =
        (0..batch_size).map(|_| transfer_public(vm, &private_key, Some(&record), rng)).collect();

    let cases = [("fee_public", &public_fee_txs), ("fee_private", &private_fee_txs)];

    let mut group = c.benchmark_group("verify");
    for (name, txs) in cases {
        let tx = &txs[0];
        assert!(tx.fee_transition().unwrap().is_fee_private() == (name == "fee_private"));
        vm.check_transaction(tx, None, rng).unwrap();

        // `check_fee` with `is_partially_verified = false` always verifies the fee proof, and never
        // touches the execution proof.
        group.bench_function(format!("check_fee ({name})"), |b| b.iter(|| vm.check_fee(tx, None, false).unwrap()));

        group.bench_function(format!("check_transaction (transfer_public, {name})"), |b| {
            b.iter(|| {
                vm.partially_verified_transactions().write().clear();
                vm.check_transaction(tx, None, rng).unwrap()
            })
        });
    }
    group.bench_function("check_transaction (transfer_public, fee_public, uncleared cache)", |b| {
        b.iter(|| vm.check_transaction(&public_fee_txs[0], None, rng).unwrap())
    });
    group.finish();

    let mut group = c.benchmark_group("verify_throughput");
    group.throughput(Throughput::Elements(batch_size as u64));
    for (name, txs) in cases {
        group.bench_function(format!("check_transaction x{batch_size} (transfer_public, {name})"), |b| {
            b.iter(|| {
                vm.partially_verified_transactions().write().clear();
                txs.par_iter().for_each(|tx| vm.check_transaction(tx, None, &mut rand::rng()).unwrap())
            })
        });
    }
    group.finish();
}

criterion_group!(benches, verify);
criterion_main!(benches);
