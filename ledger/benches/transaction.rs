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

#![allow(clippy::type_complexity)]

#[macro_use]
extern crate criterion;

use snarkvm_console::{
    account::*,
    network::{ConsensusVersion, MainnetV0, Network, varuna_version_from_consensus},
    program::{Plaintext, Record, Value},
};
use snarkvm_ledger::Ledger;
use snarkvm_ledger_block::Transition;
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer::{VM, program::Program};

use aleo_std::StorageMode;
use criterion::Criterion;
#[cfg(feature = "bench-prove")]
use std::time::Duration;

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
/// Under `test_consensus_heights`, which this benchmark requires, each version from V2 onward lasts
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

/// Fixed RNG seed so benchmark inputs are reproducible across CI runs.
const BENCH_RNG_SEED: u64 = 0xB34D_CAFE_CDEC_0123;

/// Criterion configuration for the proving benchmarks.
///
/// Proving a transaction takes seconds, so the default sample size of 100 would
/// put a single benchmark into the tens of minutes. Ten is criterion's minimum
/// and is enough to resolve the differences these benchmarks exist to show.
///
/// The measurement time is deliberately *not* generous. Criterion fills the
/// window by running several iterations per sample, so a large value multiplies
/// the cost without improving what this benchmark is used for: a value near one
/// sample per iteration keeps a run short enough to repeat, and repetition is
/// what separates a real difference from the drift between two runs. Expect a
/// warning that the samples did not fit; that is the intended trade.
///
/// Scoped to a group rather than set on `criterion_group!` so that the
/// verification benchmarks, which run in microseconds, keep the defaults.
#[cfg(feature = "bench-prove")]
fn prove_group(c: &mut Criterion) -> criterion::BenchmarkGroup<'_, criterion::measurement::WallTime> {
    let mut group = c.benchmark_group("prove");
    group.sample_size(10).measurement_time(Duration::from_secs(60));
    group
}

fn initialize_vm<R: Rng + CryptoRng>(
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
        "transaction: height {height}, {consensus_version:?}, Varuna {:?}",
        varuna_version_from_consensus(consensus_version)
    );

    (ledger, records)
}

fn deploy(c: &mut Criterion) {
    let rng = &mut TestRng::fixed(BENCH_RNG_SEED);

    // Sample a new private key and address.
    let private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();

    // Initialize the VM.
    let (ledger, records) = initialize_vm(&private_key, rng);
    let vm = ledger.vm();

    // Create a sample program.
    let program = Program::<MainnetV0>::from_str(
        r"
program helloworld.aleo;

constructor:
    assert.eq edition 0u16;

function hello:
    input r0 as u32.private;
    input r1 as u32.private;
    add r0 r1 into r2;
    output r2 as u32.private;
",
    )
    .unwrap();

    // c.bench_function("Transaction::Deploy", |b| {
    //     b.iter(|| vm.deploy(&private_key, &program, Some(records[0].clone()), 600000, None, rng).unwrap())
    // });

    let transaction = vm.deploy(&private_key, &program, Some(records[0].clone()), 600000, None, rng).unwrap();

    // `check_transaction` caches each transaction it accepts and skips proof verification on a
    // repeat, so every `cached_verify` benchmark times a cache hit after its first iteration.
    // `verify_transaction.rs` times verification itself.
    c.bench_function("Transaction::Deploy - cached_verify", |b| {
        b.iter(|| vm.check_transaction(&transaction, None, rng).unwrap())
    });
}

fn execute(c: &mut Criterion) {
    let rng = &mut TestRng::fixed(BENCH_RNG_SEED ^ 1);

    // Sample a new private key and address.
    let private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();
    let address = Address::try_from(&private_key).unwrap();

    // Initialize the VM.
    let (ledger, records) = initialize_vm(&private_key, rng);
    let vm = ledger.vm();

    {
        // Prepare the inputs.
        let inputs = [
            Value::<MainnetV0>::from_str(&address.to_string()).unwrap(),
            Value::<MainnetV0>::from_str("1u64").unwrap(),
        ]
        .into_iter();

        // Authorize the execution.
        let execute_authorization = vm.authorize(&private_key, "credits.aleo", "transfer_public", inputs, rng).unwrap();
        // Retrieve the execution ID.
        let execution_id = execute_authorization.to_execution_id().unwrap();
        // Authorize the fee.
        let fee_authorization = vm.authorize_fee_public(&private_key, 300000, 1000, execution_id, rng).unwrap();

        #[cfg(feature = "bench-prove")]
        prove_group(c).bench_function("Transaction::Execute(transfer_public)", |b| {
            b.iter(|| {
                vm.execute_authorization(
                    execute_authorization.replicate(),
                    Some(fee_authorization.replicate()),
                    None,
                    rng,
                )
                .unwrap();
            })
        });

        let transaction = vm
            .execute_authorization(execute_authorization.replicate(), Some(fee_authorization.replicate()), None, rng)
            .unwrap();

        // Bench the Transaction.write_le method using the LimitedWriter.
        c.bench_function("LimitedWriter::new - transfer_public", |b| {
            let max = MainnetV0::LATEST_MAX_TRANSACTION_SIZE();
            let mut buffer = Vec::with_capacity(3000);
            b.iter(|| {
                buffer.clear();
                transaction.write_le(LimitedWriter::new(&mut buffer, max))
            })
        });

        // Bench a cache hit in check_transaction for transfer_public.
        c.bench_function("Transaction::Execute(transfer_public) - cached_verify", |b| {
            b.iter(|| vm.check_transaction(&transaction, None, rng).unwrap())
        });
    }

    {
        // Prepare the inputs.
        let inputs = [
            Value::<MainnetV0>::Record(records[0].clone()),
            Value::<MainnetV0>::from_str(&address.to_string()).unwrap(),
            Value::<MainnetV0>::from_str("1u64").unwrap(),
        ]
        .into_iter();

        // Authorize the execution.
        let execute_authorization =
            vm.authorize(&private_key, "credits.aleo", "transfer_private", inputs, rng).unwrap();
        // Retrieve the execution ID.
        let execution_id = execute_authorization.to_execution_id().unwrap();
        // Authorize the fee.
        let fee_authorization = vm.authorize_fee_public(&private_key, 300000, 1000, execution_id, rng).unwrap();

        // Bench the execution of transfer_private.
        #[cfg(feature = "bench-prove")]
        prove_group(c).bench_function("Transaction::Execute(transfer_private)", |b| {
            b.iter(|| {
                vm.execute_authorization(
                    execute_authorization.replicate(),
                    Some(fee_authorization.replicate()),
                    None,
                    rng,
                )
                .unwrap();
            })
        });

        let transaction = vm
            .execute_authorization(execute_authorization.replicate(), Some(fee_authorization.replicate()), None, rng)
            .unwrap();

        // Bench the Transaction.write_le method using the LimitedWriter.
        c.bench_function("LimitedWriter::new - transfer_private", |b| {
            let max = MainnetV0::LATEST_MAX_TRANSACTION_SIZE();
            let mut buffer = Vec::with_capacity(3000);
            b.iter(|| {
                buffer.clear();
                transaction.write_le(LimitedWriter::new(&mut buffer, max))
            })
        });

        // Bench a cache hit in check_transaction for transfer_private.
        c.bench_function("Transaction::Execute(transfer_private) - cached_verify", |b| {
            b.iter(|| vm.check_transaction(&transaction, None, rng).unwrap())
        });
    }

    // Bench Transaction.write_le + VM.check_transaction methods for transactions above the maximum transaction size.
    //     {
    //         // Define a program that will create an execution transaction larger than the maximum transaction size.
    //         let program = Program::<MainnetV0>::from_str(
    //             r"
    // program too_big.aleo;

    // struct all_groups:
    //     g1 as [[[group; 4u32]; 4u32]; 4u32];
    //     g2 as [[[group; 4u32]; 4u32]; 4u32];

    // struct nested_groups:
    //     g1 as all_groups;
    //     g2 as all_groups;

    // function main:
    //     // Input the amount of microcredits to unbond.
    //     input r0 as group.public;
    //     cast r0 r0 r0 r0 into r1 as [group; 4u32];
    //     cast r1 r1 r1 r1 into r2 as [[group; 4u32]; 4u32];
    //     cast r2 r2 r2 r2 into r3 as [[[group; 4u32]; 4u32]; 4u32];
    //     cast r3 r3 into r4 as all_groups;
    //     cast r4 r4 into r5 as nested_groups;
    //     cast r4 r4 into r6 as nested_groups;
    //     cast r4 r4 into r7 as nested_groups;
    //     cast r4 r4 into r8 as nested_groups;
    //     cast r4 r4 into r9 as nested_groups;
    //     cast r4 r4 into r10 as nested_groups;
    //     cast r4 r4 into r11 as nested_groups;
    //     cast r4 r4 into r12 as nested_groups;
    //     cast r4 r4 into r13 as nested_groups;
    //     cast r4 r4 into r14 as nested_groups;
    //     cast r4 r4 into r15 as nested_groups;
    //     cast r4 r4 into r16 as nested_groups;
    //     cast r4 r4 into r17 as nested_groups;
    //     cast r4 r4 into r18 as nested_groups;
    //     cast r4 r4 into r19 as nested_groups;
    //     cast r4 r4 into r20 as nested_groups;
    //     cast r4 r4 into r21 as nested_groups;
    //     cast r4 r4 into r22 as nested_groups;
    //     cast r4 r4 into r23 as nested_groups;
    //     cast r4 r4 into r24 as nested_groups;
    //     cast r4 r4 into r25 as nested_groups;
    //     cast r4 r4 into r26 as nested_groups;
    //     cast r4 r4 into r27 as nested_groups;
    //     cast r4 r4 into r28 as nested_groups;
    //     cast r4 r4 into r29 as nested_groups;
    //     cast r4 r4 into r30 as nested_groups;
    //     cast r4 r4 into r31 as nested_groups;
    //     output r7 as nested_groups.public;
    //     output r8 as nested_groups.public;
    //     output r9 as nested_groups.public;
    //     output r10 as nested_groups.public;
    //     output r11 as nested_groups.public;
    //     output r12 as nested_groups.public;
    //     output r13 as nested_groups.public;
    //     output r14 as nested_groups.public;
    //     output r15 as nested_groups.public;
    //     output r16 as nested_groups.public;
    //     output r17 as nested_groups.public;
    //     output r18 as nested_groups.public;
    //     output r19 as nested_groups.public;
    //     output r20 as nested_groups.public;
    //     output r21 as nested_groups.public;
    //     output r22 as nested_groups.public;
    //     ",
    //         )
    //         .unwrap();
    //         // Prepare the inputs.
    //         let inputs = [Value::from_str("2group").unwrap()].into_iter();

    //         // Add the program to the VM.
    //         vm.process().lock().add_program(&program).unwrap();

    //         // Create an execution transaction that is 164613 bytes in size.
    //         let transaction = vm.execute(&private_key, ("too_big.aleo", "main"), inputs, None, 0, None, rng).unwrap();

    //         // Bench the Transaction.write_le method using the LimitedWriter.
    //         c.bench_function("LimitedWriter::new - too_big.aleo", |b| {
    //             let max = MainnetV0::LATEST_MAX_TRANSACTION_SIZE();
    //             let mut buffer = Vec::with_capacity(max);
    //             b.iter(|| {
    //                 buffer.clear();
    //                 transaction.write_le(LimitedWriter::new(&mut buffer, max))
    //             })
    //         });

    //         // At genesis height the active cap is V1 (128 KiB); this transaction exceeds it and rejects before full verification.
    //         c.bench_function("Transaction::Execute(too_big.aleo) - oversize_reject", |b| {
    //             b.iter(|| {
    //                 vm.check_transaction(&transaction, None, rng)
    //                     .expect_err("transaction must exceed V1 MAX_TRANSACTION_SIZE at genesis height");
    //             })
    //         });
    //     }
}

criterion_group!(transaction, deploy, execute);

criterion_main!(transaction);
