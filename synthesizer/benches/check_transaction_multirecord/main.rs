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

/*
Performs time measurements on the verification of the large one_to_many_records transaction.
 - Generate artifacts (both the blocks where programs are deployed and the transactions themselves) with:
   cargo bench --bench check_transaction_multirecord -- --generate
 - Artifacts are ignored by git. To clean them, run:
   cargo bench --bench check_transaction_multirecord -- --clean
 - Obtain time measurements with:
   cargo bench --bench check_transaction_multirecord
   The --serial feature can be added to deactivate parallelism.
 - Flamegraph with:
   cargo flamegraph --bench check_transaction_multirecord --features serial
*/

use std::{env, path::Path, time::Instant};

use snarkvm_console::{
    account::{Address, PrivateKey, ViewKey},
    network::{
        MainnetV0,
        prelude::{ConsensusVersion, CryptoRng, FromStr, Network, Result, Rng, TestRng, Zero},
    },
    program::Value,
    types::Field,
};
use snarkvm_ledger_block::{Block, Header, Metadata, Transaction};
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::VM;
use snarkvm_synthesizer_program::{FinalizeGlobalState, Program};

use aleo_std::StorageMode;
use snarkvm_utilities::{FromBytes, ToBytes};

type CurrentNetwork = MainnetV0;
type CurrentLedger = ConsensusMemory<CurrentNetwork>;

fn sample_next_block<R: Rng + CryptoRng>(
    vm: &VM<CurrentNetwork, CurrentLedger>,
    private_key: &PrivateKey<CurrentNetwork>,
    transactions: &[Transaction<CurrentNetwork>],
    rng: &mut R,
) -> Result<Block<CurrentNetwork>> {
    let block_hash = vm.block_store().get_block_hash(vm.block_store().max_height().unwrap()).unwrap().unwrap();
    let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();

    let next_block_height = previous_block.height() + 1;
    let time_since_last_block = CurrentNetwork::BLOCK_TIME as i64;
    let next_block_timestamp = previous_block.timestamp().saturating_add(time_since_last_block);
    let next_timestamp = (next_block_height
        >= CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V12).unwrap_or_default())
    .then_some(next_block_timestamp);
    let finalize_state =
        FinalizeGlobalState::from(next_block_height as u64, next_block_height, next_timestamp, [0u8; 32], None, None);

    let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) =
        vm.speculate(finalize_state, time_since_last_block, None, vec![], &None.into(), transactions.iter(), rng)?;

    let metadata = Metadata::new(
        CurrentNetwork::ID,
        previous_block.round() + 1,
        previous_block.height() + 1,
        0,
        0,
        CurrentNetwork::GENESIS_COINBASE_TARGET,
        CurrentNetwork::GENESIS_PROOF_TARGET,
        previous_block.last_coinbase_target(),
        previous_block.last_coinbase_timestamp(),
        previous_block.timestamp().saturating_add(time_since_last_block),
    )?;

    let header = Header::from(
        vm.block_store().current_state_root(),
        transactions.to_transactions_root().unwrap(),
        transactions.to_finalize_root(ratified_finalize_operations).unwrap(),
        ratifications.to_ratifications_root().unwrap(),
        Field::zero(),
        Field::zero(),
        metadata,
    )?;

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

fn main() {
    /////////////////////////// User defined
    // Number of times to verify the transaction (when not in --generate mode).
    // A higher number helps flamegraph get more precise measurements.
    let n_samples = 10;
    ///////////////////////////

    let generate = env::args().any(|arg| arg == "--generate");
    let clean = env::args().any(|arg| arg == "--clean");
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/check_transaction_multirecord/artifacts");
    let transaction_path = artifact_path.join("transactions");

    if clean {
        if generate {
            panic!(
                "--clean and --generate cannot be used together. Use --generate to generate\\
                the artifacts, --clean to delete them (and end), and neither to use the existing artifacts."
            );
        }
        std::fs::remove_dir_all(&artifact_path).unwrap();
        println!("Artifacts deleted.");
        return;
    }

    if !transaction_path.exists() {
        if !generate {
            panic!("--generate was not passed, but artifacts were not found.");
        }
        std::fs::create_dir_all(&transaction_path).unwrap();
    }

    let rng = &mut TestRng::from_seed(160426);

    // Generate the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Generate the genesis block using a temporary VM.
    let genesis = {
        let vm = VM::<CurrentNetwork, CurrentLedger>::from(ConsensusStore::open(StorageMode::new_test(None)).unwrap())
            .unwrap();
        vm.genesis_beacon(&private_key, rng).unwrap()
    };

    // Initialize the VM.
    let vm =
        VM::<CurrentNetwork, CurrentLedger>::from(ConsensusStore::open(StorageMode::new_test(None)).unwrap()).unwrap();

    // Add the genesis block.
    vm.add_next_block(&genesis).unwrap();

    // Advance the ledger to the latest consensus version (must be >= V17 so the large deployment is accepted)
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    let latest_version_height = CurrentNetwork::CONSENSUS_VERSION_HEIGHTS().last().unwrap().1;
    while vm.block_store().current_block_height() < latest_version_height {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    let view_key = ViewKey::try_from(&private_key).unwrap();
    let address = Address::try_from(&view_key).unwrap();

    // Deploy a test program to the ledger.
    let program = Program::<CurrentNetwork>::from_str(
        r"
        program one_to_many_records.aleo;
        constructor:
            assert.eq true true;
        record test:
            owner as address.private;
            amount as u64.private;
        function mint:
            input r0 as u64.private;
            cast self.caller r0 into r1 as test.record;
            output r1 as test.record;
        function one_to_many_records:
            input r0 as u64.private; // dummy input
            input r1 as address.private;
            input r2 as u64.private;
            cast r1 r2 into r3 as test.record;
            cast r1 r2 into r4 as test.record;
            cast r1 r2 into r5 as test.record;
            cast r1 r2 into r6 as test.record;
            cast r1 r2 into r7 as test.record;
            cast r1 r2 into r8 as test.record;
            cast r1 r2 into r9 as test.record;
            cast r1 r2 into r10 as test.record;
            cast r1 r2 into r11 as test.record;
            cast r1 r2 into r12 as test.record;
            cast r1 r2 into r13 as test.record;
            cast r1 r2 into r14 as test.record;
            cast r1 r2 into r15 as test.record;
            cast r1 r2 into r16 as test.record;
            cast r1 r2 into r17 as test.record;
            cast r1 r2 into r18 as test.record;
            output r3 as test.record;
            output r4 as test.record;
            output r5 as test.record;
            output r6 as test.record;
            output r7 as test.record;
            output r8 as test.record;
            output r9 as test.record;
            output r10 as test.record;
            output r11 as test.record;
            output r12 as test.record;
            output r13 as test.record;
            output r14 as test.record;
            output r15 as test.record;
            output r16 as test.record;
            output r17 as test.record;
            output r18 as test.record;
        ",
    )
    .unwrap();

    // Wrapper program to call the one_to_many_records function.
    let mut wrapper_program = r"
    import one_to_many_records.aleo;
    program wrapper.aleo;
    constructor:
        assert.eq true true;
    function call_one_to_many_records:
        input r0 as u64.private;
        input r1 as address.private;
        input r2 as u64.private;"
        .to_string();

    // Append calls to the one_to_many_records function.
    let call = |start_index: usize| {
        let mut call_str = "    call one_to_many_records.aleo/one_to_many_records r0 r1 r2 into".to_string();
        for i in start_index..start_index + 16 {
            call_str.push_str(&format!(" r{i}"));
        }
        call_str.push_str(";\n");
        call_str
    };
    for i in 0..30 {
        let start_index = 3 + (i * 16);
        wrapper_program.push_str(&call(start_index));
    }
    let wrapper_program = Program::from_str(&wrapper_program).unwrap();

    // Deploy the first program
    let deployment_block_path = artifact_path.join("deployment_block_1.bin");
    if generate {
        println!("Deploying program one_to_many_records.aleo (generating block)");
        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        let deployment_block = sample_next_block(&vm, &private_key, std::slice::from_ref(&deployment), rng).unwrap();
        assert_eq!(deployment_block.transactions().num_accepted(), 1);
        vm.add_next_block(&deployment_block).unwrap();

        std::fs::write(
            deployment_block_path,
            deployment_block.to_bytes_le().expect("Failed to write deployment block for first program"),
        )
        .unwrap();
    } else {
        println!("Deploying program one_to_many_records.aleo (loading block)");
        let deployment_block = Block::from_bytes_le(
            &std::fs::read(deployment_block_path).expect("Deployment block for first program not found"),
        )
        .unwrap();
        vm.add_next_block(&deployment_block).unwrap();
    }

    // Deploy the second program
    let deployment_block_path = artifact_path.join("deployment_block_2.bin");
    if generate {
        println!("Deploying program wrapper.aleo (generating block)");
        let deployment_wrapper = vm.deploy(&private_key, &wrapper_program, None, 0, None, rng).unwrap();
        let deployment_block = sample_next_block(&vm, &private_key, &[deployment_wrapper], rng).unwrap();
        assert_eq!(deployment_block.transactions().num_accepted(), 1);
        vm.add_next_block(&deployment_block).unwrap();

        std::fs::write(
            deployment_block_path,
            deployment_block.to_bytes_le().expect("Failed to write deployment block for second program"),
        )
        .unwrap();
    } else {
        println!("Deploying program wrapper.aleo (loading block)");
        let deployment_block = Block::from_bytes_le(
            &std::fs::read(deployment_block_path).expect("Deployment block for second program not found"),
        )
        .unwrap();
        vm.add_next_block(&deployment_block).unwrap();
    }

    // Load or execute wrapper call
    if generate {
        println!("Executing wrapper call (generating transaction) {n_samples} times...");

        for i in 0..n_samples {
            let current_transaction_path = transaction_path.join(format!("transaction_{i}.bin"));

            let value1_str = format!("{i}u64");
            let value2_str = format!("{}u64", 10_000 + i);

            let transaction = vm
                .execute(
                    &private_key,
                    ("wrapper.aleo", "call_one_to_many_records"),
                    vec![
                        Value::from_str(&value1_str).unwrap(),
                        Value::from_str(&format!("{address}")).unwrap(),
                        Value::from_str(&value2_str).unwrap(),
                    ]
                    .into_iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            assert!(vm.check_transaction(&transaction, None, rng).is_ok());

            std::fs::write(&current_transaction_path, transaction.to_bytes_le().unwrap()).unwrap();
        }
    } else {
        println!("Loading {n_samples} transactions...");

        let transactions = (0..n_samples)
            .map(|i| {
                Transaction::from_bytes_le(
                    &std::fs::read(transaction_path.join(format!("transaction_{i}.bin")))
                        .unwrap_or_else(|_| panic!("Transaction {i} not found")),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        println!("Checking {n_samples} transactions...");

        let timer = Instant::now();
        for tx in transactions.iter().take(n_samples) {
            assert!(vm.check_transaction(tx, None, rng).is_ok());
        }
        let elapsed = timer.elapsed().as_micros() as f64 / 1000.0;
        let elapsed_avg = elapsed / n_samples as f64;
        println!("Transactions checked in {elapsed:.2} ms ({elapsed_avg:.2} ms per transaction)");
    }
}
