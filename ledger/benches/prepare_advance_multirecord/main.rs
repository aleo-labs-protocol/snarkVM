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
Performs time measurements on prepare_advance_to_next_quorum_block for a block containing
a number of instances of the large one_to_many_records transaction.
 - Generate artifacts with:
   cargo bench --bench prepare_advance_multirecord -- --generate
 - Artifacts are ignored by git. To clean them, run:
   cargo bench --bench prepare_advance_multirecord -- --clean
 - Obtain time measurements with:
   cargo bench --bench prepare_advance_multirecord
   The --serial feature can be added to deactivate parallelism.
 - In order to run any of the above on a number of transfer_public instead, pass --transfer_public.
*/

use std::{env, fs, io::Write, path::Path, time::Instant};

use aleo_std::StorageMode;
use snarkvm_console::{
    account::{Address, PrivateKey, ViewKey},
    network::{
        MainnetV0,
        prelude::{FromStr, Network, TestRng},
    },
    prelude::{ConsensusVersion, FromBytes, ToBytes, Uniform},
    program::Value,
};
use snarkvm_ledger::{
    Block,
    Ledger,
    Transaction,
    store::{ConsensusStore, helpers::memory::ConsensusMemory},
    test_helpers::chain_builder::{GenerateBlockOptions, GenerateBlocksOptions, TestChainBuilder},
};
use snarkvm_synthesizer::{program::Program, vm::VM};

type CurrentNetwork = MainnetV0;

// Consistent seeds so that transactions stored to disk can be checked later on
const CHAIN_ROOT_SEED: u64 = 25042026;
const GENESIS_COMMITTEE_SEED: u64 = 0x25042027;
const RNG_DEPLOY_ONE: u64 = 250420261;
const RNG_BLOCK_ONE: u64 = 250420262;
const RNG_DEPLOY_TWO: u64 = 250420263;
const RNG_BLOCK_TWO: u64 = 250420264;
const RNG_EXECUTE: u64 = 250420265;
const RNG_PREPARE_BLOCK: u64 = 250420266;
const DETERMINISTIC_WARMUP_TIMESTAMP: i64 = CurrentNetwork::GENESIS_TIMESTAMP + 1;

/// Mirrors `TestChainBuilder::initialize_components` with a fixed committee RNG seed so the beacon
/// operator key is available for deploy/execute (that API is not exposed on `TestChainBuilder`).
fn genesis_with_fixed_committee_seed(
    rng: &mut TestRng,
    committee_size: usize,
    genesis_committee_seed: u64,
) -> (PrivateKey<CurrentNetwork>, Vec<PrivateKey<CurrentNetwork>>, Block<CurrentNetwork>) {
    let genesis_pk = PrivateKey::new(rng).unwrap();
    let store = ConsensusStore::<_, ConsensusMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    let genesis_rng = &mut TestRng::from_seed(genesis_committee_seed);
    let genesis = VM::from(store).unwrap().genesis_beacon(&genesis_pk, genesis_rng).unwrap();
    let genesis_rng = &mut TestRng::from_seed(genesis_committee_seed);
    let committee_keys = (0..committee_size).map(|_| PrivateKey::new(genesis_rng).unwrap()).collect();
    (genesis_pk, committee_keys, genesis)
}

fn main() {
    /////////////////////////// User defined
    // Number of transactions to generate and check in each of the two cases:
    // simple (transfer_public) and complex (one_to_many_records). Right now,
    // this is set to ConsensusState::MAXIMUM_CONFIRMED_TRANSACTIONS, which is 8
    // in test environments.
    let n_transactions = 8;
    ///////////////////////////

    let generate = env::args().any(|arg| arg == "--generate");
    let clean = env::args().any(|arg| arg == "--clean");
    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/prepare_advance_multirecord/artifacts");

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

    if !artifact_path.exists() {
        if !generate {
            panic!("--generate was not passed, but artifacts were not found.");
        }
        std::fs::create_dir_all(&artifact_path).unwrap();
    }

    let rng = &mut TestRng::from_seed(CHAIN_ROOT_SEED);

    // We ensure rounds are full later on so the large programs can be deployed.
    let max_validators = CurrentNetwork::LATEST_MAX_CERTIFICATES();

    let (genesis_pk, committee_keys, genesis) =
        genesis_with_fixed_committee_seed(rng, max_validators as usize, GENESIS_COMMITTEE_SEED);

    let mut chain_builder = TestChainBuilder::from_components(committee_keys, genesis.clone()).unwrap();
    let ledger =
        Ledger::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::load(genesis, StorageMode::new_test(None)).unwrap();
    let num_validators = chain_builder.private_keys().len();

    let min_blocks_to_generate = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V17).unwrap() as usize;

    for block in chain_builder
        .generate_blocks_with_opts(
            min_blocks_to_generate,
            GenerateBlocksOptions {
                skip_to_current_version: true,
                skip_nodes: (1..max_validators as usize / 3).collect(),
                num_validators,
                deterministic_block_timestamp_start: Some(DETERMINISTIC_WARMUP_TIMESTAMP),
                ..Default::default()
            },
            rng,
        )
        .unwrap()
    {
        ledger.advance_to_next_block(&block).unwrap();
    }

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
            input r0 as u64.private;
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

    let mut moderate_wrapper_program = r"
    import one_to_many_records.aleo;
    program moderate_wrapper.aleo;
    constructor:
        assert.eq true true;
    function call_one_to_many_records:
        input r0 as u64.private;
        input r1 as address.private;
        input r2 as u64.private;"
        .to_string();

    let call = |start_index: usize| {
        let mut call_str = "    call one_to_many_records.aleo/one_to_many_records r0 r1 r2 into".to_string();
        for i in start_index..start_index + 16 {
            call_str.push_str(&format!(" r{i}"));
        }
        call_str.push_str(";\n");
        call_str
    };

    for i in 0..18 {
        let start_index = 3 + (i * 16);
        moderate_wrapper_program.push_str(&call(start_index));
    }
    let moderate_wrapper_program = Program::from_str(&moderate_wrapper_program).unwrap();

    let case =
        if env::args().any(|arg| arg == "--transfer_public") { "transfer_public" } else { "one_to_many_records" };

    if case == "one_to_many_records" {
        let deploy_one_rng = &mut TestRng::from_seed(RNG_DEPLOY_ONE);

        println!("Deploying one_to_many_records.aleo");
        let deployment_one = ledger.vm().deploy(&genesis_pk, &program, None, 0, None, deploy_one_rng).unwrap();

        let block_one_rng = &mut TestRng::from_seed(RNG_BLOCK_ONE);

        let block_one = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    transactions: vec![deployment_one],
                    timestamp: chain_builder
                        .ledger()
                        .latest_timestamp()
                        .saturating_add(CurrentNetwork::BLOCK_TIME as i64),
                    ..Default::default()
                },
                block_one_rng,
            )
            .unwrap();
        ledger.advance_to_next_block(&block_one).unwrap();

        assert_eq!(block_one.transactions().num_accepted(), 1);

        let deploy_two_rng = &mut TestRng::from_seed(RNG_DEPLOY_TWO);

        println!("Deploying moderate_wrapper.aleo");
        let deployment_two =
            ledger.vm().deploy(&genesis_pk, &moderate_wrapper_program, None, 0, None, deploy_two_rng).unwrap();

        let block_two_rng = &mut TestRng::from_seed(RNG_BLOCK_TWO);

        let block_two = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    transactions: vec![deployment_two],
                    timestamp: chain_builder
                        .ledger()
                        .latest_timestamp()
                        .saturating_add(CurrentNetwork::BLOCK_TIME as i64),
                    ..Default::default()
                },
                block_two_rng,
            )
            .unwrap();
        ledger.advance_to_next_block(&block_two).unwrap();

        assert_eq!(block_two.transactions().num_accepted(), 1);
    }

    let genesis_view_key = ViewKey::try_from(&genesis_pk).unwrap();
    let genesis_address = Address::try_from(&genesis_view_key).unwrap();
    let recipient_address: Address<CurrentNetwork> = Address::rand(&mut TestRng::from_seed(112233));

    let full_artifact_path = artifact_path.join(case);

    let multi_record_transactions = if generate {
        println!("Generating artifacts for {n_transactions} {case} transaction(s)");

        fs::create_dir_all(&full_artifact_path).unwrap();

        (0..n_transactions)
            .map(|i| {
                print!("    Executing {case} transaction {i}");
                std::io::stdout().flush().unwrap();

                let timer = Instant::now();
                let execute_rng = &mut TestRng::from_seed(RNG_EXECUTE.wrapping_add(i as u64));

                let tx = if case == "one_to_many_records" {
                    ledger
                        .vm()
                        .execute(
                            &genesis_pk,
                            ("moderate_wrapper.aleo", "call_one_to_many_records"),
                            [
                                Value::from_str(&format!("{i}u64")).unwrap(),
                                Value::from_str(&format!("{genesis_address}")).unwrap(),
                                Value::from_str(&format!("{}u64", 10_000 + i)).unwrap(),
                            ]
                            .into_iter(),
                            None,
                            0,
                            None,
                            execute_rng,
                        )
                        .unwrap()
                } else {
                    ledger
                        .vm()
                        .execute(
                            &genesis_pk,
                            ("credits.aleo", "transfer_public"),
                            [
                                Value::from_str(&format!("{recipient_address}")).unwrap(),
                                Value::from_str(&format!("{}u64", 10_000 + i)).unwrap(),
                            ]
                            .into_iter(),
                            None,
                            0,
                            None,
                            execute_rng,
                        )
                        .unwrap()
                };

                println!(" (finished in {:.2}s)", timer.elapsed().as_secs_f32());

                let check_rng = &mut TestRng::from_seed(RNG_EXECUTE.wrapping_add(1000 + i as u64));
                assert!(ledger.vm().check_transaction(&tx, None, check_rng).is_ok());

                fs::write(full_artifact_path.join(format!("transaction_{i}.bin")), tx.to_bytes_le().unwrap())
                    .unwrap_or_else(|_| panic!("Failed to write artifact for transaction {i}"));

                tx
            })
            .collect::<Vec<_>>()
    } else {
        println!("Loading artifacts for {n_transactions} {case} transaction(s)");

        (0..n_transactions)
            .map(|i| {
                Transaction::from_bytes_le(
                    &std::fs::read(full_artifact_path.join(format!("transaction_{i}.bin")))
                        .unwrap_or_else(|_| panic!("Failed to load transaction {i}")),
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };

    let prepare_rng = &mut TestRng::from_seed(RNG_PREPARE_BLOCK);

    let (subdag, transmissions, leader_certificate) = chain_builder
        .build_quorum_subdag_and_transmissions_for_next_block(
            GenerateBlockOptions {
                transactions: multi_record_transactions,
                timestamp: chain_builder.ledger().latest_timestamp().saturating_add(CurrentNetwork::BLOCK_TIME as i64),
                ..Default::default()
            },
            prepare_rng,
        )
        .unwrap();

    println!("Proceeding to next block...");

    let timer = Instant::now();
    let block =
        chain_builder.ledger().prepare_advance_to_next_quorum_block(subdag, transmissions, prepare_rng).unwrap();
    let prepare_ms = timer.elapsed().as_millis();

    println!(" * prepare_advance_to_next_quorum_block finished in {prepare_ms}ms");

    let timer = Instant::now();
    chain_builder.apply_prepared_quorum_block(&block, leader_certificate).unwrap();
    let apply_ms = timer.elapsed().as_millis();
    println!(" * apply_prepared_quorum_block finished in {apply_ms}ms");

    let timer = Instant::now();
    ledger.advance_to_next_block(&block).unwrap();
    let advance_ms = timer.elapsed().as_millis();
    println!(" * advance_to_next_block finished in {advance_ms}ms");

    assert_eq!(block.transactions().num_accepted(), n_transactions);
}
