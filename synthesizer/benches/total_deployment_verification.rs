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

use std::time::Instant;

use snarkvm_console::{
    account::PrivateKey,
    network::{
        MainnetV0,
        prelude::{ConsensusVersion, CryptoRng, FromStr, Network, Result, Rng, TestRng, Zero},
    },
    types::Field,
};
use snarkvm_ledger_block::{Block, Header, Metadata, Transaction};
use snarkvm_ledger_store::{ConsensusStore, helpers::memory::ConsensusMemory};
use snarkvm_synthesizer::VM;
use snarkvm_synthesizer_program::{FinalizeGlobalState, Program};

use aleo_std::StorageMode;

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

// Samples num_deployments deployments, each for a single function with combined density ~multiplier * (2^18) (could be slightly higher or lower in practice)
fn sample_deployments(
    num_deployments: usize,
    multiplier: usize,
    name_prefix: &str,
    vm: &VM<CurrentNetwork, CurrentLedger>,
    private_key: &PrivateKey<CurrentNetwork>,
    rng: &mut TestRng,
) -> Vec<Transaction<CurrentNetwork>> {
    (0..num_deployments)
        .map(|i| {
            let mut program_str = format!(
                r"
        program {name_prefix}_{i}.aleo;

        function fun:
            input r0 as [field; 32u32].public;
    "
            );

            for j in 1..multiplier {
                program_str += &format!(
                    r"
            hash.bhp256 r0 into r{j} as field;
        "
                );
            }

            program_str += r"
        constructor:
                assert.eq true true;
        ";

            let program = Program::from_str(&program_str).unwrap();

            // The individual combined density of the deployment can be read with tx.deployment().unwrap().combined_density()
            vm.deploy(private_key, &program, None, 0, None, rng).unwrap()
        })
        .collect()
}

// This function displays the runtime of check_transactions for various groups of example deployments. It focuses on:
//  - How the runtime of check_deployment scales with the total density of the circuits in the deployment
//  - How the runtime of check_transactions behaves when the same total cross-deployments density is split
//    into actual deployments in various configurations (for instance, 4 deployments of size N vs. 2 deployments
//    of size 2N vs. 1 deployment of size 4N)
fn main() {
    // One array element = one group of deployments checked together. Each such group is represented by a pair:
    // (number of programs in the deployment, size of the program). The size of the program is in actuality the number
    // of inputs to the program's only function, which simply hashes them. The total density of the program grows
    // essentially linearly with this value.
    let deployment_configs = [
        // Each set of configurations visually grouped together corresponds to approximately the same total density.
        (1, 1 << 4),
        //
        (1, 1 << 5),
        (2, 1 << 4),
        //
        (1, 1 << 6),
        (2, 1 << 5),
        (4, 1 << 4),
        //
        (1, 1 << 7),
        (2, 1 << 6),
        (4, 1 << 5),
        (8, 1 << 4),
    ];

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

    // Advance the ledger to the latest consensus version
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height()
        < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::latest()).unwrap()
    {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    for (deployment_idx, (num_progs, multiplier)) in deployment_configs.into_iter().enumerate() {
        println!("{num_progs} deployment(s) with multiplier {multiplier}");

        let deployments =
            sample_deployments(num_progs, multiplier, &format!("test_{deployment_idx}"), &vm, &private_key, rng);

        let total_density =
            deployments.iter().map(|deployment| deployment.deployment().unwrap().combined_density()).sum::<u64>();

        println!("  Checking deployment(s). Total density: {total_density}.");
        let start = Instant::now();
        vm.check_transactions(&deployments.iter().map(|deployment| (deployment, None)).collect::<Vec<_>>(), rng)
            .unwrap();
        let elapsed = start.elapsed().as_millis() as f64 / 1000.0;
        println!("  Checked in {elapsed:.2} s\n");
    }
}
