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

use super::*;

use console::algorithms::U8;

use std::sync::OnceLock;

#[test]
fn test_increased_argument_bitsize() {
    // Define the programs.
    let program = Program::from_str(
        r"
program test_large_argument.aleo;

function large_argument_input:
    input r0 as [[u8; 512u32]; 3u32].private;
    async large_argument_input r0 into r1;
    output r1 as test_large_argument.aleo/large_argument_input.future;

finalize large_argument_input:
    input r0 as [[u8; 512u32]; 3u32].public;
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at one less than the V13 height.
    let v13_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v13_height, rng);

    // Create the deployment.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_err());

    // Advance the VM to the V14 height.
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &[], rng).unwrap();
        vm.add_next_block(&block).unwrap();
    }

    // Verify that we are at the expected height.
    assert_eq!(vm.block_store().current_block_height(), v14_height);

    // Ensure that the deployment is now valid.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Add the deployment block.
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    vm.add_next_block(&block).unwrap();

    // Construct the inputs for the execution.
    let input = Value::Plaintext(Plaintext::Array(
        vec![
            Plaintext::Array(
                vec![0u8; 512]
                    .into_iter()
                    .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                    .collect(),
                OnceLock::new(),
            )
            .clone();
            3
        ],
        OnceLock::new(),
    ));

    // Execute a transaction that verifies.
    let execution = vm
        .execute(
            &caller_private_key,
            (program.id().to_string(), "large_argument_input"),
            [input].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    assert!(vm.check_transaction(&execution, None, rng).is_ok());

    // Add the execution block.
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    vm.add_next_block(&block).unwrap();
}
/// Generates a large program string that exceeds the V13 size limit (100KB) but fits within V14 (512KB).
fn generate_large_program() -> String {
    let mut program = String::from(
        "program large_program_generated.aleo;

constructor:
    assert.eq true true;

function compute:
    input r0 as u64.public;
",
    );

    // Generate cast instructions to create large arrays.
    // Each cast with 32 elements is ~200+ bytes, so we need fewer instructions.
    let mut reg = 1u32;
    while program.len() < 110_000 {
        // Create a 32-element array from r0.
        program.push_str(&format!(
            "    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r{reg} as [u64; 32u32];\n"
        ));
        reg += 1;
    }

    program
}

// This test verifies that a large program that is over the previous size limit can be deployed after V14.
#[test]
fn test_deploy_large_program_v14() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let large_program_str = generate_large_program();
    let large_program = Program::from_str(&large_program_str).unwrap();

    println!("Generated large program size: {} bytes", large_program_str.len());

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V13 height.
    let v13_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v13_height, rng);

    // Ensure that the program is too large to be deployed at V13.
    let deployment = vm.deploy(&caller_private_key, &large_program, None, 0, None, rng).unwrap();
    let deployment_id = deployment.id();
    assert!(vm.check_transaction(&deployment, None, rng).is_err());
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids(), &[deployment_id]);
    assert_eq!(block.aborted_transaction_ids().len(), 1);

    // Advance to the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &[], rng).unwrap();
        vm.add_next_block(&block).unwrap();
    }

    // Ensure that the program can be deployed at V14.
    let deployment = vm.deploy(&caller_private_key, &large_program, None, 0, None, rng).unwrap();
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Add the deployment block.
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies serialization round-trips for large program deployment transactions at V13 and V14.
#[test]
fn test_deploy_large_program_v14_serialization() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    let large_program_str = generate_large_program();
    let large_program = Program::from_str(&large_program_str).unwrap();

    println!("Generated large program size: {} bytes", large_program_str.len());

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V13 height.
    let v13_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v13_height, rng);

    // Create a deployment transaction for the large program at V13.
    let deployment = vm.deploy(&caller_private_key, &large_program, None, 0, None, rng).unwrap();
    let deployment_id = deployment.id();

    // Verify bytes serialization round-trip at V13.
    let deployment_bytes = deployment.to_bytes_le().unwrap();
    let recovered_from_bytes = Transaction::<CurrentNetwork>::read_le(&deployment_bytes[..]).unwrap();
    assert_eq!(deployment, recovered_from_bytes);

    // Verify string (JSON) serialization round-trip at V13.
    let deployment_string = deployment.to_string();
    let recovered_from_string = Transaction::<CurrentNetwork>::from_str(&deployment_string).unwrap();
    assert_eq!(deployment, recovered_from_string);

    // Ensure that the program is too large to pass check_transaction at V13.
    assert!(vm.check_transaction(&deployment, None, rng).is_err());

    // Create block and verify the transaction is aborted.
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids(), &[deployment_id]);
    assert_eq!(block.aborted_transaction_ids().len(), 1);

    // Advance to the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &[], rng).unwrap();
        vm.add_next_block(&block).unwrap();
    }

    // Create a new deployment transaction for the large program at V14.
    let deployment = vm.deploy(&caller_private_key, &large_program, None, 0, None, rng).unwrap();

    // Verify bytes serialization round-trip at V14.
    let deployment_bytes = deployment.to_bytes_le().unwrap();
    let recovered_from_bytes = Transaction::<CurrentNetwork>::read_le(&deployment_bytes[..]).unwrap();
    assert_eq!(deployment, recovered_from_bytes);

    // Verify string (JSON) serialization round-trip at V14.
    let deployment_string = deployment.to_string();
    let recovered_from_string = Transaction::<CurrentNetwork>::from_str(&deployment_string).unwrap();
    assert_eq!(deployment, recovered_from_string);

    // Ensure that the program passes check_transaction at V14.
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Create block and verify the transaction is accepted.
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    // Add block to the VM.
    vm.add_next_block(&block).unwrap();
}

// This test verifies that:
// - programs using syntax introduced in `V14` cannot be deployed before `V14`.
// - programs using syntax introduced in `V14` can be deployed at and after `V14`.
// - a program with an array up to 2048 elements can be deployed after `V14`.
#[test]
fn test_deployments_for_v14_features() {
    // Define the programs.
    let programs = vec![
        // A program with an array with 2048 elements.
        r"
program uses_large_arrays.aleo;

mapping data:
    key as [u8; 2048u32].public;
    value as u32.public;

function dummy:

constructor:
    assert.eq true true;
",
        // A program that uses the `snark.verify` opcode.
        r"
program uses_snark_verify.aleo;

function dummy:
    input r0 as  [u8; 8u32].public;
    input r1 as [field; 8u32].public;
    input r2 as [u8; 8u32].public;
    async dummy r0 r1 r2 into r3;
    output r3 as uses_snark_verify.aleo/dummy.future;

finalize dummy:
    input r0 as  [u8; 8u32].public;
    input r1 as [field; 8u32].public;
    input r2 as [u8; 8u32].public;
    snark.verify r0 1u8 r1 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
",
    ];

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at one less than the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let num_programs = u32::try_from(programs.len()).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height - num_programs, rng);

    // Deploy each program and ensure it fails.
    for program in &programs {
        let program = Program::from_str(program).unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 0);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 1);
        vm.add_next_block(&block).unwrap();
    }

    // Verify that we are at the expected height.
    assert_eq!(vm.block_store().current_block_height(), v14_height);

    // Deploy each program and ensure it succeeds.
    for program in &programs {
        let program = Program::from_str(program).unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }
}
