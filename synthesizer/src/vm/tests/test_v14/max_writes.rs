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

#[cfg(feature = "test")]
#[test]
fn test_max_writes_migration() {
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    // Initialize the genesis block.
    let genesis = sample_genesis_block(rng);
    // Update the VM.
    vm.add_next_block(&genesis).unwrap();

    // Fetch the private key.
    let private_key = sample_genesis_private_key(rng);

    // Create a program that hits the max writes limit.
    let mut program_string = String::from(
        "program test_max_writes.aleo;

mapping foo:
    key as u16.public;
    value as field.public;

constructor:
    assert.eq true true;

function compute:
    input r0 as u8.public;
    async compute r0 into r1;
    output r1 as test_max_writes.aleo/compute.future;

finalize compute:
    input r0 as u8.public;
",
    );

    // Create a program that exceeds the max writes limit.
    let mut invalid_program_string = String::from(
        "program test_max_writes.aleo;

mapping foo:
    key as u16.public;
    value as field.public;

constructor:
    assert.eq true true;

function compute:
    input r0 as u8.public;
    async compute r0 into r1;
    output r1 as test_max_writes.aleo/compute.future;

finalize compute:
    input r0 as u8.public;
    set 0field into foo[0u16];
",
    );

    for i in 0..CurrentNetwork::LATEST_MAX_WRITES() {
        program_string.push_str(&format!("    set 0field into foo[{i}u16];\n"));
        invalid_program_string.push_str(&format!("    set 0field into foo[{i}u16];\n"));
    }

    let program = Program::<CurrentNetwork>::from_str(&program_string).unwrap();

    // Ensure that the program that exceeds max writes fails to parse.
    assert!(Program::<CurrentNetwork>::from_str(&invalid_program_string).is_err());

    // Advance the ledger past ConsensusV9 where the new varuna version and deployment version starts to take place.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() {
        // Call the function
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Construct the deployment transaction.
    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

    // Advance the ledger past ConsensusV14 where the increase to max writes starts.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        // Ensure that the deployment is invalid.
        assert!(vm.check_transaction(&deployment, None, rng).is_err());

        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Ensure that the deployment is valid after ConsensusVersion::V14.
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Deploy the program.
    let next_block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Ensure that the valid transaction was accepted.
    assert_eq!(next_block.transactions().num_accepted(), 1);

    // Create the execution transaction that hits the max writes limit.
    let inputs = [Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::U8(U8::new(1u8))))];
    let transaction =
        vm.execute(&private_key, (program.id(), "compute"), inputs.into_iter(), None, 0, None, rng).unwrap();
    let next_block = sample_next_block(&vm, &private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Ensure that the valid transaction was accepted.
    assert_eq!(next_block.transactions().num_accepted(), 1);
}

#[test]
fn test_max_writes_exceeds_finalize_amount() {
    const NUM_DEPLOYMENTS: usize = 31;

    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    // Initialize the genesis block.
    let genesis = sample_genesis_block(rng);
    // Update the VM.
    vm.add_next_block(&genesis).unwrap();

    // Fetch the private key.
    let private_key = sample_genesis_private_key(rng);

    // Advance the ledger past ConsensusV14 where the increase to max writes starts.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Deploy the base program.
    let program = Program::from_str(
        r"
program program_layer_0.aleo;

constructor:
    assert.eq true true;

mapping m:
    key as u8.public;
    value as u32.public;

function do:
    input r0 as u32.public;
    async do r0 into r1;
    output r1 as program_layer_0.aleo/do.future;

finalize do:
    input r0 as u32.public;
    set r0 into m[0u8];",
    )
    .unwrap();

    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    vm.check_transaction(&deployment, None, rng).unwrap();
    let next_block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();
    assert_eq!(next_block.transactions().num_accepted(), 1);

    // For each layer, deploy a program that calls the program from the previous layer.
    for i in 1..NUM_DEPLOYMENTS {
        let mut program_string = String::new();
        // Add the import statements.
        for j in 0..i {
            program_string.push_str(&format!("import program_layer_{j}.aleo;\n"));
        }
        // Add the program body.
        program_string.push_str(&format!(
            "program program_layer_{i}.aleo;

constructor:
    assert.eq true true;

mapping m:
    key as u8.public;
    value as u32.public;

function do:
    input r0 as u32.public;
    call program_layer_{prev}.aleo/do r0 into r1;
    async do r0 r1 into r2;
    output r2 as program_layer_{i}.aleo/do.future;

finalize do:
    input r0 as u32.public;
    input r1 as program_layer_{prev}.aleo/do.future;
    await r1;",
            prev = i - 1
        ));

        for k in 0..CurrentNetwork::LATEST_MAX_WRITES() {
            program_string.push_str(&format!("set r0 into m[{k}u8];\n"));
        }
        // Construct the program.
        let program = Program::from_str(&program_string).unwrap();

        // Deploy the program.
        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

        // Create block with deployment.
        let next_block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();

        // Add block to the VM.
        vm.add_next_block(&next_block).unwrap();
        assert_eq!(next_block.transactions().num_accepted(), 1);
    }

    // Prepare the inputs.
    let inputs = [Value::<CurrentNetwork>::from_str("1u32").unwrap()].into_iter();

    // Execute.
    let transaction = vm.execute(&private_key, ("program_layer_30.aleo", "do"), inputs, None, 0, None, rng).unwrap();

    // Verify.
    assert!(vm.check_transaction(&transaction, None, rng).is_err());
}
