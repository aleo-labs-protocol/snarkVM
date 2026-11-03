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

use console::{account::ViewKey, program::Value};
use snarkvm_synthesizer_program::{Program, StackTrait};

use crate::vm::test_helpers::{advance_vm_to_height, sample_vm_at_height};
use aleo_std::StorageMode;
use console::{
    account::{Address, Field, PrivateKey},
    network::ConsensusVersion,
    program::{Identifier, Literal, Plaintext, ProgramID, ProgramOwner},
};
use snarkvm_ledger_block::Transaction;
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer_process::Process;
use snarkvm_utilities::TestRng;
use std::panic::AssertUnwindSafe;

// This test checks that:
//   - programs without constructors can be deployed before V9
//   - programs with constructors cannot be deployed before V9
//   - programs without constructor cannot be deployed after V9
//   - program with constructors can be deployed after V9
#[test]
#[ignore]
fn test_constructor_requires_v9() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)? - 2, rng);

    // Initialize the program.
    let program = Program::from_str(
        r"
program constructor_test_0.aleo;

constructor:
    assert.eq true true;

function dummy:
    ",
    )?;

    // Attempt to deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Initialize the program.
    let program = Program::from_str(
        r"
program no_constructor_test_0.aleo;

function dummy:
    ",
    )?;

    // Attempt to deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the VM is at the V9 height.
    assert_eq!(vm.block_store().current_block_height(), CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?);

    // Initialize the program.
    let program = Program::from_str(
        r"
program constructor_test_1.aleo;

constructor:
    assert.eq true true;

function dummy:
    ",
    )?;

    // Attempt to deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Initialize the program.
    let program = Program::from_str(
        r"
program no_constructor_test_1.aleo;

function dummy:
    ",
    )?;

    // Attempt to deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that:
//  - the logic of a simple transition without records can be upgraded.
//  - once a program is upgraded, the old executions are no longer valid.
//  - a constructor with an "allow any" policy can be upgraded by anyone.
//  - a program can be upgraded to a new edition with the exact same logic.
#[test]
#[ignore]
fn test_simple_upgrade() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Initialize the program.
    let program = Program::from_str(
        r"
program adder.aleo;

function binary_add:
    input r0 as u8.public;
    input r1 as u8.public;
    add r0 r1 into r2;
    output r2 as u8.public;

constructor:
    assert.eq true true;
    ",
    )?;

    // Deploy the program.
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the program is deployed.
    let stack = vm.process().get_stack("adder.aleo")?;
    assert_eq!(stack.program_id(), &ProgramID::from_str("adder.aleo")?);
    assert_eq!(*stack.program_edition(), 0);

    // Execute the program.
    let original_execution = vm.execute(
        &caller_private_key,
        ("adder.aleo", "binary_add"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    assert!(vm.check_transaction(&original_execution, None, rng).is_ok());

    // Check that the output is correct.
    let output = match original_execution.transitions().next().unwrap().outputs().last().unwrap() {
        Output::Public(_, Some(Plaintext::Literal(Literal::U8(value), _))) => **value,
        output => bail!(format!("Unexpected output: {output}")),
    };
    assert_eq!(output, 2u8);

    // Initialize a new caller.
    let user_private_key = PrivateKey::new(rng).unwrap();
    let user_address = Address::try_from(&user_private_key)?;

    // Fund the user with a `transfer_public` transaction.
    let transaction = vm.execute(
        &caller_private_key,
        ("credits.aleo", "transfer_public"),
        vec![Value::from_str(&format!("{user_address}"))?, Value::from_str("1_000_000_000_000u64")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Upgrade the program.
    let upgraded_program = Program::from_str(
        r"
program adder.aleo;

function binary_add:
    input r0 as u8.public;
    input r1 as u8.public;
    add.w r0 r1 into r2;
    output r2 as u8.public;

constructor:
    assert.eq true true;
    ",
    )?;

    // Deploy the upgraded program.
    let transaction = vm.deploy(&user_private_key, &upgraded_program, None, 0, None, rng)?;
    assert_eq!(transaction.deployment().unwrap().edition(), 1);
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the program is upgraded.
    let stack = vm.process().get_stack("adder.aleo")?;
    assert_eq!(stack.program_id(), &ProgramID::from_str("adder.aleo")?);
    assert_eq!(*stack.program_edition(), 1);

    // Check that the old execution is no longer valid.
    assert!(vm.check_transaction(&original_execution, None, rng).is_err());

    // Upgrade the program with the same locig.
    let transaction = vm.deploy(&user_private_key, &upgraded_program, None, 0, None, rng)?;
    assert_eq!(transaction.deployment().unwrap().edition(), 2);
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the upgraded program.
    let new_execution = vm.execute(
        &user_private_key,
        ("adder.aleo", "binary_add"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    assert!(vm.check_transaction(&new_execution, None, rng).is_ok());

    // Check that the output is correct.
    let output = match new_execution.transitions().next().unwrap().outputs().last().unwrap() {
        Output::Public(_, Some(Plaintext::Literal(Literal::U8(value), _))) => **value,
        output => bail!(format!("Unexpected output: {output}")),
    };
    assert_eq!(output, 2u8);

    Ok(())
}

// This test checks that:
//  - the first instance of a program must be the zero-th edition.
//  - subsequent upgrades to the program must be sequential.
#[test]
#[ignore]
fn test_editions_are_sequential() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize two VMs at V9 (required for constructor support).
    let off_chain_vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);
    let on_chain_vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the three versions of the program.
    let program_v0 = Program::from_str(
        r"
program basic.aleo;
function foo:
constructor:
    assert.eq true true;
    ",
    )?;
    let program_v1 = Program::from_str(
        r"
program basic.aleo;
function foo:
function bar:
constructor:
    assert.eq true true;
    ",
    )?;
    let program_v2_as_v1 = Program::from_str(
        r"
program basic.aleo;
function foo:
function bar:
function baz:
constructor:
    assert.eq true true;
    ",
    )?;
    let program_v2 = Program::from_str(
        r"
program basic.aleo;
function foo:
function bar:
function baz:
constructor:
    assert.eq true true;
    ",
    )?;

    // Using the off-chain VM, generate a sequence of deployments.
    let deployment_v0_pass = off_chain_vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    off_chain_vm.process().lock().add_program(&program_v0)?;
    let deployment_v1_fail = off_chain_vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let deployment_v1_pass = off_chain_vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let deployment_v2_as_v1_fail = off_chain_vm.deploy(&caller_private_key, &program_v2_as_v1, None, 0, None, rng)?;
    off_chain_vm.process().lock().add_program(&program_v1)?;
    let deployment_v2_fail = off_chain_vm.deploy(&caller_private_key, &program_v2, None, 0, None, rng)?;
    let deployment_v2_pass = off_chain_vm.deploy(&caller_private_key, &program_v2, None, 0, None, rng)?;

    // Deploy the programs to the on-chain VM individually in the following sequence:
    // - deployment_v1_fail
    // - deployment_v0_pass
    // - deployment_v2_fail
    // - deployment_v1_pass
    // - deployment_v2_as_v1_fail
    // - deployment_v2_pass
    // Their name indicate whether the deployment should pass or fail.

    // This deployment should fail because the it is not the zero-th edition.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v1_fail], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    on_chain_vm.add_next_block(&block)?;

    // This deployment should pass.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v0_pass], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    on_chain_vm.add_next_block(&block)?;
    let stack = on_chain_vm.process().get_stack("basic.aleo")?;
    assert_eq!(*stack.program_edition(), 0);

    // This deployment should fail because it does not increment the edition.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v2_fail], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    on_chain_vm.add_next_block(&block)?;

    // This deployment should pass.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v1_pass], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    on_chain_vm.add_next_block(&block)?;
    let stack = on_chain_vm.process().get_stack("basic.aleo")?;
    assert_eq!(*stack.program_edition(), 1);

    // This deployment should fail because it attempt to redeploy at the same edition.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v2_as_v1_fail], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    on_chain_vm.add_next_block(&block)?;

    // This deployment should pass.
    let block = sample_next_block(&on_chain_vm, &caller_private_key, &[deployment_v2_pass], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    on_chain_vm.add_next_block(&block)?;
    let stack = on_chain_vm.process().get_stack("basic.aleo")?;
    assert_eq!(*stack.program_edition(), 2);

    Ok(())
}

// This test checks that:
//  - records created before an upgrade are still valid after an upgrade.
//  - records created after an upgrade can be created and used in the upgraded program.
//  - records are semantically distinct (old records cannot be used in functions that require new records).
//  - functions can be disabled using `assert.neq self.caller self.caller`.
#[test]
#[ignore]
fn test_upgrade_with_records() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the two versions of the program.
    let program_v0 = Program::from_str(
        r"
program record_test.aleo;

record data_v1:
    owner as address.private;
    data as u8.public;

function mint:
    input r0 as u8.public;
    cast self.caller r0 into r1 as data_v1.record;
    output r1 as data_v1.record;

constructor:
    assert.eq true true;
    ",
    )?;

    let program_v1 = Program::from_str(
        r"
program record_test.aleo;

record data_v1:
    owner as address.private;
    data as u8.public;

record data_v2:
    owner as address.private;
    data as u8.public;

function mint:
    input r0 as u8.public;
    assert.neq self.caller self.caller;
    cast self.caller r0 into r1 as data_v1.record;
    output r1 as data_v1.record;

function convert:
    input r0 as data_v1.record;
    cast r0.owner r0.data into r1 as data_v2.record;
    output r1 as data_v2.record;

function burn:
    input r0 as data_v2.record;

constructor:
    assert.eq true true;
    ",
    )?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the mint function twice.
    let mint_execution_0 = vm.execute(
        &caller_private_key,
        ("record_test.aleo", "mint"),
        vec![Value::from_str("0u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let mint_execution_1 = vm.execute(
        &caller_private_key,
        ("record_test.aleo", "mint"),
        vec![Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[mint_execution_0, mint_execution_1], rng)?;
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    let mut v1_records = block
        .records()
        .map(|(_, record)| record.decrypt(&caller_view_key))
        .collect::<Result<Vec<Record<CurrentNetwork, Plaintext<CurrentNetwork>>>>>()?;
    assert_eq!(v1_records.len(), 2);
    vm.add_next_block(&block)?;

    // Update the program.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to execute the mint function.
    assert!(
        vm.execute(
            &caller_private_key,
            ("record_test.aleo", "mint"),
            vec![Value::from_str("0u8")?].into_iter(),
            None,
            0,
            None,
            rng
        )
        .is_err()
    );

    // Get the first record and execute the convert function.
    let record = v1_records.pop().unwrap();
    let convert_execution = vm.execute(
        &caller_private_key,
        ("record_test.aleo", "convert"),
        vec![Value::Record(record)].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[convert_execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    let mut v2_records = block
        .records()
        .map(|(_, record)| record.decrypt(&caller_view_key))
        .collect::<Result<Vec<Record<CurrentNetwork, Plaintext<CurrentNetwork>>>>>()?;
    assert_eq!(v2_records.len(), 1);
    vm.add_next_block(&block)?;

    // Get the v2 record and execute the burn function.
    let record = v2_records.pop().unwrap();
    let burn_execution = vm.execute(
        &caller_private_key,
        ("record_test.aleo", "burn"),
        vec![Value::Record(record)].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[burn_execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to execute the burn function with the remaining v1 record.
    let record = v1_records.pop().unwrap();
    assert!(
        vm.execute(
            &caller_private_key,
            ("record_test.aleo", "burn"),
            vec![Value::Record(record)].into_iter(),
            None,
            0,
            None,
            rng
        )
        .is_err()
    );

    Ok(())
}

// This test checks that:
//  - mappings created before an upgrade are still valid after an upgrade.
//  - mappings created by and upgraded are correctly initialized and usable in the program.
//  - functions can be disabled by inserting a failing condition in the on-chain logic.
#[test]
#[ignore]
fn test_upgrade_with_mappings() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the two versions of the program.
    let program_v0 = Program::from_str(
        r"
program mapping_test.aleo;

mapping data_v1:
    key as u8.public;
    value as u8.public;

function store_data_v1:
    input r0 as u8.public;
    input r1 as u8.public;
    async store_data_v1 r0 r1 into r2;
    output r2 as mapping_test.aleo/store_data_v1.future;
finalize store_data_v1:
    input r0 as u8.public;
    input r1 as u8.public;
    set r1 into data_v1[r0];

constructor:
    assert.eq true true;
    ",
    )?;

    let program_v1 = Program::from_str(
        r"
program mapping_test.aleo;

mapping data_v1:
    key as u8.public;
    value as u8.public;

mapping data_v2:
    key as u8.public;
    value as u8.public;

function store_data_v1:
    input r0 as u8.public;
    input r1 as u8.public;
    async store_data_v1 r0 r1 into r2;
    output r2 as mapping_test.aleo/store_data_v1.future;
finalize store_data_v1:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.neq true true;

function migrate_data_v1_to_v2:
    input r0 as u8.public;
    async migrate_data_v1_to_v2 r0 into r1;
    output r1 as mapping_test.aleo/migrate_data_v1_to_v2.future;
finalize migrate_data_v1_to_v2:
    input r0 as u8.public;
    get data_v1[r0] into r1;
    remove data_v1[r0];
    set r1 into data_v2[r0];

function store_data_v2:
    input r0 as u8.public;
    input r1 as u8.public;
    async store_data_v2 r0 r1 into r2;
    output r2 as mapping_test.aleo/store_data_v2.future;
finalize store_data_v2:
    input r0 as u8.public;
    input r1 as u8.public;
    set r1 into data_v2[r0];

constructor:
    assert.eq true true;
    ",
    )?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the store_data_v1 function.
    let store_data_v1_execution = vm.execute(
        &caller_private_key,
        ("mapping_test.aleo", "store_data_v1"),
        vec![Value::from_str("0u8")?, Value::from_str("0u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[store_data_v1_execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the value was stored correctly.
    let value = match vm.finalize_store().get_value_confirmed(
        ProgramID::from_str("mapping_test.aleo")?,
        Identifier::from_str("data_v1")?,
        &Plaintext::from_str("0u8")?,
    )? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U8(value), _))) => *value,
        value => bail!(format!("Unexpected value: {value:?}")),
    };
    assert_eq!(value, 0u8);

    // Update the program.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to execute the store_data_v1 function.
    let transaction = vm.execute(
        &caller_private_key,
        ("mapping_test.aleo", "store_data_v1"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the migrate_data_v1_to_v2 function.
    let migrate_data_v1_to_v2_execution = vm.execute(
        &caller_private_key,
        ("mapping_test.aleo", "migrate_data_v1_to_v2"),
        vec![Value::from_str("0u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[migrate_data_v1_to_v2_execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the value was migrated correctly.
    let value = match vm.finalize_store().get_value_confirmed(
        ProgramID::from_str("mapping_test.aleo")?,
        Identifier::from_str("data_v2")?,
        &Plaintext::from_str("0u8")?,
    )? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U8(value), _))) => *value,
        value => bail!(format!("Unexpected value: {value:?}")),
    };
    assert_eq!(value, 0u8);

    // Check that the old value was removed.
    assert!(
        vm.finalize_store()
            .get_value_confirmed(
                ProgramID::from_str("mapping_test.aleo")?,
                Identifier::from_str("data_v1")?,
                &Plaintext::from_str("0u8")?
            )?
            .is_none()
    );

    // Execute the store_data_v2 function.
    let store_data_v2_execution = vm.execute(
        &caller_private_key,
        ("mapping_test.aleo", "store_data_v2"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[store_data_v2_execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the value was stored correctly.
    let value = match vm.finalize_store().get_value_confirmed(
        ProgramID::from_str("mapping_test.aleo")?,
        Identifier::from_str("data_v2")?,
        &Plaintext::from_str("1u8")?,
    )? {
        Some(Value::Plaintext(Plaintext::Literal(Literal::U8(value), _))) => *value,
        value => bail!(format!("Unexpected value: {value:?}")),
    };
    assert_eq!(value, 1u8);

    Ok(())
}

// This test checks that:
//  - a dependent program accepts an upgrade to off-chain logic
//  - a dependent program accepts an upgrade to on-chain logic
//  - a dependent program can fix a specific version of the dependency
//  - old executions of the dependent program are no longer valid after an upgrade
#[test]
#[ignore]
fn test_upgrade_with_dependents() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the two versions of the dependency program.
    let dependency_v0 = Program::from_str(
        r"
program dependency.aleo;

function sum:
    input r0 as u8.public;
    input r1 as u8.public;
    add r0 r1 into r2;
    output r0 as u8.public;

function sum_and_check:
    input r0 as u8.public;
    input r1 as u8.public;
    add r0 r1 into r2;
    async sum_and_check into r3;
    output r2 as u8.public;
    output r3 as dependency.aleo/sum_and_check.future;
finalize sum_and_check:
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )?;

    let dependency_v1 = Program::from_str(
        r"
program dependency.aleo;

function sum:
    input r0 as u8.public;
    input r1 as u8.public;
    add.w r0 r1 into r2;
    output r0 as u8.public;

function sum_and_check:
    input r0 as u8.public;
    input r1 as u8.public;
    add.w r0 r1 into r2;
    async sum_and_check into r3;
    output r2 as u8.public;
    output r3 as dependency.aleo/sum_and_check.future;
finalize sum_and_check:
    assert.eq true false;

constructor:
    assert.eq true true;
    ",
    )?;

    // Define the two versions of the dependent program.
    let dependent_v0 = Program::from_str(
        r"
import dependency.aleo;

program dependent.aleo;

function sum_unchecked:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum r0 r1 into r2;
    output r2 as u8.public;

function sum:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum r0 r1 into r2;
    async sum into r3;
    output r2 as u8.public;
    output r3 as dependent.aleo/sum.future;
finalize sum:
    assert.eq dependency.aleo/edition 0u16;

function sum_and_check:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum_and_check r0 r1 into r2 r3;
    async sum_and_check r3 into r4;
    output r2 as u8.public;
    output r4 as dependent.aleo/sum_and_check.future;
finalize sum_and_check:
    input r0 as dependency.aleo/sum_and_check.future;
    await r0;

constructor:
    assert.eq true true;
    ",
    )?;

    let dependent_v1 = Program::from_str(
        r"
import dependency.aleo;

program dependent.aleo;

function sum_unchecked:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum r0 r1 into r2;
    output r2 as u8.public;

function sum:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum r0 r1 into r2;
    async sum into r3;
    output r2 as u8.public;
    output r3 as dependent.aleo/sum.future;
finalize sum:
    assert.eq dependency.aleo/edition 1u16;

function sum_and_check:
    input r0 as u8.public;
    input r1 as u8.public;
    call dependency.aleo/sum_and_check r0 r1 into r2 r3;
    async sum_and_check r3 into r4;
    output r2 as u8.public;
    output r4 as dependent.aleo/sum_and_check.future;
finalize sum_and_check:
    input r0 as dependency.aleo/sum_and_check.future;
    await r0;

constructor:
    assert.eq true true;
    ",
    )?;

    // At a high level, this test will:
    // 1. Deploy the v0 dependency and v0 dependent.
    // 2. Verify that the the dependent program can be correctly executed.
    // 3. Update the dependency to v1.
    // 4. Verify that the call to `sum_and_check` automatically uses the new logic, however, the call `sum` fails because the edition is not 0.
    // 5. Update the dependent to v1.
    // 6. Verify that the call to `sum` now passes because the edition is 1.

    // Deploy the v0 dependency.
    let transaction = vm.deploy(&caller_private_key, &dependency_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the v0 dependent.
    let transaction = vm.deploy(&caller_private_key, &dependent_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the functions.
    let tx_1 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let tx_2 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum_and_check"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx_1, tx_2], rng)?;
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the sum function fails on overflow.
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        vm.execute(
            &caller_private_key,
            ("dependent.aleo", "sum"),
            vec![Value::from_str("255u8")?, Value::from_str("1u8")?].into_iter(),
            None,
            0,
            None,
            rng,
        )
    }));
    assert!(result.is_err());

    // Get a valid execution before the dependency upgrade.
    let sum_unchecked = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum_unchecked"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    assert!(vm.check_transaction(&sum_unchecked, None, rng).is_ok());

    // Update the dependency to v1.
    let transaction = vm.deploy(&caller_private_key, &dependency_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the original sum transaction fails after the dependency upgrade.
    assert!(vm.check_transaction(&sum_unchecked, None, rng).is_err());
    let block = sample_next_block(&vm, &caller_private_key, &[sum_unchecked], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Verify that the sum function fails on edition check.
    let tx_1 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let tx_2 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum_and_check"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx_1, tx_2], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 2);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Update the dependent to v1.
    let transaction = vm.deploy(&caller_private_key, &dependent_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the sum function passes.
    let tx_1 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum"),
        vec![Value::from_str("1u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let tx_2 = vm.execute(
        &caller_private_key,
        ("dependent.aleo", "sum"),
        vec![Value::from_str("255u8")?, Value::from_str("1u8")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx_1, tx_2], rng)?;
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that a deployment with a failing _init block is rejected.
#[test]
#[ignore]
fn test_failing_init_block() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the programs.
    let passing_program = Program::from_str(
        r"
program hello1.aleo;

function foo:
    input r0 as u8.public;
    output r0 as u8.public;

constructor:
    assert.eq true true;
    ",
    )?;

    let failing_program = Program::from_str(
        r"
program hello2.aleo;

function foo:
    input r0 as u8.public;
    output r0 as u8.public;

constructor:
    assert.eq true false;
    ",
    )?;

    // Deploy the passing program.
    let transaction = vm.deploy(&caller_private_key, &passing_program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the failing program.
    let transaction = vm.deploy(&caller_private_key, &failing_program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test verifies that anyone can upgrade a program whose that explicitly places no restrictions on upgrades in the constructor.
#[test]
#[ignore]
fn test_anyone_can_upgrade() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize unrelated callers.
    let unrelated_caller_private_key_0 = PrivateKey::new(rng)?;
    let unrelated_caller_address_0 = Address::try_from(&unrelated_caller_private_key_0)?;
    let unrelated_caller_private_key_1 = PrivateKey::new(rng)?;
    let unrelated_caller_address_1 = Address::try_from(&unrelated_caller_private_key_1)?;

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Fund the unrelated callers.
    let transfer_1 = vm.execute(
        &caller_private_key,
        ("credits.aleo", "transfer_public"),
        vec![Value::from_str(&format!("{unrelated_caller_address_0}"))?, Value::from_str("1_000_000_000_000u64")?]
            .into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let transfer_2 = vm.execute(
        &caller_private_key,
        ("credits.aleo", "transfer_public"),
        vec![Value::from_str(&format!("{unrelated_caller_address_1}"))?, Value::from_str("1_000_000_000_000u64")?]
            .into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transfer_1, transfer_2], rng)?;
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Define the programs.
    let program_v0 = Program::from_str(
        r"
program upgradable.aleo;
function foo:
constructor:
    assert.eq true true;
    ",
    )?;

    let program_v1 = Program::from_str(
        r"
program upgradable.aleo;
function foo:
function bar:
constructor:
    assert.eq true true;
    ",
    )?;

    let program_v2 = Program::from_str(
        r"
program upgradable.aleo;
function foo:
function bar:
function baz:
constructor:
    assert.eq true true;
    ",
    )?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the second version of the program.
    let transaction = vm.deploy(&unrelated_caller_private_key_0, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the third version of the program.
    let transaction = vm.deploy(&unrelated_caller_private_key_1, &program_v2, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that a program the fixes the expected edition cannot be upgraded.
#[test]
#[ignore]
fn test_non_upgradable_programs() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    let program_1_v0 = Program::from_str(
        r"
program non_upgradable_1.aleo;
function foo:
constructor:
    assert.eq edition 0u16;
    ",
    )?;

    let program_1_v1 = Program::from_str(
        r"
program non_upgradable_1.aleo;
function foo:
function bar:
constructor:
    assert.eq edition 0u16;
    ",
    )?;

    // Deploy the program and then upgrade. The upgrade should fail to be finalized.
    let transaction = vm.deploy(&caller_private_key, &program_1_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    let transaction = vm.deploy(&caller_private_key, &program_1_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that a program can be made non-upgradable after being upgradable.
#[test]
#[ignore]
fn test_downgrade_upgradable_program() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the programs.
    let program_v0 = Program::from_str(
        r"
program upgradable.aleo;
mapping locked:
    key as boolean.public;
    value as boolean.public;
function set_lock:
    async set_lock into r0;
    output r0 as upgradable.aleo/set_lock.future;
finalize set_lock:
    set true into locked[true];
function foo:
constructor:
    contains locked[true] into r0;
    assert.eq r0 false;
    ",
    )?;

    let program_v1 = Program::from_str(
        r"
program upgradable.aleo;
mapping locked:
    key as boolean.public;
    value as boolean.public;
function set_lock:
    async set_lock into r0;
    output r0 as upgradable.aleo/set_lock.future;
finalize set_lock:
    set true into locked[true];
function foo:
function bar:
constructor:
    contains locked[true] into r0;
    assert.eq r0 false;
    ",
    )?;

    let program_v2 = Program::from_str(
        r"
program upgradable.aleo;
mapping locked:
    key as boolean.public;
    value as boolean.public;
function set_lock:
    async set_lock into r0;
    output r0 as upgradable.aleo/set_lock.future;
finalize set_lock:
    set true into locked[true];
function foo:
function bar:
function baz:
constructor:
    contains locked[true] into r0;
    assert.eq r0 false;
    ",
    )?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the second version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Set the lock.
    let transaction = vm.execute(
        &caller_private_key,
        ("upgradable.aleo", "set_lock"),
        Vec::<Value<CurrentNetwork>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to deploy the third version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v2, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that an upgrade can be locked to a checksum.
// The checksum is managed by an admin address.
#[test]
#[ignore]
fn test_lock_upgrade_to_checksum() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the programs.
    let program_v0 = Program::from_str(&format!(
        r"
program locked_upgrade.aleo;
mapping admin:
    key as boolean.public;
    value as address.public;
mapping expected_checksum:
    key as boolean.public;
    value as [u8; 32u32].public;
function set_expected:
    input r0 as [u8; 32u32].public;
    async set_expected self.caller r0 into r1;
    output r1 as locked_upgrade.aleo/set_expected.future;
finalize set_expected:
    input r0 as address.public;
    input r1 as [u8; 32u32].public;
    get admin[true] into r2;
    assert.eq r0 r2;
    set r1 into expected_checksum[true];
constructor:
    branch.neq edition 0u16 to rest;
    set {caller_address} into admin[true];
    branch.eq true true to end;
    position rest;
    get expected_checksum[true] into r0;
    assert.eq r0 checksum;
    position end;
    "
    ))?;

    let program_v1 = Program::from_str(&format!(
        r"
program locked_upgrade.aleo;
mapping admin:
    key as boolean.public;
    value as address.public;
mapping expected_checksum:
    key as boolean.public;
    value as [u8; 32u32].public;
function bar:
function set_expected:
    input r0 as [u8; 32u32].public;
    async set_expected self.caller r0 into r1;
    output r1 as locked_upgrade.aleo/set_expected.future;
finalize set_expected:
    input r0 as address.public;
    input r1 as [u8; 32u32].public;
    get admin[true] into r2;
    assert.eq r0 r2;
    set r1 into expected_checksum[true];
constructor:
    branch.neq edition 0u16 to rest;
    set {caller_address} into admin[true];
    branch.eq true true to end;
    position rest;
    get expected_checksum[true] into r0;
    assert.eq r0 checksum;
    position end;
    "
    ))?;

    let program_v1_mismatch = Program::from_str(&format!(
        r"
program locked_upgrade.aleo;
mapping admin:
    key as boolean.public;
    value as address.public;
mapping expected_checksum:
    key as boolean.public;
    value as [u8; 32u32].public;
function baz:
function set_expected:
    input r0 as [u8; 32u32].public;
    async set_expected self.caller r0 into r1;
    output r1 as locked_upgrade.aleo/set_expected.future;
finalize set_expected:
    input r0 as address.public;
    input r1 as [u8; 32u32].public;
    get admin[true] into r2;
    assert.eq r0 r2;
    set r1 into expected_checksum[true];
constructor:
    branch.neq edition 0u16 to rest;
    set {caller_address} into admin[true];
    branch.eq true true to end;
    position rest;
    get expected_checksum[true] into r0;
    assert.eq r0 checksum;
    position end;
    "
    ))?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the caller is the admin.
    let Some(Value::Plaintext(Plaintext::Literal(Literal::Address(admin), _))) =
        vm.finalize_store().get_value_confirmed(
            ProgramID::from_str("locked_upgrade.aleo")?,
            Identifier::from_str("admin")?,
            &Plaintext::from_str("true")?,
        )?
    else {
        bail!("Unexpected entry in admin mapping");
    };
    assert_eq!(admin, caller_address);

    // Attempt to upgrade without setting the expected checksum.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to set the expected checksum with the wrong admin.
    let checksum = Value::from_str(
        r"[
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8
    ]",
    )?;
    let admin_private_key = PrivateKey::new(rng)?;
    let transaction = vm.execute(
        &admin_private_key,
        ("locked_upgrade.aleo", "set_expected"),
        vec![checksum].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Check that there is no expected checksum set.
    assert!(
        vm.finalize_store()
            .get_value_confirmed(
                ProgramID::from_str("locked_upgrade.aleo")?,
                Identifier::from_str("expected_checksum")?,
                &Plaintext::from_str("true")?,
            )?
            .is_none()
    );

    // Set the expected checksum.
    let checksum = program_v1.to_checksum();
    let transaction = vm.execute(
        &caller_private_key,
        ("locked_upgrade.aleo", "set_expected"),
        vec![Value::from_str(&format!("[{}]", checksum.iter().join(", ")))].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the expected checksum is set.
    let Some(Value::Plaintext(expected)) = vm.finalize_store().get_value_confirmed(
        ProgramID::from_str("locked_upgrade.aleo")?,
        Identifier::from_str("expected_checksum")?,
        &Plaintext::from_str("true")?,
    )?
    else {
        bail!("Unexpected entry in expected_checksum mapping");
    };
    assert_eq!(Plaintext::from(checksum), expected);

    // Attempt to upgrade with a mismatched program.
    let transaction = vm.deploy(&caller_private_key, &program_v1_mismatch, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Update with the expected checksum set.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

#[test]
#[ignore]
fn test_upgrade_without_changing_contents_passes() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?, rng);

    // Define the program.
    let program_v0 = Program::from_str(
        r"
program upgradable.aleo;
constructor:
    assert.eq true true;
function dummy:",
    )?;

    // Define a variant of the program that contains an extra mapping.
    let program_v1 = Program::from_str(
        r"
program upgradable.aleo;
constructor:
    assert.eq true true;
mapping foo:
    key as boolean.public;
    value as boolean.public;
function dummy:",
    )?;

    // Construct the first deployment.
    let transaction_first = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let deployment_first = transaction_first.deployment().unwrap();
    assert_eq!(deployment_first.edition(), 0);
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_first], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the program again without changing its contents.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let deployment = transaction.deployment().unwrap();
    assert_eq!(deployment.edition(), 1);
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Deploy the program with an extra mapping as an upgrade.
    let transaction_third = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let deployment_third = transaction_third.deployment().unwrap();
    assert_eq!(deployment_third.edition(), 2);
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_third], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    Ok(())
}

// This test verifies that the `credits` program is not upgradable.
#[test]
#[ignore]
fn test_credits_is_not_upgradable() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(), rng);

    // Add a function to the credits program.
    let credits_program = Program::<CurrentNetwork>::credits().unwrap();
    let program = Program::from_str(&format!("{credits_program}\nfunction dummy:")).unwrap();

    // Attempt to deploy the program.
    assert!(vm.deploy(&caller_private_key, &program, None, 0, None, rng).is_err());
}

// This test verifies that programs that were deployed before the upgrade cannot be upgraded.
#[test]
#[ignore]
fn test_existing_programs_cannot_be_upgraded() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)? - 2, rng);

    // Define the programs.
    let program_0_v0 = Program::from_str(
        r"
program test_program_one.aleo;
function dummy:",
    )?;

    let program_1_v0 = Program::from_str(
        r"
program test_program_two.aleo;
function dummy:",
    )?;

    let program_0_v1_without_constructor = Program::from_str(
        r"
program test_program_one.aleo;
function dummy:
function dummy_2:",
    )?;

    let program_0_v1_with_failing_constructor = Program::from_str(
        r"
program test_program_one.aleo;
function dummy:
function dummy_2:
constructor:
    assert.eq edition 0u16;",
    )?;

    let program_0_v1_valid = Program::from_str(
        r"
program test_program_one.aleo;
function dummy:
function dummy_2:
constructor:
    assert.eq edition 1u16;",
    )?;

    let program_0_v2_fails = Program::from_str(
        r"
program test_program_one.aleo;
function dummy:
function dummy_2:
function dummy_3:
constructor:
    assert.eq edition 1u16;",
    )?;

    let program_1_v1_valid = Program::from_str(
        r"
program test_program_two.aleo;
function dummy:
function dummy_2:
constructor:
    assert.eq true true;",
    )?;

    // Deploy the v0 versions of the programs.
    let transaction = vm.deploy(&caller_private_key, &program_0_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    let transaction = vm.deploy(&caller_private_key, &program_1_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Assert that the VM is after the V9 height.
    assert_eq!(vm.block_store().current_block_height(), CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?);

    // Attempt to upgrade the first program.
    let result = vm.deploy(&caller_private_key, &program_0_v1_without_constructor, None, 0, None, rng);
    assert!(result.is_err());

    // Attempt to upgrade the first program.
    let result = vm.deploy(&caller_private_key, &program_0_v1_with_failing_constructor, None, 0, None, rng);
    assert!(result.is_err());

    // Attempt to upgrade the first program.
    let result = vm.deploy(&caller_private_key, &program_0_v1_valid, None, 0, None, rng);
    assert!(result.is_err());

    // Attempt to upgrade the first program.
    let result = vm.deploy(&caller_private_key, &program_0_v2_fails, None, 0, None, rng);
    assert!(result.is_err());

    // Attempt to upgrade the second program.
    let result = vm.deploy(&caller_private_key, &program_1_v1_valid, None, 0, None, rng);
    assert!(result.is_err());

    Ok(())
}

// This test checks that a program can be upgraded using the simple admin mechanism.
#[test]
#[ignore]
fn test_simple_admin_upgrade() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(), rng);

    // Generate a separate caller.
    let separate_caller_private_key = PrivateKey::new(rng).unwrap();
    let separate_caller_address = Address::try_from(&separate_caller_private_key).unwrap();

    // Fund the new caller with 10M credits.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            vec![
                Value::from_str(&format!("{separate_caller_address}")).unwrap(),
                Value::from_str("10_000_000_000_000u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Define the programs.
    let program_v0 = Program::from_str(&format!(
        r"
program simple_admin.aleo;
function foo:
constructor:
    assert.eq program_owner {caller_address};
    "
    ))
    .unwrap();

    let program_v1 = Program::from_str(&format!(
        r"
program simple_admin.aleo;
function foo:
function bar:
constructor:
    assert.eq program_owner {caller_address};
    "
    ))
    .unwrap();

    // Attempt to deploy the first version of the program with the wrong admin.
    let transaction = vm.deploy(&separate_caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the first version of the program with the correct admin.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Attempt to upgrade the program with the wrong admin.
    let transaction = vm.deploy(&separate_caller_private_key, &program_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade the program with the correct admin.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies the behavior of `partially_verified_transactions` cache for transactions before and after a program upgrade.
#[test]
#[ignore]
fn test_verification_cache() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::latest()).unwrap(), rng);

    // Define the programs.
    let program_v0 = Program::from_str(
        r"
program test_program.aleo;
function foo:
   input r0 as boolean.private;
   assert.eq r0 true;
constructor:
   assert.eq true true;
   ",
    )
    .unwrap();

    let program_v1 = Program::from_str(
        r"
program test_program.aleo;
function foo:
   input r0 as boolean.private;
   assert.eq r0 false;
constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute a transaction with the first version of the program.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test_program.aleo", "foo"),
            vec![Value::from_str("true").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Get the size of the verification cache before running the verification.
    let cache_size_before = vm.partially_verified_transactions().read().len();

    // Verify the transaction and check the cache size.
    assert!(vm.check_transaction(&execution, None, rng).is_ok());
    let cache_size_after = vm.partially_verified_transactions().read().len();
    assert_eq!(cache_size_after, cache_size_before + 1);

    // Upgrade the program to the new version.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify the transaction again and check the cache size.
    assert!(vm.check_transaction(&execution, None, rng).is_err());
    let cache_size_after_upgrade = vm.partially_verified_transactions().read().len();
    assert_eq!(cache_size_after_upgrade, cache_size_after + 1);
}

// This test verifies that
//   - a program deployed before `V9` does not have an owner.
//   - `credits.aleo` does not have an owner.
//   - a program deployed after `V9` has an owner.
#[test]
#[ignore]
fn test_program_deployed_before_v9_do_not_have_owner() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() - 1, rng);

    // Define the programs.
    let program_before_v9 = Program::from_str(
        r"
program test_program_0.aleo;
function foo:",
    )
    .unwrap();

    let program_after_v9 = Program::from_str(
        r"
program test_program_1.aleo;
function foo:
constructor:
    assert.eq true true;
",
    )
    .unwrap();

    // Deploy the first program.
    let transaction = vm.deploy(&caller_private_key, &program_before_v9, None, 0, None, rng).unwrap();
    // Check that the deployment does not have an owner or checksum.
    assert!(transaction.deployment().unwrap().program_checksum().is_none());
    assert!(transaction.deployment().unwrap().program_owner().is_none());
    // Create the next block and check that the transaction is accepted.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the second program.
    let transaction = vm.deploy(&caller_private_key, &program_after_v9, None, 0, None, rng).unwrap();
    // Check that the deployment has an owner and checksum.
    assert!(transaction.deployment().unwrap().program_checksum().is_some());
    assert!(transaction.deployment().unwrap().program_owner().is_some());
    // Create the next block and check that the transaction is accepted.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Check the owners of the programs.
    let stack = vm.process().get_stack("credits.aleo").unwrap();
    assert!(stack.program_owner().is_none());

    let stack = vm.process().get_stack("test_program_0.aleo").unwrap();
    assert!(stack.program_owner().is_none());

    let stack = vm.process().get_stack("test_program_1.aleo").unwrap();
    assert!(stack.program_owner().is_some());
    assert_eq!(stack.program_owner().unwrap(), caller_address);
}

#[test]
#[ignore]
fn test_old_execution_is_aborted_after_upgrade() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(), rng);

    // Define the programs.
    let program_v0 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function dummy:",
    )
    .unwrap();

    let program_v1 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function dummy:
function dummy2:",
    )
    .unwrap();

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Pre-generate 3 executions of the dummy function.
    let executions = (0..3)
        .map(|_| {
            vm.execute(
                &caller_private_key,
                ("test_program.aleo", "dummy"),
                Vec::<Value<_>>::new().into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Add 2 transactions individually to blocks.
    // They are expected to pass because the program has not been upgraded.
    for execution in &executions[0..2] {
        let block = sample_next_block(&vm, &caller_private_key, std::slice::from_ref(execution), rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }

    // Upgrade the program.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Add the third transaction to a block.
    // It is expected to be aborted because the program has been upgraded.
    let block = sample_next_block(&vm, &caller_private_key, &[executions[2].clone()], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that `credits.aleo` transactions can be executed and added to blocks after the upgrade to V9.
#[test]
#[ignore]
fn test_credits_executions() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Initialize the VM.
    let vm: crate::VM<CurrentNetwork, LedgerType> =
        sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() - 1, rng);

    // Generate two executions of `transfer_public`.
    let transfer_1 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            vec![Value::from_str(&format!("{caller_address}")).unwrap(), Value::from_str("2u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    assert!(vm.check_transaction(&transfer_1, None, rng).is_ok());

    let transfer_2 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            vec![Value::from_str(&format!("{caller_address}")).unwrap(), Value::from_str("4u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    assert!(vm.check_transaction(&transfer_2, None, rng).is_ok());

    // Add the first transaction to a block.
    let block = sample_next_block(&vm, &caller_private_key, &[transfer_1], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Skip to consensus height V9.
    while vm.block_store().current_block_height() <= CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() {
        let block = sample_next_block(&vm, &caller_private_key, &[], rng).unwrap();
        vm.add_next_block(&block).unwrap();
    }

    // Add the second transaction to a block.
    let block = sample_next_block(&vm, &caller_private_key, &[transfer_2], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
}

// This tests verifies that:
//  - a set of programs with cyclic imports can be deployed and executed.
//  - a set of programs with cyclic calls cannot be deployed.
//  - the VM can be loaded from a store at the very end.
//  - the VM can be loaded directly from the latest programs.
#[test]
#[ignore]
fn test_cyclic_imports_and_call_graphs() {
    let rng = &mut TestRng::default();

    // Initialize the storage.
    let store = ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the VM.
    let mut vm = VM::<CurrentNetwork, LedgerType>::from(store.clone()).unwrap();
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis).unwrap();

    // Get the genesis private key.
    let caller_private_key = sample_genesis_private_key(rng);

    // Advance the VM to `ConsensusVersion::V9`.
    advance_vm_to_height(
        &mut vm,
        caller_private_key,
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(),
        rng,
    );

    // Define the programs with cyclic imports.
    let program_a_v0 = Program::from_str(
        r"
program cyclic_import_a.aleo;

function foo:
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    let program_b_v0 = Program::from_str(
        r"
import cyclic_import_a.aleo;

program cyclic_import_b.aleo;

function bar:
    call cyclic_import_a.aleo/foo;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    let program_a_v1 = Program::from_str(
        r"
import cyclic_import_b.aleo;

program cyclic_import_a.aleo;

function foo:
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    let program_a_v2 = Program::from_str(
        r"
import cyclic_import_b.aleo;

program cyclic_import_a.aleo;

function foo:
    call cyclic_import_b.aleo/bar;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Deploy the first version of program A.
    let transaction = vm.deploy(&caller_private_key, &program_a_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the first version of program B.
    let transaction = vm.deploy(&caller_private_key, &program_b_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute `foo` and `bar`.
    let execution_foo = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_a.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let execution_bar = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_b.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution_foo, execution_bar], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade program A to version 1.
    let transaction = vm.deploy(&caller_private_key, &program_a_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute `foo` and `bar`.
    let execution_foo = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_a.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let execution_bar = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_b.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution_foo, execution_bar], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Attempt to upgrade program A to version 2.
    let result = vm.deploy(&caller_private_key, &program_a_v2, None, 0, None, rng);
    assert!(result.is_err());

    // Drop the VM.
    drop(vm);

    // Load the VM from the store.
    let vm = VM::<CurrentNetwork, LedgerType>::from(store).unwrap();

    // Check that the latest block.
    let latest_block = vm.store.block_store().current_block_height();
    assert_eq!(latest_block, CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() + 5);

    // Check that the programs can be executed.
    let execution_foo = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_a.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let execution_bar = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_b.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution_foo, execution_bar], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Drop the VM.
    drop(vm);

    // Initialize a new VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(), rng);
    // Add the programs to the VM.
    vm.process().lock().add_programs_with_editions(&[(program_a_v1, 1), (program_b_v0, 0)]).unwrap();

    // Check that the programs can be executed.
    let execution_foo = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_a.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let execution_bar = vm
        .execute(
            &caller_private_key,
            ("cyclic_import_b.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution_foo, execution_bar], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test checks that a program can only be upgraded after a certain block height.
#[test]
#[ignore]
fn test_upgrade_after_block_height() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM at the V9 height.
    let vm: crate::VM<CurrentNetwork, LedgerType> =
        sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(), rng);

    // Define the programs.
    let program_v0 = Program::from_str(
        r"
program upgradable.aleo;
function foo:
constructor:
    branch.eq edition 0u16 to end;
    gte block.height 15u32 into r0;
    assert.eq r0 true;
    position end;
    ",
    )?;

    let program_v1 = Program::from_str(
        r"
program upgradable.aleo;
function foo:
function bar:
constructor:
    branch.eq edition 0u16 to end;
    gte block.height 15u32 into r0;
    assert.eq r0 true;
    position end;
    ",
    )?;

    // Deploy the first version of the program.
    let transaction = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.height(), 13);
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to deploy the second version of the program before block height 15.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.height(), 14);
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to deploy the second version of the program at block height 15.
    let transaction = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.height(), 15);
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test verifies that:
//  - executions of a program before an upgrade in the same block are accepted.
//  - executions of a program after an upgrade in the same block are aborted.
//  - an old execution of a program after an upgrade is accepted in a subsequent block, if the program contents match.
//  - an old execution of a program after an upgrade is aborted in a subsequent block, if the program contents do not match.
#[test]
#[ignore]
fn test_upgrade_and_execute_in_same_block() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V9 height.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v9_height, rng);

    // Define the original program.
    let program_v0 = Program::from_str(
        r"
program test_one.aleo;

constructor:
    assert.eq true true;

mapping first:
    key as field.public;
    value as field.public;

function set_first:
    input r0 as field.public;
    input r1 as field.public;
    async set_first r0 r1 into r2;
    output r2 as test_one.aleo/set_first.future;
finalize set_first:
    input r0 as field.public;
    input r1 as field.public;
    set r0 into first[r1];",
    )
    .unwrap();
    // Define the V1 program with an additional mapping.
    let program_v1 = Program::from_str(
        r"
program test_one.aleo;

constructor:
    assert.eq true true;

mapping first:
    key as field.public;
    value as field.public;

mapping second:
    key as field.public;
    value as field.public;

function set_first:
    input r0 as field.public;
    input r1 as field.public;
    async set_first r0 r1 into r2;
    output r2 as test_one.aleo/set_first.future;
finalize set_first:
    input r0 as field.public;
    input r1 as field.public;
    set r0 into first[r1];
    set r0 into second[r1];",
    )
    .unwrap();

    // Deploy the original program.
    let deployment_v0 = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_v0], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the program.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("test_one.aleo", "set_first"),
            [Value::from_str("0field").unwrap(), Value::from_str("0field").unwrap()].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the entry exists in the mapping.
    let Some(Value::Plaintext(Plaintext::Literal(Literal::Field(field), _))) = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("test_one.aleo").unwrap(),
            Identifier::from_str("first").unwrap(),
            &Plaintext::from_str("0field").unwrap(),
        )
        .unwrap()
    else {
        panic!("Expected a valid field.");
    };
    assert_eq!(field, Field::from_str("0field").unwrap());

    // Get four executions of the original program with different values.
    let executions = Vec::from_iter((1..5).map(|i| {
        vm.execute(
            &caller_private_key,
            ("test_one.aleo", "set_first"),
            [Value::from_str(&format!("{i}field")).unwrap(), Value::from_str("1field").unwrap()].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    }));

    // Deploy the original program again.
    let deployment_v0 = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    // Add the upgrade and execution to the VM.
    let block = sample_next_block(
        &vm,
        &caller_private_key,
        &[executions[0].clone(), deployment_v0, executions[1].clone()],
        rng,
    )
    .unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Check that the program was upgraded.
    let edition = *vm.process().get_stack(ProgramID::from_str("test_one.aleo").unwrap()).unwrap().program_edition();
    assert_eq!(edition, 1);

    // Verify that the first execution was successful.
    let Some(Value::Plaintext(Plaintext::Literal(Literal::Field(field), _))) = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("test_one.aleo").unwrap(),
            Identifier::from_str("first").unwrap(),
            &Plaintext::from_str("1field").unwrap(),
        )
        .unwrap()
    else {
        panic!("Expected a valid field.");
    };
    assert_eq!(field, Field::from_str("1field").unwrap());

    // Now add an old execution that was made before the upgrade.
    // This should pass because the program contents have not changed.
    let block = sample_next_block(&vm, &caller_private_key, &[executions[2].clone()], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the entry exists in the first mapping.
    let Some(Value::Plaintext(Plaintext::Literal(Literal::Field(field), _))) = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("test_one.aleo").unwrap(),
            Identifier::from_str("first").unwrap(),
            &Plaintext::from_str("1field").unwrap(),
        )
        .unwrap()
    else {
        panic!("Expected a valid field.");
    };
    assert_eq!(field, Field::from_str("3field").unwrap());

    // Now deploy the new program with the additional mapping.
    let deployment_v1 = vm.deploy(&caller_private_key, &program_v1, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_v1], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Check that the program was upgraded.
    let edition = *vm.process().get_stack(ProgramID::from_str("test_one.aleo").unwrap()).unwrap().program_edition();
    assert_eq!(edition, 2);

    // Now add an old execution that was made before the upgrade.
    // This should fail because the program contents have changed.
    let block = sample_next_block(&vm, &caller_private_key, &[executions[3].clone()], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute the new program with the new mapping.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("test_one.aleo", "set_first"),
            [Value::from_str("6field").unwrap(), Value::from_str("1field").unwrap()].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the entry exists in the second mapping.
    let Some(Value::Plaintext(Plaintext::Literal(Literal::Field(field), _))) = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("test_one.aleo").unwrap(),
            Identifier::from_str("second").unwrap(),
            &Plaintext::from_str("1field").unwrap(),
        )
        .unwrap()
    else {
        panic!("Expected a valid field.");
    };
    assert_eq!(field, Field::from_str("6field").unwrap());
}

// This test verifies that a program can be upgraded and then upgraded again in the same block.
// Note: It is important that this invariant holds, otherwise block rollbacks in the DB can be inconsistent.
#[test]
#[ignore]
fn test_upgrade_and_upgrade_in_same_block() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V9 height.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v9_height, rng);

    // Deploy the upgradable program.
    let program_v0 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function foo:
        ",
    )
    .unwrap();

    let deployment_v0 = vm.deploy(&caller_private_key, &program_v0, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_v0], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Fund two accounts to pay for the two upgrades.
    // This has to be done because only one deployment can be made per fee-paying address per block.
    let private_key_1 = PrivateKey::new(rng).unwrap();
    let private_key_2 = PrivateKey::new(rng).unwrap();
    let address_1 = Address::try_from(&private_key_1).unwrap();
    let address_2 = Address::try_from(&private_key_2).unwrap();

    let tx_1 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            [Value::from_str(&format!("{address_1}")).unwrap(), Value::from_str("100_000_000u64").unwrap()].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let tx_2 = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            [Value::from_str(&format!("{address_2}")).unwrap(), Value::from_str("100_000_000u64").unwrap()].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[tx_1, tx_2], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade the program twice.
    let program_v1 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function foo:
function bar:
        ",
    )
    .unwrap();

    let program_v2 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function foo:
function bar:
function baz:
        ",
    )
    .unwrap();

    // Generate the deployments.
    // Note that we are attempting to upgrade twice with consecutive editions.
    let process = Process::load().unwrap();
    process.lock().add_program(&program_v0).unwrap();
    let mut deployment_v1 = process.deploy::<CurrentAleo, _>(&program_v1, rng).unwrap();
    deployment_v1.set_program_checksum_raw(Some(deployment_v1.program().to_checksum()));
    deployment_v1.set_program_owner_raw(Some(Address::try_from(&private_key_1).unwrap()));
    assert_eq!(deployment_v1.edition(), 1);
    process.lock().add_program(&program_v1).unwrap();
    let mut deployment_v2 = process.deploy::<CurrentAleo, _>(&program_v2, rng).unwrap();
    deployment_v2.set_program_checksum_raw(Some(deployment_v2.program().to_checksum()));
    deployment_v2.set_program_owner_raw(Some(Address::try_from(&private_key_2).unwrap()));
    assert_eq!(deployment_v2.edition(), 2);

    // Construct the transactions.
    let fee_1 = vm
        .execute_fee_authorization(
            process
                .authorize_fee_public::<CurrentAleo, _>(
                    &private_key_1,
                    10_000_000,
                    0,
                    deployment_v1.to_deployment_id().unwrap(),
                    rng,
                )
                .unwrap(),
            None,
            rng,
        )
        .unwrap();
    let owner_1 = ProgramOwner::new(&private_key_1, deployment_v1.to_deployment_id().unwrap(), rng).unwrap();
    let transaction_1 = Transaction::from_deployment(owner_1, deployment_v1, fee_1).unwrap();
    let fee_2 = vm
        .execute_fee_authorization(
            process
                .authorize_fee_public::<CurrentAleo, _>(
                    &private_key_2,
                    10_000_000,
                    0,
                    deployment_v2.to_deployment_id().unwrap(),
                    rng,
                )
                .unwrap(),
            None,
            rng,
        )
        .unwrap();
    let owner_2 = ProgramOwner::new(&private_key_2, deployment_v2.to_deployment_id().unwrap(), rng).unwrap();
    let transaction_2 = Transaction::from_deployment(owner_2, deployment_v2, fee_2).unwrap();

    // Attempt to upgrade the program twice.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_1, transaction_2], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Attempt to upgrade twice using the same edition.
    let program_v3 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function foo:
function bar:
function baz:
function qux:
        ",
    )
    .unwrap();

    let program_v4 = Program::from_str(
        r"
program test_program.aleo;
constructor:
    assert.eq true true;
function foo:
function bar:
function baz:
function qux:
function fly:
        ",
    )
    .unwrap();

    // Generate the deployments.
    let mut deployment_v3 = process.deploy::<CurrentAleo, _>(&program_v3, rng).unwrap();
    deployment_v3.set_program_checksum_raw(Some(deployment_v3.program().to_checksum()));
    deployment_v3.set_program_owner_raw(Some(Address::try_from(&private_key_1).unwrap()));
    assert_eq!(deployment_v3.edition(), 2);
    let mut deployment_v4 = process.deploy::<CurrentAleo, _>(&program_v4, rng).unwrap();
    deployment_v4.set_program_checksum_raw(Some(deployment_v4.program().to_checksum()));
    deployment_v4.set_program_owner_raw(Some(Address::try_from(&private_key_2).unwrap()));
    assert_eq!(deployment_v4.edition(), 2);

    // Construct the transactions.
    let fee_1 = vm
        .execute_fee_authorization(
            process
                .authorize_fee_public::<CurrentAleo, _>(
                    &private_key_1,
                    10_000_000,
                    0,
                    deployment_v3.to_deployment_id().unwrap(),
                    rng,
                )
                .unwrap(),
            None,
            rng,
        )
        .unwrap();
    let owner_1 = ProgramOwner::new(&private_key_1, deployment_v3.to_deployment_id().unwrap(), rng).unwrap();
    let transaction_1 = Transaction::from_deployment(owner_1, deployment_v3, fee_1).unwrap();
    let fee_2 = vm
        .execute_fee_authorization(
            process
                .authorize_fee_public::<CurrentAleo, _>(
                    &private_key_2,
                    10_000_000,
                    0,
                    deployment_v4.to_deployment_id().unwrap(),
                    rng,
                )
                .unwrap(),
            None,
            rng,
        )
        .unwrap();
    let owner_2 = ProgramOwner::new(&private_key_2, deployment_v4.to_deployment_id().unwrap(), rng).unwrap();
    let transaction_2 = Transaction::from_deployment(owner_2, deployment_v4, fee_2).unwrap();

    // Attempt to upgrade the program twice.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_1, transaction_2], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
}

// This test checks that:
//  - an upgradable program can depend on a program deployed before `V9`.
//  - if the program deployed before `V9` has not done the one-time upgrade, then the upgradable program cannot be executed.
//  - once the program deployed before `V9` has done the one-time upgrade, the upgradable program can be executed.
#[test]
#[ignore]
fn test_upgradable_program_with_pre_v9_dependency() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM one block before the V9 height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() - 1;
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the pre-V9 program.
    let pre_v9_program = Program::from_str(
        r"
program pre_v9_program.aleo;

function foo:
    assert.eq true true;
",
    )
    .unwrap();

    // Define the upgradable program that depends on the pre-V9 program.
    let upgradable_program = Program::from_str(
        r"
import pre_v9_program.aleo;
program upgradable_program.aleo;

function bar:
    call pre_v9_program.aleo/foo;

function baz:
    assert.eq true true;

constructor:
    assert.eq true true;
",
    )
    .unwrap();

    // Deploy the pre-V9 program.
    let deployment = vm.deploy(&caller_private_key, &pre_v9_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the upgradable program.
    let deployment = vm.deploy(&caller_private_key, &upgradable_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Attempt to execute the upgradable program.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("upgradable_program.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    let execution = vm
        .execute(
            &caller_private_key,
            ("upgradable_program.aleo", "baz"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade the pre-V9 program.
    let deployment = vm.deploy(&caller_private_key, &pre_v9_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Now execute the upgradable program.
    let execution = vm
        .execute(
            &caller_private_key,
            ("upgradable_program.aleo", "bar"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that:
//  - child programs can be added beyond `MAX_TRANSITION` depth.
//  - child programs can be upgraded beyond `MAX_TRANSITION` depth.
//  - parent programs that exceed the depth exist, but fail to execute.
//  - the VM can be loaded from the store.
#[test]
#[ignore]
fn test_upgrade_beyond_max_transition_depth() {
    let rng = &mut TestRng::default();

    // Initialize the storage.
    let store = ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the VM.
    let mut vm = VM::<CurrentNetwork, LedgerType>::from(store.clone()).unwrap();
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis).unwrap();

    // Get the genesis private key.
    let caller_private_key = sample_genesis_private_key(rng);

    // Advance the VM to `ConsensusVersion::V9`.
    advance_vm_to_height(
        &mut vm,
        caller_private_key,
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(),
        rng,
    );

    // Define root program.
    let root_program = Program::from_str(
        r"
program parent_program_0.aleo;
function foo:
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Define a function to generate a program with a given depth.
    fn generate_program(depth: usize) -> Program<CurrentNetwork> {
        let mut imports = String::new();
        for i in 0..depth {
            imports.push_str(&format!("import parent_program_{i}.aleo;\n"));
        }
        let program_str = format!(
            r"
{imports}
program parent_program_{depth}.aleo;
function foo:
    call parent_program_{}.aleo/foo;

constructor:
    assert.eq true true;
    ",
            depth - 1
        );
        Program::from_str(&program_str).unwrap()
    }

    // Deploy the root program.
    let deployment = vm.deploy(&caller_private_key, &root_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy child programs up to the maximum transition depth.
    for i in 1..(Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 1) {
        let program = generate_program(i);
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }

    // Verify that the uppermost program can be executed.
    let execution = vm
        .execute(
            &caller_private_key,
            (format!("parent_program_{}.aleo", Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 2), "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy a program lower than the lowest program.
    let lower_program = Program::from_str(
        r"
program parent_program_negative.aleo;
function foo:
    assert.eq true true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    let deployment = vm.deploy(&caller_private_key, &lower_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade the zero program to call the lower program.
    let upgrade_program = Program::from_str(
        r"
import parent_program_negative.aleo;
program parent_program_0.aleo;
function foo:
    call parent_program_negative.aleo/foo;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Attempt to upgrade the zero program.
    let deployment = vm.deploy(&caller_private_key, &upgrade_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the zero program can be executed.
    let execution = vm
        .execute(
            &caller_private_key,
            ("parent_program_0.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify the uppermost parent cannot be executed.
    let execution = vm.execute(
        &caller_private_key,
        (format!("parent_program_{}.aleo", Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 2), "foo"),
        Vec::<Value<_>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(execution.is_err(), "Expected an error when executing the uppermost parent program after upgrade.");

    // Verify that the second-to-last parent can still be executed.
    let execution = vm
        .execute(
            &caller_private_key,
            (format!("parent_program_{}.aleo", Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 3), "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Drop the VM.
    drop(vm);

    // Verify that the VM can still be loaded from the store.
    let vm = VM::<CurrentNetwork, LedgerType>::from(store).unwrap();

    // Check that all programs are present in the process.
    for i in 0..(Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 1) {
        let program_id = ProgramID::from_str(&format!("parent_program_{i}.aleo")).unwrap();
        assert!(vm.process().get_stack(program_id).is_ok(), "Program parent_program_{i}.aleo should exist.");
    }
    assert!(
        vm.process().get_stack(ProgramID::from_str("parent_program_negative.aleo").unwrap()).is_ok(),
        "Program parent_program_negative.aleo should exist."
    );

    // Verify that the uppermost parent program cannot be executed.
    let execution = vm.execute(
        &caller_private_key,
        (format!("parent_program_{}.aleo", Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 2), "foo"),
        Vec::<Value<_>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(execution.is_err(), "Expected an error when executing the uppermost parent program after upgrade.");

    // Verify that the second-to-last parent can still be executed.
    let execution = vm
        .execute(
            &caller_private_key,
            (format!("parent_program_{}.aleo", Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 3), "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that:
//   - a child program can be upgraded beyond the transaction spend limit.
//   - the parent program exists, but cannot be executed.
//   - the VM can be loaded from the store.
#[test]
#[ignore]
fn test_upgrade_child_program_beyond_transaction_spend_limit() {
    let rng = &mut TestRng::default();

    // Initialize the storage.
    let store = ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the VM.
    let mut vm = VM::<CurrentNetwork, LedgerType>::from(store.clone()).unwrap();
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis).unwrap();

    // Get the genesis private key.
    let caller_private_key = sample_genesis_private_key(rng);

    // Advance the VM to `ConsensusVersion::V9`.
    advance_vm_to_height(
        &mut vm,
        caller_private_key,
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap(),
        rng,
    );

    // A helper to construct a finalize body with `n` expensive hash operations.
    fn construct_finalize_body(n: usize, register_offset: usize) -> String {
        let mut finalize_body = format!(
            r"
    cast  0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 into r{one} as [u8; 16u32];
    cast  r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} r{one} into r{two} as [[u8; 16u32]; 16u32];
    cast  r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} r{two} into r{three} as [[[u8; 16u32]; 16u32]; 16u32];",
            one = register_offset,
            two = register_offset + 1,
            three = register_offset + 2
        );
        (3..(3 + n)).for_each(|i| {
            finalize_body.push_str(&format!(
                "hash.bhp256 r{} into r{} as field;\n",
                register_offset + 2,
                i + register_offset
            ));
        });
        finalize_body
    }

    // Define the child program.
    let child_program = Program::from_str(&format!(
        r"
program child_program.aleo;

function foo:
    async foo into r0;
    output r0 as child_program.aleo/foo.future;

finalize foo:
    {}

constructor:
    assert.eq true true;
    ",
        construct_finalize_body(50, 0)
    ))
    .unwrap();

    // Define the parent program that calls the child program.
    let parent_program = Program::from_str(&format!(
        r"
import child_program.aleo;

program parent_program.aleo;
function foo:
    call child_program.aleo/foo into r0;
    async foo r0 into r1;
    output r1 as parent_program.aleo/foo.future;

finalize foo:
    input r0 as child_program.aleo/foo.future;
    await r0;
    {}

constructor:
    assert.eq true true;
    ",
        construct_finalize_body(25, 1)
    ))
    .unwrap();

    // Deploy the child program.
    let child_deployment = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[child_deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the parent program.
    let parent_deployment = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[parent_deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the parent program.
    let execution = vm
        .execute(
            &caller_private_key,
            ("parent_program.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Upgrade the child program with a more expensive finalize body.
    let upgraded_child_program = Program::from_str(&format!(
        r"
program child_program.aleo;
function foo:
    async foo into r0;
    output r0 as child_program.aleo/foo.future;
finalize foo:
    {}

constructor:
    assert.eq true true;
    ",
        construct_finalize_body(75, 0)
    ))
    .unwrap();

    // Attempt to upgrade the child program.
    let upgraded_child_deployment =
        vm.deploy(&caller_private_key, &upgraded_child_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[upgraded_child_deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the child program.
    let execution = vm
        .execute(
            &caller_private_key,
            ("child_program.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the parent program cannot be executed after the upgrade.
    let execution = vm
        .execute(
            &caller_private_key,
            ("parent_program.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Drop the VM.
    drop(vm);

    // Verify that the VM can still be loaded from the store.
    let vm = VM::<CurrentNetwork, LedgerType>::from(store).unwrap();

    // Check that the parent program exists in the process.
    let parent_program_id = ProgramID::from_str("parent_program.aleo").unwrap();
    assert!(vm.process().get_stack(parent_program_id).is_ok(), "Program parent_program.aleo should exist.");

    // Check that the child program exists in the process.
    let child_program_id = ProgramID::from_str("child_program.aleo").unwrap();
    assert!(vm.process().get_stack(child_program_id).is_ok(), "Program child_program.aleo should exist.");

    // Execute the child program to verify it still works.
    let execution = vm
        .execute(
            &caller_private_key,
            ("child_program.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Verify that the parent program still cannot be executed.
    let execution = vm
        .execute(
            &caller_private_key,
            ("parent_program.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();
}
