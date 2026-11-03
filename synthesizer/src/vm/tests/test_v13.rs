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

use console::{account::ViewKey, network::ConsensusVersion};
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::TestRng;

// This test verifies that a program with a mapping containing a missing struct can be deployed on
// consensus version 12.
#[test]
fn test_deploy_mapping_with_missing_struct_programs_v12() {
    let block = deploy_mapping_with_missing_struct_program(ConsensusVersion::V12);

    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
}

// This test verifies that a program with a mapping containing a missing struct cannot be deployed on
// consensus version 13.
#[test]
fn test_deploy_mapping_with_missing_struct_v13() {
    let block = deploy_mapping_with_missing_struct_program(ConsensusVersion::V13);

    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

fn deploy_mapping_with_missing_struct_program(consensus_version: ConsensusVersion) -> Block<CurrentNetwork> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the correct height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(consensus_version).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the first program with a record.
    let program_one = Program::from_str(
        r"
program child.aleo;

mapping foo:
    key as field.public;
    value as S.public;

function dummy:

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program_one, None, 0, None, rng).unwrap();
    sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap()
}

// This test verifies that a program with a mapping containing a missing struct cannot be deployed on
// consensus version 13.
#[test]
fn test_deploy_mapping_with_missing_external_struct_v13() {
    let block = deploy_mapping_with_missing_external_struct_programs(ConsensusVersion::V13);

    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
}

fn deploy_mapping_with_missing_external_struct_programs(consensus_version: ConsensusVersion) -> Block<CurrentNetwork> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the correct height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(consensus_version).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the first program with a record.
    let program_one = Program::from_str(
        r"
program child.aleo;

function dummy:

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the second program which refers to the external struct type.
    let program_two = Program::from_str(
        r"
import child.aleo;

program parent.aleo;

mapping foo:
    key as field.public;
    value as child.aleo/S.public;

function dummy:

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the first program.
    let deployment_one = vm.deploy(&caller_private_key, &program_one, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_one], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Deploy the second program.
    let deployment_two = vm.deploy(&caller_private_key, &program_two, None, 0, None, rng).unwrap();

    // Return the block but don't try to add it to the VM. We're really just interested in
    // inspecting the transactions in the block to see if they are accepted, rejected, or aborted,
    // likely depending on the conesnsus version.
    sample_next_block(&vm, &caller_private_key, &[deployment_two], rng).unwrap()
}

// This test verifies that path traversal through external structs works correctly when the
// external struct contains a member that is a LOCAL struct reference (not an ExternalStruct).
#[test]
fn test_external_struct_with_local_nested_struct() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V13 height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the first program with nested structs where Inner is a LOCAL reference in Outer.
    // This is the key distinction: Outer.inner is declared as `inner as Inner` (local), not
    // `inner as parent.aleo/Inner` (external).
    let program_parent = Program::from_str(
        r"
program parent.aleo;

struct Inner:
    x as field;

struct Outer:
    inner as Inner;

function make_outer:
    cast 42field into r0 as Inner;
    cast r0 into r1 as Outer;
    output r1 as Outer.public;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the child program that accesses nested path r0.inner.x on an external struct.
    let program_child = Program::from_str(
        r"
import parent.aleo;

program child.aleo;

function access_nested:
    input r0 as parent.aleo/Outer.private;
    assert.eq r0.inner.x 42field;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the parent program.
    let deployment_parent = vm.deploy(&caller_private_key, &program_parent, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_parent], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the child program.
    let deployment_child = vm.deploy(&caller_private_key, &program_child, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Child program deployment should succeed");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies path traversal through external records when the record entry is a
// local struct in the external program.
#[test]
fn test_external_record_with_local_struct_entry() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V13 height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the parent program with a record containing a local struct.
    let program_parent = Program::from_str(
        r"
program parent.aleo;

struct Data:
    amount as field;

record Token:
    owner as address.private;
    data as Data.private;

function mint:
    input r0 as address.private;
    cast 100field into r1 as Data;
    cast r0 r1 into r2 as Token.record;
    output r2 as Token.record;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the child program that accesses the external record's local struct field.
    let program_child = Program::from_str(
        r"
import parent.aleo;

program child.aleo;

function check_token:
    input r0 as parent.aleo/Token.record;
    assert.eq r0.data.amount 100field;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the parent program.
    let deployment_parent = vm.deploy(&caller_private_key, &program_parent, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_parent], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the child program.
    let deployment_child = vm.deploy(&caller_private_key, &program_child, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Child program deployment should succeed");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies path traversal through external structs containing arrays of local structs.
#[test]
fn test_external_struct_with_array_of_local_structs() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V13 height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the parent program with a struct containing an array of local structs.
    let program_parent = Program::from_str(
        r"
program parent.aleo;

struct Item:
    x as field;

struct Container:
    items as [Item; 2u32];

function make_container:
    cast 1field into r0 as Item;
    cast 2field into r1 as Item;
    cast r0 r1 into r2 as [Item; 2u32];
    cast r2 into r3 as Container;
    output r3 as Container.public;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the child program that accesses the array element's field.
    let program_child = Program::from_str(
        r"
import parent.aleo;

program child.aleo;

function access_array_element:
    input r0 as parent.aleo/Container.private;
    assert.eq r0.items[0u32].x 1field;
    assert.eq r0.items[1u32].x 2field;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the parent program.
    let deployment_parent = vm.deploy(&caller_private_key, &program_parent, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_parent], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the child program.
    let deployment_child = vm.deploy(&caller_private_key, &program_child, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Child program deployment should succeed");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that future validation works correctly when an external function's finalize
// block takes a local struct as a parameter.
#[test]
fn test_external_future_with_local_struct_finalize_param() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V13 height.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the parent program with a function that has a finalize block taking a local struct.
    let program_parent = Program::from_str(
        r"
program parent.aleo;

struct Data:
    amount as field;

mapping store:
    key as field.public;
    value as field.public;

function save:
    input r0 as Data.public;
    async save r0 into r1;
    output r1 as parent.aleo/save.future;

finalize save:
    input r0 as Data.public;
    set r0.amount into store[0field];

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the child program that calls the parent function.
    let program_child = Program::from_str(
        r"
import parent.aleo;

program child.aleo;

function call_save:
    cast 42field into r0 as parent.aleo/Data;
    call parent.aleo/save r0 into r1;
    async call_save r1 into r2;
    output r2 as child.aleo/call_save.future;

finalize call_save:
    input r0 as parent.aleo/save.future;
    await r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the parent program.
    let deployment_parent = vm.deploy(&caller_private_key, &program_parent, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_parent], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the child program.
    let deployment_child = vm.deploy(&caller_private_key, &program_child, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Child program deployment should succeed");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the child function to verify runtime validation also works.
    let execution = vm
        .execute(
            &caller_private_key,
            ("child.aleo", "call_save"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Execution should succeed");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
}

struct ExecutionTest<'a> {
    program: &'a str,
    function: &'a str,
    inputs: Vec<Value<CurrentNetwork>>,
}

/// Deploys two programs sequentially on a VM at a given consensus version and optionally executes a function post-deploy.
///
/// # Parameters
/// - `consensus_version`: The consensus version at which to deploy the programs.
/// - `program_one`: The first program to deploy; expected to always succeed.
/// - `program_two`: The second program to deploy; success or failure depends on the consensus rules.
/// - `execution_test`: Describes a function to execute post-deploy (only runs on V13).
///   Includes the program name, function name, and input values.
///
/// # Behavior
/// - Always deploys `program_one` and asserts that the deployment succeeds.
/// - Deploys `program_two` and asserts expected behavior according to `assert_pre_post_v13`.
/// - On V13, commits the second block and executes the function described in `execution_test`.
///   The execution results are asserted to succeed.
///
/// # Panics
/// Panics if:
/// - Either program fails to deploy.
/// - Any internal assertions fail (e.g., number of accepted or aborted transactions).
/// - Execution on V13 fails.
///
/// # Notes
/// This helper abstracts VM initialization, block creation, deployment, and optional execution logic
/// to reduce boilerplate in multiple tests and ensure consistent pre-/post-V13 behavior.
fn deploy_two_programs_and_execute_v13(
    consensus_version: ConsensusVersion,
    program_one: &Program<CurrentNetwork>,
    program_two: &Program<CurrentNetwork>,
    execution_test: ExecutionTest,
    mint_record: bool,
) {
    let rng = &mut TestRng::default();

    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    let height = CurrentNetwork::CONSENSUS_HEIGHT(consensus_version).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // ── Deploy first program (should always succeed)
    let deployment_one = vm.deploy(&caller_private_key, program_one, None, 0, None, rng).unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[deployment_one], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    vm.add_next_block(&block).unwrap();

    // ── Deploy second program (version-dependent)
    let deployment_two = vm.deploy(&caller_private_key, program_two, None, 0, None, rng).unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[deployment_two], rng).unwrap();

    // Assert deploy semantics
    assert_pre_post_v13(block.clone(), consensus_version);

    // ── Post-V13 only: add next block + execute
    if consensus_version == ConsensusVersion::V13 {
        vm.add_next_block(&block).unwrap();

        let ExecutionTest { program, function, mut inputs } = execution_test;

        // If a record must be minted, we construct it from the received input value and replace the latter by the output Record.
        if mint_record {
            let mint_execution = vm
                .execute(&caller_private_key, (program_one.id(), "mint_record"), inputs.into_iter(), None, 0, None, rng)
                .unwrap();

            let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_execution.transitions().next().unwrap().outputs().iter().next().unwrap() {
                Output::Record(_, _, Some(record_ciphertext), _) => {
                    record_ciphertext.decrypt(&caller_view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            assert_eq!(**output_record.owner(), Address::try_from(&caller_private_key).unwrap());

            inputs = vec![Value::Record(output_record)];

            let block = sample_next_block(&vm, &caller_private_key, &[mint_execution], rng).unwrap();
            assert_eq!(block.transactions().num_accepted(), 1);
            assert_eq!(block.aborted_transaction_ids().len(), 0);
            vm.add_next_block(&block).unwrap()
        }

        let execution =
            vm.execute(&caller_private_key, (program, function), inputs.into_iter(), None, 0, None, rng).unwrap();

        let exec_block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();

        assert_eq!(exec_block.transactions().num_accepted(), 1, "Execution should succeed on V13");
        assert_eq!(exec_block.aborted_transaction_ids().len(), 0);
    }
}

/// Asserts that a block's transaction outcomes match the expected behavior
/// for pre-V13 and V13 consensus versions.
///
/// # Parameters
/// - `block`: The block whose transactions will be inspected.
/// - `consensus_version`: The consensus version at which the block was produced.
///
/// # Panics
/// Panics if the number of accepted, rejected, or aborted transactions does
/// not match the expected rules for the given consensus version.
///
/// # Behavior
/// - For pre V13, all transactions are expected to aborted (pre-V13 rules).
/// - For `V13`, the transaction is expected to be accepted with no aborted
///   transactions.
fn assert_pre_post_v13(block: Block<CurrentNetwork>, consensus_version: ConsensusVersion) {
    match consensus_version {
        ConsensusVersion::V11 | ConsensusVersion::V12 => {
            assert_eq!(block.transactions().num_accepted(), 0);
            assert_eq!(block.transactions().num_rejected(), 0);
            assert_eq!(block.aborted_transaction_ids().len(), 1);
        }
        ConsensusVersion::V13 => {
            assert_eq!(block.transactions().num_accepted(), 1);
            assert_eq!(block.transactions().num_rejected(), 0);
            assert_eq!(block.aborted_transaction_ids().len(), 0);
        }
        _ => unreachable!("unexpected consensus version"),
    }
}

#[test]
fn test_deploy_external_structs_pre_and_post_v13() {
    let program_one = Program::from_str(
        r"
program test_one.aleo;

constructor:
    assert.eq true true;

struct S:
    x as field;

function make_s:
    cast 0field into r0 as S;
    output r0 as S.public;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import test_one.aleo;

program test_two.aleo;

constructor:
    assert.eq true true;

function second:
    call test_one.aleo/make_s into r0;
    output r0 as test_one.aleo/S.public;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "test_two.aleo", function: "second", inputs: vec![] },
            false,
        );
    }
}

#[test]
fn test_nonlocal_struct_in_external_future() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Foo:
    x as u32;

function main:
    cast 42u32 into r0 as Foo;
    async main r0 into r1;
    output r1 as child.aleo/main.future;

finalize main:
    input r0 as Foo.public;
    assert.eq true true;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;
program external_future.aleo;

function main:
    call child.aleo/main into r0;
    async main r0 into r1;
    output r1 as external_future.aleo/main.future;

finalize main:
    input r0 as child.aleo/main.future;
    await r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "external_future.aleo", function: "main", inputs: vec![] },
            false,
        );
    }
}

#[test]
fn test_nonlocal_struct_in_array_in_external_future() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Foo:
    x as u32;

function main:
    cast 42u32 into r0 as Foo;
    cast r0 r0 into r1 as [Foo; 2u32];
    async main r1 into r2;
    output r2 as child.aleo/main.future;

finalize main:
    input r0 as [Foo; 2u32].public;
    assert.eq true true;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;
program external_future.aleo;

function main:
    call child.aleo/main into r0;
    async main r0 into r1;
    output r1 as external_future.aleo/main.future;

finalize main:
    input r0 as child.aleo/main.future;
    await r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "external_future.aleo", function: "main", inputs: vec![] },
            false,
        );
    }
}

#[test]
fn test_nonlocal_struct_in_external_record_from_call() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Woo:
    a as u32;
    b as u32;

record BooHoo:
    owner as address.private;
    woo as Woo.private;

record Foo:
    owner as address.private;
    x as u32.private;

function wrapper:
    cast 1u32 2u32 into r0 as Woo;
    cast self.signer r0 into r1 as BooHoo.record;
    output r1 as BooHoo.record;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;
program parent.aleo;

function omega_wrapper:
    call child.aleo/wrapper into r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "parent.aleo", function: "omega_wrapper", inputs: vec![] },
            false,
        );
    }
}

#[test]
fn test_nonlocal_struct_in_external_record_input() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Woo:
    a as u32;
    b as u32;

record BooHoo:
    owner as address.private;
    woo as Woo.private;

record Foo:
    owner as address.private;
    x as u32.private;

function wrapper:
    cast 1u32 2u32 into r0 as Woo;
    cast self.signer r0 into r1 as BooHoo.record;
    output r1 as BooHoo.record;

function mint_record:
    cast 1u32 2u32 into r0 as Woo;
    cast self.signer r0 into r1 as BooHoo.record;
    output r1 as BooHoo.record;

function consume_record:
    input r0 as BooHoo.record;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;
program parent.aleo;

function omega_wrapper:
    input r0 as child.aleo/BooHoo.record;
    call child.aleo/consume_record r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "parent.aleo", function: "omega_wrapper", inputs: Vec::new() },
            true,
        );
    }
}

#[test]
fn test_nonlocal_struct_in_array_in_external_record_input() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Foo:
    x as u32;

record R:
    owner as address.private;
    a as [Foo; 2u32].private;

function main:
    input r0 as address.private;
    cast 42u32 into r1 as Foo;
    cast r1 r1 into r2 as [Foo; 2u32];
    cast r0 r2 into r3 as R.record;
    output r3 as R.record;

function mint_record:
    cast 0u32 into r0 as Foo;
    cast r0 r0 into r1 as [Foo; 2u32];
    cast self.signer r1 into r2 as R.record;
    output r2 as R.record;

function consume_record:
    input r0 as R.record;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;
program test.aleo;

function main:
    input r0 as child.aleo/R.record;

    call child.aleo/consume_record r0;
    
    output r0 as child.aleo/R.record;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "test.aleo", function: "main", inputs: Vec::new() },
            true,
        );
    }
}

#[test]
fn test_nonlocal_struct_access_from_external_future() {
    let program_one = Program::from_str(
        r"
program child.aleo;

struct Params:
    amount as u64;

mapping store:
    key as u8.public;
    value as u64.public;

function compute:
    input r0 as u64.public;
    cast r0 into r1 as Params;
    async compute r1 into r2;
    output r2 as child.aleo/compute.future;

finalize compute:
    input r0 as Params.public;
    set r0.amount into store[0u8];

constructor:
    assert.eq true true;
",
    )
    .unwrap();

    let program_two = Program::from_str(
        r"
import child.aleo;

program parent.aleo;

mapping results:
    key as u8.public;
    value as u64.public;

function relay:
    input r0 as u64.public;
    call child.aleo/compute r0 into r1;
    async relay r1 into r2;
    output r2 as parent.aleo/relay.future;

finalize relay:
    input r0 as child.aleo/compute.future;
    set r0[0u32].amount into results[0u8];
    await r0;

constructor:
    assert.eq true true;
",
    )
    .unwrap();

    // Use V11 rather than V12 to make sure we still won't be on V13
    for consensus_version in [ConsensusVersion::V11, ConsensusVersion::V13] {
        deploy_two_programs_and_execute_v13(
            consensus_version,
            &program_one,
            &program_two,
            ExecutionTest { program: "parent.aleo", function: "relay", inputs: vec![Value::from_str("0u64").unwrap()] },
            false,
        );
    }
}

#[test]
fn test_external_mapping_external_struct_v13() {
    let rng = &mut TestRng::default();

    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // child.aleo defines a local struct `Point` and stores it as the value of
    // a mapping. This program is always valid across versions.
    let program_child = Program::from_str(
        r"
program child.aleo;

struct Point:
    x as field;
    y as field;

mapping point__:
    key as Point.public;
    value as Point.public;

function initialize:
    async initialize into r0;
    output r0 as child.aleo/initialize.future;

finalize initialize:
    cast 0field 0field into r0 as Point;
    set r0 into point__[r0];

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // test.aleo reads a value from an external mapping whose value type is
    // an external struct. This is the operation under test.
    let program_test = Program::from_str(
        r"
import child.aleo;

program test.aleo;

function check_initialized:
    async check_initialized into r0;
    output r0 as test.aleo/check_initialized.future;

finalize check_initialized:
    cast 0field 0field into r0 as child.aleo/Point;
    get child.aleo/point__[r0] into r1;
    get.or_use child.aleo/point__[r0] r0 into r2;
    contains child.aleo/point__[r0] into r3;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // ── Deploy child.aleo
    let deployment_child = vm.deploy(&caller_private_key, &program_child, None, 0, None, rng).unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // ── Deploy test.aleo and execute child.initialize in the same block.
    // This ensures the mapping is populated before it is read.
    let deployment_test = vm.deploy(&caller_private_key, &program_test, None, 0, None, rng).unwrap();

    let execution = vm
        .execute(
            &caller_private_key,
            ("child.aleo", "initialize"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[deployment_test, execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    vm.add_next_block(&block).unwrap();

    // ── Execute test.check_initialized.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test.aleo", "check_initialized"),
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
}

/// This test verifies that using the `get` command to read from an external mapping fails on V12
/// when the mapping value contains an external struct (i.e. a struct that is not local to the program
/// containing the `get`). The same scenario should succeed on V13, where the underlying bug has
/// been fixed.
#[test]
fn test_external_mapping_external_struct_runtime_pre_post_v13() {
    let rng = &mut TestRng::default();
    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    // Start the VM at consensus version V9 to ensure we're not at V13 by the time we get to the
    // execution transaction that calls the second program.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // child.aleo defines a local struct `Point` and stores it as the value of
    // a mapping. This program is always valid across versions.
    let program_child = Program::from_str(
        r"
program child.aleo;

struct Point:
    x as field;
    y as field;

mapping point__:
    key as boolean.public;
    value as Point.public;

function initialize:
    async initialize into r0;
    output r0 as child.aleo/initialize.future;

finalize initialize:
    cast 0field 0field into r0 as Point;
    set r0 into point__[true];

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // test.aleo reads a value from an external mapping whose value type is
    // an external struct. This is the operation under test.
    let program_test = Program::from_str(
        r"
import child.aleo;

program test.aleo;

function check_initialized:
    async check_initialized into r0;
    output r0 as test.aleo/check_initialized.future;

finalize check_initialized:
    get child.aleo/point__[true] into r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // ── Deploy child.aleo (always succeeds)
    let deployment_child = vm.deploy(&private_key, &program_child, None, 0, None, rng).unwrap();

    let block = sample_next_block(&vm, &private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // ── Deploy test.aleo and execute child.initialize in the same block.
    // This ensures the mapping is populated before it is read.
    let deployment_test = vm.deploy(&private_key, &program_test, None, 0, None, rng).unwrap();
    let execution = vm
        .execute(&private_key, ("child.aleo", "initialize"), Vec::<Value<_>>::new().into_iter(), None, 0, None, rng)
        .unwrap();

    let block = sample_next_block(&vm, &private_key, &[deployment_test, execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    vm.add_next_block(&block).unwrap();

    // ── Execute test.check_initialized.
    //
    // Pre-V13: rejected due to external struct usage in external mapping access.
    let execution = vm
        .execute(
            &private_key,
            ("test.aleo", "check_initialized"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Advance the ledger past ConsensusVersion::V13.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Now we try again after we've advanced to V13. The same execution transaction should now succeed.
    let execution = vm
        .execute(
            &private_key,
            ("test.aleo", "check_initialized"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

/// This test verifies that using the `get` command to read from an external mapping fails on V12
/// when the mapping value contains an external struct (i.e. a struct that is not local to the program
/// containing the `get`). The same scenario should succeed on V13, where the underlying bug has
/// been fixed.
#[test]
fn test_external_mapping_external_struct_in_array_runtime_pre_post_v13() {
    let rng = &mut TestRng::default();
    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    // Start the VM at consensus version V9 to ensure we're not at V13 by the time we get to the
    // execution transaction that calls the second program.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // child.aleo defines a local array of `Point`s and stores it as the value of
    // a mapping. This program is always valid across versions.
    let program_child = Program::from_str(
        r"
program child.aleo;

struct Point:
    x as field;
    y as field;

mapping point__:
    key as boolean.public;
    value as [Point; 2u32].public;

function initialize:
    async initialize into r0;
    output r0 as child.aleo/initialize.future;

finalize initialize:
    cast 0field 0field into r0 as Point;
    cast r0 r0 into r1 as [Point; 2u32];
    set r1 into point__[true];

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // test.aleo reads a value from an external mapping whose value type is
    // an array of external structs. This is the operation under test.
    let program_test = Program::from_str(
        r"
import child.aleo;

program test.aleo;

function check_initialized:
    async check_initialized into r0;
    output r0 as test.aleo/check_initialized.future;

finalize check_initialized:
    get child.aleo/point__[true] into r0;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // ── Deploy child.aleo (always succeeds)
    let deployment_child = vm.deploy(&private_key, &program_child, None, 0, None, rng).unwrap();

    let block = sample_next_block(&vm, &private_key, &[deployment_child], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // ── Deploy test.aleo and execute child.initialize in the same block.
    // This ensures the mapping is populated before it is read.
    let deployment_test = vm.deploy(&private_key, &program_test, None, 0, None, rng).unwrap();
    let execution = vm
        .execute(&private_key, ("child.aleo", "initialize"), Vec::<Value<_>>::new().into_iter(), None, 0, None, rng)
        .unwrap();

    let block = sample_next_block(&vm, &private_key, &[deployment_test, execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    vm.add_next_block(&block).unwrap();

    // ── Execute test.check_initialized.
    //
    // Pre-V13: rejected due to external struct usage in external mapping access.
    let execution = vm
        .execute(
            &private_key,
            ("test.aleo", "check_initialized"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Advance the ledger past ConsensusVersion::V13.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Now we try again after we've advanced to V13. The same execution transaction should now succeed.
    let execution = vm
        .execute(
            &private_key,
            ("test.aleo", "check_initialized"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// This test verifies that runtime validation works correctly when an external function's finalize
// block takes a local struct as a parameter but that local struct is also copied in the primary
// program. This should pass on both V12 and V13.
#[test]
fn test_external_mapping_external_struct_copied_locally_pre_post_v13() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V9 height. This ensures we're still on pre-V13 by the time we get to
    // the execution transaction we want to test.
    let height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(height, rng);

    // Define the parent program with a function that has a finalize block taking a local struct.
    let program_parent = Program::from_str(
        r"
program veru_oracle_data_v3.aleo;

struct AttestedData:
    data as u128;
    attestation_timestamp as u128;

mapping sgx_attested_data:
    key as u128.public;
    value as AttestedData.public;

function foo:
    async foo into r0;
    output r0 as veru_oracle_data_v3.aleo/foo.future;
finalize foo:
    cast 0u128 0u128 into r0 as AttestedData;
    set r0 into sgx_attested_data[0u128];

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Define the child program that calls the parent function.
    let program_child = Program::from_str(
        r"
import veru_oracle_data_v3.aleo;
program amm_oracle_v1.aleo;

struct AttestedData:
    data as u128;
    attestation_timestamp as u128;

function set_price_paleo:
    input r0 as [u128; 2u32].private;
    async set_price_paleo r0 into r1;
    output r1 as amm_oracle_v1.aleo/set_price_paleo.future;
finalize set_price_paleo:
    input r0 as [u128; 2u32].public;
    cast 0u128 0u128 into r1 as AttestedData;
    get veru_oracle_data_v3.aleo/sgx_attested_data[r0[0u32]] into r2;

constructor:
    assert.eq edition 0u16;
",
    )
    .unwrap();

    // Deploy the parent program.
    let deployment_parent = vm.deploy(&private_key, &program_parent, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment_parent], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the child program.
    let deployment_child = vm.deploy(&private_key, &program_child, None, 0, None, rng).unwrap();
    let execution = vm
        .execute(
            &private_key,
            ("veru_oracle_data_v3.aleo", "foo"),
            Vec::<Value<_>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &private_key, &[deployment_child, execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2, "Child program deployment should succeed and init should pass");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the child function to verify runtime validation works in pre-V13 because the
    // external struct `AttestedData` is also copied locally.
    let execution = vm
        .execute(
            &private_key,
            ("amm_oracle_v1.aleo", "set_price_paleo"),
            vec![Value::from_str("[0u128, 1u128]")].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Execution should succeed");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Advance the ledger past ConsensusVersion::V13.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Now we try again after we've advanced to V13. The same execution transaction should also succeed.
    let execution = vm
        .execute(
            &private_key,
            ("amm_oracle_v1.aleo", "set_price_paleo"),
            vec![Value::from_str("[0u128, 1u128]")].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}
