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

use console::{
    network::ConsensusVersion,
    program::{Identifier, Plaintext, Value},
};
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::TestRng;

// A program that selects between two `[field; 3u32]` arrays with `ternary`.
const TERNARY_ARRAY_PROGRAM: &str = r"
program ternary_array_test.aleo;

function run:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [field; 3u32].public;

constructor:
    assert.eq true true;
";

// A program that selects between two `point` structs with `ternary`.
const TERNARY_STRUCT_PROGRAM: &str = r"
program ternary_struct_test.aleo;

struct point:
    x as field;
    y as field;

function run:
    input r0 as boolean.public;
    input r1 as point.public;
    input r2 as point.public;
    ternary r0 r1 r2 into r3;
    output r3 as point.public;

constructor:
    assert.eq true true;
";

// Tests that a program using `ternary` on array operands is aborted before
// `ConsensusVersion::V23` and accepted at `V23`.
#[test]
fn test_deploy_ternary_array_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Start one block before V23 so that after the rejected block we land at V23.
    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_ARRAY_PROGRAM).unwrap();

    // Deployment before V23 should be aborted.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0, "Array ternary deployment before V23 should not be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Array ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    // We should now be at V23.
    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Array ternary deployment at V23 should be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// Tests that a program using `ternary` on struct operands is aborted before
// `ConsensusVersion::V23` and accepted at `V23`.
#[test]
fn test_deploy_ternary_struct_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_STRUCT_PROGRAM).unwrap();

    // Deployment before V23 should be aborted.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0, "Struct ternary deployment before V23 should not be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Struct ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Struct ternary deployment at V23 should be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// A program that uses `ternary` on non-literal operands inside a `finalize` block.
const TERNARY_FINALIZE_PRE_V23_PROGRAM: &str = r"
program ternary_finalize_pre_v23.aleo;

mapping selected:
    key as u8.public;
    value as [field; 3u32].public;

function run:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    async run r0 r1 r2 into r3;
    output r3 as ternary_finalize_pre_v23.aleo/run.future;

finalize run:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    ternary r0 r1 r2 into r3;
    set r3 into selected[0u8];

constructor:
    assert.eq true true;
";

// A program that uses `ternary` on non-literal operands inside the `constructor`.
const TERNARY_CONSTRUCTOR_PRE_V23_PROGRAM: &str = r"
program ternary_constructor_pre_v23.aleo;

struct point:
    x as field;
    y as field;

function dummy:
    input r0 as u32.public;
    output r0 as u32.public;

constructor:
    cast 1field 2field into r0 as point;
    cast 3field 4field into r1 as point;
    ternary true r0 r1 into r2;
    assert.eq true true;
";

// Tests that a program using non-literal `ternary` inside a `finalize` block is aborted before
// `ConsensusVersion::V23` and accepted at `V23`.
#[test]
fn test_deploy_ternary_in_finalize_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Start one block before V23 so that after the rejected block we land at V23.
    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_FINALIZE_PRE_V23_PROGRAM).unwrap();

    // Deployment before V23 should be aborted because the finalize uses ternary on arrays.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0, "Finalize ternary deployment before V23 should not be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Finalize ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    // We should now be at V23.
    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Finalize ternary deployment at V23 should be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// Tests that a program using non-literal `ternary` inside the `constructor` is aborted before
// `ConsensusVersion::V23` and accepted at `V23`.
#[test]
fn test_deploy_ternary_in_constructor_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_CONSTRUCTOR_PRE_V23_PROGRAM).unwrap();

    // Deployment before V23 should be aborted because the constructor uses ternary on structs.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(
        block.transactions().num_accepted(),
        0,
        "Constructor ternary deployment before V23 should not be accepted"
    );
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Constructor ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Constructor ternary deployment at V23 should be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

// Tests that `ternary` on array operands selects the correct branch at V23.
#[test]
fn test_execute_ternary_array() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM at V23 so that non-literal ternary programs can be deployed.
    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    // Deploy the array ternary program.
    let program = Program::from_str(TERNARY_ARRAY_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Array ternary deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let first = "[ 1field, 2field, 3field ]";
    let second = "[ 4field, 5field, 6field ]";

    // Execute with `true` condition: output should equal `first`.
    let inputs_true = [
        Value::<CurrentNetwork>::from_str("true").unwrap(),
        Value::from_str(first).unwrap(),
        Value::from_str(second).unwrap(),
    ];
    let execution = vm
        .execute(&caller_private_key, ("ternary_array_test.aleo", "run"), inputs_true.iter(), None, 0, None, rng)
        .unwrap();
    let expected_first = Plaintext::<CurrentNetwork>::from_str(first).unwrap();
    match &execution.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected_first),
        other => panic!("Expected public output, got: {other:?}"),
    }
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Array ternary execution (true) should be accepted");
    vm.add_next_block(&block).unwrap();

    // Execute with `false` condition: output should equal `second`.
    let inputs_false = [
        Value::<CurrentNetwork>::from_str("false").unwrap(),
        Value::from_str(first).unwrap(),
        Value::from_str(second).unwrap(),
    ];
    let execution = vm
        .execute(&caller_private_key, ("ternary_array_test.aleo", "run"), inputs_false.iter(), None, 0, None, rng)
        .unwrap();
    let expected_second = Plaintext::<CurrentNetwork>::from_str(second).unwrap();
    match &execution.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected_second),
        other => panic!("Expected public output, got: {other:?}"),
    }
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Array ternary execution (false) should be accepted");
    vm.add_next_block(&block).unwrap();
}

// Tests that `ternary` on struct operands selects the correct branch at V23.
#[test]
fn test_execute_ternary_struct() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_STRUCT_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Struct ternary deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let first = "{ x: 1field, y: 2field }";
    let second = "{ x: 3field, y: 4field }";

    // Execute with `true` condition.
    let inputs_true = [
        Value::<CurrentNetwork>::from_str("true").unwrap(),
        Value::from_str(first).unwrap(),
        Value::from_str(second).unwrap(),
    ];
    let execution = vm
        .execute(&caller_private_key, ("ternary_struct_test.aleo", "run"), inputs_true.iter(), None, 0, None, rng)
        .unwrap();
    let expected_first = Plaintext::<CurrentNetwork>::from_str(first).unwrap();
    match &execution.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected_first),
        other => panic!("Expected public output, got: {other:?}"),
    }
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Struct ternary execution (true) should be accepted");
    vm.add_next_block(&block).unwrap();

    // Execute with `false` condition.
    let inputs_false = [
        Value::<CurrentNetwork>::from_str("false").unwrap(),
        Value::from_str(first).unwrap(),
        Value::from_str(second).unwrap(),
    ];
    let execution = vm
        .execute(&caller_private_key, ("ternary_struct_test.aleo", "run"), inputs_false.iter(), None, 0, None, rng)
        .unwrap();
    let expected_second = Plaintext::<CurrentNetwork>::from_str(second).unwrap();
    match &execution.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected_second),
        other => panic!("Expected public output, got: {other:?}"),
    }
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Struct ternary execution (false) should be accepted");
    vm.add_next_block(&block).unwrap();
}

// A program exercising `ternary` on arrays of several sizes and element types, including a
// nested array. The three functions share the same program so a single deployment suffices.
const TERNARY_ARRAY_VARIOUS_SIZES_PROGRAM: &str = r"
program ternary_array_sizes.aleo;

function run_single:
    input r0 as boolean.public;
    input r1 as [u8; 1u32].public;
    input r2 as [u8; 1u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [u8; 1u32].public;

function run_large:
    input r0 as boolean.public;
    input r1 as [u32; 10u32].public;
    input r2 as [u32; 10u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [u32; 10u32].public;

function run_nested:
    input r0 as boolean.public;
    input r1 as [[field; 2u32]; 3u32].public;
    input r2 as [[field; 2u32]; 3u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [[field; 2u32]; 3u32].public;

constructor:
    assert.eq true true;
";

// Tests `ternary` on arrays of varying element types, array lengths, and nesting depth.
#[test]
fn test_execute_ternary_various_array_sizes() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_ARRAY_VARIOUS_SIZES_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    // For each (function, first, second) tuple, run ternary with both `true` and `false` and
    // verify the output matches the expected branch.
    let cases: &[(&str, &str, &str)] = &[
        ("run_single", "[ 7u8 ]", "[ 42u8 ]"),
        (
            "run_large",
            "[ 0u32, 1u32, 2u32, 3u32, 4u32, 5u32, 6u32, 7u32, 8u32, 9u32 ]",
            "[ 10u32, 11u32, 12u32, 13u32, 14u32, 15u32, 16u32, 17u32, 18u32, 19u32 ]",
        ),
        (
            "run_nested",
            "[ [ 1field, 2field ], [ 3field, 4field ], [ 5field, 6field ] ]",
            "[ [ 7field, 8field ], [ 9field, 10field ], [ 11field, 12field ] ]",
        ),
    ];

    for (function, first, second) in cases {
        for (cond_str, expected_str) in [("true", *first), ("false", *second)] {
            let inputs = [
                Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
                Value::from_str(first).unwrap(),
                Value::from_str(second).unwrap(),
            ];
            let execution = vm
                .execute(
                    &caller_private_key,
                    ("ternary_array_sizes.aleo", *function),
                    inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();
            let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
            match &execution.transitions().next().unwrap().outputs()[0] {
                Output::Public(_, Some(plaintext)) => {
                    assert_eq!(*plaintext, expected, "{function} with condition={cond_str}")
                }
                other => panic!("Expected public output, got: {other:?}"),
            }
            let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
            assert_eq!(
                block.transactions().num_accepted(),
                1,
                "{function} with condition={cond_str} should be accepted"
            );
            vm.add_next_block(&block).unwrap();
        }
    }
}

// Tests that deploying a program where `ternary` branches have arrays of different lengths
// is rejected by the type checker.
#[test]
fn test_deploy_ternary_array_size_mismatch_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_array_mismatch.aleo;

        function bad:
            input r0 as boolean.public;
            input r1 as [field; 2u32].public;
            input r2 as [field; 3u32].public;
            ternary r0 r1 r2 into r3;
            output r3 as [field; 2u32].public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on arrays of different lengths");
}

// Tests that deploying a program where `ternary` branches have different struct types is
// rejected by the type checker.
#[test]
fn test_deploy_ternary_struct_mismatch_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_struct_mismatch.aleo;

        struct point_a:
            x as field;
            y as field;

        struct point_b:
            x as field;
            z as field;

        function bad:
            input r0 as boolean.public;
            input r1 as point_a.public;
            input r2 as point_b.public;
            ternary r0 r1 r2 into r3;
            output r3 as point_a.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on two distinct struct types");
}

// Tests `ternary` on a struct imported from another program (external struct). The child
// program imports the parent's `shared_point` struct and uses it as both branch operands.
#[test]
fn test_execute_ternary_external_struct() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    // Parent program declares `shared_point` and has a noop function so it deploys cleanly.
    let parent_program = Program::from_str(
        r"
        program ternary_ext_parent.aleo;

        struct shared_point:
            x as field;
            y as field;

        function noop:
            input r0 as u32.public;
            output r0 as u32.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Child program imports the parent and uses the external struct as both ternary branches.
    let child_program = Program::from_str(
        r"
        import ternary_ext_parent.aleo;

        program ternary_ext_child.aleo;

        function run:
            input r0 as boolean.public;
            input r1 as ternary_ext_parent.aleo/shared_point.public;
            input r2 as ternary_ext_parent.aleo/shared_point.public;
            ternary r0 r1 r2 into r3;
            output r3 as ternary_ext_parent.aleo/shared_point.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Deploy the parent, then the child.
    let deployment = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Parent deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let deployment = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Child deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let first = "{ x: 1field, y: 2field }";
    let second = "{ x: 3field, y: 4field }";

    // Execute with both `true` and `false` conditions and verify the correct branch is returned.
    for (cond_str, expected_str) in [("true", first), ("false", second)] {
        let inputs = [
            Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
            Value::from_str(first).unwrap(),
            Value::from_str(second).unwrap(),
        ];
        let execution = vm
            .execute(&caller_private_key, ("ternary_ext_child.aleo", "run"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
        match &execution.transitions().next().unwrap().outputs()[0] {
            Output::Public(_, Some(plaintext)) => {
                assert_eq!(*plaintext, expected, "external struct ternary with condition={cond_str}")
            }
            other => panic!("Expected public output, got: {other:?}"),
        }
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(
            block.transactions().num_accepted(),
            1,
            "external struct ternary execution (condition={cond_str}) should be accepted"
        );
        vm.add_next_block(&block).unwrap();
    }
}

// A program that exercises `ternary` on arrays and structs inside finalize blocks. Each
// finalize writes the selected branch to a mapping so that the on-chain result can be
// verified by reading the mapping value back.
const TERNARY_FINALIZE_PROGRAM: &str = r"
program ternary_finalize_test.aleo;

struct point:
    x as field;
    y as field;

mapping selected_array:
    key as u8.public;
    value as [field; 3u32].public;

mapping selected_struct:
    key as u8.public;
    value as point.public;

function run_array:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    async run_array r0 r1 r2 into r3;
    output r3 as ternary_finalize_test.aleo/run_array.future;

finalize run_array:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    ternary r0 r1 r2 into r3;
    set r3 into selected_array[0u8];

function run_struct:
    input r0 as boolean.public;
    input r1 as point.public;
    input r2 as point.public;
    async run_struct r0 r1 r2 into r3;
    output r3 as ternary_finalize_test.aleo/run_struct.future;

finalize run_struct:
    input r0 as boolean.public;
    input r1 as point.public;
    input r2 as point.public;
    ternary r0 r1 r2 into r3;
    set r3 into selected_struct[0u8];

constructor:
    assert.eq true true;
";

// Tests that `ternary` on arrays and structs works in a finalize block at V23: the selected
// branch is written to a mapping and verified by reading the mapping value back.
#[test]
fn test_execute_ternary_in_finalize() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_FINALIZE_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Finalize ternary deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let program_id = ProgramID::<CurrentNetwork>::from_str("ternary_finalize_test.aleo").unwrap();
    let zero_key = Plaintext::<CurrentNetwork>::from_str("0u8").unwrap();

    // Reads the value stored under key `0u8` in the named mapping and asserts it equals the
    // expected plaintext.
    let assert_mapping = |mapping_name: &str, expected_str: &str| {
        let mapping_id = Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap();
        let value = vm.finalize_store().get_value_confirmed(program_id, mapping_id, &zero_key).unwrap();
        let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
        match value {
            Some(Value::Plaintext(p)) => assert_eq!(p, expected, "{mapping_name} mismatch"),
            other => panic!("expected plaintext value in mapping {mapping_name}, got: {other:?}"),
        }
    };

    // (function, first, second, mapping) tuples covering both array and struct ternary in finalize.
    let cases: &[(&str, &str, &str, &str)] = &[
        ("run_array", "[ 1field, 2field, 3field ]", "[ 4field, 5field, 6field ]", "selected_array"),
        ("run_struct", "{ x: 1field, y: 2field }", "{ x: 3field, y: 4field }", "selected_struct"),
    ];

    for (function, first, second, mapping) in cases {
        for (cond_str, expected_str) in [("true", *first), ("false", *second)] {
            let inputs = [
                Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
                Value::from_str(first).unwrap(),
                Value::from_str(second).unwrap(),
            ];
            let execution = vm
                .execute(
                    &caller_private_key,
                    ("ternary_finalize_test.aleo", *function),
                    inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();
            let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
            assert_eq!(
                block.transactions().num_accepted(),
                1,
                "{function} finalize ternary (condition={cond_str}) should be accepted"
            );
            vm.add_next_block(&block).unwrap();
            assert_mapping(mapping, expected_str);
        }
    }
}

// Tests that `ternary` on `string` operands is rejected by the type checker at V23.
// The Aleo `string` type has a variable byte-length, so it cannot be selected by a byte-wise
// MUX circuit; `output_types` refuses any plaintext whose leaves include `string`.
#[test]
fn test_deploy_ternary_string_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_string_bad.aleo;

        function bad:
            input r0 as boolean.public;
            input r1 as string.public;
            input r2 as string.public;
            ternary r0 r1 r2 into r3;
            output r3 as string.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on string operands");
}

// A program that selects between two `identifier` operands with `ternary`.
const TERNARY_IDENTIFIER_PROGRAM: &str = r"
program ternary_identifier_test.aleo;

function run:
    input r0 as boolean.public;
    input r1 as identifier.public;
    input r2 as identifier.public;
    ternary r0 r1 r2 into r3;
    output r3 as identifier.public;

constructor:
    assert.eq true true;
";

// Tests that a program using `ternary` on `identifier` operands is aborted before
// `ConsensusVersion::V23` and accepted at `V23`. Identifier ternary was not supported pre-V23,
// so `check_no_non_literal_ternary` must reject it at V14 to preserve consensus.
#[test]
fn test_deploy_ternary_identifier_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_IDENTIFIER_PROGRAM).unwrap();

    // Deployment before V23 should be aborted because `identifier` is not a pre-V23 ternary operand.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(
        block.transactions().num_accepted(),
        0,
        "Identifier ternary deployment before V23 should not be accepted"
    );
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Identifier ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Identifier ternary deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();
}

// Tests that `ternary` on `identifier` operands selects the correct branch at V23.
#[test]
fn test_execute_ternary_identifier() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_IDENTIFIER_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    let first = "'alpha'";
    let second = "'beta'";
    for (cond_str, expected_str) in [("true", first), ("false", second)] {
        let inputs = [
            Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
            Value::from_str(first).unwrap(),
            Value::from_str(second).unwrap(),
        ];
        let execution = vm
            .execute(&caller_private_key, ("ternary_identifier_test.aleo", "run"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
        match &execution.transitions().next().unwrap().outputs()[0] {
            Output::Public(_, Some(plaintext)) => {
                assert_eq!(*plaintext, expected, "identifier ternary with condition={cond_str}")
            }
            other => panic!("Expected public output, got: {other:?}"),
        }
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(
            block.transactions().num_accepted(),
            1,
            "identifier ternary execution (condition={cond_str}) should be accepted"
        );
        vm.add_next_block(&block).unwrap();
    }
}

// Tests that `ternary` on a struct whose field is a `string` is rejected at V23. The
// `ensure_no_string_leaves` check walks the struct members and refuses the operation because
// strings cannot be selected by a byte-wise MUX.
#[test]
fn test_deploy_ternary_struct_with_string_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_struct_string_bad.aleo;

        struct tagged:
            payload as field;
            label as string;

        function bad:
            input r0 as boolean.public;
            input r1 as tagged.public;
            input r2 as tagged.public;
            ternary r0 r1 r2 into r3;
            output r3 as tagged.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on a struct with a string field");
}

// A program that uses `ternary` on non-literal operands inside a `closure` body. Closures are
// walked by `check_no_non_literal_ternary`, so deployment must be aborted before V23.
const TERNARY_CLOSURE_PROGRAM: &str = r"
program ternary_closure_test.aleo;

closure select_array:
    input r0 as boolean;
    input r1 as [field; 3u32];
    input r2 as [field; 3u32];
    ternary r0 r1 r2 into r3;
    output r3 as [field; 3u32];

function run:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    call select_array r0 r1 r2 into r3;
    output r3 as [field; 3u32].public;

constructor:
    assert.eq true true;
";

// Tests that a program containing a `ternary` on array operands inside a closure is aborted
// before V23 and accepted at V23, and that the function calling the closure executes correctly.
#[test]
fn test_deploy_ternary_in_closure_before_and_at_v23() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height - 1, rng);

    let program = Program::from_str(TERNARY_CLOSURE_PROGRAM).unwrap();

    // Deployment before V23 should be aborted because the closure uses ternary on arrays.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0, "Closure ternary deployment before V23 should not be accepted");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Closure ternary deployment before V23 should be aborted");
    vm.add_next_block(&block).unwrap();

    // We should now be at V23.
    assert_eq!(vm.block_store().current_block_height(), v23_height);

    // Deployment at V23 should succeed.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Closure ternary deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    // Execute and confirm the closure's ternary selects the correct branch.
    let first = "[ 1field, 2field, 3field ]";
    let second = "[ 4field, 5field, 6field ]";
    for (cond_str, expected_str) in [("true", first), ("false", second)] {
        let inputs = [
            Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
            Value::from_str(first).unwrap(),
            Value::from_str(second).unwrap(),
        ];
        let execution = vm
            .execute(&caller_private_key, ("ternary_closure_test.aleo", "run"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
        match &execution.transitions().next().unwrap().outputs()[0] {
            Output::Public(_, Some(plaintext)) => {
                assert_eq!(*plaintext, expected, "closure ternary with condition={cond_str}")
            }
            other => panic!("Expected public output, got: {other:?}"),
        }
        let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
        assert_eq!(
            block.transactions().num_accepted(),
            1,
            "closure ternary execution (condition={cond_str}) should be accepted"
        );
        vm.add_next_block(&block).unwrap();
    }
}

// A program that exposes one function per supported literal variant in the ternary instruction.
// The functions share a single deployment so all variants are exercised in one VM setup.
const TERNARY_LITERAL_VARIANTS_PROGRAM: &str = r"
program ternary_lit_variants.aleo;

function sel_address:
    input r0 as boolean.public;
    input r1 as address.public;
    input r2 as address.public;
    ternary r0 r1 r2 into r3;
    output r3 as address.public;

function sel_boolean:
    input r0 as boolean.public;
    input r1 as boolean.public;
    input r2 as boolean.public;
    ternary r0 r1 r2 into r3;
    output r3 as boolean.public;

function sel_field:
    input r0 as boolean.public;
    input r1 as field.public;
    input r2 as field.public;
    ternary r0 r1 r2 into r3;
    output r3 as field.public;

function sel_group:
    input r0 as boolean.public;
    input r1 as group.public;
    input r2 as group.public;
    ternary r0 r1 r2 into r3;
    output r3 as group.public;

function sel_scalar:
    input r0 as boolean.public;
    input r1 as scalar.public;
    input r2 as scalar.public;
    ternary r0 r1 r2 into r3;
    output r3 as scalar.public;

function sel_i8:
    input r0 as boolean.public;
    input r1 as i8.public;
    input r2 as i8.public;
    ternary r0 r1 r2 into r3;
    output r3 as i8.public;

function sel_i16:
    input r0 as boolean.public;
    input r1 as i16.public;
    input r2 as i16.public;
    ternary r0 r1 r2 into r3;
    output r3 as i16.public;

function sel_i32:
    input r0 as boolean.public;
    input r1 as i32.public;
    input r2 as i32.public;
    ternary r0 r1 r2 into r3;
    output r3 as i32.public;

function sel_i64:
    input r0 as boolean.public;
    input r1 as i64.public;
    input r2 as i64.public;
    ternary r0 r1 r2 into r3;
    output r3 as i64.public;

function sel_i128:
    input r0 as boolean.public;
    input r1 as i128.public;
    input r2 as i128.public;
    ternary r0 r1 r2 into r3;
    output r3 as i128.public;

function sel_u8:
    input r0 as boolean.public;
    input r1 as u8.public;
    input r2 as u8.public;
    ternary r0 r1 r2 into r3;
    output r3 as u8.public;

function sel_u16:
    input r0 as boolean.public;
    input r1 as u16.public;
    input r2 as u16.public;
    ternary r0 r1 r2 into r3;
    output r3 as u16.public;

function sel_u32:
    input r0 as boolean.public;
    input r1 as u32.public;
    input r2 as u32.public;
    ternary r0 r1 r2 into r3;
    output r3 as u32.public;

function sel_u64:
    input r0 as boolean.public;
    input r1 as u64.public;
    input r2 as u64.public;
    ternary r0 r1 r2 into r3;
    output r3 as u64.public;

function sel_u128:
    input r0 as boolean.public;
    input r1 as u128.public;
    input r2 as u128.public;
    ternary r0 r1 r2 into r3;
    output r3 as u128.public;

constructor:
    assert.eq true true;
";

// Tests `ternary` end-to-end on every supported literal variant that can be used as a function
// input. Signature is intentionally omitted because signatures cannot be supplied as inputs
// directly; the dispatch for signatures is exercised in `console/program` unit tests.
#[test]
fn test_execute_ternary_all_literal_variants() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_LITERAL_VARIANTS_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    // Sample two distinct addresses to use as ternary branches.
    let addr_first = Address::try_from(&PrivateKey::<CurrentNetwork>::new(rng).unwrap()).unwrap().to_string();
    let addr_second = Address::try_from(&PrivateKey::<CurrentNetwork>::new(rng).unwrap()).unwrap().to_string();

    // One (function, first_value, second_value) tuple per supported literal variant.
    let cases: &[(&str, &str, &str)] = &[
        ("sel_address", addr_first.as_str(), addr_second.as_str()),
        ("sel_boolean", "true", "false"),
        ("sel_field", "1field", "2field"),
        ("sel_group", "0group", "2group"),
        ("sel_scalar", "1scalar", "2scalar"),
        ("sel_i8", "1i8", "-1i8"),
        ("sel_i16", "1000i16", "-1000i16"),
        ("sel_i32", "1000000i32", "-1000000i32"),
        ("sel_i64", "1000000000i64", "-1000000000i64"),
        ("sel_i128", "123456789i128", "-123456789i128"),
        ("sel_u8", "7u8", "42u8"),
        ("sel_u16", "7u16", "42u16"),
        ("sel_u32", "7u32", "42u32"),
        ("sel_u64", "7u64", "42u64"),
        ("sel_u128", "7u128", "42u128"),
    ];

    for (function, first, second) in cases {
        for (cond_str, expected_str) in [("true", *first), ("false", *second)] {
            let inputs = [
                Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
                Value::from_str(first).unwrap(),
                Value::from_str(second).unwrap(),
            ];
            let execution = vm
                .execute(
                    &caller_private_key,
                    ("ternary_lit_variants.aleo", *function),
                    inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();
            let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
            match &execution.transitions().next().unwrap().outputs()[0] {
                Output::Public(_, Some(plaintext)) => {
                    assert_eq!(*plaintext, expected, "{function} with condition={cond_str}")
                }
                other => panic!("Expected public output, got: {other:?}"),
            }
            let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
            assert_eq!(
                block.transactions().num_accepted(),
                1,
                "{function} with condition={cond_str} should be accepted"
            );
            vm.add_next_block(&block).unwrap();
        }
    }
}

// Tests that `ternary` on record operands is rejected by the type checker: records are not
// plaintext and must be refused before reaching `Literal::ternary` dispatch.
#[test]
fn test_deploy_ternary_on_record_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_record_bad.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function bad:
            input r0 as boolean.public;
            input r1 as token.record;
            input r2 as token.record;
            ternary r0 r1 r2 into r3;
            output r3 as token.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on record operands");
}

// Tests that `ternary` on future operands in a finalize block is rejected: futures are not
// plaintext and must be refused by the type checker.
#[test]
fn test_deploy_ternary_on_future_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    // A program where finalize tries to ternary-select between two futures. The finalize
    // receives two futures and attempts a ternary on them, which the type checker must reject.
    let program = Program::from_str(
        r"
        program ternary_future_bad.aleo;

        function inner:
            input r0 as u8.public;
            async inner r0 into r1;
            output r1 as ternary_future_bad.aleo/inner.future;

        finalize inner:
            input r0 as u8.public;
            assert.eq r0 r0;

        function bad:
            input r0 as boolean.public;
            input r1 as u8.public;
            call inner r1 into r2;
            call inner r1 into r3;
            async bad r0 r2 r3 into r4;
            output r4 as ternary_future_bad.aleo/bad.future;

        finalize bad:
            input r0 as boolean.public;
            input r1 as ternary_future_bad.aleo/inner.future;
            input r2 as ternary_future_bad.aleo/inner.future;
            ternary r0 r1 r2 into r3;
            await r3;

        constructor:
            assert.eq true true;
        ",
    );

    // Depending on earlier parse-time validation, construction may already fail; if parsing
    // succeeds, deployment must fail because futures are not plaintext.
    match program {
        Err(_) => {}
        Ok(program) => {
            let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
            assert!(result.is_err(), "Deployment should fail for ternary on future operands");
        }
    }
}

// A program exercising `ternary` at greater nesting depths than the basic tests above: a
// triply-nested array, and a struct whose field is itself an array of structs.
const TERNARY_DEEP_NESTING_PROGRAM: &str = r"
program ternary_deep_nesting.aleo;

struct inner:
    a as field;
    b as field;

struct wrapper:
    items as [inner; 2u32];

function run_triple_array:
    input r0 as boolean.public;
    input r1 as [[[field; 2u32]; 2u32]; 2u32].public;
    input r2 as [[[field; 2u32]; 2u32]; 2u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [[[field; 2u32]; 2u32]; 2u32].public;

function run_struct_array_struct:
    input r0 as boolean.public;
    input r1 as wrapper.public;
    input r2 as wrapper.public;
    ternary r0 r1 r2 into r3;
    output r3 as wrapper.public;

constructor:
    assert.eq true true;
";

// Tests `ternary` at greater nesting depths: a triply-nested array and a struct holding an
// array of structs. Exercises the recursive equivalence check and the `Plaintext::ternary`
// dispatch on deep structures.
#[test]
fn test_execute_ternary_deep_nesting() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_DEEP_NESTING_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Deep-nesting deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let cases: &[(&str, &str, &str)] = &[
        (
            "run_triple_array",
            "[ [ [ 1field, 2field ], [ 3field, 4field ] ], [ [ 5field, 6field ], [ 7field, 8field ] ] ]",
            "[ [ [ 9field, 10field ], [ 11field, 12field ] ], [ [ 13field, 14field ], [ 15field, 16field ] ] ]",
        ),
        (
            "run_struct_array_struct",
            "{ items: [ { a: 1field, b: 2field }, { a: 3field, b: 4field } ] }",
            "{ items: [ { a: 5field, b: 6field }, { a: 7field, b: 8field } ] }",
        ),
    ];

    for (function, first, second) in cases {
        for (cond_str, expected_str) in [("true", *first), ("false", *second)] {
            let inputs = [
                Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
                Value::from_str(first).unwrap(),
                Value::from_str(second).unwrap(),
            ];
            let execution = vm
                .execute(
                    &caller_private_key,
                    ("ternary_deep_nesting.aleo", *function),
                    inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();
            let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
            match &execution.transitions().next().unwrap().outputs()[0] {
                Output::Public(_, Some(plaintext)) => {
                    assert_eq!(*plaintext, expected, "{function} with condition={cond_str}")
                }
                other => panic!("Expected public output, got: {other:?}"),
            }
            let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
            assert_eq!(
                block.transactions().num_accepted(),
                1,
                "{function} with condition={cond_str} should be accepted"
            );
            vm.add_next_block(&block).unwrap();
        }
    }
}

// Tests that nested arrays whose outer length matches but whose element types differ are
// rejected by the type checker. Complements `test_deploy_ternary_array_size_mismatch_rejected`
// which checks the outer length.
#[test]
fn test_deploy_ternary_nested_shape_mismatch_rejected() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(
        r"
        program ternary_nested_mismatch.aleo;

        function bad:
            input r0 as boolean.public;
            input r1 as [[field; 2u32]; 3u32].public;
            input r2 as [[field; 3u32]; 3u32].public;
            ternary r0 r1 r2 into r3;
            output r3 as [[field; 2u32]; 3u32].public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "Deployment should fail for ternary on nested arrays with different inner lengths");
}

// A program that feeds the result of a non-literal `ternary` into a downstream instruction:
// extracts an element via `cast` semantics and asserts equality on a struct field.
const TERNARY_RESULT_USE_PROGRAM: &str = r"
program ternary_result_use.aleo;

struct point:
    x as field;
    y as field;

function use_struct_result:
    input r0 as boolean.public;
    input r1 as point.public;
    input r2 as point.public;
    ternary r0 r1 r2 into r3;
    // The selected struct is cast back into its own type, then fed to assert.eq.
    cast r3.x r3.y into r4 as point;
    assert.eq r3 r4;
    output r3 as point.public;

function use_array_result:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    ternary r0 r1 r2 into r3;
    // Rebuild the array from the selected operand's elements and assert equality.
    cast r3[0u32] r3[1u32] r3[2u32] into r4 as [field; 3u32];
    assert.eq r3 r4;
    output r3 as [field; 3u32].public;

constructor:
    assert.eq true true;
";

// Tests that the result of a non-literal `ternary` can be consumed by downstream instructions
// (`cast` and `assert.eq`). Ensures the destination register is correctly typed and usable.
#[test]
fn test_execute_ternary_result_is_usable() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_RESULT_USE_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1, "Result-use deployment at V23 should be accepted");
    vm.add_next_block(&block).unwrap();

    let cases: &[(&str, &str, &str)] = &[
        ("use_struct_result", "{ x: 1field, y: 2field }", "{ x: 3field, y: 4field }"),
        ("use_array_result", "[ 1field, 2field, 3field ]", "[ 4field, 5field, 6field ]"),
    ];

    for (function, first, second) in cases {
        for (cond_str, expected_str) in [("true", *first), ("false", *second)] {
            let inputs = [
                Value::<CurrentNetwork>::from_str(cond_str).unwrap(),
                Value::from_str(first).unwrap(),
                Value::from_str(second).unwrap(),
            ];
            let execution = vm
                .execute(&caller_private_key, ("ternary_result_use.aleo", *function), inputs.iter(), None, 0, None, rng)
                .unwrap();
            let expected = Plaintext::<CurrentNetwork>::from_str(expected_str).unwrap();
            match &execution.transitions().next().unwrap().outputs()[0] {
                Output::Public(_, Some(plaintext)) => {
                    assert_eq!(*plaintext, expected, "{function} with condition={cond_str}")
                }
                other => panic!("Expected public output, got: {other:?}"),
            }
            let block = sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap();
            assert_eq!(
                block.transactions().num_accepted(),
                1,
                "{function} with condition={cond_str} should be accepted"
            );
            vm.add_next_block(&block).unwrap();
        }
    }
}

// A program that exercises a non-literal `ternary` inside a finalize block, so that the
// size-based cost path (`TERNARY_BASE_COST + TERNARY_PER_BYTE_COST * size`) is hit.
const TERNARY_COST_PROGRAM: &str = r"
program ternary_cost_test.aleo;

mapping selected:
    key as u8.public;
    value as [field; 4u32].public;

function run:
    input r0 as boolean.public;
    input r1 as [field; 4u32].public;
    input r2 as [field; 4u32].public;
    async run r0 r1 r2 into r3;
    output r3 as ternary_cost_test.aleo/run.future;

finalize run:
    input r0 as boolean.public;
    input r1 as [field; 4u32].public;
    input r2 as [field; 4u32].public;
    ternary r0 r1 r2 into r3;
    set r3 into selected[0u8];

constructor:
    assert.eq true true;
";

// Tests that the cost of a non-literal `ternary` in a finalize block is estimated correctly by
// running the execution through `add_and_test_with_costs`, which asserts that the estimated
// and actual fees match.
#[test]
fn test_execute_ternary_finalize_cost_matches() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let v23_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V23).unwrap();
    let vm = sample_vm_at_height(v23_height, rng);

    let program = Program::from_str(TERNARY_COST_PROGRAM).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);

    let inputs = [
        Value::<CurrentNetwork>::from_str("true").unwrap(),
        Value::from_str("[ 1field, 2field, 3field, 4field ]").unwrap(),
        Value::from_str("[ 5field, 6field, 7field, 8field ]").unwrap(),
    ];
    let execution =
        vm.execute(&caller_private_key, ("ternary_cost_test.aleo", "run"), inputs.iter(), None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[execution], rng);
}

#[test]
fn test_ternary_view_legacy_gate() -> anyhow::Result<()> {
    let program = Program::<CurrentNetwork>::from_str(
        r"
program ternary_view_gate.aleo;

function run:
    input r0 as field.public;
    output r0 as field.public;

view select:
    input r0 as boolean.public;
    input r1 as [field; 3u32].public;
    input r2 as [field; 3u32].public;
    ternary r0 r1 r2 into r3;
    output r3 as [field; 3u32].public;
",
    )?;
    let process = Process::<CurrentNetwork>::load()?;
    let stack = Stack::new(&process, &program)?;
    let error =
        check_no_non_literal_ternary(&program, &stack).expect_err("Array ternary in a view must fail the legacy gate.");
    assert!(error.to_string().contains("ConsensusVersion::V23"));

    let literal_program = Program::<CurrentNetwork>::from_str(&program.to_string().replace("[field; 3u32]", "field"))?;
    let literal_stack = Stack::new(&process, &literal_program)?;
    check_no_non_literal_ternary(&literal_program, &literal_stack)?;
    Ok(())
}
