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

// A helper function to create a program that sets and removes values from a mapping.
fn basic_program(program_name: &str, mapping_name: &str) -> Program<CurrentNetwork> {
    Program::from_str(&format!(
        r"
program {program_name}.aleo;

mapping {mapping_name}:
    key as u32.public;
    value as u32.public;

function set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    async set_mapping r0 r1 into r2;
    output r2 as {program_name}.aleo/set_mapping.future;
finalize set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    set r1 into {mapping_name}[r0];

function remove_mapping:
    input r0 as u32.public;
    async remove_mapping r0 into r1;
    output r1 as {program_name}.aleo/remove_mapping.future;
finalize remove_mapping:
    input r0 as u32.public;
    remove {mapping_name}[r0];

constructor:
    assert.eq true true;
"
    ))
    .unwrap()
}

// This test verifies that `contains.dynamic`:
// - Returns a result when called on an external program and mapping.
// - Returns a result when called on a mapping in the current program.
// - Fails when the program or mapping does not exist.
// - Fails when the key is of the wrong type.
#[test]
fn test_dynamic_contains() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Initialize two instances of the basic program.
    let program_0 = basic_program("basic_program0", "data0");
    let program_1 = basic_program("basic_program1", "data1");

    // Initialize the main program.
    let main_program = Program::from_str(
        r"
program main_program.aleo;

mapping data_main:
    key as u32.public;
    value as u32.public;

function test_dynamic_contains:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as boolean.public;
    async test_dynamic_contains r0 r1 r2 r3 r4 into r5;
    output r5 as main_program.aleo/test_dynamic_contains.future;
finalize test_dynamic_contains:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as boolean.public;
    contains.dynamic r0 r1 r2[r3] into r5;
    assert.eq r5 r4;

function set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    async set_mapping r0 r1 into r2;
    output r2 as main_program.aleo/set_mapping.future;
finalize set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    set r1 into data_main[r0];

function remove_mapping:
    input r0 as u32.public;
    async remove_mapping r0 into r1;
    output r1 as main_program.aleo/remove_mapping.future;
finalize remove_mapping:
    input r0 as u32.public;
    remove data_main[r0];

constructor:
    assert.eq true true;",
    )
    .unwrap();

    // Deploy the programs individually.
    for program in [&program_0, &program_1, &main_program] {
        println!("Deploying program: {}", program.id());
        let deployment = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    // Create a helper to execute the `test_dynamic_contains` function.
    let test_dynamic_contains = |program_name: &str,
                                 program_network: &str,
                                 mapping_name: &str,
                                 key: Value<CurrentNetwork>,
                                 expected: Option<bool>, // If None, expect an error.
                                 rng: &mut TestRng| {
        println!(
            "Testing dynamic contains for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}, expected: {expected:?}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the transaction to call `test_dynamic_contains`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo".to_string(), "test_dynamic_contains"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                key,
                Value::from_str(&expected.unwrap_or(false).to_string()).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) if expected.is_none() => {
                println!("Expected error occurred: {e}");
                return;
            }
            Err(e) => panic!("Unexpected error occurred: {e}"),
        };
        // Check and add the transaction to the VM.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), expected.is_some() as usize);
        assert_eq!(block.transactions().num_rejected(), expected.is_none() as usize);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Check that the local mapping does not contain the key 42 initially.
    test_dynamic_contains("main_program", "aleo", "data_main", Value::from_str("42u32").unwrap(), Some(false), rng);

    // Set the key 42 in the local mapping.
    let set_inputs = vec![Value::from_str("42u32").unwrap(), Value::from_str("100u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that the local mapping now contains the key 42.
    test_dynamic_contains("main_program", "aleo", "data_main", Value::from_str("42u32").unwrap(), Some(true), rng);

    // Check that if the program does not exist, an error is returned.
    test_dynamic_contains("main_progra", "aleo", "data_main", Value::from_str("42u32").unwrap(), None, rng);
    // Check that if the network is wrong, an error is returned.
    test_dynamic_contains("main_program", "aleoo", "data_main", Value::from_str("42u32").unwrap(), None, rng);
    // Check that if the mapping does not exist, an error is returned.
    test_dynamic_contains("main_program", "aleo", "data_maine", Value::from_str("42u32").unwrap(), None, rng);
    // Check that if the key is of the wrong type, an error is returned.
    test_dynamic_contains("main_program", "aleo", "data_main", Value::from_str("true").unwrap(), None, rng);

    // Remove the key 42 from the local mapping.
    let remove_inputs = vec![Value::from_str("42u32").unwrap()];
    let remove_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "remove_mapping"), remove_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that the local mapping no longer contains the key 42.
    test_dynamic_contains("main_program", "aleo", "data_main", Value::from_str("42u32").unwrap(), Some(false), rng);

    // Set the key 7 in the first external program's mapping.
    let set_inputs = vec![Value::from_str("7u32").unwrap(), Value::from_str("200u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program0.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Set the key 15 in the second external program's mapping.
    let set_inputs = vec![Value::from_str("15u32").unwrap(), Value::from_str("300u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program1.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that the first external mapping contains the key 7.
    test_dynamic_contains("basic_program0", "aleo", "data0", Value::from_str("7u32").unwrap(), Some(true), rng);
    // Check that the second external mapping contains the key 15.
    test_dynamic_contains("basic_program1", "aleo", "data1", Value::from_str("15u32").unwrap(), Some(true), rng);

    // Remove the key 7 from the first external program's mapping.
    let remove_inputs = vec![Value::from_str("7u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program0.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Remove the key 15 from the second external program's mapping.
    let remove_inputs = vec![Value::from_str("15u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program1.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that the first external mapping no longer contains the key 7.
    test_dynamic_contains("basic_program0", "aleo", "data0", Value::from_str("7u32").unwrap(), Some(false), rng);
    // Check that the second external mapping no longer contains the key 15.
    test_dynamic_contains("basic_program1", "aleo", "data1", Value::from_str("15u32").unwrap(), Some(false), rng);
}

// A helper function to create a program with a struct-valued mapping.
fn struct_program(program_name: &str, mapping_name: &str) -> Program<CurrentNetwork> {
    Program::from_str(&format!(
        r"
program {program_name}.aleo;

struct data_struct:
    a as u32;
    b as u64;

mapping {mapping_name}:
    key as u32.public;
    value as data_struct.public;

function set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    async set_mapping r0 r1 r2 into r3;
    output r3 as {program_name}.aleo/set_mapping.future;
finalize set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    cast r1 r2 into r3 as data_struct;
    set r3 into {mapping_name}[r0];

function remove_mapping:
    input r0 as u32.public;
    async remove_mapping r0 into r1;
    output r1 as {program_name}.aleo/remove_mapping.future;
finalize remove_mapping:
    input r0 as u32.public;
    remove {mapping_name}[r0];

constructor:
    assert.eq true true;
"
    ))
    .unwrap()
}

// This test verifies that `get.dynamic`:
// - Returns a value when called on an external program and mapping.
// - Returns a value when called on a mapping in the current program.
// - Fails when the key does not exist in the mapping.
// - Fails when the program or mapping does not exist.
// - Fails when the key is of the wrong type.
// - Fails when the destination type does not match the mapping value type.
// - Works with struct value types.
#[test]
fn test_dynamic_get() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Initialize two instances of the basic program (u32 values).
    let program_0 = basic_program("basic_program0", "data0");
    let program_1 = basic_program("basic_program1", "data1");

    // Initialize a struct program (struct values).
    let struct_program_0 = struct_program("struct_program0", "struct_data0");

    // Initialize the main program with test functions for get.dynamic.
    let main_program = Program::from_str(
        r"
program main_program.aleo;

struct data_struct:
    a as u32;
    b as u64;

mapping data_main:
    key as u32.public;
    value as u32.public;

mapping struct_data_main:
    key as u32.public;
    value as data_struct.public;

// Test get.dynamic with u32 value type.
function test_dynamic_get_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    async test_dynamic_get_u32 r0 r1 r2 r3 r4 into r5;
    output r5 as main_program.aleo/test_dynamic_get_u32.future;
finalize test_dynamic_get_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    get.dynamic r0 r1 r2[r3] into r5 as u32;
    assert.eq r5 r4;

// Test get.dynamic with struct value type.
function test_dynamic_get_struct:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u64.public;
    async test_dynamic_get_struct r0 r1 r2 r3 r4 r5 into r6;
    output r6 as main_program.aleo/test_dynamic_get_struct.future;
finalize test_dynamic_get_struct:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u64.public;
    get.dynamic r0 r1 r2[r3] into r6 as data_struct;
    assert.eq r6.a r4;
    assert.eq r6.b r5;

// Test get.dynamic with wrong destination type (u64 instead of u32).
function test_dynamic_get_wrong_type:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    async test_dynamic_get_wrong_type r0 r1 r2 r3 into r4;
    output r4 as main_program.aleo/test_dynamic_get_wrong_type.future;
finalize test_dynamic_get_wrong_type:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    get.dynamic r0 r1 r2[r3] into r4 as u64;

function set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    async set_mapping r0 r1 into r2;
    output r2 as main_program.aleo/set_mapping.future;
finalize set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    set r1 into data_main[r0];

function set_struct_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    async set_struct_mapping r0 r1 r2 into r3;
    output r3 as main_program.aleo/set_struct_mapping.future;
finalize set_struct_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    cast r1 r2 into r3 as data_struct;
    set r3 into struct_data_main[r0];

function remove_mapping:
    input r0 as u32.public;
    async remove_mapping r0 into r1;
    output r1 as main_program.aleo/remove_mapping.future;
finalize remove_mapping:
    input r0 as u32.public;
    remove data_main[r0];

function remove_struct_mapping:
    input r0 as u32.public;
    async remove_struct_mapping r0 into r1;
    output r1 as main_program.aleo/remove_struct_mapping.future;
finalize remove_struct_mapping:
    input r0 as u32.public;
    remove struct_data_main[r0];

constructor:
    assert.eq true true;",
    )
    .unwrap();

    // Deploy the programs individually.
    for program in [&program_0, &program_1, &struct_program_0, &main_program] {
        println!("Deploying program: {}", program.id());
        let deployment = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    // Create a helper to execute the `test_dynamic_get_u32` function.
    let test_dynamic_get_u32 = |vm: &VM<CurrentNetwork, _>,
                                program_name: &str,
                                program_network: &str,
                                mapping_name: &str,
                                key: u32,
                                expected: Option<u32>, // If None, expect an error.
                                rng: &mut TestRng| {
        println!(
            "Testing dynamic get (u32) for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}, expected: {expected:?}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the transaction to call `test_dynamic_get_u32`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_u32"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                Value::from_str(&format!("{key}u32")).unwrap(),
                Value::from_str(&format!("{}u32", expected.unwrap_or(0))).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) if expected.is_none() => {
                println!("Expected error occurred: {e}");
                return;
            }
            Err(e) => panic!("Unexpected error occurred: {e}"),
        };
        // Check and add the transaction to the VM.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), expected.is_some() as usize);
        assert_eq!(block.transactions().num_rejected(), expected.is_none() as usize);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Create a helper to execute the `test_dynamic_get_struct` function.
    let test_dynamic_get_struct = |vm: &VM<CurrentNetwork, _>,
                                   program_name: &str,
                                   program_network: &str,
                                   mapping_name: &str,
                                   key: u32,
                                   expected: Option<(u32, u64)>, // If None, expect an error.
                                   rng: &mut TestRng| {
        println!(
            "Testing dynamic get (struct) for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}, expected: {expected:?}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        let (expected_a, expected_b) = expected.unwrap_or((0, 0));
        // Create the transaction to call `test_dynamic_get_struct`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_struct"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                Value::from_str(&format!("{key}u32")).unwrap(),
                Value::from_str(&format!("{expected_a}u32")).unwrap(),
                Value::from_str(&format!("{expected_b}u64")).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) if expected.is_none() => {
                println!("Expected error occurred: {e}");
                return;
            }
            Err(e) => panic!("Unexpected error occurred: {e}"),
        };
        // Check and add the transaction to the VM.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), expected.is_some() as usize);
        assert_eq!(block.transactions().num_rejected(), expected.is_none() as usize);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Create a helper to test get.dynamic with wrong destination type.
    let test_dynamic_get_wrong_type = |vm: &VM<CurrentNetwork, _>,
                                       program_name: &str,
                                       program_network: &str,
                                       mapping_name: &str,
                                       key: u32,
                                       rng: &mut TestRng| {
        println!(
            "Testing dynamic get (wrong type) for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the transaction to call `test_dynamic_get_wrong_type`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_wrong_type"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                Value::from_str(&format!("{key}u32")).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                println!("Expected error occurred during execution: {e}");
                return;
            }
        };
        // Check and add the transaction to the VM - expect rejection due to type mismatch.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 0);
        assert_eq!(block.transactions().num_rejected(), 1);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Check that get.dynamic fails when the key does not exist in the local mapping.
    test_dynamic_get_u32(&vm, "main_program", "aleo", "data_main", 42, None, rng);

    // Set the key 42 in the local mapping.
    let set_inputs = vec![Value::from_str("42u32").unwrap(), Value::from_str("100u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.dynamic returns the correct value for the local mapping.
    test_dynamic_get_u32(&vm, "main_program", "aleo", "data_main", 42, Some(100), rng);

    // Check that get.dynamic fails if the program does not exist.
    test_dynamic_get_u32(&vm, "main_progra", "aleo", "data_main", 42, None, rng);
    // Check that get.dynamic fails if the network is wrong.
    test_dynamic_get_u32(&vm, "main_program", "aleoo", "data_main", 42, None, rng);
    // Check that get.dynamic fails if the mapping does not exist.
    test_dynamic_get_u32(&vm, "main_program", "aleo", "data_maine", 42, None, rng);

    // Check that get.dynamic fails with destination type mismatch.
    test_dynamic_get_wrong_type(&vm, "main_program", "aleo", "data_main", 42, rng);

    // Remove the key 42 from the local mapping.
    let remove_inputs = vec![Value::from_str("42u32").unwrap()];
    let remove_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "remove_mapping"), remove_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.dynamic fails after removal.
    test_dynamic_get_u32(&vm, "main_program", "aleo", "data_main", 42, None, rng);

    // Set the key 7 in the first external program's mapping.
    let set_inputs = vec![Value::from_str("7u32").unwrap(), Value::from_str("200u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program0.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Set the key 15 in the second external program's mapping.
    let set_inputs = vec![Value::from_str("15u32").unwrap(), Value::from_str("300u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program1.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.dynamic returns correct values from external programs.
    test_dynamic_get_u32(&vm, "basic_program0", "aleo", "data0", 7, Some(200), rng);
    test_dynamic_get_u32(&vm, "basic_program1", "aleo", "data1", 15, Some(300), rng);

    // Check that get.dynamic fails for non-existent keys in external programs.
    test_dynamic_get_u32(&vm, "basic_program0", "aleo", "data0", 99, None, rng);
    test_dynamic_get_u32(&vm, "basic_program1", "aleo", "data1", 99, None, rng);

    // Remove the keys from external programs.
    let remove_inputs = vec![Value::from_str("7u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program0.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    let remove_inputs = vec![Value::from_str("15u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program1.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.dynamic fails after removal from external programs.
    test_dynamic_get_u32(&vm, "basic_program0", "aleo", "data0", 7, None, rng);
    test_dynamic_get_u32(&vm, "basic_program1", "aleo", "data1", 15, None, rng);

    // Set a struct value in the local struct mapping.
    let set_inputs =
        vec![Value::from_str("10u32").unwrap(), Value::from_str("111u32").unwrap(), Value::from_str("222u64").unwrap()];
    let set_tx = vm
        .execute(
            &caller_private_key,
            ("main_program.aleo", "set_struct_mapping"),
            set_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.dynamic returns the correct struct value from the local mapping.
    test_dynamic_get_struct(&vm, "main_program", "aleo", "struct_data_main", 10, Some((111, 222)), rng);

    // Set a struct value in the external struct program's mapping.
    let set_inputs =
        vec![Value::from_str("20u32").unwrap(), Value::from_str("333u32").unwrap(), Value::from_str("444u64").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("struct_program0.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.dynamic returns the correct struct value from the external mapping.
    test_dynamic_get_struct(&vm, "struct_program0", "aleo", "struct_data0", 20, Some((333, 444)), rng);

    // Check that get.dynamic fails for non-existent struct keys.
    test_dynamic_get_struct(&vm, "main_program", "aleo", "struct_data_main", 99, None, rng);
    test_dynamic_get_struct(&vm, "struct_program0", "aleo", "struct_data0", 99, None, rng);

    // Remove struct values.
    let remove_inputs = vec![Value::from_str("10u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("main_program.aleo", "remove_struct_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    let remove_inputs = vec![Value::from_str("20u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("struct_program0.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.dynamic fails after struct removal.
    test_dynamic_get_struct(&vm, "main_program", "aleo", "struct_data_main", 10, None, rng);
    test_dynamic_get_struct(&vm, "struct_program0", "aleo", "struct_data0", 20, None, rng);
}

// This test verifies that `get.or_use.dynamic`:
// - Returns the stored value when the key exists in the mapping.
// - Returns the default value when the key does not exist in the mapping.
// - Works with external programs and mappings.
// - Works with the current program's mapping.
// - Fails when the program or mapping does not exist.
// - Works with struct value types.
// Note: destination type mismatches and default value type mismatches are caught at
// deployment time (static type check in `check_get_or_use_dynamic`), not at runtime.
#[test]
fn test_dynamic_get_or_use() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Initialize two instances of the basic program (u32 values).
    let program_0 = basic_program("basic_program0", "data0");
    let program_1 = basic_program("basic_program1", "data1");

    // Initialize a struct program (struct values).
    let struct_program_0 = struct_program("struct_program0", "struct_data0");

    // Initialize the main program with test functions for get.or_use.dynamic.
    let main_program = Program::from_str(
        r"
program main_program.aleo;

struct data_struct:
    a as u32;
    b as u64;

mapping data_main:
    key as u32.public;
    value as u32.public;

mapping struct_data_main:
    key as u32.public;
    value as data_struct.public;

// Test get.or_use.dynamic with u32 value type.
function test_dynamic_get_or_use_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u32.public;
    async test_dynamic_get_or_use_u32 r0 r1 r2 r3 r4 r5 into r6;
    output r6 as main_program.aleo/test_dynamic_get_or_use_u32.future;
finalize test_dynamic_get_or_use_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u32.public;
    get.or_use.dynamic r0 r1 r2[r3] r4 into r6 as u32;
    assert.eq r6 r5;

// Test get.or_use.dynamic with struct value type.
function test_dynamic_get_or_use_struct:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u64.public;
    input r6 as u32.public;
    input r7 as u64.public;
    async test_dynamic_get_or_use_struct r0 r1 r2 r3 r4 r5 r6 r7 into r8;
    output r8 as main_program.aleo/test_dynamic_get_or_use_struct.future;
finalize test_dynamic_get_or_use_struct:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    input r5 as u64.public;
    input r6 as u32.public;
    input r7 as u64.public;
    cast r4 r5 into r8 as data_struct;
    get.or_use.dynamic r0 r1 r2[r3] r8 into r9 as data_struct;
    assert.eq r9.a r6;
    assert.eq r9.b r7;

function set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    async set_mapping r0 r1 into r2;
    output r2 as main_program.aleo/set_mapping.future;
finalize set_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    set r1 into data_main[r0];

function set_struct_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    async set_struct_mapping r0 r1 r2 into r3;
    output r3 as main_program.aleo/set_struct_mapping.future;
finalize set_struct_mapping:
    input r0 as u32.public;
    input r1 as u32.public;
    input r2 as u64.public;
    cast r1 r2 into r3 as data_struct;
    set r3 into struct_data_main[r0];

function remove_mapping:
    input r0 as u32.public;
    async remove_mapping r0 into r1;
    output r1 as main_program.aleo/remove_mapping.future;
finalize remove_mapping:
    input r0 as u32.public;
    remove data_main[r0];

function remove_struct_mapping:
    input r0 as u32.public;
    async remove_struct_mapping r0 into r1;
    output r1 as main_program.aleo/remove_struct_mapping.future;
finalize remove_struct_mapping:
    input r0 as u32.public;
    remove struct_data_main[r0];

constructor:
    assert.eq true true;",
    )
    .unwrap();

    // Deploy the programs individually.
    for program in [&program_0, &program_1, &struct_program_0, &main_program] {
        println!("Deploying program: {}", program.id());
        let deployment = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    // Create a helper to execute the `test_dynamic_get_or_use_u32` function.
    let test_dynamic_get_or_use_u32 = |vm: &VM<CurrentNetwork, _>,
                                       program_name: &str,
                                       program_network: &str,
                                       mapping_name: &str,
                                       key: u32,
                                       default_value: u32,
                                       expected: Option<u32>, // If None, expect an error.
                                       rng: &mut TestRng| {
        println!(
            "Testing dynamic get_or_use (u32) for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}, default: {default_value}, expected: {expected:?}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the transaction to call `test_dynamic_get_or_use_u32`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_or_use_u32"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                Value::from_str(&format!("{key}u32")).unwrap(),
                Value::from_str(&format!("{default_value}u32")).unwrap(),
                Value::from_str(&format!("{}u32", expected.unwrap_or(0))).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) if expected.is_none() => {
                println!("Expected error occurred: {e}");
                return;
            }
            Err(e) => panic!("Unexpected error occurred: {e}"),
        };
        // Check and add the transaction to the VM.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), expected.is_some() as usize);
        assert_eq!(block.transactions().num_rejected(), expected.is_none() as usize);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Create a helper to execute the `test_dynamic_get_or_use_struct` function.
    let test_dynamic_get_or_use_struct = |vm: &VM<CurrentNetwork, _>,
                                          program_name: &str,
                                          program_network: &str,
                                          mapping_name: &str,
                                          key: u32,
                                          default_value: (u32, u64),
                                          expected: Option<(u32, u64)>, // If None, expect an error.
                                          rng: &mut TestRng| {
        println!(
            "Testing dynamic get_or_use (struct) for program: {program_name}, network: {program_network}, mapping: {mapping_name}, key: {key}, default: {default_value:?}, expected: {expected:?}"
        );
        // Create the program name as a field element.
        let program_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the program network as a field element.
        let program_network_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(program_network).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        // Create the mapping name as a field element.
        let mapping_name_as_field = Value::from_str(
            &Identifier::<CurrentNetwork>::from_str(mapping_name).unwrap().to_field().unwrap().to_string(),
        )
        .unwrap();
        let (expected_a, expected_b) = expected.unwrap_or((0, 0));
        // Create the transaction to call `test_dynamic_get_or_use_struct`.
        let transaction = match vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_or_use_struct"),
            vec![
                program_name_as_field,
                program_network_as_field,
                mapping_name_as_field,
                Value::from_str(&format!("{key}u32")).unwrap(),
                Value::from_str(&format!("{}u32", default_value.0)).unwrap(),
                Value::from_str(&format!("{}u64", default_value.1)).unwrap(),
                Value::from_str(&format!("{expected_a}u32")).unwrap(),
                Value::from_str(&format!("{expected_b}u64")).unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        ) {
            Ok(tx) => tx,
            Err(e) if expected.is_none() => {
                println!("Expected error occurred: {e}");
                return;
            }
            Err(e) => panic!("Unexpected error occurred: {e}"),
        };
        // Check and add the transaction to the VM.
        vm.check_transaction(&transaction, None, rng).map_err(|e| anyhow!("Transaction check failed: {e}")).unwrap();
        let block = sample_next_block(vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), expected.is_some() as usize);
        assert_eq!(block.transactions().num_rejected(), expected.is_none() as usize);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    };

    // Check that get.or_use.dynamic returns the default value when key doesn't exist.
    test_dynamic_get_or_use_u32(&vm, "main_program", "aleo", "data_main", 42, 999, Some(999), rng);

    // Set the key 42 in the local mapping.
    let set_inputs = vec![Value::from_str("42u32").unwrap(), Value::from_str("100u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.or_use.dynamic returns the stored value (not the default) when key exists.
    test_dynamic_get_or_use_u32(&vm, "main_program", "aleo", "data_main", 42, 999, Some(100), rng);

    // Check that get.or_use.dynamic fails if the program does not exist.
    test_dynamic_get_or_use_u32(&vm, "main_progra", "aleo", "data_main", 42, 999, None, rng);
    // Check that get.or_use.dynamic fails if the network is wrong.
    test_dynamic_get_or_use_u32(&vm, "main_program", "aleoo", "data_main", 42, 999, None, rng);
    // Check that get.or_use.dynamic fails if the mapping does not exist.
    test_dynamic_get_or_use_u32(&vm, "main_program", "aleo", "data_maine", 42, 999, None, rng);

    // Note: destination type mismatch is caught at deployment time (static type check),
    // so it cannot be tested as a runtime failure like get.dynamic.

    // Remove the key 42 from the local mapping.
    let remove_inputs = vec![Value::from_str("42u32").unwrap()];
    let remove_tx = vm
        .execute(&caller_private_key, ("main_program.aleo", "remove_mapping"), remove_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.or_use.dynamic returns default after removal.
    test_dynamic_get_or_use_u32(&vm, "main_program", "aleo", "data_main", 42, 888, Some(888), rng);

    // Check default value for non-existent keys in external programs.
    test_dynamic_get_or_use_u32(&vm, "basic_program0", "aleo", "data0", 7, 500, Some(500), rng);
    test_dynamic_get_or_use_u32(&vm, "basic_program1", "aleo", "data1", 15, 600, Some(600), rng);

    // Set the key 7 in the first external program's mapping.
    let set_inputs = vec![Value::from_str("7u32").unwrap(), Value::from_str("200u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program0.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Set the key 15 in the second external program's mapping.
    let set_inputs = vec![Value::from_str("15u32").unwrap(), Value::from_str("300u32").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("basic_program1.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.or_use.dynamic returns stored values from external programs.
    test_dynamic_get_or_use_u32(&vm, "basic_program0", "aleo", "data0", 7, 500, Some(200), rng);
    test_dynamic_get_or_use_u32(&vm, "basic_program1", "aleo", "data1", 15, 600, Some(300), rng);

    // Check default values for different non-existent keys in external programs.
    test_dynamic_get_or_use_u32(&vm, "basic_program0", "aleo", "data0", 99, 777, Some(777), rng);
    test_dynamic_get_or_use_u32(&vm, "basic_program1", "aleo", "data1", 99, 888, Some(888), rng);

    // Remove the keys from external programs.
    let remove_inputs = vec![Value::from_str("7u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program0.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    let remove_inputs = vec![Value::from_str("15u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("basic_program1.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.or_use.dynamic returns default after removal from external programs.
    test_dynamic_get_or_use_u32(&vm, "basic_program0", "aleo", "data0", 7, 111, Some(111), rng);
    test_dynamic_get_or_use_u32(&vm, "basic_program1", "aleo", "data1", 15, 222, Some(222), rng);

    // Check default struct value for non-existent key.
    test_dynamic_get_or_use_struct(&vm, "main_program", "aleo", "struct_data_main", 10, (50, 60), Some((50, 60)), rng);

    // Set a struct value in the local struct mapping.
    let set_inputs =
        vec![Value::from_str("10u32").unwrap(), Value::from_str("111u32").unwrap(), Value::from_str("222u64").unwrap()];
    let set_tx = vm
        .execute(
            &caller_private_key,
            ("main_program.aleo", "set_struct_mapping"),
            set_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.or_use.dynamic returns the stored struct value (not default).
    test_dynamic_get_or_use_struct(
        &vm,
        "main_program",
        "aleo",
        "struct_data_main",
        10,
        (50, 60),
        Some((111, 222)),
        rng,
    );

    // Check default struct value for external program's non-existent key.
    test_dynamic_get_or_use_struct(&vm, "struct_program0", "aleo", "struct_data0", 20, (70, 80), Some((70, 80)), rng);

    // Set a struct value in the external struct program's mapping.
    let set_inputs =
        vec![Value::from_str("20u32").unwrap(), Value::from_str("333u32").unwrap(), Value::from_str("444u64").unwrap()];
    let set_tx = vm
        .execute(&caller_private_key, ("struct_program0.aleo", "set_mapping"), set_inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Check that get.or_use.dynamic returns the stored struct value from external mapping.
    test_dynamic_get_or_use_struct(&vm, "struct_program0", "aleo", "struct_data0", 20, (70, 80), Some((333, 444)), rng);

    // Check default for non-existent struct keys.
    test_dynamic_get_or_use_struct(&vm, "main_program", "aleo", "struct_data_main", 99, (1, 2), Some((1, 2)), rng);
    test_dynamic_get_or_use_struct(&vm, "struct_program0", "aleo", "struct_data0", 99, (3, 4), Some((3, 4)), rng);

    // Remove struct values.
    let remove_inputs = vec![Value::from_str("10u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("main_program.aleo", "remove_struct_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    let remove_inputs = vec![Value::from_str("20u32").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("struct_program0.aleo", "remove_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Check that get.or_use.dynamic returns default after struct removal.
    test_dynamic_get_or_use_struct(&vm, "main_program", "aleo", "struct_data_main", 10, (5, 6), Some((5, 6)), rng);
    test_dynamic_get_or_use_struct(&vm, "struct_program0", "aleo", "struct_data0", 20, (7, 8), Some((7, 8)), rng);
}

// Tests that `get.dynamic` fails when accessing a key in an empty mapping while `contains.dynamic` returns false.
#[test]
fn test_get_dynamic_empty_mapping() {
    let rng = &mut TestRng::default();

    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    let vm = crate::vm::test_helpers::sample_vm_at_height(
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(),
        rng,
    );

    // Create a program with an empty mapping (no entries ever set)
    let empty_mapping_program = Program::<CurrentNetwork>::from_str(
        r"
        program empty_mapping.aleo;

        mapping empty_data:
            key as u32.public;
            value as u64.public;

        function test_get_empty:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as u32.public;
            async test_get_empty r0 r1 r2 r3 into r4;
            output r4 as empty_mapping.aleo/test_get_empty.future;

        finalize test_get_empty:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as u32.public;
            get.dynamic r0 r1 r2[r3] into r4 as u64;

        function test_contains_empty:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as u32.public;
            async test_contains_empty r0 r1 r2 r3 into r4;
            output r4 as empty_mapping.aleo/test_contains_empty.future;

        finalize test_contains_empty:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as u32.public;
            contains.dynamic r0 r1 r2[r3] into r4;
            assert.eq r4 false;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Deploy the program
    println!("Deploying empty_mapping.aleo...");
    let deployment = vm.deploy(&caller_private_key, &empty_mapping_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);

    // Create field values for the program, network, and mapping names
    let program_name_field =
        Identifier::<CurrentNetwork>::from_str("empty_mapping").unwrap().to_field().unwrap().to_string();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap().to_string();
    let mapping_name_field =
        Identifier::<CurrentNetwork>::from_str("empty_data").unwrap().to_field().unwrap().to_string();

    // First verify that contains.dynamic returns false for any key in the empty mapping
    println!("Testing contains.dynamic on empty mapping...");
    let contains_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("42u32").unwrap(),
    ];
    let contains_tx = vm
        .execute(
            &caller_private_key,
            ("empty_mapping.aleo", "test_contains_empty"),
            contains_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // contains.dynamic should succeed and return false
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&contains_inputs]), &[contains_tx], rng);

    // Now test that get.dynamic fails on the empty mapping
    println!("Testing get.dynamic on empty mapping (should fail)...");
    let get_tx = vm
        .execute(
            &caller_private_key,
            ("empty_mapping.aleo", "test_get_empty"),
            vec![
                Value::from_str(&program_name_field).unwrap(),
                Value::from_str(&network_field).unwrap(),
                Value::from_str(&mapping_name_field).unwrap(),
                Value::from_str("42u32").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // get.dynamic should fail because the key doesn't exist
    let block = sample_next_block(&vm, &caller_private_key, &[get_tx], rng).unwrap();
    assert_eq!(block.transactions().num_rejected(), 1, "get.dynamic on empty mapping should be rejected");
    vm.add_next_block(&block).unwrap();
}

// Tests contains.dynamic with array keys to verify composite key type handling.
#[test]
fn test_contains_dynamic_with_array_keys() {
    let rng = &mut TestRng::default();

    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    let vm = crate::vm::test_helpers::sample_vm_at_height(
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(),
        rng,
    );

    // Create a program with an array-keyed mapping
    let array_key_program = Program::<CurrentNetwork>::from_str(
        r"
        program array_key_mapping.aleo;

        mapping array_data:
            key as [u8; 4u32].public;
            value as u64.public;

        function set_array_mapping:
            input r0 as [u8; 4u32].public;
            input r1 as u64.public;
            async set_array_mapping r0 r1 into r2;
            output r2 as array_key_mapping.aleo/set_array_mapping.future;

        finalize set_array_mapping:
            input r0 as [u8; 4u32].public;
            input r1 as u64.public;
            set r1 into array_data[r0];

        function test_contains_array:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as [u8; 4u32].public;
            input r4 as boolean.public;
            async test_contains_array r0 r1 r2 r3 r4 into r5;
            output r5 as array_key_mapping.aleo/test_contains_array.future;

        finalize test_contains_array:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as [u8; 4u32].public;
            input r4 as boolean.public;
            contains.dynamic r0 r1 r2[r3] into r5;
            assert.eq r5 r4;

        function test_get_array:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as [u8; 4u32].public;
            input r4 as u64.public;
            async test_get_array r0 r1 r2 r3 r4 into r5;
            output r5 as array_key_mapping.aleo/test_get_array.future;

        finalize test_get_array:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as [u8; 4u32].public;
            input r4 as u64.public;
            get.dynamic r0 r1 r2[r3] into r5 as u64;
            assert.eq r5 r4;

        function remove_array_mapping:
            input r0 as [u8; 4u32].public;
            async remove_array_mapping r0 into r1;
            output r1 as array_key_mapping.aleo/remove_array_mapping.future;

        finalize remove_array_mapping:
            input r0 as [u8; 4u32].public;
            remove array_data[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Deploy the program
    println!("Deploying array_key_mapping.aleo...");
    let deployment = vm.deploy(&caller_private_key, &array_key_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);

    // Create field values for dynamic operations
    let program_name_field =
        Identifier::<CurrentNetwork>::from_str("array_key_mapping").unwrap().to_field().unwrap().to_string();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap().to_string();
    let mapping_name_field =
        Identifier::<CurrentNetwork>::from_str("array_data").unwrap().to_field().unwrap().to_string();

    // Test that contains.dynamic returns false for non-existent array key
    println!("Testing contains.dynamic with array key (should be false)...");
    let contains_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap(),
        Value::from_str("false").unwrap(),
    ];
    let contains_tx = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "test_contains_array"),
            contains_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&contains_inputs]), &[contains_tx], rng);

    // Set a value with an array key
    println!("Setting value with array key...");
    let set_inputs = vec![Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap(), Value::from_str("12345u64").unwrap()];
    let set_tx = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "set_array_mapping"),
            set_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&set_inputs]), &[set_tx], rng);

    // Test that contains.dynamic returns true for existing array key
    println!("Testing contains.dynamic with array key (should be true)...");
    let contains_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap(),
        Value::from_str("true").unwrap(),
    ];
    let contains_tx2 = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "test_contains_array"),
            contains_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&contains_inputs]), &[contains_tx2], rng);

    // Test that get.dynamic returns the correct value for the array key
    println!("Testing get.dynamic with array key...");
    let get_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap(),
        Value::from_str("12345u64").unwrap(),
    ];
    let get_tx = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "test_get_array"),
            get_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&get_inputs]), &[get_tx], rng);

    // Test that a different array key still returns false
    println!("Testing contains.dynamic with different array key (should be false)...");
    let contains_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("[5u8, 6u8, 7u8, 8u8]").unwrap(), // Different key
        Value::from_str("false").unwrap(),
    ];
    let contains_tx3 = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "test_contains_array"),
            contains_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&contains_inputs]), &[contains_tx3], rng);

    // Remove the array key and verify contains returns false again
    println!("Removing array key...");
    let remove_inputs = vec![Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap()];
    let remove_tx = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "remove_array_mapping"),
            remove_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&remove_inputs]), &[remove_tx], rng);

    // Verify contains returns false after removal
    println!("Testing contains.dynamic after removal (should be false)...");
    let contains_inputs = vec![
        Value::from_str(&program_name_field).unwrap(),
        Value::from_str(&network_field).unwrap(),
        Value::from_str(&mapping_name_field).unwrap(),
        Value::from_str("[1u8, 2u8, 3u8, 4u8]").unwrap(),
        Value::from_str("false").unwrap(),
    ];
    let contains_tx4 = vm
        .execute(
            &caller_private_key,
            ("array_key_mapping.aleo", "test_contains_array"),
            contains_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&contains_inputs]), &[contains_tx4], rng);
}

// This test verifies that `get.dynamic` properly rejects invalid program IDs at finalize time:
// - Uppercase program names are rejected by `ProgramID::try_from`, which enforces lowercase-alphanumeric.
// - Garbage field values (e.g., the field element 1) are rejected by `Identifier::from_field`
//   because the first decoded byte (0x01) is not an ASCII letter.
#[test]
fn test_dynamic_get_rejects_invalid_program_ids() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Initialize a basic program (u32 mapping) and a main program with `test_dynamic_get_u32`.
    let program_0 = basic_program("basic_program0", "data0");
    let main_program = Program::from_str(
        r"program main_program.aleo;

mapping data_main:
    key as u32.public;
    value as u32.public;

function test_dynamic_get_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    async test_dynamic_get_u32 r0 r1 r2 r3 r4 into r5;
    output r5 as main_program.aleo/test_dynamic_get_u32.future;
finalize test_dynamic_get_u32:
    input r0 as field.public;
    input r1 as field.public;
    input r2 as field.public;
    input r3 as u32.public;
    input r4 as u32.public;
    get.dynamic r0 r1 r2[r3] into r5 as u32;
    assert.eq r5 r4;

constructor:
    assert.eq true true;",
    )
    .unwrap();

    // Deploy the programs.
    for program in [&program_0, &main_program] {
        println!("Deploying program: {}", program.id());
        let deployment = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    // Pre-compute field elements for valid network ("aleo") and mapping ("data0") identifiers.
    let valid_network_field =
        Value::from_str(&Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap().to_string())
            .unwrap();
    let valid_mapping_field =
        Value::from_str(&Identifier::<CurrentNetwork>::from_str("data0").unwrap().to_field().unwrap().to_string())
            .unwrap();

    // A helper that attempts `get.dynamic` with the given program-name field and returns `true`
    // if the transaction was accepted (i.e., finalize succeeded).
    let try_get = |program_name_field: Value<CurrentNetwork>, rng: &mut TestRng| -> bool {
        let result = vm.execute(
            &caller_private_key,
            ("main_program.aleo", "test_dynamic_get_u32"),
            vec![
                program_name_field,
                valid_network_field.clone(),
                valid_mapping_field.clone(),
                Value::from_str("42u32").unwrap(),
                Value::from_str("0u32").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        );
        match result {
            Err(e) => {
                // An error at execute time means finalize failed speculatively — expected.
                println!("Expected rejection (execute error): {e}");
                false
            }
            Ok(tx) => {
                vm.check_transaction(&tx, None, rng).unwrap();
                let block = sample_next_block(&vm, &caller_private_key, &[tx], rng).unwrap();
                let accepted = block.transactions().num_accepted() == 1;
                vm.add_next_block(&block).unwrap();
                accepted
            }
        }
    };

    // Test 1: An uppercase program name is rejected by `ProgramID::try_from`, which enforces
    // lowercase-alphanumeric names. "BasicProgram0" is a valid `Identifier` (uppercase is
    // allowed at that level) but is rejected by `ProgramID::try_from` in `get.dynamic`.
    let uppercase_name_field = Value::from_str(
        &Identifier::<CurrentNetwork>::from_str("BasicProgram0").unwrap().to_field().unwrap().to_string(),
    )
    .unwrap();
    assert!(!try_get(uppercase_name_field, rng), "Uppercase program name should be rejected by get.dynamic");

    // Test 2: A garbage field value (field element 1) decodes to bytes [0x01, 0x00, ...].
    // `Identifier::from_field` finds the null terminator at index 1, producing the string "\x01",
    // which fails the `is_ascii_alphabetic()` check in `Identifier::from_str`.
    let garbage_field = Value::from_str("1field").unwrap();
    assert!(!try_get(garbage_field, rng), "Garbage field value should be rejected by get.dynamic");
}
