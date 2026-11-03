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
use snarkvm_synthesizer_program::Program;

use console::network::ConsensusVersion;
use snarkvm_utilities::TestRng;

// This test verifies that:
//  - a dependency cycle can be created between two programs that use records in their calls.
//  - a program with a call cycle cannot be deployed.
//  - a program that changes an output record index cannot be deployed.
//  - a program that returns a local record as an external record cannot be deployed.
//  - a record cannot be consumed twice in the same program.
//  - a local record cannot be created and consumed in the same program.
#[test]
#[ignore]
fn test_upgrade_cycle_with_records() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

    // Initialize the VM at the V10 height.
    let v10_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V10).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v10_height, rng);

    // Define the first program with a record.
    let program_one = Program::from_str(
        r"
program test_one.aleo;

record First:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function mint:
    input r0 as field.private;
    cast self.caller r0 into r1 as First.record;
    output r1 as First.record;

function first:
    input r0 as First.record;
    cast r0.owner r0.data into r1 as First.record;
    output r1 as First.record;
",
    )
    .unwrap();

    // Define the second program with a record that calls the first program.
    let program_two = Program::from_str(
        r"
import test_one.aleo;

program test_two.aleo;

record Second:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function second:
    input r0 as test_one.aleo/First.record;
    call test_one.aleo/first r0 into r1;
    cast r0.owner r0.data into r2 as Second.record;
    output r2 as Second.record;

function cannot_be_called_from_test_one:
    input r0 as test_one.aleo/First.record;
    call test_one.aleo/first r0 into r1;
    output r1 as test_one.aleo/First.record;
    ",
    )
    .unwrap();

    // Define an invalid program that creates a cycle.
    let program_cycle = Program::from_str(
        r"
import test_two.aleo;

program test_one.aleo;

record First:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function mint:
    input r0 as field.private;
    cast self.caller r0 into r1 as First.record;
    output r1 as First.record;

function first:
    input r0 as First.record;
    cast r0.owner r0.data into r1 as First.record;
    cast r0.owner r0.data into r2 as First.record;
    call test_two.aleo/second r2 into r3;
    output r1 as First.record;
    ",
    )
    .unwrap();

    // Define a program that has a local record that is returned as an external record.
    let program_invalid_local_record = Program::from_str(
        r"
import test_two.aleo;

program test_one.aleo;

record First:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function mint:
    input r0 as field.private;
    cast self.caller r0 into r1 as First.record;
    output r1 as First.record;

function first:
    input r0 as First.record;
    cast r0.owner r0.data into r1 as First.record;
    output r1 as First.record;

function third:
    input r0 as First.record;
    call test_two.aleo/cannot_be_called_from_test_one r0 into r1;
    ",
    )
    .unwrap();

    // Define a new version of the first program.
    let program_chain = Program::from_str(
        r"
import test_two.aleo;

program test_one.aleo;

record First:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function mint:
    input r0 as field.private;
    cast self.caller r0 into r1 as First.record;
    output r1 as First.record;

function first:
    input r0 as First.record;
    cast r0.owner r0.data into r1 as First.record;
    output r1 as First.record;

function third:
    input r0 as First.record;
    call test_two.aleo/second r0 into r1;
    output r1 as test_two.aleo/Second.record;

function fourth:
    input r0 as First.record;
    cast r0.owner r0.data into r1 as First.record;
    call test_two.aleo/second r1 into r2;
    output r2 as test_two.aleo/Second.record;
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

    // Execute the first program to mint four records.
    let transactions = (0..4)
        .map(|i| {
            vm.execute(
                &caller_private_key,
                ("test_one.aleo", "mint"),
                vec![Value::from_str(&format!("{i}field"))].into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 4);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Get the records from the transactions.
    let records = block
        .transactions()
        .records()
        .map(|(cm, r)| r.clone().decrypt(&caller_view_key).map(|r| (*cm, r)))
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(records.len(), 4, "Expected four records to be minted.");
    let mut records = records.into_iter();

    // Execute the `first` function to verify that the program works correctly.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test_one.aleo", "first"),
            vec![Value::Record(records.next().unwrap().1)].into_iter(),
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

    // Deploy the second program.
    let deployment_two = vm.deploy(&caller_private_key, &program_two, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_two], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Attempt to deploy the program that creates a cycle.
    let deployment_cycle = vm.deploy(&caller_private_key, &program_cycle, None, 0, None, rng);
    assert!(deployment_cycle.is_err(), "Expected an error when deploying a program with a cycle.");

    // Attempt to deploy the program that returns a local record as an external record.
    let deployment = vm.deploy(&caller_private_key, &program_invalid_local_record, None, 0, None, rng);
    match deployment {
        Ok(_) => {
            panic!("Expected an error when deploying a program that returns a local record as an external record.")
        }
        Err(e) => println!("The expected deployment error is: {e}"),
    }

    // Deploy the program that creates a chain.
    let deployment_chain = vm.deploy(&caller_private_key, &program_chain, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_chain], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Execute the `third` function which should fail due to double ownership.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test_one.aleo", "third"),
            vec![Value::Record(records.next().unwrap().1)].into_iter(),
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

    // Execute the `fourth` function which should fail because the local record is created and consumed in the same program.
    let (cm, record) = records.next().unwrap();
    println!("Commitment: {cm}");
    let execution = vm.execute(
        &caller_private_key,
        ("test_one.aleo", "fourth"),
        vec![Value::Record(record)].into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(execution.is_err());
    match execution {
        Ok(_) => {
            panic!("Expected an error when deploying a program that returns a local record as an external record.")
        }
        Err(e) => println!("The expected execution error is: {e}"),
    }

    // Test an invalid upgrade where the output record index of `second` is changed.
    let upgraded_program_two = Program::from_str(
        r"
import test_one.aleo;

program test_two.aleo;

record Second:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function second:
    input r0 as test_one.aleo/First.record;
    cast r0.owner r0.data into r1 as Second.record;
    output r1 as Second.record;

function cannot_be_called_from_test_one:
    input r0 as test_one.aleo/First.record;
    call test_one.aleo/first r0 into r1;
    output r1 as test_one.aleo/First.record;
    ",
    )
    .unwrap();

    // Attempt to deploy the upgraded program.
    // This should fail because the output record index of `second` has changed.
    let deployment_upgraded_two = vm.deploy(&caller_private_key, &upgraded_program_two, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_upgraded_two], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Upgrade `test_two` so that `second` does not call `test_one` anymore.
    let upgraded_program_two = Program::from_str(
        r"
import test_one.aleo;

program test_two.aleo;

record Second:
    owner as address.private;
    data as field.private;

constructor:
    assert.eq true true;

function second:
    input r0 as test_one.aleo/First.record;
    add 0u8 0u8 into r1;
    cast r0.owner r0.data into r2 as Second.record;
    output r2 as Second.record;

function cannot_be_called_from_test_one:
    input r0 as test_one.aleo/First.record;
    call test_one.aleo/first r0 into r1;
    output r1 as test_one.aleo/First.record;
    ",
    )
    .unwrap();

    // Deploy the upgraded program.
    let deployment_upgraded_two = vm.deploy(&caller_private_key, &upgraded_program_two, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment_upgraded_two], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    println!("Calling final execution...");

    // Call `test_one.aleo/third` again, which should now succeed.
    let execution = vm
        .execute(
            &caller_private_key,
            ("test_one.aleo", "third"),
            vec![Value::Record(records.next().unwrap().1)].into_iter(),
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
