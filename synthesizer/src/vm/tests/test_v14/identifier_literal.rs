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

use console::program::ProgramID;

/// Verifies that a program using identifier literal syntax cannot be deployed before V14,
/// and can be deployed and executed after V14.
#[cfg(feature = "test")]
#[test]
fn test_identifier_literal_migration() {
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    // Initialize the genesis block.
    let genesis = sample_genesis_block(rng);
    // Update the VM.
    vm.add_next_block(&genesis).unwrap();

    // Fetch the private key.
    let private_key = sample_genesis_private_key(rng);

    // Deploy a test program that uses identifier literal syntax.
    let program_id = ProgramID::<CurrentNetwork>::from_str("identifier_literal_test.aleo").unwrap();
    let program = Program::<CurrentNetwork>::from_str(&format!(
        r"
    program {program_id};
    function foo:
        input r0 as identifier.public;
        is.eq r0 'hello' into r1;
        output r1 as boolean.public;

    constructor:
        assert.eq edition 0u16;",
    ))
    .unwrap();

    // Advance the ledger past ConsensusVersion::V9 where the new deployment version starts.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Construct the deployment transaction.
    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

    // Advance the ledger past ConsensusVersion::V14 where identifier literals become valid.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        // Ensure that the deployment is invalid before V14.
        assert!(vm.check_transaction(&deployment, None, rng).is_err());

        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Ensure that the deployment is valid after ConsensusVersion::V14.
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Deploy the program.
    let next_block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Execute the function with an identifier literal input to verify parsing works correctly.
    let input = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let valid_transaction =
        vm.execute(&private_key, (&program_id.to_string(), "foo"), [input].into_iter(), None, 0, None, rng).unwrap();

    // Construct a block with the execution.
    let next_block = sample_next_block(&vm, &private_key, &[valid_transaction], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Ensure the transaction was accepted.
    assert_eq!(next_block.transactions().num_accepted(), 1);
}

/// Verifies that identifier literals can be used with cast, serialize.bits, and deserialize.bits.
#[test]
fn test_identifier_literal_cast_serialize_deserialize() {
    // Define the program.
    let program = Program::from_str(
        r"
program identifier_ops_test.aleo;

function test_cast:
    input r0 as identifier.public;
    cast r0 into r1 as field;
    cast r1 into r2 as identifier;
    is.eq r0 r2 into r3;
    output r3 as boolean.public;

function test_serialize:
    input r0 as identifier.public;
    serialize.bits r0 (identifier) into r1 ([boolean; 274u32]);
    deserialize.bits r1 ([boolean; 274u32]) into r2 (identifier);
    is.eq r0 r2 into r3;
    output r3 as boolean.public;

function test_serialize_raw:
    input r0 as identifier.public;
    serialize.bits.raw r0 (identifier) into r1 ([boolean; 248u32]);
    deserialize.bits.raw r1 ([boolean; 248u32]) into r2 (identifier);
    is.eq r0 r2 into r3;
    output r3 as boolean.public;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at one block before V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height - 1, rng);

    // Deploy the program before V14 and ensure it is aborted.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block).unwrap();

    // Verify that we are now at V14.
    assert_eq!(vm.block_store().current_block_height(), v14_height);

    // Deploy the program after V14 and ensure it succeeds.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute the cast round-trip function.
    let input = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let cast_tx = vm
        .execute(&caller_private_key, (program.id().to_string(), "test_cast"), [input].into_iter(), None, 0, None, rng)
        .unwrap();

    // Execute the serialize/deserialize round-trip function.
    let input = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let serde_tx = vm
        .execute(
            &caller_private_key,
            (program.id().to_string(), "test_serialize"),
            [input].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Execute the raw serialize/deserialize round-trip function.
    let input = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let serde_raw_tx = vm
        .execute(
            &caller_private_key,
            (program.id().to_string(), "test_serialize_raw"),
            [input].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Construct a block with all executions and ensure they are all accepted.
    let block = sample_next_block(&vm, &caller_private_key, &[cast_tx, serde_tx, serde_raw_tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 3);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

/// Verifies that `call.dynamic` accepts identifier literals as program name, network, and function
/// name operands, allowing programs to hardcode target identities without field arithmetic.
#[cfg(feature = "test")]
#[test]
fn test_call_dynamic_with_identifier_literals() {
    let rng = &mut TestRng::default();

    let private_key = sample_genesis_private_key(rng);
    let address = Address::try_from(&private_key).unwrap();

    // Initialize the VM at V14.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy a caller program that uses identifier literals directly in `call.dynamic`.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program caller_id_lit_call.aleo;

constructor:
    assert.eq true true;

// Calls credits.aleo/transfer_public_as_signer using identifier literals.
function transfer_public_via_literals:
    input r0 as address.public;
    input r1 as u64.public;
    call.dynamic 'credits' 'aleo' 'transfer_public_as_signer' with r0 r1 (as address.public u64.public) into r2 (as dynamic.future);
    async transfer_public_via_literals r2 into r3;
    output r3 as caller_id_lit_call.aleo/transfer_public_via_literals.future;
finalize transfer_public_via_literals:
    input r0 as dynamic.future;
    await r0;

// Calls credits.aleo/transfer_public_as_signer a second time to verify that multiple
// call.dynamic instructions using identifier literals work correctly in the same program.
function transfer_public_via_literals_2:
    input r0 as address.public;
    input r1 as u64.public;
    call.dynamic 'credits' 'aleo' 'transfer_public_as_signer' with r0 r1 (as address.public u64.public) into r2 (as dynamic.future);
    async transfer_public_via_literals_2 r2 into r3;
    output r3 as caller_id_lit_call.aleo/transfer_public_via_literals_2.future;
finalize transfer_public_via_literals_2:
    input r0 as dynamic.future;
    await r0;
",
    )
    .unwrap();

    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute transfer_public_via_literals.
    let tx = vm
        .execute(
            &private_key,
            ("caller_id_lit_call.aleo", "transfer_public_via_literals"),
            [
                Value::<CurrentNetwork>::from_str(&format!("{address}")).unwrap(),
                Value::<CurrentNetwork>::from_str("100u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute transfer_public_via_literals_2.
    let tx = vm
        .execute(
            &private_key,
            ("caller_id_lit_call.aleo", "transfer_public_via_literals_2"),
            [
                Value::<CurrentNetwork>::from_str(&format!("{address}")).unwrap(),
                Value::<CurrentNetwork>::from_str("100u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();
}

/// Verifies that dynamic mapping operations (contains.dynamic, get.dynamic, get.or_use.dynamic)
/// accept identifier literals as program name, network, and mapping name operands.
#[cfg(feature = "test")]
#[test]
fn test_identifier_literal_in_dynamic_mapping_ops() {
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis).unwrap();

    let private_key = sample_genesis_private_key(rng);

    // Advance the VM to V14.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Deploy a target program with a mapping.
    let target_program = Program::<CurrentNetwork>::from_str(
        r"
program target_id_lit.aleo;

mapping balances:
    key as address.public;
    value as u64.public;

constructor:
    assert.eq true true;

function set_balance:
    input r0 as address.public;
    input r1 as u64.public;
    async set_balance r0 r1 into r2;
    output r2 as target_id_lit.aleo/set_balance.future;

finalize set_balance:
    input r0 as address.public;
    input r1 as u64.public;
    set r1 into balances[r0];",
    )
    .unwrap();
    let deployment = vm.deploy(&private_key, &target_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy a caller program that uses identifier literals in dynamic mapping operations.
    let caller_program = Program::<CurrentNetwork>::from_str(
        r"
import target_id_lit.aleo;

program caller_id_lit.aleo;

constructor:
    assert.eq true true;

function check_contains:
    input r0 as address.public;
    async check_contains r0 into r1;
    output r1 as caller_id_lit.aleo/check_contains.future;

finalize check_contains:
    input r0 as address.public;
    contains.dynamic 'target_id_lit' 'aleo' 'balances'[r0] into r1;
    assert.eq r1 false;",
    )
    .unwrap();
    let deployment = vm.deploy(&private_key, &caller_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute the check_contains function.
    let caller_address = Address::try_from(&private_key).unwrap();
    let address = Value::<CurrentNetwork>::from_str(&format!("{caller_address}")).unwrap();
    let tx = vm
        .execute(&private_key, ("caller_id_lit.aleo", "check_contains"), [address].into_iter(), None, 0, None, rng)
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();
}

/// Verifies that `is.eq`, `is.neq`, `assert.eq`, and `assert.neq` work with identifier literals
/// in function scope.
#[test]
fn test_identifier_literal_equality_ops_in_function() {
    let rng = &mut TestRng::default();

    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Define a program exercising all equality/assertion ops on identifier literals.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program id_eq_fn.aleo;

function test_is_eq:
    input r0 as identifier.public;
    input r1 as identifier.public;
    is.eq r0 r1 into r2;
    output r2 as boolean.public;

function test_is_neq:
    input r0 as identifier.public;
    input r1 as identifier.public;
    is.neq r0 r1 into r2;
    output r2 as boolean.public;

function test_assert_eq:
    input r0 as identifier.public;
    input r1 as identifier.public;
    assert.eq r0 r1;

function test_assert_neq:
    input r0 as identifier.public;
    input r1 as identifier.public;
    assert.neq r0 r1;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Deploy the program.
    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    let hello = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let world = Value::<CurrentNetwork>::from_str("'world'").unwrap();
    let program_id = program.id().to_string();

    // is.eq with equal identifiers — should return true.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_eq"),
            [hello.clone(), hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // is.eq with different identifiers — should return false.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_eq"),
            [hello.clone(), world.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // is.neq with different identifiers — should return true.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_neq"),
            [hello.clone(), world.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // is.neq with equal identifiers — should return false.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_neq"),
            [hello.clone(), hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // assert.eq with equal identifiers — should succeed.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_assert_eq"),
            [hello.clone(), hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // assert.eq with different identifiers — execution should fail.
    let result = vm.execute(
        &private_key,
        (&program_id, "test_assert_eq"),
        [hello.clone(), world.clone()].into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(result.is_err(), "assert.eq on different identifiers should fail");

    // assert.neq with different identifiers — should succeed.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_assert_neq"),
            [hello.clone(), world.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // assert.neq with equal identifiers — execution should fail.
    let result = vm.execute(
        &private_key,
        (&program_id, "test_assert_neq"),
        [hello.clone(), hello.clone()].into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(result.is_err(), "assert.neq on equal identifiers should fail");
}

/// Verifies that `cast`, `is.eq`, `is.neq`, `assert.eq`, `assert.neq`, `serialize.bits`,
/// `serialize.bits.raw`, `deserialize.bits`, and `deserialize.bits.raw` work with identifier
/// literals in finalize scope.
#[test]
fn test_identifier_literal_ops_in_finalize() {
    let rng = &mut TestRng::default();

    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Define a program exercising identifier literal ops in finalize blocks.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program id_fin_ops.aleo;

// Cast round-trip in finalize.
function test_cast_finalize:
    input r0 as identifier.public;
    async test_cast_finalize r0 into r1;
    output r1 as id_fin_ops.aleo/test_cast_finalize.future;
finalize test_cast_finalize:
    input r0 as identifier.public;
    cast r0 into r1 as field;
    cast r1 into r2 as identifier;
    assert.eq r0 r2;

// is.eq in finalize.
function test_is_eq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    async test_is_eq_finalize r0 r1 into r2;
    output r2 as id_fin_ops.aleo/test_is_eq_finalize.future;
finalize test_is_eq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    is.eq r0 r1 into r2;
    assert.eq r2 true;

// is.neq in finalize.
function test_is_neq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    async test_is_neq_finalize r0 r1 into r2;
    output r2 as id_fin_ops.aleo/test_is_neq_finalize.future;
finalize test_is_neq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    is.neq r0 r1 into r2;
    assert.eq r2 true;

// assert.eq in finalize.
function test_assert_eq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    async test_assert_eq_finalize r0 r1 into r2;
    output r2 as id_fin_ops.aleo/test_assert_eq_finalize.future;
finalize test_assert_eq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    assert.eq r0 r1;

// assert.neq in finalize.
function test_assert_neq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    async test_assert_neq_finalize r0 r1 into r2;
    output r2 as id_fin_ops.aleo/test_assert_neq_finalize.future;
finalize test_assert_neq_finalize:
    input r0 as identifier.public;
    input r1 as identifier.public;
    assert.neq r0 r1;

// serialize.bits round-trip in finalize.
function test_serialize_finalize:
    input r0 as identifier.public;
    async test_serialize_finalize r0 into r1;
    output r1 as id_fin_ops.aleo/test_serialize_finalize.future;
finalize test_serialize_finalize:
    input r0 as identifier.public;
    serialize.bits r0 (identifier) into r1 ([boolean; 274u32]);
    deserialize.bits r1 ([boolean; 274u32]) into r2 (identifier);
    assert.eq r0 r2;

// serialize.bits.raw round-trip in finalize.
function test_serialize_raw_finalize:
    input r0 as identifier.public;
    async test_serialize_raw_finalize r0 into r1;
    output r1 as id_fin_ops.aleo/test_serialize_raw_finalize.future;
finalize test_serialize_raw_finalize:
    input r0 as identifier.public;
    serialize.bits.raw r0 (identifier) into r1 ([boolean; 248u32]);
    deserialize.bits.raw r1 ([boolean; 248u32]) into r2 (identifier);
    assert.eq r0 r2;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Deploy the program.
    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    let hello = Value::<CurrentNetwork>::from_str("'hello'").unwrap();
    let world = Value::<CurrentNetwork>::from_str("'world'").unwrap();
    let program_id = program.id().to_string();

    // Cast round-trip in finalize.
    let tx = vm
        .execute(&private_key, (&program_id, "test_cast_finalize"), [hello.clone()].into_iter(), None, 0, None, rng)
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // is.eq in finalize with equal identifiers.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_eq_finalize"),
            [hello.clone(), hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // is.neq in finalize with different identifiers.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_is_neq_finalize"),
            [hello.clone(), world.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // assert.eq in finalize with equal identifiers.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_assert_eq_finalize"),
            [hello.clone(), hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // assert.neq in finalize with different identifiers.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_assert_neq_finalize"),
            [hello.clone(), world.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // serialize.bits round-trip in finalize.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_serialize_finalize"),
            [hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // serialize.bits.raw round-trip in finalize.
    let tx = vm
        .execute(
            &private_key,
            (&program_id, "test_serialize_raw_finalize"),
            [hello.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();
}

/// Verifies that ternary operations on identifier literals are rejected in function scope.
/// Ternary is not defined for the Identifier type, so deployment should fail.
#[test]
fn test_identifier_literal_ternary_rejected_in_function() {
    let rng = &mut TestRng::default();

    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Define a program that uses ternary on identifier literals in a function.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program ternary_id_fn.aleo;

function test_ternary:
    input r0 as boolean.public;
    input r1 as identifier.public;
    input r2 as identifier.public;
    ternary r0 r1 r2 into r3;
    output r3 as identifier.public;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Attempt to deploy — should fail because ternary does not support Identifier.
    let result = vm.deploy(&private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "ternary on identifier should be rejected in function scope");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("ternary"), "error should mention the ternary instruction, got: {err}");
}

/// Verifies that ternary operations on identifier literals are rejected in finalize scope.
/// Ternary is not defined for the Identifier type, so deployment should fail.
#[test]
fn test_identifier_literal_ternary_rejected_in_finalize() {
    let rng = &mut TestRng::default();

    let private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Define a program that uses ternary on identifier literals in a finalize block.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program ternary_id_fin.aleo;

function test_ternary:
    input r0 as boolean.public;
    input r1 as identifier.public;
    input r2 as identifier.public;
    async test_ternary r0 r1 r2 into r3;
    output r3 as ternary_id_fin.aleo/test_ternary.future;

finalize test_ternary:
    input r0 as boolean.public;
    input r1 as identifier.public;
    input r2 as identifier.public;
    ternary r0 r1 r2 into r3;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Attempt to deploy — should fail because ternary does not support Identifier.
    let result = vm.deploy(&private_key, &program, None, 0, None, rng);
    assert!(result.is_err(), "ternary on identifier should be rejected in finalize scope");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("ternary"), "error should mention the ternary instruction, got: {err}");
}

/// Verifies that `get.dynamic` and `get.or_use.dynamic` accept identifier literals as program
/// name, network, and mapping name operands.
#[cfg(feature = "test")]
#[test]
fn test_get_and_get_or_use_dynamic_with_identifier_literals() {
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis).unwrap();

    let private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&private_key).unwrap();

    // Advance the VM to V14.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Deploy the target program with a mapping.
    let target_program = Program::<CurrentNetwork>::from_str(
        r"
program target_get_lit.aleo;

mapping scores:
    key as address.public;
    value as u64.public;

constructor:
    assert.eq true true;

function set_score:
    input r0 as address.public;
    input r1 as u64.public;
    async set_score r0 r1 into r2;
    output r2 as target_get_lit.aleo/set_score.future;

finalize set_score:
    input r0 as address.public;
    input r1 as u64.public;
    set r1 into scores[r0];",
    )
    .unwrap();
    let deployment = vm.deploy(&private_key, &target_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Deploy the caller program exercising get.or_use.dynamic and get.dynamic with identifier literals.
    let caller_program = Program::<CurrentNetwork>::from_str(
        r"
import target_get_lit.aleo;

program caller_get_lit.aleo;

constructor:
    assert.eq true true;

// get.or_use.dynamic with a default — key not yet in mapping, should return the default.
function get_or_use_default:
    input r0 as address.public;
    input r1 as u64.public;
    async get_or_use_default r0 r1 into r2;
    output r2 as caller_get_lit.aleo/get_or_use_default.future;
finalize get_or_use_default:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use.dynamic 'target_get_lit' 'aleo' 'scores'[r0] r1 into r2 as u64;
    assert.eq r2 r1;

// get.dynamic — key present in mapping, returns the stored value.
function get_score:
    input r0 as address.public;
    input r1 as u64.public;
    async get_score r0 r1 into r2;
    output r2 as caller_get_lit.aleo/get_score.future;
finalize get_score:
    input r0 as address.public;
    input r1 as u64.public;
    get.dynamic 'target_get_lit' 'aleo' 'scores'[r0] into r2 as u64;
    assert.eq r2 r1;

// get.or_use.dynamic — key present, should return actual value not the default.
function get_or_use_with_value:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    async get_or_use_with_value r0 r1 r2 into r3;
    output r3 as caller_get_lit.aleo/get_or_use_with_value.future;
finalize get_or_use_with_value:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    get.or_use.dynamic 'target_get_lit' 'aleo' 'scores'[r0] r2 into r3 as u64;
    assert.eq r3 r1;",
    )
    .unwrap();
    let deployment = vm.deploy(&private_key, &caller_program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    let address_val = Value::<CurrentNetwork>::from_str(&format!("{caller_address}")).unwrap();

    let default_val = Value::<CurrentNetwork>::from_str("999u64").unwrap();
    let score_val = Value::<CurrentNetwork>::from_str("42u64").unwrap();

    // get.or_use.dynamic before the key exists — should return default 999u64.
    let tx = vm
        .execute(
            &private_key,
            ("caller_get_lit.aleo", "get_or_use_default"),
            [address_val.clone(), default_val.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Set the score to 42 in the target mapping.
    let tx = vm
        .execute(
            &private_key,
            ("target_get_lit.aleo", "set_score"),
            [address_val.clone(), score_val.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // get.dynamic — key now present, should return 42u64.
    let tx = vm
        .execute(
            &private_key,
            ("caller_get_lit.aleo", "get_score"),
            [address_val.clone(), score_val.clone()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // get.or_use.dynamic — key present, should return 42u64 (not 999u64).
    let tx = vm
        .execute(
            &private_key,
            ("caller_get_lit.aleo", "get_or_use_with_value"),
            [address_val, score_val, default_val].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &private_key, &[tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();
}
