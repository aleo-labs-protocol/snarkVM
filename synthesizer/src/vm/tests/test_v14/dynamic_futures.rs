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

// Tests that awaiting `DynamicFuture` instances in the same order they were created works correctly.
#[test]
fn test_await_in_order() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Program with two dynamic calls, awaited in creation order
    let counter_program = Program::<CurrentNetwork>::from_str(
        r"
        program counter.aleo;

        mapping counts:
            key as address.public;
            value as u64.public;

        function increment:
            input r0 as u64.public;
            async increment self.signer r0 into r1;
            output r1 as counter.aleo/increment.future;

        finalize increment:
            input r0 as address.public;
            input r1 as u64.public;
            get.or_use counts[r0] 0u64 into r2;
            add r2 r1 into r3;
            set r3 into counts[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let counter_program_field = Identifier::<CurrentNetwork>::from_str("counter").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let increment_field = Identifier::<CurrentNetwork>::from_str("increment").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program await_order_caller.aleo;

        function call_twice_await_in_order:
            input r0 as u64.public;
            input r1 as u64.public;
            call.dynamic {counter_program_field} {aleo_field} {increment_field} with r0 (as u64.public) into r2 (as dynamic.future);
            call.dynamic {counter_program_field} {aleo_field} {increment_field} with r1 (as u64.public) into r3 (as dynamic.future);
            async call_twice_await_in_order r2 r3 into r4;
            output r4 as await_order_caller.aleo/call_twice_await_in_order.future;

        finalize call_twice_await_in_order:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            await r0;
            await r1;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    // Initialize the VM
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy programs
    let deploy_counter = vm.deploy(&caller_private_key, &counter_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_counter], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execute: increment by 5, then by 3
    let inputs = vec![Value::from_str("5u64").unwrap(), Value::from_str("3u64").unwrap()];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("await_order_caller.aleo", "call_twice_await_in_order"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify the final count is 8 (5 + 3)
    let count = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("counter.aleo").unwrap(),
            Identifier::from_str("counts").unwrap(),
            &Plaintext::from_str(&caller_address.to_string()).unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(count, Value::from_str("8u64").unwrap());
}

// Tests that awaiting `DynamicFuture` instances in reverse order works correctly.
#[test]
fn test_await_reverse_order() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program that tracks order of execution via a mapping
    let tracker_program = Program::<CurrentNetwork>::from_str(
        r"
        program tracker.aleo;

        mapping order:
            key as u8.public;
            value as u64.public;

        function record_value:
            input r0 as u8.public;
            input r1 as u64.public;
            async record_value r0 r1 into r2;
            output r2 as tracker.aleo/record_value.future;

        finalize record_value:
            input r0 as u8.public;
            input r1 as u64.public;
            set r1 into order[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let tracker_program_field = Identifier::<CurrentNetwork>::from_str("tracker").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let record_value_field = Identifier::<CurrentNetwork>::from_str("record_value").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program reverse_order_caller.aleo;

        function call_twice_await_reverse:
            call.dynamic {tracker_program_field} {aleo_field} {record_value_field} with 1u8 100u64 (as u8.public u64.public) into r0 (as dynamic.future);
            call.dynamic {tracker_program_field} {aleo_field} {record_value_field} with 2u8 200u64 (as u8.public u64.public) into r1 (as dynamic.future);
            async call_twice_await_reverse r0 r1 into r2;
            output r2 as reverse_order_caller.aleo/call_twice_await_reverse.future;

        finalize call_twice_await_reverse:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            await r1;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_tracker = vm.deploy(&caller_private_key, &tracker_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tracker], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    let transaction = vm
        .execute(
            &caller_private_key,
            ("reverse_order_caller.aleo", "call_twice_await_reverse"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);

    // Verify both values were set correctly
    let value1 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("tracker.aleo").unwrap(),
            Identifier::from_str("order").unwrap(),
            &Plaintext::from_str("1u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let value2 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("tracker.aleo").unwrap(),
            Identifier::from_str("order").unwrap(),
            &Plaintext::from_str("2u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(value1, Value::from_str("100u64").unwrap());
    assert_eq!(value2, Value::from_str("200u64").unwrap());
}

// Tests nested `call.dynamic` where A -> B -> C, each with finalize that modifies state.
#[test]
fn test_nested_dynamic_futures() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Leaf program (C) - just sets a value
    let leaf_program = Program::<CurrentNetwork>::from_str(
        r"
        program leaf_c.aleo;

        mapping leaf_data:
            key as u8.public;
            value as u64.public;

        function leaf_op:
            input r0 as u64.public;
            async leaf_op r0 into r1;
            output r1 as leaf_c.aleo/leaf_op.future;

        finalize leaf_op:
            input r0 as u64.public;
            set r0 into leaf_data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let leaf_program_field = Identifier::<CurrentNetwork>::from_str("leaf_c").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let leaf_op_field = Identifier::<CurrentNetwork>::from_str("leaf_op").unwrap().to_field().unwrap();

    // Middle program (B) - calls leaf and has its own finalize
    let middle_program_str = format!(
        r"
        program middle_b.aleo;

        mapping middle_data:
            key as u8.public;
            value as u64.public;

        function middle_op:
            input r0 as u64.public;
            call.dynamic {leaf_program_field} {aleo_field} {leaf_op_field} with r0 (as u64.public) into r1 (as dynamic.future);
            add r0 10u64 into r2;
            async middle_op r1 r2 into r3;
            output r3 as middle_b.aleo/middle_op.future;

        finalize middle_op:
            input r0 as dynamic.future;
            input r1 as u64.public;
            await r0;
            set r1 into middle_data[0u8];

        constructor:
            assert.eq true true;
        "
    );

    let middle_program = Program::<CurrentNetwork>::from_str(&middle_program_str).unwrap();

    let middle_program_field = Identifier::<CurrentNetwork>::from_str("middle_b").unwrap().to_field().unwrap();
    let middle_op_field = Identifier::<CurrentNetwork>::from_str("middle_op").unwrap().to_field().unwrap();

    // Root program (A) - calls middle and has its own finalize
    let root_program_str = format!(
        r"
        program root_a.aleo;

        mapping root_data:
            key as u8.public;
            value as u64.public;

        function root_op:
            input r0 as u64.public;
            call.dynamic {middle_program_field} {aleo_field} {middle_op_field} with r0 (as u64.public) into r1 (as dynamic.future);
            add r0 100u64 into r2;
            async root_op r1 r2 into r3;
            output r3 as root_a.aleo/root_op.future;

        finalize root_op:
            input r0 as dynamic.future;
            input r1 as u64.public;
            await r0;
            set r1 into root_data[0u8];

        constructor:
            assert.eq true true;
        "
    );

    let root_program = Program::<CurrentNetwork>::from_str(&root_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy in dependency order
    let deploy_leaf = vm.deploy(&caller_private_key, &leaf_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_leaf], rng);

    let deploy_middle = vm.deploy(&caller_private_key, &middle_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_middle], rng);

    let deploy_root = vm.deploy(&caller_private_key, &root_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_root], rng);

    // Execute with value 5
    // Expected: leaf_data[0] = 5, middle_data[0] = 15, root_data[0] = 105
    let inputs = vec![Value::from_str("5u64").unwrap()];
    let transaction =
        vm.execute(&caller_private_key, ("root_a.aleo", "root_op"), inputs.iter(), None, 0, None, rng).unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify all three mappings were updated correctly
    let leaf_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("leaf_c.aleo").unwrap(),
            Identifier::from_str("leaf_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let middle_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("middle_b.aleo").unwrap(),
            Identifier::from_str("middle_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let root_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("root_a.aleo").unwrap(),
            Identifier::from_str("root_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(leaf_value, Value::from_str("5u64").unwrap());
    assert_eq!(middle_value, Value::from_str("15u64").unwrap());
    assert_eq!(root_value, Value::from_str("105u64").unwrap());
}

// Tests that when a `DynamicFuture`'s finalize fails, the transaction is properly rejected.
#[test]
fn test_dynamic_future_finalize_failure() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program with a finalize that can fail
    let failing_program = Program::<CurrentNetwork>::from_str(
        r"
        program failing_finalize.aleo;

        mapping data:
            key as u8.public;
            value as u64.public;

        function will_fail:
            input r0 as boolean.public;
            async will_fail r0 into r1;
            output r1 as failing_finalize.aleo/will_fail.future;

        finalize will_fail:
            input r0 as boolean.public;
            assert.eq r0 true;
            set 1u64 into data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let failing_program_field = Identifier::<CurrentNetwork>::from_str("failing_finalize").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let will_fail_field = Identifier::<CurrentNetwork>::from_str("will_fail").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program failure_caller.aleo;

        function call_failing:
            input r0 as boolean.public;
            call.dynamic {failing_program_field} {aleo_field} {will_fail_field} with r0 (as boolean.public) into r1 (as dynamic.future);
            async call_failing r1 into r2;
            output r2 as failure_caller.aleo/call_failing.future;

        finalize call_failing:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_failing = vm.deploy(&caller_private_key, &failing_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_failing], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // First, test with true (should succeed)
    let inputs = vec![Value::from_str("true").unwrap()];
    let transaction_success = vm
        .execute(&caller_private_key, ("failure_caller.aleo", "call_failing"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction_success], rng);

    // Now test with false (should fail in finalize)
    let transaction_fail = vm
        .execute(
            &caller_private_key,
            ("failure_caller.aleo", "call_failing"),
            vec![Value::from_str("false").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, std::slice::from_ref(&transaction_fail), rng).unwrap();

    // The transaction should be rejected due to finalize failure
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 1);
}

// Tests calling the same `call.dynamic` function multiple times and awaiting all `DynamicFuture` instances.
#[test]
fn test_multiple_futures_same_function() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let accumulator_program = Program::<CurrentNetwork>::from_str(
        r"
        program accumulator.aleo;

        mapping total:
            key as u8.public;
            value as u64.public;

        function add_value:
            input r0 as u64.public;
            async add_value r0 into r1;
            output r1 as accumulator.aleo/add_value.future;

        finalize add_value:
            input r0 as u64.public;
            get.or_use total[0u8] 0u64 into r1;
            add r1 r0 into r2;
            set r2 into total[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let accumulator_field = Identifier::<CurrentNetwork>::from_str("accumulator").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let add_value_field = Identifier::<CurrentNetwork>::from_str("add_value").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program multi_future_caller.aleo;

        function call_three_times:
            input r0 as u64.public;
            input r1 as u64.public;
            input r2 as u64.public;
            call.dynamic {accumulator_field} {aleo_field} {add_value_field} with r0 (as u64.public) into r3 (as dynamic.future);
            call.dynamic {accumulator_field} {aleo_field} {add_value_field} with r1 (as u64.public) into r4 (as dynamic.future);
            call.dynamic {accumulator_field} {aleo_field} {add_value_field} with r2 (as u64.public) into r5 (as dynamic.future);
            async call_three_times r3 r4 r5 into r6;
            output r6 as multi_future_caller.aleo/call_three_times.future;

        finalize call_three_times:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            input r2 as dynamic.future;
            await r0;
            await r1;
            await r2;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_acc = vm.deploy(&caller_private_key, &accumulator_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_acc], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Call with 10, 20, 30 - expect total of 60
    let inputs =
        vec![Value::from_str("10u64").unwrap(), Value::from_str("20u64").unwrap(), Value::from_str("30u64").unwrap()];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("multi_future_caller.aleo", "call_three_times"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    let total = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("accumulator.aleo").unwrap(),
            Identifier::from_str("total").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(total, Value::from_str("60u64").unwrap());
}

// Tests reading state modified by a `DynamicFuture`'s finalize using `get.dynamic` after await.
#[test]
fn test_read_state_after_dynamic_await() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let writer_program = Program::<CurrentNetwork>::from_str(
        r"
        program state_writer.aleo;

        mapping values:
            key as u8.public;
            value as u64.public;

        function write_value:
            input r0 as u8.public;
            input r1 as u64.public;
            async write_value r0 r1 into r2;
            output r2 as state_writer.aleo/write_value.future;

        finalize write_value:
            input r0 as u8.public;
            input r1 as u64.public;
            set r1 into values[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let writer_field = Identifier::<CurrentNetwork>::from_str("state_writer").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let write_value_field = Identifier::<CurrentNetwork>::from_str("write_value").unwrap().to_field().unwrap();
    let values_field = Identifier::<CurrentNetwork>::from_str("values").unwrap().to_field().unwrap();

    // Caller that writes a value then reads it back using get.dynamic
    // The field values are passed through async inputs and used as registers in finalize
    let caller_program_str = format!(
        r"
        program state_reader_caller.aleo;

        mapping read_results:
            key as u8.public;
            value as u64.public;

        function write_then_read:
            input r0 as u64.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as field.public;
            call.dynamic {writer_field} {aleo_field} {write_value_field} with 1u8 r0 (as u8.public u64.public) into r4 (as dynamic.future);
            async write_then_read r4 r1 r2 r3 into r5;
            output r5 as state_reader_caller.aleo/write_then_read.future;

        finalize write_then_read:
            input r0 as dynamic.future;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as field.public;
            await r0;
            get.dynamic r1 r2 r3[1u8] into r4 as u64;
            set r4 into read_results[0u8];

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_writer = vm.deploy(&caller_private_key, &writer_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_writer], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Write 42, then read it back
    // Pass the field values for program, network, and mapping names using proper formatting
    let inputs = vec![
        Value::from_str("42u64").unwrap(),
        Value::from_str(&writer_field.to_string()).unwrap(),
        Value::from_str(&aleo_field.to_string()).unwrap(),
        Value::from_str(&values_field.to_string()).unwrap(),
    ];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("state_reader_caller.aleo", "write_then_read"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify the read value was stored
    let read_result = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("state_reader_caller.aleo").unwrap(),
            Identifier::from_str("read_results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(read_result, Value::from_str("42u64").unwrap());
}

// Tests a `call.dynamic` that returns both a `dynamic.record` and a `DynamicFuture`.
#[test]
fn test_dynamic_future_with_dynamic_record() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let token_program = Program::<CurrentNetwork>::from_str(
        r"
        program dyn_token.aleo;

        record token:
            owner as address.private;
            amount as u64.public;

        mapping supply:
            key as u8.public;
            value as u64.public;

        function mint:
            input r0 as address.private;
            input r1 as u64.public;
            cast r0 r1 into r2 as token.record;
            async mint r1 into r3;
            output r2 as token.record;
            output r3 as dyn_token.aleo/mint.future;

        finalize mint:
            input r0 as u64.public;
            get.or_use supply[0u8] 0u64 into r1;
            add r1 r0 into r2;
            set r2 into supply[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let token_field = Identifier::<CurrentNetwork>::from_str("dyn_token").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let mint_field = Identifier::<CurrentNetwork>::from_str("mint").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program record_future_caller.aleo;

        function mint_and_track:
            input r0 as u64.public;
            call.dynamic {token_field} {aleo_field} {mint_field} with self.signer r0 (as address.private u64.public) into r1 r2 (as dynamic.record dynamic.future);
            async mint_and_track r2 into r3;
            output r1 as dynamic.record;
            output r3 as record_future_caller.aleo/mint_and_track.future;

        finalize mint_and_track:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_token = vm.deploy(&caller_private_key, &token_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_token], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Mint 100 tokens
    let inputs = vec![Value::from_str("100u64").unwrap()];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("record_future_caller.aleo", "mint_and_track"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Verify there's a record output
    let root_transition = transaction.transitions().nth(1).unwrap(); // Skip the mint transition
    let has_record = root_transition.outputs().iter().any(|o| matches!(o, Output::Record(..)));
    assert!(has_record || root_transition.outputs().iter().any(|o| matches!(o, Output::DynamicRecord(..))));

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify supply was updated
    let supply = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("dyn_token.aleo").unwrap(),
            Identifier::from_str("supply").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(supply, Value::from_str("100u64").unwrap());
}

// Tests awaiting `DynamicFuture` instances from different programs in an interleaved order.
#[test]
fn test_interleaved_awaits_different_programs() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // First program
    let program_alpha = Program::<CurrentNetwork>::from_str(
        r"
        program alpha.aleo;

        mapping alpha_data:
            key as u8.public;
            value as u64.public;

        function alpha_op:
            input r0 as u64.public;
            async alpha_op r0 into r1;
            output r1 as alpha.aleo/alpha_op.future;

        finalize alpha_op:
            input r0 as u64.public;
            set r0 into alpha_data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Second program
    let program_beta = Program::<CurrentNetwork>::from_str(
        r"
        program beta.aleo;

        mapping beta_data:
            key as u8.public;
            value as u64.public;

        function beta_op:
            input r0 as u64.public;
            async beta_op r0 into r1;
            output r1 as beta.aleo/beta_op.future;

        finalize beta_op:
            input r0 as u64.public;
            set r0 into beta_data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let alpha_field = Identifier::<CurrentNetwork>::from_str("alpha").unwrap().to_field().unwrap();
    let beta_field = Identifier::<CurrentNetwork>::from_str("beta").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let alpha_op_field = Identifier::<CurrentNetwork>::from_str("alpha_op").unwrap().to_field().unwrap();
    let beta_op_field = Identifier::<CurrentNetwork>::from_str("beta_op").unwrap().to_field().unwrap();

    // Caller that interleaves calls and awaits
    let caller_program_str = format!(
        r"
        program interleave_caller.aleo;

        function interleaved_calls:
            call.dynamic {alpha_field} {aleo_field} {alpha_op_field} with 1u64 (as u64.public) into r0 (as dynamic.future);
            call.dynamic {beta_field} {aleo_field} {beta_op_field} with 2u64 (as u64.public) into r1 (as dynamic.future);
            call.dynamic {alpha_field} {aleo_field} {alpha_op_field} with 3u64 (as u64.public) into r2 (as dynamic.future);
            call.dynamic {beta_field} {aleo_field} {beta_op_field} with 4u64 (as u64.public) into r3 (as dynamic.future);
            async interleaved_calls r0 r1 r2 r3 into r4;
            output r4 as interleave_caller.aleo/interleaved_calls.future;

        finalize interleaved_calls:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            input r2 as dynamic.future;
            input r3 as dynamic.future;
            await r1;
            await r0;
            await r3;
            await r2;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_alpha = vm.deploy(&caller_private_key, &program_alpha, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_alpha], rng);

    let deploy_beta = vm.deploy(&caller_private_key, &program_beta, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_beta], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    let transaction = vm
        .execute(
            &caller_private_key,
            ("interleave_caller.aleo", "interleaved_calls"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);

    // Verify both programs received the last value written to them
    // Alpha: 1 then 3, so final value should be 3
    // Beta: 2 then 4, so final value should be 4
    let alpha_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("alpha.aleo").unwrap(),
            Identifier::from_str("alpha_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let beta_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("beta.aleo").unwrap(),
            Identifier::from_str("beta_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(alpha_value, Value::from_str("3u64").unwrap());
    assert_eq!(beta_value, Value::from_str("4u64").unwrap());
}

// Tests a `DynamicFuture` with complex finalize logic including multiple mapping operations and conditionals.
#[test]
fn test_dynamic_future_complex_finalize() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let complex_program = Program::<CurrentNetwork>::from_str(
        r"
        program complex_finalize.aleo;

        mapping balances:
            key as address.public;
            value as u64.public;

        mapping transaction_count:
            key as address.public;
            value as u64.public;

        function transfer:
            input r0 as address.public;
            input r1 as u64.public;
            async transfer self.signer r0 r1 into r2;
            output r2 as complex_finalize.aleo/transfer.future;

        finalize transfer:
            input r0 as address.public;
            input r1 as address.public;
            input r2 as u64.public;
            get.or_use balances[r0] 1000u64 into r3;
            gte r3 r2 into r4;
            assert.eq r4 true;
            sub r3 r2 into r5;
            set r5 into balances[r0];
            get.or_use balances[r1] 0u64 into r6;
            add r6 r2 into r7;
            set r7 into balances[r1];
            get.or_use transaction_count[r0] 0u64 into r8;
            add r8 1u64 into r9;
            set r9 into transaction_count[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let complex_field = Identifier::<CurrentNetwork>::from_str("complex_finalize").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let transfer_field = Identifier::<CurrentNetwork>::from_str("transfer").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program complex_caller.aleo;

        function do_transfer:
            input r0 as address.public;
            input r1 as u64.public;
            call.dynamic {complex_field} {aleo_field} {transfer_field} with r0 r1 (as address.public u64.public) into r2 (as dynamic.future);
            async do_transfer r2 into r3;
            output r3 as complex_caller.aleo/do_transfer.future;

        finalize do_transfer:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_complex = vm.deploy(&caller_private_key, &complex_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_complex], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    let recipient = Address::try_from(&PrivateKey::<CurrentNetwork>::new(rng).unwrap()).unwrap();

    // Transfer 100 to recipient
    let inputs = vec![Value::from_str(&recipient.to_string()).unwrap(), Value::from_str("100u64").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("complex_caller.aleo", "do_transfer"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify balances

    let sender_balance = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("complex_finalize.aleo").unwrap(),
            Identifier::from_str("balances").unwrap(),
            &Plaintext::from_str(&caller_address.to_string()).unwrap(),
        )
        .unwrap()
        .unwrap();

    let recipient_balance = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("complex_finalize.aleo").unwrap(),
            Identifier::from_str("balances").unwrap(),
            &Plaintext::from_str(&recipient.to_string()).unwrap(),
        )
        .unwrap()
        .unwrap();

    let tx_count = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("complex_finalize.aleo").unwrap(),
            Identifier::from_str("transaction_count").unwrap(),
            &Plaintext::from_str(&caller_address.to_string()).unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(sender_balance, Value::from_str("900u64").unwrap());
    assert_eq!(recipient_balance, Value::from_str("100u64").unwrap());
    assert_eq!(tx_count, Value::from_str("1u64").unwrap());
}

// Tests conditional future behavior by selecting `call.dynamic` targets based on conditions and awaiting both futures.
#[test]
fn test_conditional_future_via_branch() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program with two different functions that write different values
    let worker_program = Program::<CurrentNetwork>::from_str(
        r"
        program conditional_worker.aleo;

        mapping results:
            key as u8.public;
            value as u64.public;

        function write_value:
            input r0 as u64.public;
            async write_value r0 into r1;
            output r1 as conditional_worker.aleo/write_value.future;

        finalize write_value:
            input r0 as u64.public;
            set r0 into results[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_field = Identifier::<CurrentNetwork>::from_str("conditional_worker").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let write_value_field = Identifier::<CurrentNetwork>::from_str("write_value").unwrap().to_field().unwrap();

    // Caller that uses ternary on the value to write, not on the future itself
    let caller_program_str = format!(
        r"
        program conditional_caller.aleo;

        function conditional_write:
            input r0 as boolean.public;
            ternary r0 100u64 200u64 into r1;
            call.dynamic {worker_field} {aleo_field} {write_value_field} with r1 (as u64.public) into r2 (as dynamic.future);
            async conditional_write r2 into r3;
            output r3 as conditional_caller.aleo/conditional_write.future;

        finalize conditional_write:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_worker = vm.deploy(&caller_private_key, &worker_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_worker], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Call with true - should write 100
    let inputs_true = vec![Value::from_str("true").unwrap()];
    let transaction_true = vm
        .execute(
            &caller_private_key,
            ("conditional_caller.aleo", "conditional_write"),
            inputs_true.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_true]), &[transaction_true], rng);

    let result_true = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("conditional_worker.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(result_true, Value::from_str("100u64").unwrap());

    // Call with false - should write 200
    let inputs_false = vec![Value::from_str("false").unwrap()];
    let transaction_false = vm
        .execute(
            &caller_private_key,
            ("conditional_caller.aleo", "conditional_write"),
            inputs_false.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_false]), &[transaction_false], rng);

    let result_false = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("conditional_worker.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(result_false, Value::from_str("200u64").unwrap());
}

// Tests that a `call.dynamic` that passes the wrong input type fails at execution time.
#[test]
fn test_interface_mismatch_wrong_input_type() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program expecting u64 input
    let u64_program = Program::<CurrentNetwork>::from_str(
        r"
        program u64_input.aleo;

        mapping data:
            key as u8.public;
            value as u64.public;

        function store:
            input r0 as u64.public;
            async store r0 into r1;
            output r1 as u64_input.aleo/store.future;

        finalize store:
            input r0 as u64.public;
            set r0 into data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let u64_input_field = Identifier::<CurrentNetwork>::from_str("u64_input").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let store_field = Identifier::<CurrentNetwork>::from_str("store").unwrap().to_field().unwrap();

    // Caller that passes wrong type (u32 instead of u64)
    let caller_program_str = format!(
        r"
        program type_mismatch_caller.aleo;

        function call_with_wrong_type:
            input r0 as u32.public;
            call.dynamic {u64_input_field} {aleo_field} {store_field} with r0 (as u32.public) into r1 (as dynamic.future);
            async call_with_wrong_type r1 into r2;
            output r2 as type_mismatch_caller.aleo/call_with_wrong_type.future;

        finalize call_with_wrong_type:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_u64 = vm.deploy(&caller_private_key, &u64_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_u64], rng);

    // The caller program is syntactically valid, so parsing and deployment must succeed.
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // A type-mismatched dynamic call must be rejected — either at execute time or at
    // check_transaction time.
    let exec_result = vm.execute(
        &caller_private_key,
        ("type_mismatch_caller.aleo", "call_with_wrong_type"),
        vec![Value::from_str("5u32").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );
    let mismatch_was_rejected = match exec_result {
        Err(_) => true,
        Ok(tx) => vm.check_transaction(&tx, None, rng).is_err(),
    };
    assert!(mismatch_was_rejected, "Type mismatch (caller declares u32, callee expects u64) must be rejected");
}

// Tests that attempting to await the same `DynamicFuture` twice fails.
#[test]
fn test_double_await_fails() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let simple_program = Program::<CurrentNetwork>::from_str(
        r"
        program simple_future.aleo;

        mapping data:
            key as u8.public;
            value as u64.public;

        function set_value:
            input r0 as u64.public;
            async set_value r0 into r1;
            output r1 as simple_future.aleo/set_value.future;

        finalize set_value:
            input r0 as u64.public;
            set r0 into data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let simple_field = Identifier::<CurrentNetwork>::from_str("simple_future").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let set_value_field = Identifier::<CurrentNetwork>::from_str("set_value").unwrap().to_field().unwrap();

    // Caller that tries to await the same future twice
    let caller_program_str = format!(
        r"
        program double_await_caller.aleo;

        function double_await:
            input r0 as u64.public;
            call.dynamic {simple_field} {aleo_field} {set_value_field} with r0 (as u64.public) into r1 (as dynamic.future);
            async double_await r1 r1 into r2;
            output r2 as double_await_caller.aleo/double_await.future;

        finalize double_await:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            await r0;
            await r1;

        constructor:
            assert.eq true true;
        "
    );

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_simple = vm.deploy(&caller_private_key, &simple_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_simple], rng);

    // The caller program is syntactically valid. Rejection may occur at deployment, execution,
    // or check_transaction time — but it must be rejected at some stage.
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let was_rejected = 'pipeline: {
        let deploy_tx = match vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng) {
            Err(_) => break 'pipeline true,
            Ok(tx) => tx,
        };
        // Deployment succeeded; add to chain and attempt execution.
        let block = sample_next_block(&vm, &caller_private_key, &[deploy_tx], rng).unwrap();
        if block.transactions().num_rejected() > 0 || !block.aborted_transaction_ids().is_empty() {
            break 'pipeline true;
        }
        vm.add_next_block(&block).unwrap();
        let exec_result = vm.execute(
            &caller_private_key,
            ("double_await_caller.aleo", "double_await"),
            vec![Value::from_str("42u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        );
        match exec_result {
            Err(_) => true,
            Ok(tx) => vm.check_transaction(&tx, None, rng).is_err(),
        }
    };
    assert!(was_rejected, "Awaiting the same DynamicFuture twice must be rejected");
}

// Tests a deeply nested chain of `call.dynamic` (4 levels), each with finalize.
#[test]
fn test_deep_nested_futures() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Level 4 (deepest) - just sets a value
    let level4_program = Program::<CurrentNetwork>::from_str(
        r"
        program level4.aleo;

        mapping depth:
            key as u8.public;
            value as u64.public;

        function depth4:
            input r0 as u64.public;
            async depth4 r0 into r1;
            output r1 as level4.aleo/depth4.future;

        finalize depth4:
            input r0 as u64.public;
            set r0 into depth[4u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let level4_field = Identifier::<CurrentNetwork>::from_str("level4").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let depth4_field = Identifier::<CurrentNetwork>::from_str("depth4").unwrap().to_field().unwrap();

    // Level 3
    let level3_program_str = format!(
        r"
        program level3.aleo;

        mapping depth:
            key as u8.public;
            value as u64.public;

        function depth3:
            input r0 as u64.public;
            call.dynamic {level4_field} {aleo_field} {depth4_field} with r0 (as u64.public) into r1 (as dynamic.future);
            add r0 10u64 into r2;
            async depth3 r1 r2 into r3;
            output r3 as level3.aleo/depth3.future;

        finalize depth3:
            input r0 as dynamic.future;
            input r1 as u64.public;
            await r0;
            set r1 into depth[3u8];

        constructor:
            assert.eq true true;
        "
    );

    let level3_program = Program::<CurrentNetwork>::from_str(&level3_program_str).unwrap();

    let level3_field = Identifier::<CurrentNetwork>::from_str("level3").unwrap().to_field().unwrap();
    let depth3_field = Identifier::<CurrentNetwork>::from_str("depth3").unwrap().to_field().unwrap();

    // Level 2
    let level2_program_str = format!(
        r"
        program level2.aleo;

        mapping depth:
            key as u8.public;
            value as u64.public;

        function depth2:
            input r0 as u64.public;
            call.dynamic {level3_field} {aleo_field} {depth3_field} with r0 (as u64.public) into r1 (as dynamic.future);
            add r0 100u64 into r2;
            async depth2 r1 r2 into r3;
            output r3 as level2.aleo/depth2.future;

        finalize depth2:
            input r0 as dynamic.future;
            input r1 as u64.public;
            await r0;
            set r1 into depth[2u8];

        constructor:
            assert.eq true true;
        "
    );

    let level2_program = Program::<CurrentNetwork>::from_str(&level2_program_str).unwrap();

    let level2_field = Identifier::<CurrentNetwork>::from_str("level2").unwrap().to_field().unwrap();
    let depth2_field = Identifier::<CurrentNetwork>::from_str("depth2").unwrap().to_field().unwrap();

    // Level 1 (root)
    let level1_program_str = format!(
        r"
        program level1.aleo;

        mapping depth:
            key as u8.public;
            value as u64.public;

        function depth1:
            input r0 as u64.public;
            call.dynamic {level2_field} {aleo_field} {depth2_field} with r0 (as u64.public) into r1 (as dynamic.future);
            add r0 1000u64 into r2;
            async depth1 r1 r2 into r3;
            output r3 as level1.aleo/depth1.future;

        finalize depth1:
            input r0 as dynamic.future;
            input r1 as u64.public;
            await r0;
            set r1 into depth[1u8];

        constructor:
            assert.eq true true;
        "
    );

    let level1_program = Program::<CurrentNetwork>::from_str(&level1_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy in order from deepest to shallowest
    let deploy4 = vm.deploy(&caller_private_key, &level4_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy4], rng);

    let deploy3 = vm.deploy(&caller_private_key, &level3_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy3], rng);

    let deploy2 = vm.deploy(&caller_private_key, &level2_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy2], rng);

    let deploy1 = vm.deploy(&caller_private_key, &level1_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy1], rng);

    // Execute starting from level 1 with value 5
    // Expected: level4 = 5, level3 = 15, level2 = 105, level1 = 1005
    let inputs = vec![Value::from_str("5u64").unwrap()];
    let transaction =
        vm.execute(&caller_private_key, ("level1.aleo", "depth1"), inputs.iter(), None, 0, None, rng).unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Verify all depths were set correctly
    let depth4 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("level4.aleo").unwrap(),
            Identifier::from_str("depth").unwrap(),
            &Plaintext::from_str("4u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let depth3 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("level3.aleo").unwrap(),
            Identifier::from_str("depth").unwrap(),
            &Plaintext::from_str("3u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let depth2 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("level2.aleo").unwrap(),
            Identifier::from_str("depth").unwrap(),
            &Plaintext::from_str("2u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let depth1 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("level1.aleo").unwrap(),
            Identifier::from_str("depth").unwrap(),
            &Plaintext::from_str("1u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(depth4, Value::from_str("5u64").unwrap());
    assert_eq!(depth3, Value::from_str("15u64").unwrap());
    assert_eq!(depth2, Value::from_str("105u64").unwrap());
    assert_eq!(depth1, Value::from_str("1005u64").unwrap());
}

// Tests that `call.dynamic` passing a public value when callee expects private fails at execution time.
#[test]
fn test_interface_mismatch_public_to_private() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program expecting private input
    let private_program = Program::<CurrentNetwork>::from_str(
        r"
        program private_input.aleo;

        mapping data:
            key as u8.public;
            value as u64.public;

        function store:
            input r0 as u64.private;
            async store r0 into r1;
            output r1 as private_input.aleo/store.future;

        finalize store:
            input r0 as u64.public;
            set r0 into data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let private_input_field = Identifier::<CurrentNetwork>::from_str("private_input").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let store_field = Identifier::<CurrentNetwork>::from_str("store").unwrap().to_field().unwrap();

    // Caller that passes public when private is expected
    let caller_program_str = format!(
        r"
        program public_to_private_caller.aleo;

        function call_with_wrong_mode:
            input r0 as u64.public;
            call.dynamic {private_input_field} {aleo_field} {store_field} with r0 (as u64.public) into r1 (as dynamic.future);
            async call_with_wrong_mode r1 into r2;
            output r2 as public_to_private_caller.aleo/call_with_wrong_mode.future;

        finalize call_with_wrong_mode:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_private = vm.deploy(&caller_private_key, &private_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_private], rng);

    // The caller program is syntactically valid, so parsing and deployment must succeed.
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // A mode-mismatched dynamic call must be rejected — either at execute time or at
    // check_transaction time.
    let exec_result = vm.execute(
        &caller_private_key,
        ("public_to_private_caller.aleo", "call_with_wrong_mode"),
        vec![Value::from_str("42u64").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );
    let mismatch_was_rejected = match exec_result {
        Err(_) => true,
        Ok(tx) => vm.check_transaction(&tx, None, rng).is_err(),
    };
    assert!(mismatch_was_rejected, "Mode mismatch (caller declares public, callee expects private) must be rejected");
}

// Tests that `call.dynamic` passing a private value when callee expects public fails at execution time.
#[test]
fn test_interface_mismatch_private_to_public() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Program expecting public input
    let public_program = Program::<CurrentNetwork>::from_str(
        r"
        program public_input.aleo;

        mapping data:
            key as u8.public;
            value as u64.public;

        function store:
            input r0 as u64.public;
            async store r0 into r1;
            output r1 as public_input.aleo/store.future;

        finalize store:
            input r0 as u64.public;
            set r0 into data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let public_input_field = Identifier::<CurrentNetwork>::from_str("public_input").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let store_field = Identifier::<CurrentNetwork>::from_str("store").unwrap().to_field().unwrap();

    // Caller that passes private when public is expected
    let caller_program_str = format!(
        r"
        program private_to_public_caller.aleo;

        function call_with_wrong_mode:
            input r0 as u64.private;
            call.dynamic {public_input_field} {aleo_field} {store_field} with r0 (as u64.private) into r1 (as dynamic.future);
            async call_with_wrong_mode r1 into r2;
            output r2 as private_to_public_caller.aleo/call_with_wrong_mode.future;

        finalize call_with_wrong_mode:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_public = vm.deploy(&caller_private_key, &public_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_public], rng);

    // The caller program is syntactically valid, so parsing and deployment must succeed.
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // A mode-mismatched dynamic call must be rejected — either at execute time or at
    // check_transaction time.
    let exec_result = vm.execute(
        &caller_private_key,
        ("private_to_public_caller.aleo", "call_with_wrong_mode"),
        vec![Value::from_str("42u64").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );
    let mismatch_was_rejected = match exec_result {
        Err(_) => true,
        Ok(tx) => vm.check_transaction(&tx, None, rng).is_err(),
    };
    assert!(mismatch_was_rejected, "Mode mismatch (caller declares private, callee expects public) must be rejected");
}

// Tests conditional `DynamicFuture` execution with `branch.eq`/`branch.neq` and verifies skipped awaits are caught.
#[test]
fn test_conditional_future_execution_with_branches() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Two worker programs that write to different mappings
    let worker_a = Program::<CurrentNetwork>::from_str(
        r"
        program worker_a.aleo;

        mapping results:
            key as u8.public;
            value as u64.public;

        function work:
            input r0 as u64.public;
            async work r0 into r1;
            output r1 as worker_a.aleo/work.future;

        finalize work:
            input r0 as u64.public;
            set r0 into results[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_b = Program::<CurrentNetwork>::from_str(
        r"
        program worker_b.aleo;

        mapping results:
            key as u8.public;
            value as u64.public;

        function work:
            input r0 as u64.public;
            async work r0 into r1;
            output r1 as worker_b.aleo/work.future;

        finalize work:
            input r0 as u64.public;
            set r0 into results[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_a_field = Identifier::<CurrentNetwork>::from_str("worker_a").unwrap().to_field().unwrap();
    let worker_b_field = Identifier::<CurrentNetwork>::from_str("worker_b").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let work_field = Identifier::<CurrentNetwork>::from_str("work").unwrap().to_field().unwrap();

    // Caller that creates two futures and awaits them in order determined by a condition
    let caller_program_str = format!(
        r"
        program branch_caller.aleo;

        function call_both:
            input r0 as boolean.public;
            input r1 as u64.public;
            input r2 as u64.public;
            call.dynamic {worker_a_field} {aleo_field} {work_field} with r1 (as u64.public) into r3 (as dynamic.future);
            call.dynamic {worker_b_field} {aleo_field} {work_field} with r2 (as u64.public) into r4 (as dynamic.future);
            async call_both r0 r3 r4 into r5;
            output r5 as branch_caller.aleo/call_both.future;

        finalize call_both:
            input r0 as boolean.public;
            input r1 as dynamic.future;
            input r2 as dynamic.future;
            branch.eq r0 true to await_a_first;
            await r2;
            await r1;
            branch.eq true true to done;
            position await_a_first;
            await r1;
            await r2;
            position done;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy workers
    let deploy_a = vm.deploy(&caller_private_key, &worker_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_a], rng);

    let deploy_b = vm.deploy(&caller_private_key, &worker_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_b], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Test with condition = true (await A first, then B)
    let tx_true = vm
        .execute(
            &caller_private_key,
            ("branch_caller.aleo", "call_both"),
            vec![
                Value::from_str("true").unwrap(),
                Value::from_str("100u64").unwrap(),
                Value::from_str("200u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block_true = sample_next_block(&vm, &caller_private_key, &[tx_true], rng).unwrap();
    assert_eq!(block_true.aborted_transaction_ids().len(), 0, "Transaction with condition=true should succeed");
    vm.add_next_block(&block_true).unwrap();

    // Verify values were written
    let result_a = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("worker_a.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    let result_b = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("worker_b.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(result_a, Value::from_str("100u64").unwrap());
    assert_eq!(result_b, Value::from_str("200u64").unwrap());

    // Test with condition = false (await B first, then A)
    let tx_false = vm
        .execute(
            &caller_private_key,
            ("branch_caller.aleo", "call_both"),
            vec![
                Value::from_str("false").unwrap(),
                Value::from_str("300u64").unwrap(),
                Value::from_str("400u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block_false = sample_next_block(&vm, &caller_private_key, &[tx_false], rng).unwrap();
    assert_eq!(block_false.aborted_transaction_ids().len(), 0, "Transaction with condition=false should succeed");
    vm.add_next_block(&block_false).unwrap();

    // Verify updated values
    let result_a = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("worker_a.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    let result_b = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("worker_b.aleo").unwrap(),
            Identifier::from_str("results").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(result_a, Value::from_str("300u64").unwrap());
    assert_eq!(result_b, Value::from_str("400u64").unwrap());
}

// Tests that skipping a `DynamicFuture` await (not awaiting all created futures) is caught and results in transaction abort.
#[test]
fn test_skipped_future_await_is_caught() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Worker program
    let worker = Program::<CurrentNetwork>::from_str(
        r"
        program skip_worker.aleo;

        mapping results:
            key as u8.public;
            value as u64.public;

        function work:
            input r0 as u64.public;
            async work r0 into r1;
            output r1 as skip_worker.aleo/work.future;

        finalize work:
            input r0 as u64.public;
            set r0 into results[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_field = Identifier::<CurrentNetwork>::from_str("skip_worker").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let work_field = Identifier::<CurrentNetwork>::from_str("work").unwrap().to_field().unwrap();

    // Caller that creates two futures but only awaits one via branching
    let caller_program_str = format!(
        r"
        program skip_caller.aleo;

        function call_and_skip:
            input r0 as u64.public;
            input r1 as u64.public;
            call.dynamic {worker_field} {aleo_field} {work_field} with r0 (as u64.public) into r2 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {work_field} with r1 (as u64.public) into r3 (as dynamic.future);
            async call_and_skip r2 r3 into r4;
            output r4 as skip_caller.aleo/call_and_skip.future;

        finalize call_and_skip:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            await r0;
            // Intentionally skip awaiting r1 by branching to end
            branch.eq true true to done;
            await r1;
            position done;

        constructor:
            assert.eq true true;
        "
    );

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_worker = vm.deploy(&caller_private_key, &worker, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_worker], rng);

    // The caller program is syntactically valid. Rejection may occur at deployment, execution,
    // or check_transaction time — but it must be rejected at some stage.
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let was_rejected = 'pipeline: {
        let deploy_tx = match vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng) {
            Err(_) => break 'pipeline true,
            Ok(tx) => tx,
        };
        // Deployment succeeded; add to chain and attempt execution.
        let block = sample_next_block(&vm, &caller_private_key, &[deploy_tx], rng).unwrap();
        if block.transactions().num_rejected() > 0 || !block.aborted_transaction_ids().is_empty() {
            break 'pipeline true;
        }
        vm.add_next_block(&block).unwrap();
        let exec_result = vm.execute(
            &caller_private_key,
            ("skip_caller.aleo", "call_and_skip"),
            vec![Value::from_str("100u64").unwrap(), Value::from_str("200u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        );
        // Unawaited-future errors are only caught during finalize execution, which runs at
        // block-building time — not at vm.execute() or check_transaction() time.
        match exec_result {
            Err(_) => true,
            Ok(tx) => {
                if vm.check_transaction(&tx, None, rng).is_err() {
                    true
                } else {
                    let block = sample_next_block(&vm, &caller_private_key, &[tx], rng).unwrap();
                    block.transactions().num_rejected() > 0 || !block.aborted_transaction_ids().is_empty()
                }
            }
        }
    };
    assert!(was_rejected, "A DynamicFuture that is always skipped via branch must be rejected");
}

// Tests that when one `DynamicFuture` fails during finalize, the entire transaction is rejected and no state changes are committed.
#[test]
fn test_finalize_partial_failure_rollback() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // First program - always succeeds
    let success_program = Program::<CurrentNetwork>::from_str(
        r"
        program always_succeeds.aleo;

        mapping success_data:
            key as u8.public;
            value as u64.public;

        function succeed:
            input r0 as u64.public;
            async succeed r0 into r1;
            output r1 as always_succeeds.aleo/succeed.future;

        finalize succeed:
            input r0 as u64.public;
            set r0 into success_data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Second program - fails based on input
    let conditional_program = Program::<CurrentNetwork>::from_str(
        r"
        program conditional_fail.aleo;

        mapping conditional_data:
            key as u8.public;
            value as u64.public;

        function maybe_fail:
            input r0 as boolean.public;
            input r1 as u64.public;
            async maybe_fail r0 r1 into r2;
            output r2 as conditional_fail.aleo/maybe_fail.future;

        finalize maybe_fail:
            input r0 as boolean.public;
            input r1 as u64.public;
            // Fail if r0 is false
            assert.eq r0 true;
            set r1 into conditional_data[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let success_field = Identifier::<CurrentNetwork>::from_str("always_succeeds").unwrap().to_field().unwrap();
    let conditional_field = Identifier::<CurrentNetwork>::from_str("conditional_fail").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let succeed_field = Identifier::<CurrentNetwork>::from_str("succeed").unwrap().to_field().unwrap();
    let maybe_fail_field = Identifier::<CurrentNetwork>::from_str("maybe_fail").unwrap().to_field().unwrap();

    // Caller that invokes both: first succeeds, second fails
    let caller_program_str = format!(
        r"
        program partial_fail_caller.aleo;

        function call_both:
            input r0 as boolean.public;
            // First call always succeeds
            call.dynamic {success_field} {aleo_field} {succeed_field} with 100u64 (as u64.public) into r1 (as dynamic.future);
            // Second call conditionally fails
            call.dynamic {conditional_field} {aleo_field} {maybe_fail_field} with r0 200u64 (as boolean.public u64.public) into r2 (as dynamic.future);
            async call_both r1 r2 into r3;
            output r3 as partial_fail_caller.aleo/call_both.future;

        finalize call_both:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            await r0;
            await r1;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy all programs
    let deploy_success = vm.deploy(&caller_private_key, &success_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_success], rng);

    let deploy_conditional = vm.deploy(&caller_private_key, &conditional_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_conditional], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // First test: both succeed (input = true)
    let inputs = vec![Value::from_str("true").unwrap()];
    let tx_success = vm
        .execute(&caller_private_key, ("partial_fail_caller.aleo", "call_both"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx_success], rng);

    // Verify both values were written
    let success_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("always_succeeds.aleo").unwrap(),
            Identifier::from_str("success_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let conditional_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("conditional_fail.aleo").unwrap(),
            Identifier::from_str("conditional_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(success_value, Value::from_str("100u64").unwrap());
    assert_eq!(conditional_value, Value::from_str("200u64").unwrap());

    // Second test: first succeeds, second fails (input = false)
    // This should cause the entire transaction to be rejected
    let tx_partial_fail = vm
        .execute(
            &caller_private_key,
            ("partial_fail_caller.aleo", "call_both"),
            vec![Value::from_str("false").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[tx_partial_fail], rng).unwrap();

    // The transaction should be rejected due to the second future's finalize failing
    assert_eq!(block.transactions().num_rejected(), 1, "Transaction with partial failure should be rejected");

    // Verify the original values are still intact (no partial state change)
    let success_value_after = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("always_succeeds.aleo").unwrap(),
            Identifier::from_str("success_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    let conditional_value_after = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("conditional_fail.aleo").unwrap(),
            Identifier::from_str("conditional_data").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    // Values should remain unchanged from the successful transaction
    assert_eq!(success_value_after, Value::from_str("100u64").unwrap());
    assert_eq!(conditional_value_after, Value::from_str("200u64").unwrap());
}

// Tests that multiple sequential `call.dynamic` invocations create distinct `DynamicFuture` instances that can be awaited independently.
#[test]
fn test_future_isolation_sequential_calls() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Worker program that increments a counter
    let worker_program = Program::<CurrentNetwork>::from_str(
        r"
        program isolation_worker.aleo;

        mapping counter:
            key as u8.public;
            value as u64.public;

        function increment:
            input r0 as u8.public;
            input r1 as u64.public;
            async increment r0 r1 into r2;
            output r2 as isolation_worker.aleo/increment.future;

        finalize increment:
            input r0 as u8.public;
            input r1 as u64.public;
            get.or_use counter[r0] 0u64 into r2;
            add r2 r1 into r3;
            set r3 into counter[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_field = Identifier::<CurrentNetwork>::from_str("isolation_worker").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let increment_field = Identifier::<CurrentNetwork>::from_str("increment").unwrap().to_field().unwrap();

    // Caller that makes 5 sequential calls to the same function with different keys
    let caller_program_str = format!(
        r"
        program isolation_caller.aleo;

        function call_five_times:
            // Each call increments a different key
            call.dynamic {worker_field} {aleo_field} {increment_field} with 0u8 10u64 (as u8.public u64.public) into r0 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {increment_field} with 1u8 20u64 (as u8.public u64.public) into r1 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {increment_field} with 2u8 30u64 (as u8.public u64.public) into r2 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {increment_field} with 3u8 40u64 (as u8.public u64.public) into r3 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {increment_field} with 4u8 50u64 (as u8.public u64.public) into r4 (as dynamic.future);
            async call_five_times r0 r1 r2 r3 r4 into r5;
            output r5 as isolation_caller.aleo/call_five_times.future;

        finalize call_five_times:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            input r2 as dynamic.future;
            input r3 as dynamic.future;
            input r4 as dynamic.future;
            // Await in a different order than creation to test isolation
            await r4;
            await r2;
            await r0;
            await r3;
            await r1;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_worker = vm.deploy(&caller_private_key, &worker_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_worker], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execute the function
    let transaction = vm
        .execute(
            &caller_private_key,
            ("isolation_caller.aleo", "call_five_times"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);

    // Verify all 5 counters were incremented correctly (each future wrote to its own key)
    for (key, expected_value) in [(0u8, 10u64), (1u8, 20u64), (2u8, 30u64), (3u8, 40u64), (4u8, 50u64)] {
        let value = vm
            .finalize_store()
            .get_value_confirmed(
                ProgramID::from_str("isolation_worker.aleo").unwrap(),
                Identifier::from_str("counter").unwrap(),
                &Plaintext::from_str(&format!("{key}u8")).unwrap(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            value,
            Value::from_str(&format!("{expected_value}u64")).unwrap(),
            "Counter {key} should be {expected_value}"
        );
    }
}

// Tests that 10 `DynamicFuture` instances in a single transaction are handled correctly.
#[test]
fn test_many_futures_in_single_transaction() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Worker program
    let worker_program = Program::<CurrentNetwork>::from_str(
        r"
        program many_futures_worker.aleo;

        mapping values:
            key as u8.public;
            value as u64.public;

        function store:
            input r0 as u8.public;
            input r1 as u64.public;
            async store r0 r1 into r2;
            output r2 as many_futures_worker.aleo/store.future;

        finalize store:
            input r0 as u8.public;
            input r1 as u64.public;
            set r1 into values[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let worker_field = Identifier::<CurrentNetwork>::from_str("many_futures_worker").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let store_field = Identifier::<CurrentNetwork>::from_str("store").unwrap().to_field().unwrap();

    // Caller that creates 10 futures
    let caller_program_str = format!(
        r"
        program many_futures_caller.aleo;

        function store_ten_values:
            call.dynamic {worker_field} {aleo_field} {store_field} with 0u8 100u64 (as u8.public u64.public) into r0 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 1u8 101u64 (as u8.public u64.public) into r1 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 2u8 102u64 (as u8.public u64.public) into r2 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 3u8 103u64 (as u8.public u64.public) into r3 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 4u8 104u64 (as u8.public u64.public) into r4 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 5u8 105u64 (as u8.public u64.public) into r5 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 6u8 106u64 (as u8.public u64.public) into r6 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 7u8 107u64 (as u8.public u64.public) into r7 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 8u8 108u64 (as u8.public u64.public) into r8 (as dynamic.future);
            call.dynamic {worker_field} {aleo_field} {store_field} with 9u8 109u64 (as u8.public u64.public) into r9 (as dynamic.future);
            async store_ten_values r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 into r10;
            output r10 as many_futures_caller.aleo/store_ten_values.future;

        finalize store_ten_values:
            input r0 as dynamic.future;
            input r1 as dynamic.future;
            input r2 as dynamic.future;
            input r3 as dynamic.future;
            input r4 as dynamic.future;
            input r5 as dynamic.future;
            input r6 as dynamic.future;
            input r7 as dynamic.future;
            input r8 as dynamic.future;
            input r9 as dynamic.future;
            await r0;
            await r1;
            await r2;
            await r3;
            await r4;
            await r5;
            await r6;
            await r7;
            await r8;
            await r9;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_worker = vm.deploy(&caller_private_key, &worker_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_worker], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execute
    let transaction = vm
        .execute(
            &caller_private_key,
            ("many_futures_caller.aleo", "store_ten_values"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);

    // Verify all 10 values were stored
    for i in 0..10u8 {
        let value = vm
            .finalize_store()
            .get_value_confirmed(
                ProgramID::from_str("many_futures_worker.aleo").unwrap(),
                Identifier::from_str("values").unwrap(),
                &Plaintext::from_str(&format!("{i}u8")).unwrap(),
            )
            .unwrap()
            .unwrap();

        let expected = 100u64 + i as u64;
        assert_eq!(value, Value::from_str(&format!("{expected}u64")).unwrap());
    }
}

// Tests a `DynamicFuture` with exactly 16 arguments (MAX_INPUTS boundary).
// This verifies that the Merkle tree of depth 4 can handle the maximum number of future arguments.
#[test]
fn test_dynamic_future_max_arguments() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let program_field = Identifier::<CurrentNetwork>::from_str("max_args").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let sum_sixteen_field = Identifier::<CurrentNetwork>::from_str("sum_sixteen").unwrap().to_field().unwrap();

    // Generate finalize input declarations for 16 u64 arguments
    let finalize_inputs: String = (0..16).map(|i| format!("            input r{i} as u64.public;\n")).collect();

    // Generate sum computation: add all 16 arguments together
    let mut sum_computation = String::new();
    sum_computation.push_str("            add r0 r1 into r16;\n");
    for i in 2..16 {
        let prev = 14 + i; // r16, r17, ... r29
        let result = 15 + i; // r17, r18, ... r30
        sum_computation.push_str(&format!("            add r{prev} r{i} into r{result};\n"));
    }

    // Program with a function that takes 16 arguments in its finalize
    let callee_program_str = format!(
        r"
        program max_args.aleo;

        mapping result:
            key as u8.public;
            value as u64.public;

        // Function with finalize that takes 16 arguments
        function sum_sixteen:
            input r0 as u64.public;
            input r1 as u64.public;
            input r2 as u64.public;
            input r3 as u64.public;
            input r4 as u64.public;
            input r5 as u64.public;
            input r6 as u64.public;
            input r7 as u64.public;
            input r8 as u64.public;
            input r9 as u64.public;
            input r10 as u64.public;
            input r11 as u64.public;
            input r12 as u64.public;
            input r13 as u64.public;
            input r14 as u64.public;
            input r15 as u64.public;
            async sum_sixteen r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 into r16;
            output r16 as max_args.aleo/sum_sixteen.future;

        finalize sum_sixteen:
{finalize_inputs}{sum_computation}            set r30 into result[0u8];

        constructor:
            assert.eq true true;
        "
    );

    // Caller that invokes sum_sixteen dynamically and receives a DynamicFuture with 16 arguments
    let caller_program_str = format!(
        r"
        program max_args_caller.aleo;

        function call_sum_sixteen:
            call.dynamic {program_field} {aleo_field} {sum_sixteen_field}
                with 1u64 2u64 3u64 4u64 5u64 6u64 7u64 8u64 9u64 10u64 11u64 12u64 13u64 14u64 15u64 16u64
                (as u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public u64.public)
                into r0 (as dynamic.future);
            async call_sum_sixteen r0 into r1;
            output r1 as max_args_caller.aleo/call_sum_sixteen.future;

        finalize call_sum_sixteen:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let callee_program = Program::<CurrentNetwork>::from_str(&callee_program_str).unwrap();
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy callee first
    println!("Deploying max_args.aleo with 16-argument finalize...");
    let deploy_callee = vm.deploy(&caller_private_key, &callee_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_callee], rng);

    // Deploy caller
    println!("Deploying max_args_caller.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execute the dynamic call
    println!("Executing call.dynamic with DynamicFuture containing 16 arguments...");
    let transaction = vm
        .execute(
            &caller_private_key,
            ("max_args_caller.aleo", "call_sum_sixteen"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);

    // Verify the sum was computed correctly (1+2+3+...+16 = 136)
    let result_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("max_args.aleo").unwrap(),
            Identifier::from_str("result").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(result_value, Value::from_str("136u64").unwrap());
    println!("Successfully handled DynamicFuture with 16 arguments (MAX_INPUTS boundary)");
}

// Tests state consistency when multiple dynamic-call transactions in the same block
// update the same mapping key.
#[test]
fn test_multiple_dynamic_transactions_same_mapping_key() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let counter_field = Identifier::<CurrentNetwork>::from_str("counter").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let increment_field = Identifier::<CurrentNetwork>::from_str("increment").unwrap().to_field().unwrap();

    // Program with a counter mapping that can be incremented
    let counter_program = Program::<CurrentNetwork>::from_str(
        r"
        program counter.aleo;

        mapping values:
            key as u8.public;
            value as u64.public;

        function increment:
            input r0 as u8.public;
            input r1 as u64.public;
            async increment r0 r1 into r2;
            output r2 as counter.aleo/increment.future;

        finalize increment:
            input r0 as u8.public;
            input r1 as u64.public;
            get.or_use values[r0] 0u64 into r2;
            add r2 r1 into r3;
            set r3 into values[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Caller that uses dynamic call to increment the counter
    let caller_program_str = format!(
        r"
        program dynamic_counter.aleo;

        function dynamic_increment:
            input r0 as u8.public;
            input r1 as u64.public;
            call.dynamic {counter_field} {aleo_field} {increment_field}
                with r0 r1 (as u8.public u64.public)
                into r2 (as dynamic.future);
            async dynamic_increment r2 into r3;
            output r3 as dynamic_counter.aleo/dynamic_increment.future;

        finalize dynamic_increment:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    // Deploy programs
    println!("Deploying counter.aleo...");
    let deploy_counter = vm.deploy(&caller_private_key, &counter_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_counter], rng);

    println!("Deploying dynamic_counter.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Create 3 transactions that all increment the same key (key=0)
    // Each adds a different value: 10, 20, 30
    // Expected final value: 0 + 10 + 20 + 30 = 60
    println!("\nCreating 3 transactions to increment the same mapping key...");

    let tx1 = vm
        .execute(
            &caller_private_key,
            ("dynamic_counter.aleo", "dynamic_increment"),
            vec![Value::from_str("0u8").unwrap(), Value::from_str("10u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let tx2 = vm
        .execute(
            &caller_private_key,
            ("dynamic_counter.aleo", "dynamic_increment"),
            vec![Value::from_str("0u8").unwrap(), Value::from_str("20u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let tx3 = vm
        .execute(
            &caller_private_key,
            ("dynamic_counter.aleo", "dynamic_increment"),
            vec![Value::from_str("0u8").unwrap(), Value::from_str("30u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Add all 3 transactions in a single block
    println!("Adding all 3 transactions in a single block...");
    let block = sample_next_block(&vm, &caller_private_key, &[tx1, tx2, tx3], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 3, "All 3 transactions should be accepted");
    vm.add_next_block(&block).unwrap();

    // Verify the final state
    let final_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("counter.aleo").unwrap(),
            Identifier::from_str("values").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    println!("Final value at key 0: {final_value}");
    assert_eq!(final_value, Value::from_str("60u64").unwrap(), "Final value should be 10 + 20 + 30 = 60");

    println!("\nSUCCESS: Multiple transactions updated same mapping key correctly");
}

// Tests that a failed finalize rejects only that transaction while others commit.
#[test]
fn test_multiple_dynamic_transactions_one_fails() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let conditional_field = Identifier::<CurrentNetwork>::from_str("conditional").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let maybe_fail_field = Identifier::<CurrentNetwork>::from_str("maybe_fail").unwrap().to_field().unwrap();

    // Program that conditionally fails during finalize
    let conditional_program = Program::<CurrentNetwork>::from_str(
        r"
        program conditional.aleo;

        mapping counter:
            key as u8.public;
            value as u64.public;

        function maybe_fail:
            input r0 as boolean.public;
            input r1 as u64.public;
            async maybe_fail r0 r1 into r2;
            output r2 as conditional.aleo/maybe_fail.future;

        finalize maybe_fail:
            input r0 as boolean.public;
            input r1 as u64.public;
            // Fail if r0 is false
            assert.eq r0 true;
            // If we get here, increment the counter
            get.or_use counter[0u8] 0u64 into r2;
            add r2 r1 into r3;
            set r3 into counter[0u8];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Caller that uses dynamic call
    let caller_program_str = format!(
        r"
        program conditional_caller.aleo;

        function dynamic_maybe_fail:
            input r0 as boolean.public;
            input r1 as u64.public;
            call.dynamic {conditional_field} {aleo_field} {maybe_fail_field}
                with r0 r1 (as boolean.public u64.public)
                into r2 (as dynamic.future);
            async dynamic_maybe_fail r2 into r3;
            output r3 as conditional_caller.aleo/dynamic_maybe_fail.future;

        finalize dynamic_maybe_fail:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    // Deploy programs
    println!("Deploying conditional.aleo...");
    let deploy_conditional = vm.deploy(&caller_private_key, &conditional_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_conditional], rng);

    println!("Deploying conditional_caller.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Create 3 transactions:
    // tx1: succeeds (true), adds 10
    // tx2: fails (false), tries to add 20
    // tx3: succeeds (true), adds 30
    // Expected final value: 0 + 10 + 30 = 40 (tx2's 20 is not added)
    println!("\nCreating 3 transactions (tx2 will fail during finalize)...");

    let tx1 = vm
        .execute(
            &caller_private_key,
            ("conditional_caller.aleo", "dynamic_maybe_fail"),
            vec![Value::from_str("true").unwrap(), Value::from_str("10u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let tx2 = vm
        .execute(
            &caller_private_key,
            ("conditional_caller.aleo", "dynamic_maybe_fail"),
            vec![Value::from_str("false").unwrap(), Value::from_str("20u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let tx3 = vm
        .execute(
            &caller_private_key,
            ("conditional_caller.aleo", "dynamic_maybe_fail"),
            vec![Value::from_str("true").unwrap(), Value::from_str("30u64").unwrap()].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let tx2_id = tx2.id();

    // Add all 3 transactions in a single block
    println!("Adding all 3 transactions in a single block...");
    let block = sample_next_block(&vm, &caller_private_key, &[tx1, tx2, tx3], rng).unwrap();

    // tx2 should be rejected, tx1 and tx3 should succeed
    println!("Accepted: {}, Rejected: {}", block.transactions().num_accepted(), block.transactions().num_rejected());
    assert_eq!(block.transactions().num_accepted(), 2, "2 transactions should be accepted");
    assert_eq!(block.transactions().num_rejected(), 1, "1 transaction should be rejected");

    // Final state value confirms which transaction was rejected:
    // tx1 (10) + tx3 (30) = 40 means tx2 (20) was rejected.
    println!("Expected tx2 ID that should be rejected: {tx2_id}");

    vm.add_next_block(&block).unwrap();

    // Verify the final state only includes tx1 and tx3's contributions
    let final_value = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("conditional.aleo").unwrap(),
            Identifier::from_str("counter").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();

    println!("Final value at key 0: {final_value}");
    assert_eq!(
        final_value,
        Value::from_str("40u64").unwrap(),
        "Final value should be 10 + 30 = 40 (tx2's 20 was not added due to finalize failure)"
    );

    println!("\nSUCCESS: Failed transaction rejected, others committed");
}
