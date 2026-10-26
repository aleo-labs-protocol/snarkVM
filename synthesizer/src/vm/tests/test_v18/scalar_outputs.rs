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

use console::program::DynamicRecord;

// Since |scalar field| ~ |base field|/4, we deploy each program template enough times N = 3 that a
// value which does not fit inside a Scalar will be sampled with a high enough probability 1 - 1/4^N.
const NUM_DEPLOYMENTS: usize = 3;

// Tests that a function which receives a Field/Group/Address input, casts it to
// a Scalar and outputs the latter, deploys correctly.
#[test]
fn test_program_with_output_scalar_from_atomic() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    // The three types which can be cast to a Scalar but do not always fit
    // inside one are Field, Group and Address.
    let operand_types = ["field", "group", "address"];

    for i in 0..NUM_DEPLOYMENTS {
        let mut program_str = format!(
            r"
            program test_{i}.aleo;

        "
        );

        for operand_type in operand_types.iter() {
            program_str += &format!(
                r"
            function fun_cast_pub_pub_{operand_type}:
                input r0 as {operand_type}.public;
                cast r0 into r1 as scalar;
                output r1 as scalar.public;

            function fun_cast_pub_pri_{operand_type}:
                input r0 as {operand_type}.public;
                cast r0 into r1 as scalar;
                output r1 as scalar.private;

            function fun_cast_pri_pri_{operand_type}:
                input r0 as {operand_type}.private;
                cast r0 into r1 as scalar;
                output r1 as scalar.private;

            function fun_cast_pri_pub_{operand_type}:
                input r0 as {operand_type}.private;
                cast r0 into r1 as scalar;
                output r1 as scalar.public;

            function fun_cast_in_closure_{operand_type}:
                input r0 as {operand_type}.public;
                call clo_cast_{operand_type} r0 into r1;
                output r1 as scalar.public;

            closure clo_cast_{operand_type}:
                input r0 as {operand_type};
                cast r0 into r1 as scalar;
                output r1 as scalar;

            "
            );
        }

        program_str += r"
        constructor:
            assert.eq true true;
        ";

        let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

        // Build and apply the deployment transaction.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // The deployment must be accepted: not rejected and not aborted.
        assert_eq!(block.transactions().num_accepted(), 1, "expected the deployment to be accepted");
        assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
        assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");

        // Commit the deployment so the program can be executed below.
        vm.add_next_block(&block).unwrap();
    }

    // Execute the cast functions on the first deployed program, using inputs whose
    // scalar representation is guaranteed to fit: `1field` -> `1scalar`, and the
    // identity `0group`/zero-address (x-coordinate 0) -> `0scalar`. Both the direct
    // and the closure-based cast paths are exercised for each operand type.
    let zero_address = Address::<CurrentNetwork>::zero().to_string();
    let cases = [
        ("fun_cast_pub_pub_field", "1field", "1scalar"),
        ("fun_cast_in_closure_field", "1field", "1scalar"),
        ("fun_cast_pub_pub_group", "0group", "0scalar"),
        ("fun_cast_in_closure_group", "0group", "0scalar"),
        ("fun_cast_pub_pub_address", zero_address.as_str(), "0scalar"),
        ("fun_cast_in_closure_address", zero_address.as_str(), "0scalar"),
    ];

    let mut transactions = Vec::with_capacity(cases.len());
    for (function, input, expected) in cases {
        let inputs = [Value::<CurrentNetwork>::from_str(input).unwrap()];
        let transaction =
            vm.execute(&caller_private_key, ("test_0.aleo", function), inputs.iter(), None, 0, None, rng).unwrap();
        let expected_output = Plaintext::<CurrentNetwork>::from_str(expected).unwrap();
        assert!(
            matches!(transaction.execution().unwrap().transitions().last().unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
            "unexpected output for {function}"
        );
        transactions.push(transaction);
    }

    let block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), transactions.len(), "expected all executions to be accepted");
    assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
    assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");
}

// Tests that a function which receives a record holding a Scalar entry, reads the
// entry and outputs it, deploys correctly.
#[test]
fn test_program_with_output_scalar_from_record() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    for i in 0..NUM_DEPLOYMENTS {
        let program_str = format!(
            r"
            program test_scalar_record_{i}.aleo;

            record token:
                owner as address.private;
                amount as scalar.private;

            function mint:
                input r0 as scalar.private;
                cast self.caller r0 into r1 as token.record;
                output r1 as token.record;

            function read_scalar_record_pub:
                input r0 as token.record;
                output r0.amount as scalar.public;
            
            function read_scalar_record_pri:
                input r0 as token.record;
                output r0.amount as scalar.private;

            constructor:
                assert.eq true true;
        "
        );

        let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

        // Build and apply the deployment transaction.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // The deployment must be accepted: not rejected and not aborted.
        assert_eq!(block.transactions().num_accepted(), 1, "expected the deployment to be accepted");
        assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
        assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");

        // Commit the deployment so the program can be executed below.
        vm.add_next_block(&block).unwrap();
    }

    // Mint two `token` records on-ledger (V18 requires input records to exist), then
    // execute both read functions to confirm the scalar entry is read at runtime.
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let mut records = Vec::with_capacity(2);
    for amount in ["7scalar", "8scalar"] {
        let mint_inputs = [Value::<CurrentNetwork>::from_str(amount).unwrap()];
        let mint_tx = vm
            .execute(&caller_private_key, ("test_scalar_record_0.aleo", "mint"), mint_inputs.iter(), None, 0, None, rng)
            .unwrap();
        let record = match mint_tx.execution().unwrap().transitions().last().unwrap().outputs().iter().next().unwrap() {
            Output::Record(_, _, ciphertext, _) => ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
            _ => panic!("expected a record output from mint"),
        };
        let block = sample_next_block(&vm, &caller_private_key, &[mint_tx], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1, "expected the mint to be accepted");
        vm.add_next_block(&block).unwrap();
        records.push(record);
    }

    // Read the scalar entry with a public output and confirm its value.
    let read_pub_inputs = [Value::Record(records[0].clone())];
    let read_pub_tx = vm
        .execute(
            &caller_private_key,
            ("test_scalar_record_0.aleo", "read_scalar_record_pub"),
            read_pub_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let expected_output = Plaintext::<CurrentNetwork>::from_str("7scalar").unwrap();
    assert!(
        matches!(read_pub_tx.execution().unwrap().transitions().last().unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "unexpected output for read_scalar_record_pub"
    );

    // Read the scalar entry with a private output.
    let read_pri_inputs = [Value::Record(records[1].clone())];
    let read_pri_tx = vm
        .execute(
            &caller_private_key,
            ("test_scalar_record_0.aleo", "read_scalar_record_pri"),
            read_pri_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[read_pub_tx, read_pri_tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2, "expected both reads to be accepted");
    assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
    assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");
}

// Tests that a function which receives a dynamic record, reads a Scalar entry with
// `get.record.dynamic` and outputs it, deploys correctly.
#[test]
fn test_program_with_output_scalar_from_dynamic_record() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    // The read functions materialize the dynamic record with a `call.dynamic` to
    // `consume` so it passes the record-existence check at execution time.
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_field = Identifier::<CurrentNetwork>::from_str("consume").unwrap().to_field().unwrap();

    for i in 0..NUM_DEPLOYMENTS {
        let program_field =
            Identifier::<CurrentNetwork>::from_str(&format!("test_scalar_dynamic_{i}")).unwrap().to_field().unwrap();
        let program_str = format!(
            r"
            program test_scalar_dynamic_{i}.aleo;

            record token:
                owner as address.private;
                amount as scalar.private;

            function mint:
                input r0 as scalar.private;
                cast self.caller r0 into r1 as token.record;
                output r1 as token.record;

            function consume:
                input r0 as token.record;

            function read_scalar_dyn_rec_pub:
                input r0 as dynamic.record;
                get.record.dynamic r0.amount into r1 as scalar;
                call.dynamic {program_field} {network_field} {consume_field} with r0 (as dynamic.record);
                output r1 as scalar.public;

            function read_scalar_dyn_rec_pri:
                input r0 as dynamic.record;
                get.record.dynamic r0.amount into r1 as scalar;
                call.dynamic {program_field} {network_field} {consume_field} with r0 (as dynamic.record);
                output r1 as scalar.private;

            constructor:
                assert.eq true true;
        "
        );

        let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

        // Build and apply the deployment transaction.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // The deployment must be accepted: not rejected and not aborted.
        assert_eq!(block.transactions().num_accepted(), 1, "expected the deployment to be accepted");
        assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
        assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");

        // Commit the deployment so the program can be executed below.
        vm.add_next_block(&block).unwrap();
    }

    // Mint two `token` records on-ledger, convert them to dynamic records, and execute
    // both read functions to confirm the scalar entry is read via `get.record.dynamic`.
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let mut dynamic_records = Vec::with_capacity(2);
    for amount in ["9scalar", "10scalar"] {
        let mint_inputs = [Value::<CurrentNetwork>::from_str(amount).unwrap()];
        let mint_tx = vm
            .execute(
                &caller_private_key,
                ("test_scalar_dynamic_0.aleo", "mint"),
                mint_inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let record = match mint_tx.execution().unwrap().transitions().last().unwrap().outputs().iter().next().unwrap() {
            Output::Record(_, _, ciphertext, _) => ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
            _ => panic!("expected a record output from mint"),
        };
        let block = sample_next_block(&vm, &caller_private_key, &[mint_tx], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1, "expected the mint to be accepted");
        vm.add_next_block(&block).unwrap();
        dynamic_records.push(DynamicRecord::<CurrentNetwork>::from_record(&record).unwrap());
    }

    // Read the scalar entry with a public output and confirm its value. The root
    // transition is the last one (the `call.dynamic` to `consume` comes first).
    let read_pub_inputs = [Value::DynamicRecord(dynamic_records[0].clone())];
    let read_pub_tx = vm
        .execute(
            &caller_private_key,
            ("test_scalar_dynamic_0.aleo", "read_scalar_dyn_rec_pub"),
            read_pub_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let expected_output = Plaintext::<CurrentNetwork>::from_str("9scalar").unwrap();
    assert!(
        matches!(read_pub_tx.execution().unwrap().transitions().last().unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "unexpected output for read_scalar_dyn_rec_pub"
    );

    // Read the scalar entry with a private output.
    let read_pri_inputs = [Value::DynamicRecord(dynamic_records[1].clone())];
    let read_pri_tx = vm
        .execute(
            &caller_private_key,
            ("test_scalar_dynamic_0.aleo", "read_scalar_dyn_rec_pri"),
            read_pri_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block = sample_next_block(&vm, &caller_private_key, &[read_pub_tx, read_pri_tx], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2, "expected both reads to be accepted");
    assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
    assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");
}

// Tests that a function which receives an array of Scalars, reads the first element
// and outputs it, deploys correctly.
#[test]
fn test_program_with_output_scalar_from_array() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    for i in 0..NUM_DEPLOYMENTS {
        let program_str = format!(
            r"
            program test_scalar_array_{i}.aleo;

            function read_scalar_array_pub_pub:
                input r0 as [scalar; 4u32].public;
                output r0[0u32] as scalar.public;

            function read_scalar_array_pub_pri:
                input r0 as [scalar; 4u32].public;
                output r0[0u32] as scalar.private;

            function read_scalar_array_pri_pri:
                input r0 as [scalar; 4u32].private;
                output r0[0u32] as scalar.private;

            function read_scalar_array_pri_pub:
                input r0 as [scalar; 4u32].private;
                output r0[0u32] as scalar.public;

            function closure_wrapper:
                input r0 as [scalar; 4u32].public;
                call clo_read_scalar_array r0 into r1;
                output r1 as scalar.public;

            closure clo_read_scalar_array:
                input r0 as [scalar; 4u32];
                add r0[0u32] 0scalar into r1;
                output r1 as scalar;

            constructor:
                assert.eq true true;
        "
        );

        let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

        // Build and apply the deployment transaction.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // The deployment must be accepted: not rejected and not aborted.
        assert_eq!(block.transactions().num_accepted(), 1, "expected the deployment to be accepted");
        assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
        assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");

        // Commit the deployment so the program can be executed below.
        vm.add_next_block(&block).unwrap();
    }

    // Execute the array-reading functions with a fixed `[scalar; 4]` input and confirm
    // the first element (`1scalar`) is returned by both the direct and closure paths.
    let array_input = [Value::<CurrentNetwork>::from_str("[1scalar, 2scalar, 3scalar, 4scalar]").unwrap()];
    let expected_output = Plaintext::<CurrentNetwork>::from_str("1scalar").unwrap();

    let mut transactions = Vec::with_capacity(2);
    for function in ["read_scalar_array_pub_pub", "closure_wrapper"] {
        let transaction = vm
            .execute(
                &caller_private_key,
                ("test_scalar_array_0.aleo", function),
                array_input.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        assert!(
            matches!(transaction.execution().unwrap().transitions().last().unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
            "unexpected output for {function}"
        );
        transactions.push(transaction);
    }

    let block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), transactions.len(), "expected all executions to be accepted");
    assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
    assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");
}

// Tests that a function which receives a struct holding a Scalar field, reads the
// field and outputs it, deploys correctly.
#[test]
fn test_program_with_output_scalar_from_struct() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    for i in 0..NUM_DEPLOYMENTS {
        let program_str = format!(
            r"
            program test_scalar_struct_{i}.aleo;

            struct wrapper:
                amount as scalar;

            function read_scalar_struct_pub_pub:
                input r0 as wrapper.public;
                output r0.amount as scalar.public;

            function read_scalar_struct_pub_pri:
                input r0 as wrapper.public;
                output r0.amount as scalar.private;

            function read_scalar_struct_pri_pri:
                input r0 as wrapper.private;
                output r0.amount as scalar.private;

            function read_scalar_struct_pri_pub:
                input r0 as wrapper.private;
                output r0.amount as scalar.public;

            function closure_wrapper:
                input r0 as wrapper.public;
                call clo_read_scalar_struct r0 into r1;
                output r1 as scalar.public;

            closure clo_read_scalar_struct:
                input r0 as wrapper;
                add r0.amount 0scalar into r1;
                output r1 as scalar;

            constructor:
                assert.eq true true;
        "
        );

        let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

        // Build and apply the deployment transaction.
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();

        // The deployment must be accepted: not rejected and not aborted.
        assert_eq!(block.transactions().num_accepted(), 1, "expected the deployment to be accepted");
        assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
        assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");

        // Commit the deployment so the program can be executed below.
        vm.add_next_block(&block).unwrap();
    }

    // Execute the struct-reading functions with a fixed `wrapper` input and confirm
    // the scalar field (`1scalar`) is returned by both the direct and closure paths.
    let struct_input = [Value::<CurrentNetwork>::from_str("{ amount: 1scalar }").unwrap()];
    let expected_output = Plaintext::<CurrentNetwork>::from_str("1scalar").unwrap();

    let mut transactions = Vec::with_capacity(2);
    for function in ["read_scalar_struct_pub_pub", "closure_wrapper"] {
        let transaction = vm
            .execute(
                &caller_private_key,
                ("test_scalar_struct_0.aleo", function),
                struct_input.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        assert!(
            matches!(transaction.execution().unwrap().transitions().last().unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
            "unexpected output for {function}"
        );
        transactions.push(transaction);
    }

    let block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), transactions.len(), "expected all executions to be accepted");
    assert_eq!(block.transactions().num_rejected(), 0, "expected no rejected transactions");
    assert!(block.aborted_transaction_ids().is_empty(), "expected no aborted transactions");
}
