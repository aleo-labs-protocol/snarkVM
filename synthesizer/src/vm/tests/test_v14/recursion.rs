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

// This test tests self-recursive dynamic function calls for plaintext types by computing Fibonacci numbers.
#[test]
fn test_fibonacci() {
    let recursive_calls_program_name = Identifier::<CurrentNetwork>::from_str("recursive_calls").unwrap();
    let recursive_calls_program_field = recursive_calls_program_name.to_field().unwrap();

    let fibonacci_name = Identifier::<CurrentNetwork>::from_str("fibonacci").unwrap();
    let fibonacci_function_field = fibonacci_name.to_field().unwrap();

    let base_name = Identifier::<CurrentNetwork>::from_str("base").unwrap();
    let base_function_field = base_name.to_field().unwrap();

    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    // Define the swap program.
    let recursive_calls_program_str = format!(
        r"
        program {recursive_calls_program_name}.aleo; 

        // The recursive case for Fibonacci numbers.
        function {fibonacci_name}:
            input r0 as u64.public;

            // Determine whether the input is zero or one.
            is.eq r0 0u64 into r1;
            is.eq r0 1u64 into r2;
            or r1 r2 into r3;

            // Subtract 1 and 2 from the current index for the recursive cases.
            sub.w r0 1u64 into r4;
            sub.w r0 2u64 into r5;

            // Select the inputs and function based on whether we are handling the recursive case or base case.
            ternary r3 r0 r4 into r6;
            ternary r3 r0 r5 into r7;
            ternary r3 {base_function_field} {fibonacci_function_field} into r8;

            // Call fibonnaci(r0 - 1)
            call.dynamic {recursive_calls_program_field} {aleo_field} r8 with r6 (as u64.public) into r9 (as u64.public);

            // Call fibonacci(r0 - 2)
            call.dynamic {recursive_calls_program_field} {aleo_field} r8 with r7 (as u64.public) into r10 (as u64.public);

            // Return the sum.
            add r9 r10 into r11;
            ternary r3 r9 r11 into r12;
            output r12 as u64.public;

        // The base case for Fibonacci numbers.
        function {base_name}:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
    "
    );

    // Parse program
    let recursive_calls_program = Program::<CurrentNetwork>::from_str(&recursive_calls_program_str).unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program
    println!("Deploying program {recursive_calls_program_name}.aleo...");
    let deployment = vm.deploy(&caller_private_key, &recursive_calls_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);

    // Execute the fibonacci function for the given inputs, expected output, and expected number of transitions.
    #[rustfmt::skip]
    let test_cases = [
        (0, 0, 3), 
        (1, 1, 3), 
        (2, 1, 7), 
        (3, 2, 11), 
        (4, 3, 19)
    ];
    for (fibonnaci_index, expected_output, expected_num_transitions) in test_cases {
        println!("Executing {recursive_calls_program_name}.aleo/{fibonacci_name}...");
        let inputs = vec![Value::from_str(&format!("{fibonnaci_index}u64")).unwrap()];
        let transaction = vm
            .execute(
                &caller_private_key,
                (format!("{recursive_calls_program_name}.aleo"), fibonacci_name),
                inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let execution = transaction.execution().unwrap();
        assert_eq!(execution.transitions().count(), expected_num_transitions);
        assert_eq!(
            execution
                .transitions()
                .last()
                .unwrap()
                .outputs()
                .iter()
                .find_map(|output| match output {
                    Output::Public(_, Some(plaintext)) => Some(plaintext),
                    _ => None,
                })
                .unwrap(),
            &Plaintext::from_str(&format!("{expected_output}u64")).unwrap()
        );
        add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
    }
}

// Tests recursive double-spend detection with static/dynamic records across various call patterns.
//
// This test defines the following functions:
// - `one`: Takes a static record, re-casts it, and outputs the static record.
// - `two`: Takes a static record and returns nothing.
// - `three`: Takes a dynamic record and outputs the dynamic record.
// - `four`: Takes a dynamic record and returns nothing.
// - `five`: Takes a dynamic record and calls `two` twice. This should fail due to double-spend.
// - `six`: Takes a dynamic record and calls `four` twice. This should pass because the record is dynamic.
// - `seven`: Takes a dynamic record and index. If index is zero it calls `two_indexed` (which accepts `dynamic.record`), else it calls itself recursively with index - 1. No translation occurs at any level, so this should pass until the index exceeds the maximum call depth.
// - `eight`: Takes a dynamic record and index. First calls `two`, then either calls `four` if index is zero, or calls itself recursively with index - 1. This should pass if index is zero and fail otherwise due to double-spend.
// - `nine`: Takes a dynamic record and index. First calls `one`, then either calls `three` if index is zero, or calls itself recursively with index - 1 and the new record. This should pass as long as transitions do not exceed the maximum allowed.
//
// `six` passes because `four` accepts `dynamic.record`, so no translation occurs: no serial
// number is created, and the same underlying record can be forwarded to multiple
// `dynamic.record`-accepting callees without double-spend. `five` fails because `two` accepts a
// static `Data.record`, which triggers translation — creating a serial number — so calling it
// twice with the same dynamic record constitutes a double-spend.
#[test]
fn test_recursive_dynamic_record_calls() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Define the first program that defines a record and functions `one`, `two`, `three`, and `four`.
    let basic_records_ops_program_name = Identifier::<CurrentNetwork>::from_str("basic_record_ops").unwrap();

    let one_name = Identifier::<CurrentNetwork>::from_str("one").unwrap();
    let one_field = one_name.to_field().unwrap();

    let two_name = Identifier::<CurrentNetwork>::from_str("two").unwrap();
    let two_field = two_name.to_field().unwrap();

    let three_name = Identifier::<CurrentNetwork>::from_str("three").unwrap();

    let four_name = Identifier::<CurrentNetwork>::from_str("four").unwrap();
    let four_field = four_name.to_field().unwrap();

    let two_indexed_name = Identifier::<CurrentNetwork>::from_str("two_indexed").unwrap();
    let two_indexed_field = two_indexed_name.to_field().unwrap();

    let three_indexed_name = Identifier::<CurrentNetwork>::from_str("three_indexed").unwrap();
    let three_indexed_field = three_indexed_name.to_field().unwrap();

    let four_indexed_name = Identifier::<CurrentNetwork>::from_str("four_indexed").unwrap();
    let four_indexed_field = four_indexed_name.to_field().unwrap();

    let consume_data_name = Identifier::<CurrentNetwork>::from_str("consume_data").unwrap();
    let consume_data_field = consume_data_name.to_field().unwrap();

    // Define the second program that defines functions `five`, `six`, `seven`, `eight`, and `nine`.
    let test_functions_program_name = Identifier::<CurrentNetwork>::from_str("test_functions").unwrap();

    let five_name = Identifier::<CurrentNetwork>::from_str("five").unwrap();

    let six_name = Identifier::<CurrentNetwork>::from_str("six").unwrap();

    let seven_name = Identifier::<CurrentNetwork>::from_str("seven").unwrap();
    let seven_field = seven_name.to_field().unwrap();

    let eight_name = Identifier::<CurrentNetwork>::from_str("eight").unwrap();
    let eight_field = eight_name.to_field().unwrap();

    let nine_name = Identifier::<CurrentNetwork>::from_str("nine").unwrap();
    let nine_field = nine_name.to_field().unwrap();

    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let basic_records_ops_program_field = basic_records_ops_program_name.to_field().unwrap();
    let test_functions_program_field = test_functions_program_name.to_field().unwrap();

    let basic_records_ops_program_str = format!(
        r"
program {basic_records_ops_program_name}.aleo;

record Data:
    owner as address.private;
    data as u64.private;

function mint:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as Data.record;
    output r2 as Data.record;

function {consume_data_name}:
    input r0 as Data.record;

function {one_name}:
    input r0 as Data.record;
    cast r0.owner r0.data into r1 as Data.record;
    output r1 as Data.record;

function {two_name}:
    input r0 as Data.record;

function {three_name}:
    input r0 as dynamic.record;
    output r0 as dynamic.record;

function {four_name}:
    input r0 as dynamic.record;

function {two_indexed_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;

    // Needed to pass the record-existence check (r0 must materialize)
    call.dynamic {basic_records_ops_program_field} {aleo_field} {consume_data_field} with r0 (as dynamic.record);

function {three_indexed_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;
    output r0 as dynamic.record;

function {four_indexed_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;

constructor:
    assert.eq true true;
"
    );

    let test_functions_program_str = format!(
        r"
program {test_functions_program_name}.aleo;

function {five_name}:
    input r0 as dynamic.record;
    call.dynamic {basic_records_ops_program_field} {aleo_field} {two_field} with r0 (as dynamic.record);
    call.dynamic {basic_records_ops_program_field} {aleo_field} {two_field} with r0 (as dynamic.record);

function {six_name}:
    input r0 as dynamic.record;
    call.dynamic {basic_records_ops_program_field} {aleo_field} {four_field} with r0 (as dynamic.record);
    call.dynamic {basic_records_ops_program_field} {aleo_field} {four_field} with r0 (as dynamic.record);

    // Needed to pass the record-existence check (r0 must materialize)
    call.dynamic {basic_records_ops_program_field} {aleo_field} {consume_data_field} with r0 (as dynamic.record);

function {seven_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;
    is.eq r1 0u8 into r2;
    sub.w r1 1u8 into r3;
    ternary r2 {two_indexed_field} {seven_field} into r4;
    ternary r2 {basic_records_ops_program_field} {test_functions_program_field} into r5;
    call.dynamic r5 {aleo_field} r4 with r0 r3 (as dynamic.record u8.public);

function {eight_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;
    call.dynamic {basic_records_ops_program_field} {aleo_field} {two_field} with r0 (as dynamic.record);
    is.eq r1 0u8 into r2;
    sub.w r1 1u8 into r3;
    ternary r2 {four_indexed_field} {eight_field} into r4;
    ternary r2 {basic_records_ops_program_field} {test_functions_program_field} into r5;
    call.dynamic r5 {aleo_field} r4 with r0 r3 (as dynamic.record u8.public);

function {nine_name}:
    input r0 as dynamic.record;
    input r1 as u8.public;
    call.dynamic {basic_records_ops_program_field} {aleo_field} {one_field} with r0 (as dynamic.record) into r2 (as dynamic.record);
    is.eq r1 0u8 into r3;
    sub.w r1 1u8 into r4;
    ternary r3 {three_indexed_field} {nine_field} into r5;
    ternary r3 {basic_records_ops_program_field} {test_functions_program_field} into r6;
    call.dynamic r6 {aleo_field} r5 with r2 r4 (as dynamic.record u8.public) into r7 (as dynamic.record);
    output r7 as dynamic.record;

constructor:
    assert.eq true true;
    "
    );

    // Deploy the programs.
    let basic_records_ops_program = Program::<CurrentNetwork>::from_str(&basic_records_ops_program_str).unwrap();
    let test_functions_program = Program::<CurrentNetwork>::from_str(&test_functions_program_str).unwrap();

    println!("Deploying program {basic_records_ops_program_name}.aleo...");
    let deployment1 = vm.deploy(&caller_private_key, &basic_records_ops_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment1], rng);

    println!("Deploying program {test_functions_program_name}.aleo...");
    let deployment2 = vm.deploy(&caller_private_key, &test_functions_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment2], rng);

    // A helper function to mint a record for the caller.
    let mint_record = |rng: &mut TestRng| {
        println!("Minting record...");
        let mint_inputs =
            vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("100u64").unwrap()];
        let mint_transaction = vm
            .execute(
                &caller_private_key,
                (
                    format!("{basic_records_ops_program_name}.aleo"),
                    Identifier::<CurrentNetwork>::from_str("mint").unwrap(),
                ),
                mint_inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let execution = mint_transaction.execution().unwrap();
        let minted_record = execution
            .transitions()
            .last()
            .unwrap()
            .outputs()
            .iter()
            .find_map(|output| match output {
                Output::Record(_, _, Some(record), _) => Some(record.decrypt(&caller_view_key).unwrap()),
                _ => None,
            })
            .unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[mint_transaction], rng);

        minted_record
    };

    // A helper function to execute a function and check if it succeeds or fails as expected.
    // When `expected_error_substring` is `Some(s)` and execution returns an error, the error
    // message must contain `s`; this guards against silent regressions where the wrong error
    // is raised at execution time.
    let execute_and_check = |function_name: Identifier<CurrentNetwork>,
                             inputs: Vec<Value<CurrentNetwork>>,
                             should_succeed: bool,
                             test_description: &str,
                             expected_error_substring: Option<&str>,
                             rng: &mut TestRng| {
        println!("{test_description}");
        let result = vm.execute(
            &caller_private_key,
            (format!("{test_functions_program_name}.aleo"), function_name),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        );

        if should_succeed {
            let transaction = result.map_err(|e| anyhow!("{function_name} failed with: {e}")).unwrap();
            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
        } else {
            match result {
                Ok(transaction) => {
                    // Check that the transaction fails during addition to the ledger.
                    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
                    assert_eq!(block.transactions().num_accepted(), 0);
                    assert_eq!(block.transactions().num_rejected(), 0);
                    assert_eq!(block.aborted_transaction_ids().len(), 1);
                    vm.add_next_block(&block).unwrap();
                }
                Err(e) => {
                    // Execution-time rejection is valid — verify the error matches expectations.
                    let msg = e.to_string();
                    if let Some(expected) = expected_error_substring {
                        assert!(
                            msg.contains(expected),
                            "{test_description}: expected error containing '{expected}', got: {msg}"
                        );
                    }
                    println!("{test_description}: rejected at execution time: {msg}");
                }
            }
        }
    };

    // Test function `five` which should fail due to double-spend.
    execute_and_check(
        five_name,
        vec![Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap())],
        false,
        &format!("Testing function {five_name} which should fail due to double-spend"),
        Some("serial number"),
        rng,
    );

    // Test function `six` which should pass because the record is dynamic.
    execute_and_check(
        six_name,
        vec![Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap())],
        true,
        &format!("Testing function {six_name} which should pass because the record is dynamic"),
        None,
        rng,
    );

    // Test function `seven` at a valid depth which should pass.
    {
        let test_index = 5u8;
        execute_and_check(
            seven_name,
            vec![
                Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
                Value::from_str(&format!("{test_index}u8")).unwrap(),
            ],
            true,
            &format!("Testing function {seven_name} at index {test_index} which should pass"),
            None,
            rng,
        );
    }

    // Test function `seven` at the maximum valid depth which should pass.
    {
        let test_index = Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 4; // Account for the fee transition, record-consumption and zero indexing.
        execute_and_check(
            seven_name,
            vec![
                Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
                Value::from_str(&format!("{test_index}u8")).unwrap(),
            ],
            true,
            &format!("Testing function {seven_name} at index {test_index} which should pass"),
            None,
            rng,
        );
    }

    // Test function `seven` at the maximum call depth which should fail.
    {
        let test_index = Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 3; // Account for the fee transition, record-consumption and zero indexing.
        execute_and_check(
            seven_name,
            vec![
                Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
                Value::from_str(&format!("{test_index}u8")).unwrap(),
            ],
            false,
            &format!(
                "Testing function {seven_name} at index {test_index} which should fail due to exceeding max call depth"
            ),
            Some("less than"),
            rng,
        );
    }

    // Test function `eight` at index zero which should pass.
    execute_and_check(
        eight_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("0u8").unwrap(),
        ],
        true,
        &format!("Testing function {eight_name} at index 0 which should pass"),
        None,
        rng,
    );

    // Test function `eight` at index one which should fail due to double-spend.
    execute_and_check(
        eight_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("1u8").unwrap(),
        ],
        false,
        &format!("Testing function {eight_name} at index 1 which should fail due to double-spend"),
        Some("serial number"),
        rng,
    );

    // Test function `nine` at index zero which should pass.
    execute_and_check(
        nine_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("0u8").unwrap(),
        ],
        true,
        &format!("Testing function {nine_name} at index 0 which should pass"),
        None,
        rng,
    );

    // Test function `nine` at index one which should pass.
    execute_and_check(
        nine_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("1u8").unwrap(),
        ],
        true,
        &format!("Testing function {nine_name} at index 1 which should pass"),
        None,
        rng,
    );

    // Test function `nine` at index two which should pass.
    execute_and_check(
        nine_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("2u8").unwrap(),
        ],
        true,
        &format!("Testing function {nine_name} at index 2 which should pass"),
        None,
        rng,
    );

    // Test function `nine` at index 15 which should fail due to exceeding the maximum number of transitions.
    execute_and_check(
        nine_name,
        vec![
            Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap()),
            Value::from_str("15u8").unwrap(),
        ],
        false,
        &format!(
            "Testing function {nine_name} at index 15 which should fail due to exceeding the maximum number of transitions"
        ),
        Some("less than"),
        rng,
    );
}

// Tests record-translation security for same-program dynamic calls.
//
// Scenario 1 (PASS): A ledger-committed dynamic record forwarded once to a same-program static consumer.
// Scenario 2 (FAIL): Caller holds a static record, casts it to dynamic, then calls the same-program static consumer — double-spend.
// Scenario 3 (FAIL): Same dynamic record forwarded twice at position 0 to the same-program static consumer.
// Scenario 4 (FAIL): Same dynamic record forwarded at position 0 and position 1 to two different same-program static consumers.
#[test]
fn test_same_program_dynamic_record_security() {
    let rng = &mut TestRng::default();

    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Identifiers used in call.dynamic operands.
    let prog_name = Identifier::<CurrentNetwork>::from_str("record_security").unwrap();
    let prog_field = prog_name.to_field().unwrap();
    let net_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_field = Identifier::<CurrentNetwork>::from_str("consume").unwrap().to_field().unwrap();
    let consume_with_prefix_field =
        Identifier::<CurrentNetwork>::from_str("consume_with_prefix").unwrap().to_field().unwrap();

    // Define the program under test. All functions are in the same program so
    // that each call.dynamic targets the same-program case.
    let program_str = format!(
        r"
program record_security.aleo;

record Data:
    owner as address.private;
    amount as u64.private;

// Mints a Data record.
function mint:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as Data.record;
    output r2 as Data.record;

// Takes a static record as input and consumes it (no output).
// When called via call.dynamic, requires translation of the dynamic record.
function consume:
    input r0 as Data.record;

// Takes a u64 prefix and a static record, consuming the record.
// The record is at operand index 1 (not 0), so id_dynamic differs from
// `consume` when both are called with the same underlying dynamic record.
function consume_with_prefix:
    input r0 as u64.public;
    input r1 as Data.record;

// Scenario 1: valid — dynamic record forwarded to same-program static consumer
// once. The commitment is already in the ledger so translation succeeds and
// the serial number is spent exactly once.
function consume_once:
    input r0 as dynamic.record;
    call.dynamic {prog_field} {net_field} {consume_field}
        with r0 (as dynamic.record);

// Scenario 2: double spend — caller takes the static record as an input (spending
// its serial number), casts it to dynamic, then forwards it to the same-program
// static consumer, which translates and tries to spend the same serial number.
function self_cast_and_call:
    input r0 as Data.record;
    cast r0 into r1 as dynamic.record;
    call.dynamic {prog_field} {net_field} {consume_field}
        with r1 (as dynamic.record);

// Scenario 3: same-position double translation — the same dynamic record is
// forwarded to `consume` at operand position 0 in two successive call.dynamic
// instructions. Both produce an identical id_dynamic and therefore the same
// translated serial number.
function double_consume_same_pos:
    input r0 as dynamic.record;
    call.dynamic {prog_field} {net_field} {consume_field}
        with r0 (as dynamic.record);
    call.dynamic {prog_field} {net_field} {consume_field}
        with r0 (as dynamic.record);

// Scenario 4: different-position double translation — the same dynamic record
// is forwarded at operand position 0 in the first call (to `consume`) and at
// operand position 1 in the second call (to `consume_with_prefix`, which takes
// a u64 prefix before the record). The id_dynamic values differ between the two
// calls; this scenario tests whether the protection extends to position-mismatched
// reuse of the same underlying record.
function double_consume_diff_pos:
    input r0 as dynamic.record;
    call.dynamic {prog_field} {net_field} {consume_field}
        with r0 (as dynamic.record);
    call.dynamic {prog_field} {net_field} {consume_with_prefix_field}
        with 42u64 r0 (as u64.public dynamic.record);

constructor:
    assert.eq true true;
"
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    println!("Deploying record_security.aleo...");
    let deploy_tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Helper: mint a Data record and add it to the ledger.
    let mint_record = |rng: &mut TestRng| {
        let mint_inputs =
            vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("100u64").unwrap()];
        let tx = vm
            .execute(&caller_private_key, ("record_security.aleo", "mint"), mint_inputs.iter(), None, 0, None, rng)
            .unwrap();
        let record = tx
            .transitions()
            .next()
            .unwrap()
            .outputs()
            .iter()
            .find_map(|o| match o {
                Output::Record(_, _, Some(ct), _) => Some(ct.decrypt(&caller_view_key).unwrap()),
                _ => None,
            })
            .unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[tx], rng);
        record
    };

    // Helper: execute a function and verify it succeeds or fails as expected.
    // A transaction that is aborted when added to the ledger is treated as a failure.
    // When `expected_error_substring` is `Some(s)` and execution returns an error, the error
    // message must contain `s`; this guards against silent regressions where the wrong error
    // is raised at execution time.
    let execute_and_check = |function_name: &str,
                             inputs: Vec<Value<CurrentNetwork>>,
                             should_succeed: bool,
                             description: &str,
                             expected_error_substring: Option<&str>,
                             rng: &mut TestRng| {
        println!("{description}");
        let result =
            vm.execute(&caller_private_key, ("record_security.aleo", function_name), inputs.iter(), None, 0, None, rng);

        if should_succeed {
            let tx = result.unwrap_or_else(|e| panic!("Expected {description} to succeed: {e}"));
            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);
        } else {
            match result {
                Ok(tx) => {
                    let block = sample_next_block(&vm, &caller_private_key, &[tx], rng).unwrap();
                    assert_eq!(block.transactions().num_accepted(), 0, "{description}: expected 0 accepted");
                    assert_eq!(block.aborted_transaction_ids().len(), 1, "{description}: expected 1 aborted");
                    vm.add_next_block(&block).unwrap();
                }
                Err(e) => {
                    // Execution-time rejection is valid — verify the error matches expectations.
                    let msg = e.to_string();
                    if let Some(expected) = expected_error_substring {
                        assert!(
                            msg.contains(expected),
                            "{description}: expected error containing '{expected}', got: {msg}"
                        );
                    }
                    println!("{description}: rejected at execution time: {msg}");
                }
            }
        }
    };

    execute_and_check(
        "consume_once",
        vec![Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap())],
        true,
        "Scenario 1: valid single same-program translation should succeed",
        None,
        rng,
    );

    execute_and_check(
        "self_cast_and_call",
        vec![Value::Record(mint_record(rng))],
        false,
        "Scenario 2: self-cast double spend must fail",
        Some("serial number"),
        rng,
    );

    execute_and_check(
        "double_consume_same_pos",
        vec![Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap())],
        false,
        "Scenario 3: same-position double translation must fail",
        Some("serial number"),
        rng,
    );

    execute_and_check(
        "double_consume_diff_pos",
        vec![Value::DynamicRecord(DynamicRecord::from_record(&mint_record(rng)).unwrap())],
        false,
        "Scenario 4: different-position double translation must fail",
        Some("serial number"),
        rng,
    );
}
