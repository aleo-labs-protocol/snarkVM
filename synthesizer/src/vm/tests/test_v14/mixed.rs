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

use console::types::Scalar;

use super::*;

// These tests mix translation, casting to `dynamic.record`, `get.record.dynamic` and other functionality.

// Tests that `execution_cost_for_authorization()` and
// `execution_cost_for_call()` compute correct costs for transactions with
// inclusion and translation proofs. Complements test cases in
// `synthesizer/tests/test_vm_execute_and_finalize.rs` and
// `test_v15/cost_for_call.rs` which also verify cost estimation correctness.
#[test]
fn test_execution_cost_for_authorization_and_call() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();
    let caller_address_str = caller_address.to_string();
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    let program_a_str = "welder";
    let program_b_str = "payment_checker";
    let network_str = "aleo";
    let weld_function_str = "weld";
    let check_tossed_coin_str = "check_tossed_coin";

    let program_a_field = Identifier::<CurrentNetwork>::from_str(program_a_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str(network_str).unwrap().to_field().unwrap();
    let weld_function_id = Identifier::<CurrentNetwork>::from_str(weld_function_str).unwrap();
    let weld_function_field = weld_function_id.to_field().unwrap();

    let program_a_source = format!(
        r"
        program {program_a_str}.aleo;

        record base_metal:
            owner as address.private;
            metal_id as u16.public;
            grams as u32.private;
            weldable as boolean.public;
        
        record accessory_metal:
            owner as address.private;
            metal_id as u16.public;
            grams as u32.private;
            signature_val as group.public;
        
        struct welding_pair:
            base_metal_id as u16;
            accessory_metal_id as u16;

        record welding_metal:
            owner as address.private;
            welds as welding_pair.public;

        record welded_chunk:
            owner as address.private;
            grams as u32.private;
        
        function mint_base_metal:
            input r0 as address.private;
            input r1 as u16.public;
            input r2 as u32.private;
            input r3 as boolean.public;

            cast r0 r1 r2 r3 into r4 as base_metal.record;

            output r4 as base_metal.record;

        function mint_accessory_metal:
            input r0 as address.private;
            input r1 as u16.public;
            input r2 as u32.private;
            input r3 as group.public;

            cast r0 r1 r2 r3 into r4 as accessory_metal.record;

            output r4 as accessory_metal.record;

        function mint_welding_metal:
            input r0 as address.private;
            input r1 as u16.public;
            input r2 as u16.public;

            cast r1 r2 into r3 as welding_pair;

            cast r0 r3 into r4 as welding_metal.record;

            output r4 as welding_metal.record;

        function {weld_function_str}:
            input r0 as base_metal.record;
            input r1 as accessory_metal.record;
            input r2 as welding_metal.record;

            assert.eq r0.metal_id r2.welds.base_metal_id;
            assert.eq r1.metal_id r2.welds.accessory_metal_id;
            assert.eq r0.weldable true;

            add r0.grams r1.grams into r3;

            cast r0.owner r3 into r4 as welded_chunk.record;

            output r4 as welded_chunk.record;

        function weld_dynamically:
            // Expected type: base_metal.record
            input r0 as dynamic.record;
            // Expected type: accessory_metal.record
            input r1 as dynamic.record;
            // Expected type: welding_metal.record
            input r2 as dynamic.record;

            call.dynamic {program_a_field} {network_field} {weld_function_field}
                with r0 r1 r2 (as dynamic.record dynamic.record dynamic.record)
                into r3 (as dynamic.record);

            get.record.dynamic r3.grams into r4 as u32;

            output r4 as u32.public;

        function consume_base_metal:
            input r0 as base_metal.record;
        
        constructor:
            assert.eq true true;
        "
    );

    let program_b_source = format!(
        r"
        import {program_a_str}.aleo;

        program {program_b_str}.aleo;

        // Check that the metal used to pay for the welding in program a is not weldable
        function {check_tossed_coin_str}:
            input r0 as {program_a_str}.aleo/base_metal.record;
            assert.eq r0.weldable false;
        
        constructor:
            assert.eq true true;
        "
    );

    let program_a = Program::<CurrentNetwork>::from_str(&program_a_source).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_source).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the programs.
    println!("Deploying program {program_a_str}.aleo...");
    let transaction_deploy_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy_a], rng);

    println!("Deploying program {program_b_str}.aleo...");
    let transaction_deploy_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy_b], rng);

    let record_names = ["base_metal", "accessory_metal", "welding_metal"];

    let entry_values = vec![
        [&caller_address_str, "183u16", "999u32", "true"]
            .iter()
            .map(|value| Value::from_str(value).unwrap())
            .collect_vec(),
        [&caller_address_str, "82u16", "27u32", "0group"]
            .iter()
            .map(|value| Value::from_str(value).unwrap())
            .collect_vec(),
        [&caller_address_str, "183u16", "82u16"].iter().map(|value| Value::from_str(value).unwrap()).collect_vec(),
    ];

    let transactions_and_records = record_names
        .into_iter()
        .zip(entry_values.clone())
        .map(|(record_name, entry_values)| {
            let function_name = format!("mint_{record_name}");

            println!("Calling {program_a_str}.aleo/{function_name}...");

            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("welder.aleo", function_name),
                    entry_values.into_iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            let record = match &transaction_mint.transitions().next().unwrap().outputs()[0] {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
                }
                _ => panic!("Expected output record is not a record"),
            };

            (transaction_mint, record)
        })
        .collect_vec();

    let (transactions_mint, records): (Vec<_>, Vec<_>) = transactions_and_records.into_iter().unzip();

    let entry_value_slice = entry_values.iter().map(|values| values.as_slice()).collect_vec();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&entry_value_slice), &transactions_mint, rng);

    let dynamic_records = records
        .into_iter()
        .map(|record| Value::DynamicRecord(DynamicRecord::<CurrentNetwork>::from_record(&record).unwrap()))
        .collect_vec();

    println!("Executing {program_a_str}.aleo/weld_dynamically...");

    let count_before_weld_dynamically = vm.transition_store().records().count();

    let transaction = vm
        .execute(&caller_private_key, ("welder.aleo", "weld_dynamically"), dynamic_records.iter(), None, 0, None, rng)
        .unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("1026u32").unwrap();

    assert!(
        // The root transition is at index 1.
        matches!(transaction.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "Expected output: {:?}, got: {:?}",
        expected_output,
        transaction.transitions().next().unwrap().outputs()
    );

    // The batch sizes involved in the cost computation are [1, 1, 1, 3, 2, 1, 1], where:
    // - the first 3 ones come from the three distinct transitions
    // - the next three comes from the single batch of three inclusion proofs, one for each record consumed.
    //   Note the second base_metal record is never consumed, since it is received as a dynamic record by weld
    //   and as an external record by check_tossed_coin.
    // - the next two comes from the two (input) translations for base_metal.record
    //   - as a non-external static record in weld
    //   - as an external static record in check_tossed_coin
    // - the next 2 ones come from the (input) translations for accessory_metal.record and welding_metal.record
    // - the next one comes from the (output) translation for welded_chunk.record

    // Ensuring transaction verification passes
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&dynamic_records]), &[transaction], rng);

    // We check exactly one static record has been produced, even though it was
    // translated to a dynamic one when output
    assert_eq!(vm.transition_store().records().count(), count_before_weld_dynamically + 1);
}

// Tests an integration scenario combining translation, `get.record.dynamic`, and cast to `dynamic.record` with signature verification.
#[test]
fn test_translation_get_dynamic_cast_to_dynamic() {
    let rng = &mut TestRng::default();

    let factory_private_key = sample_genesis_private_key(rng);

    let client_1_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let client_1_address = Address::try_from(&client_1_private_key).unwrap();
    let client_1_view_key = ViewKey::<CurrentNetwork>::try_from(client_1_private_key).unwrap();

    let client_2_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let client_2_address = Address::try_from(&client_2_private_key).unwrap();
    let client_2_view_key = ViewKey::<CurrentNetwork>::try_from(client_2_private_key).unwrap();

    let program_a_name = Identifier::<CurrentNetwork>::from_str("manager").unwrap();
    let program_b_name = Identifier::<CurrentNetwork>::from_str("factory").unwrap();
    let network_name = Identifier::<CurrentNetwork>::from_str("aleo").unwrap();
    let function_verify_signature_name = Identifier::<CurrentNetwork>::from_str("verify_signature").unwrap();

    let program_a_field = program_a_name.to_field().unwrap();
    let network_field = network_name.to_field().unwrap();
    let function_verify_signature_field = function_verify_signature_name.to_field().unwrap();

    let generator = CurrentNetwork::g_scalar_multiply(&Scalar::one());

    // Signatures for products operate as follows:
    // 1. The factory receives a request for a toy/ladder from a client and
    //    generates a random product ID (it can e. g. keep an off-chain registry
    //    to avoid duplicates). It then produces the requested product record,
    //    which includes the generated ID.
    // 2. The client can decrypt the record and compute the signature
    //        s = vk + product_id
    //    where vk is the client account' view key
    // 3. A function called by the client and receiving this signature as a
    //    private input can verify it by checking
    //        s * G = owner_address + (product_id * G),
    //    since owner_address = vk * G.

    let program_a_str = format!(
        r"
        program {program_a_name}.aleo;

        // Checks that the equation s * G == owner_address + (product_id * G) holds,
        // where s is a private value passed as the second input and G is the
        // generator of the distinguished subgroup inside the protocol curve.
        function {function_verify_signature_name}:
            input r0 as dynamic.record;
            input r1 as scalar.private;

            // Left-hand side (the group element is G)
            mul r1 {generator} into r2;
            
            // Right-hand side
            cast r0.owner into r3 as group;
            get.record.dynamic r0.product_id into r4 as scalar;
            mul r4 {generator} into r5;
            add r3 r5 into r6;

            is.eq r2 r6 into r7;

            output r7 as boolean.public;

        constructor:
            assert.eq true true;
        "
    );

    // Note: by making the product ID private for toys and public for ladders,
    // we are also testing get.dynamic.crecord can read entries regardless of
    // their visibility, as expected.
    let program_b_str = format!(
        r"
        import {program_a_name}.aleo;
    
        program {program_b_name}.aleo;

        record toy:
            owner as address.private;
            
            // The ID of the type of toy
            type_id as u16.public;
            // The unique (also across ladders below) ID of this specific product
            // It is private for toys
            product_id as scalar.private;
            // Years since the toy was manufactured
            years_old as u8.private;

        record ladder:
            owner as address.private;

            // The unique (also across toys above) ID of this specific product
            // It is public for ladders
            product_id as scalar.public;
            // Whether the ladder has been painted or not
            painted as boolean.public;

        function manufacture_toy:
            input r0 as address.private;
            input r1 as u16.public;
            input r2 as scalar.private;

            cast r0 r1 r2 0u8 into r3 as toy.record;

            output r3 as toy.record;

        function manufacture_ladder:
            input r0 as address.private;
            input r1 as scalar.private;

            cast r0 r1 false into r2 as ladder.record;

            output r2 as ladder.record;

        // Consume the toy assuming the provided secret is valid
        function decomission_toy:
            input r0 as toy.record;
            input r1 as scalar.private;

            cast r0 into r2 as dynamic.record;

            call.dynamic {program_a_field} {network_field} {function_verify_signature_field}
                with r2 r1 (as dynamic.record scalar.private)
                into r3 (as boolean.public);

            assert.eq r3 true;
        
        // Consume the ladder assuming the provided secret is valid
        function decomission_ladder:
            input r0 as ladder.record;
            input r1 as scalar.private;

            cast r0 into r2 as dynamic.record;

            call.dynamic {program_a_field} {network_field} {function_verify_signature_field}
                with r2 r1 (as dynamic.record scalar.private)
                into r3 (as boolean.public);

            assert.eq r3 true;

        // Paint the ladder
        function paint_ladder:
            input r0 as ladder.record;

            assert.eq r0.painted false;

            cast r0.owner r0.product_id true into r1 as ladder.record;

            output r1 as ladder.record;

        constructor:
            assert.eq true true;
        "
    );

    let program_a = Program::<CurrentNetwork>::from_str(&program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the programs.
    println!("Deploying program {program_a_name}.aleo...");
    let transaction_deploy_a = vm.deploy(&factory_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &factory_private_key, None, &[transaction_deploy_a], rng);

    println!("Deploying program {program_b_name}.aleo...");
    let transaction_deploy_b = vm.deploy(&factory_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &factory_private_key, None, &[transaction_deploy_b], rng);

    // Fund the clients so they can call functions, e. g. to decomission toys

    let inputs_1 = [Value::from_str(&format!("{client_1_address}")).unwrap(), Value::from_str("1000000u64").unwrap()];

    let transaction_funding_1 = vm
        .execute(&factory_private_key, ("credits.aleo", "transfer_public"), inputs_1.iter(), None, 0, None, rng)
        .unwrap();

    let inputs_2 = [Value::from_str(&format!("{client_2_address}")).unwrap(), Value::from_str("1000000u64").unwrap()];

    let transaction_funding_2 = vm
        .execute(&factory_private_key, ("credits.aleo", "transfer_public"), inputs_2.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(
        &vm,
        &factory_private_key,
        Some(&[&inputs_1, &inputs_2]),
        &[transaction_funding_1, transaction_funding_2],
        rng,
    );

    // ************************** Case 1: Toy decomissioning **************************

    // Manufacture a toy for client 1
    let toy_1_id: Scalar<CurrentNetwork> = Uniform::rand(rng);

    let toy_1_inputs = [
        Value::from_str(&client_1_address.to_string()).unwrap(),
        Value::from_str("34u16").unwrap(),
        Value::from_str(&toy_1_id.to_string()).unwrap(),
    ];

    println!("Executing {program_b_name}.aleo/manufacture_toy...");

    let transaction_mint_toy_1 = vm
        .execute(&client_1_private_key, ("factory.aleo", "manufacture_toy"), toy_1_inputs.iter(), None, 0, None, rng)
        .unwrap();

    let toy_1_record = match &transaction_mint_toy_1.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&client_1_view_key).unwrap()
        }
        _ => panic!("Expected output record is not a record"),
    };

    add_and_test_with_costs(&vm, &client_1_private_key, Some(&[&toy_1_inputs]), &[transaction_mint_toy_1], rng);

    // Computing the signature
    let toy_1_signature = toy_1_id + *client_1_view_key;

    let decomission_toy_inputs =
        [Value::from_str(&toy_1_record.to_string()).unwrap(), Value::from_str(&toy_1_signature.to_string()).unwrap()];

    let number_of_consumed_records_before = vm.transition_store().serial_numbers().count();

    println!("Executing {program_b_name}.aleo/decomission_toy...");

    let transaction_decomission_toy_1 = vm
        .execute(
            &client_1_private_key,
            ("factory.aleo", "decomission_toy"),
            decomission_toy_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(
        &vm,
        &client_1_private_key,
        Some(&[&decomission_toy_inputs]),
        &[transaction_decomission_toy_1],
        rng,
    );

    // Check exactly one record has been consumed (despite the cast to dynamic +
    // dynamic call)
    assert_eq!(vm.transition_store().serial_numbers().count(), number_of_consumed_records_before + 1);

    // ********** Case 2: Ladder painting, failed and successful decomissioning **********

    // Manufacture a ladder for client 2
    let ladder_1_id: Scalar<CurrentNetwork> = Uniform::rand(rng);

    let ladder_1_inputs =
        [Value::from_str(&client_2_address.to_string()).unwrap(), Value::from_str(&ladder_1_id.to_string()).unwrap()];

    println!("Executing {program_b_name}.aleo/manufacture_ladder...");

    let transaction_mint_ladder_1 = vm
        .execute(
            &factory_private_key,
            ("factory.aleo", "manufacture_ladder"),
            ladder_1_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let unpainted_ladder_1_record = match &transaction_mint_ladder_1.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&client_2_view_key).unwrap()
        }
        _ => panic!("Expected output record is not a record"),
    };

    let unpainted_entry_1 = match unpainted_ladder_1_record
        .data()
        .get(&Identifier::<CurrentNetwork>::from_str("painted").unwrap())
        .unwrap()
    {
        Entry::Public(plaintext) => plaintext,
        _ => panic!("Expected painted entry to be public"),
    };

    assert_eq!(unpainted_entry_1, &Plaintext::from_str("false").unwrap());

    add_and_test_with_costs(&vm, &factory_private_key, Some(&[&ladder_1_inputs]), &[transaction_mint_ladder_1], rng);

    println!("Executing {program_b_name}.aleo/paint_ladder...");

    // Paint the ladder
    let paint_inputs = vec![Value::Record(unpainted_ladder_1_record)];
    let transaction_paint_ladder_1 = vm
        .execute(&client_2_private_key, ("factory.aleo", "paint_ladder"), paint_inputs.iter(), None, 0, None, rng)
        .unwrap();

    let painted_ladder_1_record = match &transaction_paint_ladder_1.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&client_2_view_key).unwrap()
        }
        _ => panic!("Expected output record is not a record"),
    };

    let painted_entry_1 = match painted_ladder_1_record
        .data()
        .get(&Identifier::<CurrentNetwork>::from_str("painted").unwrap())
        .unwrap()
    {
        Entry::Public(plaintext) => plaintext,
        _ => panic!("Expected painted entry to be public"),
    };

    assert_eq!(painted_entry_1, &Plaintext::from_str("true").unwrap());

    add_and_test_with_costs(&vm, &client_2_private_key, Some(&[&paint_inputs]), &[transaction_paint_ladder_1], rng);

    // Computing an incorrect signature (uses client 1's view key)
    let ladder_1_incorrect_signature = ladder_1_id + *client_1_view_key;

    let decomission_toy_inputs = [
        Value::from_str(&painted_ladder_1_record.to_string()).unwrap(),
        Value::from_str(&ladder_1_incorrect_signature.to_string()).unwrap(),
    ];

    println!("Executing {program_b_name}.aleo/decomission_ladder (incorrect)...");

    assert!(
        vm.execute(
            // We still execute with client 2's private key so that record
            // consumption can proceed - it is the product-signature we would
            // like to fail.
            &client_2_private_key,
            ("factory.aleo", "decomission_ladder"),
            decomission_toy_inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .is_err()
    );

    // Correctly decomission the ladder (uses client 2's view key)
    let ladder_1_correct_signature = ladder_1_id + *client_2_view_key;

    let decomission_ladder_inputs = [
        Value::from_str(&painted_ladder_1_record.to_string()).unwrap(),
        Value::from_str(&ladder_1_correct_signature.to_string()).unwrap(),
    ];

    println!("Executing {program_b_name}.aleo/decomission_ladder...");

    let transaction_correct_decomission_ladder_1 = vm
        .execute(
            &client_2_private_key,
            ("factory.aleo", "decomission_ladder"),
            decomission_ladder_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    println!("Executing {program_b_name}.aleo/decomission_ladder (incorrect)...");

    // Attemtping to decomission the ladder again should fail (the record has already been nullified)
    let transaction_decomission_ladder_1_again = vm
        .execute(
            &client_2_private_key,
            ("factory.aleo", "decomission_ladder"),
            decomission_ladder_inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let decomission_ladder_1_again_id = transaction_decomission_ladder_1_again.id();

    let ladder_1_decomission_transactions =
        [transaction_correct_decomission_ladder_1, transaction_decomission_ladder_1_again];

    let block = sample_next_block(&vm, &client_1_private_key, &ladder_1_decomission_transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids(), &[decomission_ladder_1_again_id]);
}
