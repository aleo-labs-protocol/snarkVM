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

// Tests `get.record.dynamic` for extracting entries from dynamic records including polymorphic reads and failure modes.
#[test]
fn test_get_record_dynamic() {
    // Parameters for dynamic function calls
    let program_name_str = "warehouse";
    let network_str = "aleo";
    let mint_nineties_bleach_function_str = "mint_nineties_bleach";
    let mint_fake_compliance_cert_function_str = "mint_fake_compliance_cert";

    let program_name_field = Identifier::<CurrentNetwork>::from_str(program_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str(network_str).unwrap().to_field().unwrap();
    let mint_nineties_bleach_function_field =
        Identifier::<CurrentNetwork>::from_str(mint_nineties_bleach_function_str).unwrap().to_field().unwrap();
    let mint_fake_compliance_cert_function_field =
        Identifier::<CurrentNetwork>::from_str(mint_fake_compliance_cert_function_str).unwrap().to_field().unwrap();
    let consume_function_field = Identifier::<CurrentNetwork>::from_str("consume").unwrap().to_field().unwrap();

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

    // Initialize a new program.
    let program_str = format!(
        r"
        program {program_name_str}.aleo;

        struct safety_struct:
            first as field;
            second as field;

        record consumable:
            owner as address.private;
            // D, M, Y
            expiry_date as [u8; 3u32].private;
            critical as boolean.public;
            // D, M, Y
            production_date as [u8; 3u32].public;

        record non_consumable:
            owner as address.private;
            amount as u64.private;
            producer_country_code as u16.public;
            producer_pk as group.private;
            id as field.public;
            production_date as [u8; 3u32].public;
            safety as safety_struct.public;

        function mint_consumable:
            cast 2u8 3u8 92u8 into r0 as [u8; 3u32];
            cast 10u8 7u8 12u8 into r1 as [u8; 3u32];
            cast {caller_address} r0 true r1 into r2 as consumable.record;
            
            output r2 as consumable.record;

        function consume:
            input r0 as consumable.record;

        function production_month:
            input r0 as dynamic.record;
            get.record.dynamic r0.production_date into r1 as [u8; 3u32];
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_function_field} with r0 (as dynamic.record);
            output r1[1u32] as u8.public;

        function production_month_as_u16:
            input r0 as dynamic.record;
            get.record.dynamic r0.production_date into r1 as [u16; 3u32];
            output r1[1u32] as u16.public;
        
        function production_year_difference:
            call.dynamic {program_name_field} {network_field} {mint_nineties_bleach_function_field} into r0 (as dynamic.record);
            call.dynamic {program_name_field} {network_field} {mint_fake_compliance_cert_function_field} into r1 (as dynamic.record);
            
            get.record.dynamic r0.production_date into r2 as [u8; 3u32];
            get.record.dynamic r1.production_date into r3 as [u8; 3u32];

            sub r2[2u32] r3[2u32] into r4;

            output r4 as u8.public;

        function {mint_nineties_bleach_function_str}:
            cast 10u8 9u8 92u8 into r0 as [u8; 3u32];
            cast 10u8 9u8 42u8 into r1 as [u8; 3u32];

            cast {caller_address} r0 true r1 into r2 as consumable.record;

            output r2 as consumable.record;

        function {mint_fake_compliance_cert_function_str}:
            cast 11u8 7u8 17u8 into r0 as [u8; 3u32];
            cast 10field 13field into r1 as safety_struct;

            cast {caller_address} 2u64 91u16 2group 1field r0 r1 into r2 as non_consumable.record;

            output r2 as non_consumable.record;

        function read_producer_country:
            input r0 as dynamic.record;
            get.record.dynamic r0.producer_country_code into r1 as u16;
            output r1 as u16.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program.
    println!("Deploying program warehouse.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    /************** Case 1: Simple read **************/

    let mut dynamic_consumable_records = (0..3)
        .map(|_| {
            // Mint a consumable record
            println!("Minting consumable record...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("warehouse.aleo", "mint_consumable"),
                    mint_inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap().clone();

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    println!("Executing root function warehouse.aleo/production_month...");
    let inputs_1 = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_consumable_records.pop().unwrap())];
    let transaction_1 = vm
        .execute(&caller_private_key, ("warehouse.aleo", "production_month"), inputs_1.iter(), None, 0, None, rng)
        .unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("7u8").unwrap();

    assert!(
        matches!(transaction_1.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "Expected output: {:?}, got: {:?}",
        expected_output,
        transaction_1.transitions().nth(1).unwrap().outputs()
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_1]), &[transaction_1], rng);

    /************** Case 2: Read from minted records (using polymorphy) **************/

    // In this case a function outputs two static records of different types that are received as
    // dynamic by the caller; and the caller then proceeds to field two fields with the same name
    // that the two static-record types happen to have.

    println!("Executing root function warehouse.aleo/production_year_difference...");
    let inputs_2: Vec<Value<CurrentNetwork>> = vec![];
    let transaction_2 = vm
        .execute(
            &caller_private_key,
            ("warehouse.aleo", "production_year_difference"),
            inputs_2.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("25u8").unwrap();

    assert!(
        // The first two transactions correspond to the two minting operations
        matches!(transaction_2.transitions().nth(2).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "Expected output: {:?}, got: {:?}",
        expected_output,
        transaction_2.transitions().next().unwrap().outputs()
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_2]), &[transaction_2], rng);

    /************** Case 3: Various incorrect readings **************/

    // We trigger get.record.dynamic failures in various ways

    // Case 3.1: We attempt to read the field "producer_country_code" from a
    // dynamic record derived from a static consumable.record, which does not
    // have one.

    println!("Executing root function warehouse.aleo/read_producer_country (should fail)...");

    let record_dynamic = dynamic_consumable_records.pop().unwrap();
    assert!(
        vm.execute(
            &caller_private_key,
            ("warehouse.aleo", "read_producer_country"),
            vec![Value::<CurrentNetwork>::DynamicRecord(record_dynamic.clone())].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("does not contain entry producer_country_code")
    );

    // Case 3.2: We manipulate the root of the already created dynamic record,
    // which will cause the Merkle root to fail in a read which would otherwise
    // succeed. Note that failure already occurs at the (honest) prover side.
    let manipulated_record_dynamic = DynamicRecord::new_unchecked(
        *record_dynamic.owner(),
        Uniform::rand(rng),
        *record_dynamic.nonce(),
        *record_dynamic.version(),
        record_dynamic.data().clone(),
    );

    println!("Executing root function warehouse.aleo/production_month (should fail)...");

    assert!(
        vm.execute(
            &caller_private_key,
            ("warehouse.aleo", "production_month"),
            vec![Value::<CurrentNetwork>::DynamicRecord(manipulated_record_dynamic)].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("root in the dynamic record does not match")
    );

    // Case 3.3: We attempt to read the field "production_date" as an array of
    // u16 instead of the actual u8.
    println!("Executing root function warehouse.aleo/production_month_as_u16 (should fail)...");

    let record_dynamic = dynamic_consumable_records.pop().unwrap();

    assert!(
        vm.execute(
            &caller_private_key,
            ("warehouse.aleo", "production_month_as_u16"),
            vec![Value::<CurrentNetwork>::DynamicRecord(record_dynamic.clone())].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("Type mismatch")
    );

    // Case 3.4: We attempt to read the field "production_date" from a different
    // leaf index than it had when the Merkle root was computed.

    let mut manipulated_record_data = record_dynamic.data().clone().unwrap();
    assert!(
        manipulated_record_data
            .get_index_of(&Identifier::<CurrentNetwork>::from_str("production_date").unwrap())
            .unwrap()
            == 2
    );
    manipulated_record_data.swap_indices(1, 2);

    let manipulated_record_dynamic_2 = DynamicRecord::new_unchecked(
        *record_dynamic.owner(),
        Uniform::rand(rng),
        *record_dynamic.nonce(),
        *record_dynamic.version(),
        Some(manipulated_record_data),
    );

    println!("Executing root function warehouse.aleo/production_month (should fail)...");

    assert!(
        vm.execute(
            &caller_private_key,
            ("warehouse.aleo", "production_month"),
            vec![Value::<CurrentNetwork>::DynamicRecord(manipulated_record_dynamic_2)].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("root in the dynamic record does not match")
    );
}

// Translates the output of a call to `credits.aleo/transfer_public_to_private` into a dynamic record.
// This ensures signature verification has not been broken by the new caller metadata.
// **** Note **** This test must exceptionally be run at ConsensusVersion::V18 now that credits
//                translation has been gated by that version.
#[test]
fn translate_transfer_public_to_private() {
    let credits_program_str = Identifier::<CurrentNetwork>::from_str("credits").unwrap();
    let network_str = "aleo";
    let transfer_function_name = Identifier::<CurrentNetwork>::from_str("transfer_public_to_private").unwrap();
    let credits_field = credits_program_str.to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str(network_str).unwrap().to_field().unwrap();
    let transfer_function_field = transfer_function_name.to_field().unwrap();

    let program_str = format!(
        r"
        program dynamic_credits.aleo;

        // Calls transfer_public_to_private and publicly outputs amount
        function transfer_pub_priv_and_inform:
            input r0 as u64.private;

            call.dynamic {credits_field} {network_field} {transfer_function_field}
                with self.caller r0 (as address.private u64.public)
                into r1 r2 (as dynamic.record dynamic.future);

            get.record.dynamic r1.microcredits into r3 as u64;

            async transfer_pub_priv_and_inform r2 into r4;

            output r3 as u64.public;
            output r4 as dynamic_credits.aleo/transfer_pub_priv_and_inform.future;

        finalize transfer_pub_priv_and_inform:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
    "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let rng = &mut TestRng::default();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18).unwrap(), rng);

    let caller_private_key = sample_genesis_private_key(rng);
    let address = Address::try_from(&caller_private_key).unwrap();
    println!("Caller address: {address}");

    // Deploy the program
    println!("Deploying program dynamic_credits.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    // Print the initial balance
    let Some(Value::Plaintext(Plaintext::Literal(Literal::U64(initial_balance), _))) = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::<CurrentNetwork>::from_str("credits.aleo").unwrap(),
            Identifier::from_str("account").unwrap(),
            &Plaintext::from_str(&address.to_string()).unwrap(),
        )
        .unwrap()
    else {
        panic!("Failed to get initial balance");
    };
    println!("Initial balance: {initial_balance}");

    // Deposit some credits to the program.
    let transfer_public_inputs = vec![
        Value::from_str(
            &ProgramID::<CurrentNetwork>::from_str("dynamic_credits.aleo").unwrap().to_address().unwrap().to_string(),
        )
        .unwrap(),
        Value::<CurrentNetwork>::from_str("57u64").unwrap(),
    ];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            transfer_public_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&transfer_public_inputs]), &[transaction], rng);

    // Execute the dynamic call.
    println!("Executing root function dynamic_credits.aleo/transfer_pub_priv_and_inform...");
    let transfer_inputs = vec![Value::<CurrentNetwork>::from_str("57u64").unwrap()];
    let transaction_transfer = vm
        .execute(
            &caller_private_key,
            ("dynamic_credits.aleo", "transfer_pub_priv_and_inform"),
            transfer_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&transfer_inputs]), &[transaction_transfer], rng);
}

// Tests `dynamic.record` with 10 fields to verify the depth-5 Merkle tree handles larger records correctly.
#[test]
fn test_dynamic_record_with_many_fields() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("many_fields").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_large_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_large").unwrap().to_field().unwrap();

    // Program with a record containing many fields
    let program_str = format!(
        r"
        program many_fields.aleo;

        record large_record:
            owner as address.private;
            field1 as u64.public;
            field2 as u64.public;
            field3 as u64.public;
            field4 as u64.public;
            field5 as u64.public;
            field6 as u64.private;
            field7 as u64.private;
            field8 as u64.private;
            field9 as u64.private;
            field10 as u64.private;

        function consume_large:
            input r0 as large_record.record;

        function mint_large:
            cast {caller_address} 1u64 2u64 3u64 4u64 5u64 6u64 7u64 8u64 9u64 10u64 into r0 as large_record.record;
            output r0 as large_record.record;

        function read_field5:
            input r0 as dynamic.record;
            get.record.dynamic r0.field5 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_large_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_field10:
            input r0 as dynamic.record;
            get.record.dynamic r0.field10 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_large_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    println!("Deploying program many_fields.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    let mut dynamic_records = (0..2)
        .map(|_| {
            // Mint a large record
            println!("Minting large record...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("many_fields.aleo", "mint_large"),
                    mint_inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            // Get the record from the transaction
            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
            let view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            // Convert to dynamic record
            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    // Read field5 (public field in the middle)
    println!("Reading field5 from dynamic record...");
    let inputs_read5 = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let transaction_read5 = vm
        .execute(&caller_private_key, ("many_fields.aleo", "read_field5"), inputs_read5.iter(), None, 0, None, rng)
        .unwrap();

    let expected_output5 = Plaintext::<CurrentNetwork>::from_str("5u64").unwrap();
    assert!(
        matches!(transaction_read5.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output5),
        "Expected field5 = 5u64"
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read5]), &[transaction_read5], rng);

    // Read field10 (last private field)
    println!("Reading field10 from dynamic record...");
    let inputs_read10 = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let transaction_read10 = vm
        .execute(&caller_private_key, ("many_fields.aleo", "read_field10"), inputs_read10.iter(), None, 0, None, rng)
        .unwrap();

    let expected_output10 = Plaintext::<CurrentNetwork>::from_str("10u64").unwrap();
    assert!(
        matches!(transaction_read10.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output10),
        "Expected field10 = 10u64"
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read10]), &[transaction_read10], rng);
}

// Tests dynamic records with nested struct fields to verify complex data structures work correctly.
#[test]
fn test_dynamic_record_with_nested_structs() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("nested_structs").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_complex_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_complex").unwrap().to_field().unwrap();

    // Program with nested structures in records
    let program_str = format!(
        r"
        program nested_structs.aleo;

        struct inner_struct:
            value_a as u64;
            value_b as u64;

        struct outer_struct:
            inner as inner_struct;
            extra as field;

        record complex_record:
            owner as address.private;
            simple_field as u64.public;
            nested as outer_struct.public;

        function consume_complex:
            input r0 as complex_record.record;

        function mint_complex:
            cast 100u64 200u64 into r0 as inner_struct;
            cast r0 999field into r1 as outer_struct;
            cast {caller_address} 42u64 r1 into r2 as complex_record.record;
            output r2 as complex_record.record;

        function read_nested:
            input r0 as dynamic.record;
            get.record.dynamic r0.nested into r1 as outer_struct;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_complex_function_field} with r0 (as dynamic.record);
            output r1.extra as field.public;

        function read_simple:
            input r0 as dynamic.record;
            get.record.dynamic r0.simple_field into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_complex_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    println!("Deploying program nested_structs.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    let mut dynamic_records = (0..2)
        .map(|_| {
            // Mint a complex record
            println!("Minting complex record with nested structs...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("nested_structs.aleo", "mint_complex"),
                    mint_inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            // Get the record from the transaction
            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
            let view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            // Convert to dynamic record
            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    // Read the nested struct field
    println!("Reading nested struct from dynamic record...");
    let inputs_read_nested = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let transaction_read_nested = vm
        .execute(
            &caller_private_key,
            ("nested_structs.aleo", "read_nested"),
            inputs_read_nested.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_extra = Plaintext::<CurrentNetwork>::from_str("999field").unwrap();
    assert!(
        matches!(transaction_read_nested.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_extra),
        "Expected nested.extra = 999field"
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read_nested]), &[transaction_read_nested], rng);

    // Read the simple field
    println!("Reading simple field from dynamic record...");
    let inputs_read_simple = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let transaction_read_simple = vm
        .execute(
            &caller_private_key,
            ("nested_structs.aleo", "read_simple"),
            inputs_read_simple.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_simple = Plaintext::<CurrentNetwork>::from_str("42u64").unwrap();
    assert!(
        matches!(transaction_read_simple.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_simple),
        "Expected simple_field = 42u64"
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read_simple]), &[transaction_read_simple], rng);
}

// Tests `dynamic.record` with minimal fields (owner only) to verify the smallest possible record structure works.
#[test]
fn test_dynamic_record_minimal_fields() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("minimal_record").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_minimal_static_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_minimal_static").unwrap().to_field().unwrap();

    // Program with a minimal record (only owner field)
    let program_str = format!(
        r"
        program minimal_record.aleo;

        record empty_record:
            owner as address.private;

        function mint_minimal:
            cast {caller_address} into r0 as empty_record.record;
            output r0 as empty_record.record;

        function consume_minimal_static:
            input r0 as empty_record.record;

        function consume_minimal_dynamic:
            input r0 as dynamic.record;

            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_minimal_static_function_field} with r0 (as dynamic.record);

            // Just verify we can receive the dynamic record
            output true as boolean.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    println!("Deploying program minimal_record.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    // Mint a minimal record
    println!("Minting minimal record...");
    let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
    let transaction_mint = vm
        .execute(&caller_private_key, ("minimal_record.aleo", "mint_minimal"), mint_inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Get the record from the transaction
    let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
    let view_key = ViewKey::try_from(&caller_private_key).unwrap();

    let output_record = match mint_output {
        Output::Record(_, _, record_ciphertext, _) => record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap(),
        _ => panic!("Expected record output"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

    // Convert to dynamic record
    let dynamic_record = DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap();

    // Consume the minimal dynamic record
    println!("Consuming minimal dynamic record...");
    let inputs_consume = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_record)];
    let transaction_consume = vm
        .execute(
            &caller_private_key,
            ("minimal_record.aleo", "consume_minimal_dynamic"),
            inputs_consume.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("true").unwrap();
    assert!(
        matches!(transaction_consume.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_output),
        "Minimal record should be consumable as dynamic record"
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_consume]), &[transaction_consume], rng);
}

// Tests `dynamic.record` with 20 fields to verify near-maximum capacity for the depth-5 Merkle tree (max 32 entries).
#[test]
fn test_dynamic_record_near_maximum_fields() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("max_fields").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_max_function_field = Identifier::<CurrentNetwork>::from_str("consume_max").unwrap().to_field().unwrap();

    // Program with a record containing 20 fields (testing near but not at limit)
    // Note: Each field plus owner, nonce, version takes slots
    let program_str = format!(
        r"
        program max_fields.aleo;

        record large_record:
            owner as address.private;
            f1 as u64.public;
            f2 as u64.public;
            f3 as u64.public;
            f4 as u64.public;
            f5 as u64.public;
            f6 as u64.public;
            f7 as u64.public;
            f8 as u64.public;
            f9 as u64.public;
            f10 as u64.public;
            f11 as u64.private;
            f12 as u64.private;
            f13 as u64.private;
            f14 as u64.private;
            f15 as u64.private;
            f16 as u64.private;
            f17 as u64.private;
            f18 as u64.private;
            f19 as u64.private;
            f20 as u64.private;

        function mint_max:
            cast {caller_address} 1u64 2u64 3u64 4u64 5u64 6u64 7u64 8u64 9u64 10u64 11u64 12u64 13u64 14u64 15u64 16u64 17u64 18u64 19u64 20u64 into r0 as large_record.record;
            output r0 as large_record.record;

        function consume_max:
            input r0 as large_record.record;

        function read_first:
            input r0 as dynamic.record;
            get.record.dynamic r0.f1 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_max_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_middle:
            input r0 as dynamic.record;
            get.record.dynamic r0.f10 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_max_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_last:
            input r0 as dynamic.record;
            get.record.dynamic r0.f20 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_max_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    println!("Deploying program max_fields.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    let mut dynamic_records = (0..3)
        .map(|_| {
            // Mint the large record
            println!("Minting record with 20 fields...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(&caller_private_key, ("max_fields.aleo", "mint_max"), mint_inputs.iter(), None, 0, None, rng)
                .unwrap();

            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
            let view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    // Read the first field
    println!("Reading f1 from large record...");
    let inputs_read_first = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_read_first = vm
        .execute(&caller_private_key, ("max_fields.aleo", "read_first"), inputs_read_first.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f1 = Plaintext::<CurrentNetwork>::from_str("1u64").unwrap();
    assert!(
        matches!(tx_read_first.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f1),
        "Expected f1 = 1u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read_first]), &[tx_read_first], rng);

    // Read a middle field
    println!("Reading f10 from large record...");
    let inputs_read_middle = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_read_middle = vm
        .execute(&caller_private_key, ("max_fields.aleo", "read_middle"), inputs_read_middle.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f10 = Plaintext::<CurrentNetwork>::from_str("10u64").unwrap();
    assert!(
        matches!(tx_read_middle.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f10),
        "Expected f10 = 10u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read_middle]), &[tx_read_middle], rng);

    // Read the last field
    println!("Reading f20 from large record...");
    let inputs_read_last = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_read_last = vm
        .execute(&caller_private_key, ("max_fields.aleo", "read_last"), inputs_read_last.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f20 = Plaintext::<CurrentNetwork>::from_str("20u64").unwrap();
    assert!(
        matches!(tx_read_last.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f20),
        "Expected f20 = 20u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_read_last]), &[tx_read_last], rng);
}

// Tests `get.record.dynamic` with exactly 32 data fields — the MAX_DATA_ENTRIES boundary.
// Verifies that the depth-5 Merkle tree (2^5 = 32 leaves) correctly handles the maximum
// number of data entries by reading the first, middle, and last fields.
#[test]
fn test_dynamic_record_maximum_fields() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("max32_record").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_data32_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_data32").unwrap().to_field().unwrap();

    // Generate field declarations for f1..=f32: f1..=f16 public, f17..=f32 private.
    let field_declarations: String = (1..=32)
        .map(|i| {
            let vis = if i <= 16 { "public" } else { "private" };
            format!("            f{i} as u64.{vis};\n")
        })
        .collect();

    // Generate cast arguments: address followed by 1u64..=32u64.
    let cast_args: String = (1u64..=32).map(|i| format!("{i}u64 ")).collect::<String>().trim_end().to_string();

    let program_str = format!(
        r"
        program max32_record.aleo;

        record data32:
            owner as address.private;
{field_declarations}
        function mint_data32:
            cast {caller_address} {cast_args} into r0 as data32.record;
            output r0 as data32.record;

        function consume_data32:
            input r0 as data32.record;

        function read_first:
            input r0 as dynamic.record;
            get.record.dynamic r0.f1 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_data32_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_middle:
            input r0 as dynamic.record;
            get.record.dynamic r0.f16 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_data32_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_boundary:
            input r0 as dynamic.record;
            get.record.dynamic r0.f17 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_data32_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_last:
            input r0 as dynamic.record;
            get.record.dynamic r0.f32 into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_data32_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program.
    println!("Deploying program max32_record.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    let mut dynamic_records = (0..4)
        .map(|_| {
            // Mint a record with all 32 fields set to their 1-based index value.
            println!("Minting data32 record with 32 fields...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("max32_record.aleo", "mint_data32"),
                    mint_inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
            let view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    // Read f1 (first public field, value == 1).
    println!("Reading f1 from 32-field record (MAX_DATA_ENTRIES boundary)...");
    let inputs_first = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_first = vm
        .execute(&caller_private_key, ("max32_record.aleo", "read_first"), inputs_first.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f1 = Plaintext::<CurrentNetwork>::from_str("1u64").unwrap();
    assert!(
        matches!(tx_first.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f1),
        "Expected f1 = 1u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_first]), &[tx_first], rng);

    // Read f16 (last public field, value == 16).
    println!("Reading f16 from 32-field record...");
    let inputs_middle = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_middle = vm
        .execute(&caller_private_key, ("max32_record.aleo", "read_middle"), inputs_middle.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f16 = Plaintext::<CurrentNetwork>::from_str("16u64").unwrap();
    assert!(
        matches!(tx_middle.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f16),
        "Expected f16 = 16u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_middle]), &[tx_middle], rng);

    // Read f17 (first private field, value == 17, at the public/private visibility boundary).
    println!("Reading f17 from 32-field record (first private field, visibility boundary)...");
    let inputs_boundary = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_boundary = vm
        .execute(
            &caller_private_key,
            ("max32_record.aleo", "read_boundary"),
            inputs_boundary.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_f17 = Plaintext::<CurrentNetwork>::from_str("17u64").unwrap();
    assert!(
        matches!(tx_boundary.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f17),
        "Expected f17 = 17u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_boundary]), &[tx_boundary], rng);

    // Read f32 (last field, value == 32, exercising all 32 Merkle leaves).
    println!("Reading f32 from 32-field record...");
    let inputs_last = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_last = vm
        .execute(&caller_private_key, ("max32_record.aleo", "read_last"), inputs_last.iter(), None, 0, None, rng)
        .unwrap();

    let expected_f32 = Plaintext::<CurrentNetwork>::from_str("32u64").unwrap();
    assert!(
        matches!(tx_last.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_f32),
        "Expected f32 = 32u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_last]), &[tx_last], rng);
}

// Tests `get.record.dynamic` with explicit visibility suffixes (`.private`, `.public`, `.constant`).
// Verifies that matching visibility succeeds and mismatching visibility fails.
#[test]
fn test_get_record_dynamic_visibility() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("visibility_test").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_mixed_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_mixed").unwrap().to_field().unwrap();

    // Program with a record containing private and public fields.
    let program_str = format!(
        r"
        program visibility_test.aleo;

        record mixed_record:
            owner as address.private;
            secret as u64.private;
            visible as u64.public;

        function mint_mixed:
            cast {caller_address} 42u64 99u64 into r0 as mixed_record.record;
            output r0 as mixed_record.record;

        function consume_mixed:
            input r0 as mixed_record.record;

        function read_secret_as_private:
            input r0 as dynamic.record;
            get.record.dynamic r0.secret into r1 as u64.private;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_mixed_function_field} with r0 (as dynamic.record);

            output r1 as u64.public;

        function read_visible_as_public:
            input r0 as dynamic.record;
            get.record.dynamic r0.visible into r1 as u64.public;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_mixed_function_field} with r0 (as dynamic.record);

            output r1 as u64.public;

        function read_secret_as_public:
            input r0 as dynamic.record;
            get.record.dynamic r0.secret into r1 as u64.public;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_mixed_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_visible_as_private:
            input r0 as dynamic.record;
            get.record.dynamic r0.visible into r1 as u64.private;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_mixed_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        function read_secret_no_visibility:
            input r0 as dynamic.record;
            get.record.dynamic r0.secret into r1 as u64;
            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {program_name_field} {network_field} {consume_mixed_function_field} with r0 (as dynamic.record);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program.
    println!("Deploying program visibility_test.aleo...");
    let transaction_deploy = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_deploy], rng);

    let mut dynamic_records = (0..5)
        .map(|_| {
            // Mint a record with private and public fields.
            println!("Minting mixed record...");
            let mint_inputs: Vec<Value<CurrentNetwork>> = vec![];
            let transaction_mint = vm
                .execute(
                    &caller_private_key,
                    ("visibility_test.aleo", "mint_mixed"),
                    mint_inputs.iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
            let view_key = ViewKey::try_from(&caller_private_key).unwrap();

            let output_record = match mint_output {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&view_key).unwrap()
                }
                _ => panic!("Expected record output"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&mint_inputs]), &[transaction_mint], rng);

            DynamicRecord::<CurrentNetwork>::from_record(&output_record).unwrap()
        })
        .collect_vec();

    /************** Case 1: Read private field with matching .private visibility **************/

    println!("Reading secret as u64.private (should succeed)...");
    let inputs_private_match = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_private_match = vm
        .execute(
            &caller_private_key,
            ("visibility_test.aleo", "read_secret_as_private"),
            inputs_private_match.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_secret = Plaintext::<CurrentNetwork>::from_str("42u64").unwrap();
    assert!(
        matches!(tx_private_match.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_secret),
        "Expected secret = 42u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_private_match]), &[tx_private_match], rng);

    /************** Case 2: Read public field with matching .public visibility **************/

    println!("Reading visible as u64.public (should succeed)...");
    let inputs_public_match = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_public_match = vm
        .execute(
            &caller_private_key,
            ("visibility_test.aleo", "read_visible_as_public"),
            inputs_public_match.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let expected_visible = Plaintext::<CurrentNetwork>::from_str("99u64").unwrap();
    assert!(
        matches!(tx_public_match.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_visible),
        "Expected visible = 99u64"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_public_match]), &[tx_public_match], rng);

    /************** Case 3: Read private field with mismatching .public visibility **************/

    println!("Reading secret as u64.public (should fail)...");
    assert!(
        vm.execute(
            &caller_private_key,
            ("visibility_test.aleo", "read_secret_as_public"),
            vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("Visibility mismatch")
    );

    /************** Case 4: Read public field with mismatching .private visibility **************/

    println!("Reading visible as u64.private (should fail)...");
    assert!(
        vm.execute(
            &caller_private_key,
            ("visibility_test.aleo", "read_visible_as_private"),
            vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap_err()
        .to_string()
        .contains("Visibility mismatch")
    );

    /************** Case 5: Read private field without visibility suffix (should succeed) **************/

    println!("Reading secret as u64 (no visibility, should succeed)...");
    let inputs_no_vis = vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_records.pop().unwrap())];
    let tx_no_vis = vm
        .execute(
            &caller_private_key,
            ("visibility_test.aleo", "read_secret_no_visibility"),
            inputs_no_vis.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    assert!(
        matches!(tx_no_vis.transitions().nth(1).unwrap().outputs(), [Output::Public(_, Some(plaintext))] if *plaintext == expected_secret),
        "Expected secret = 42u64 (no visibility check)"
    );
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_no_vis]), &[tx_no_vis], rng);
}
