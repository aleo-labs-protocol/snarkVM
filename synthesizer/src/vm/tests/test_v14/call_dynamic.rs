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

use console::network::varuna_version_from_consensus;

// Tests `call.dynamic` to `credits.aleo` functions including `transfer_public_as_signer`, `transfer_public_to_private`, and `transfer_private`.
#[test]
fn test_dynamic_calls_to_credits_aleo() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;
    let caller_address = Address::try_from(&caller_private_key)?;

    let test_dcall_program_id = ProgramID::<CurrentNetwork>::from_str("test_dcall.aleo").unwrap();
    let test_dcall_program_address = test_dcall_program_id.to_address()?;

    // Define the program to be executed.
    let program = Program::from_str(
        r"
            program test_dcall.aleo;

            // This static variant fails to parse because we can't parse identifiers as literals yet
            // function static:
            //    input r0 as address.public;
            //    input r1 as u64.public;
            //    call.dynamic credits aleo transfer_public_as_signer with r0 r1 (as address.public u64.public) into r2 (as dynamic.future);
            //    async static r2 into r3;
            //    output r3 as test_dcall.aleo/static.future;
            // finalize static:
            //    input r0 as dynamic.future;
            //    await r0; 
                    
            function two_transfer_publics:
                input r0 as field.public;
                input r1 as field.public;
                input r2 as field.public;
                input r3 as address.public;
                input r4 as u64.public;
                call.dynamic r0 r1 r2 with r3 r4 (as address.public u64.public) into r5 (as dynamic.future);
                call.dynamic r0 r1 r2 with r3 r4 (as address.public u64.public) into r6 (as dynamic.future);
                async two_transfer_publics r5 r6 into r7;
                output r7 as test_dcall.aleo/two_transfer_publics.future;
            finalize two_transfer_publics:
                input r0 as dynamic.future;
                input r1 as dynamic.future;
                await r1;
                await r0;

            function dynamic_transfer_pub_to_priv:
                input r0 as field.public;
                input r1 as field.public;
                input r2 as field.public;
                input r3 as address.private;
                input r4 as u64.public;
                call.dynamic r0 r1 r2 with r3 r4 (as address.private u64.public) into r5 r6 (as dynamic.record dynamic.future);
                async dynamic_transfer_pub_to_priv r6 into r7;
                output r5 as dynamic.record;
                output r7 as test_dcall.aleo/dynamic_transfer_pub_to_priv.future;
            finalize dynamic_transfer_pub_to_priv:
                input r0 as dynamic.future;
                await r0;

            function dynamic_transfer_private:
                input r0 as field.public;
                input r1 as field.public;
                input r2 as field.public;
                input r3 as dynamic.record;
                input r4 as address.private;
                input r5 as u64.private;
                call.dynamic r0 r1 r2 with r3 r4 r5 (as dynamic.record address.private u64.private) into r6 r7 (as dynamic.record dynamic.record);
                output r6 as dynamic.record;
                output r7 as dynamic.record;

            constructor:
                assert.eq true true;
                ",
    )?;

    // Initialize the VM at V18, when native credits record translation is enabled.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V18)?, rng);

    // Deploy the program.
    println!("Deploying program: {}", program.id());
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let deployment = transaction.deployment().ok_or_else(|| anyhow!("Expected a deployment transaction"))?.clone();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Get the program and function identifiers as fields and check that they are expected.
    println!("Executing the `dynamic` function...");
    let credits_field = Identifier::<CurrentNetwork>::from_str("credits")?.to_field()?;
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo")?.to_field()?;
    let transfer_public_as_signer_field =
        Identifier::<CurrentNetwork>::from_str("transfer_public_as_signer")?.to_field()?;
    let transfer_public_to_private_field =
        Identifier::<CurrentNetwork>::from_str("transfer_public_to_private")?.to_field()?;
    let transfer_private_field = Identifier::<CurrentNetwork>::from_str("transfer_private")?.to_field()?;
    println!("credits_field: {credits_field}");
    println!("aleo_field: {aleo_field}");
    println!("transfer_public_as_signer_field: {transfer_public_as_signer_field}");
    println!("transfer_public_to_private_field: {transfer_public_to_private_field}");

    let program_id_fields = ProgramID::<CurrentNetwork>::from_str("credits.aleo")?.to_fields()?;
    assert_eq!(program_id_fields.len(), 2);
    assert_eq!(program_id_fields[0], credits_field);
    assert_eq!(program_id_fields[1], aleo_field);

    // Execute 'two_transfer_publics'.
    let transaction = vm.execute(
        &caller_private_key,
        ("test_dcall.aleo", "two_transfer_publics"),
        vec![
            Value::from_str(&format!("{credits_field}"))?,
            Value::from_str(&format!("{aleo_field}"))?,
            Value::from_str(&format!("{transfer_public_as_signer_field}"))?,
            Value::from_str(&format!("{test_dcall_program_address}"))?,
            Value::from_str("1000000u64")?,
        ]
        .into_iter(),
        None,
        0,
        None,
        rng,
    )?;

    vm.check_transaction(&transaction, None, rng)?;

    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute 'dynamic_transfer_public_to_private'.
    let transaction = vm.execute(
        &caller_private_key,
        ("test_dcall.aleo", "dynamic_transfer_pub_to_priv"),
        vec![
            Value::from_str(&format!("{credits_field}"))?,
            Value::from_str(&format!("{aleo_field}"))?,
            Value::from_str(&format!("{transfer_public_to_private_field}"))?,
            Value::from_str(&format!("{caller_address}"))?,
            Value::from_str("1234u64")?,
        ]
        .into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    vm.check_transaction(&transaction, None, rng)?;

    // Verify the proof in a fresh process that did not synthesize the credits translation key while proving.
    let verifier = Process::<CurrentNetwork>::load()?;
    verifier.load_deployment(&deployment)?;
    let execution = transaction.execution().ok_or_else(|| anyhow!("Expected an execution transaction"))?;
    let execution_stacks = verifier.get_stacks(execution.transitions(), false)?;
    let error = Process::verify_execution(
        ConsensusVersion::V17,
        varuna_version_from_consensus(ConsensusVersion::V17),
        InclusionVersion::V1,
        execution,
        &execution_stacks,
    )
    .expect_err("Native credits record translation must not verify before V18");
    assert!(
        error.to_string().contains("credits record translation is not enabled before ConsensusVersion::V18"),
        "Unexpected V17 verification error: {error}"
    );
    Process::verify_execution(
        ConsensusVersion::V18,
        varuna_version_from_consensus(ConsensusVersion::V18),
        InclusionVersion::V1,
        execution,
        &execution_stacks,
    )?;

    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Collect the record
    ensure!(block.records().collect_vec().len() == 1, "Expected 1 record, got {}", block.records().collect_vec().len());
    let record = block.records().collect_vec().last().unwrap().1.decrypt(&caller_view_key).unwrap();
    let dynamic_record = DynamicRecord::<CurrentNetwork>::from_record(&record).unwrap();
    // Execute 'dynamic_transfer_private'.
    println!("Executing 'dynamic_transfer_private'...");
    let transaction = vm.execute(
        &caller_private_key,
        ("test_dcall.aleo", "dynamic_transfer_private"),
        vec![
            Value::from_str(&format!("{credits_field}"))?,
            Value::from_str(&format!("{aleo_field}"))?,
            Value::from_str(&format!("{transfer_private_field}"))?,
            Value::<CurrentNetwork>::DynamicRecord(dynamic_record),
            Value::from_str(&format!("{caller_address}"))?,
            Value::from_str("1u64")?,
        ]
        .into_iter(),
        None,
        0,
        None,
        rng,
    )?;

    vm.check_transaction(&transaction, None, rng)?;

    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Collect the record
    let records = block.records().collect_vec();
    println!("records: {records:?}");

    Ok(())
}

// Tests a universal AMM swap pattern where the AMM dynamically calls transfer functions on arbitrary token programs.
#[test]
fn test_universal_swap() {
    // Turn on trace logging.
    tracing_subscriber::fmt::init();
    // Define a mint_private function and constructor.
    let mint_private_function = r"
        function mint_private:
            input r0 as u64.private;
            cast self.caller r0 into r1 as credits.record;
            cast self.caller r0 into r2 as credits.record;
            output r1 as credits.record;
            output r2 as credits.record;
        constructor:
            assert.eq true true;
        ";

    // Define the credits programs.
    let credits_program = Program::<CurrentNetwork>::credits().unwrap().to_string();
    let mut credits_a_program = credits_program.replace("credits.aleo", "credits_a.aleo");
    credits_a_program.push_str(mint_private_function);
    let credits_a_program = Program::from_str(&credits_a_program).unwrap();
    let mut credits_b_program = credits_program.replace("credits.aleo", "credits_b.aleo");
    credits_b_program.push_str(mint_private_function);
    let credits_b_program = Program::from_str(&credits_b_program).unwrap();

    // Define the swap program.
    let amm_program = Program::from_str(r"
        program amm.aleo;

        struct reserves:
            // corresponds to credits_a.aleo
            token_a as u64;
            // corresponds to credits_b.aleo
            token_b as u64;

        mapping reserves_mapping:
            key as address.public;
            value as reserves.public;

        function buy_token_b:
            // credits_a
            input r0 as field.public;
            // credits_b
            input r1 as field.public;
            // aleo
            input r2 as field.public;
            // transfer_private_to_public function
            input r3 as field.public;
            // transfer_public_to_private function
            input r4 as field.public;
            // credits_a record
            input r5 as dynamic.record;
            // Token a amount to send
            input r6 as u64.public;
            // Token b amount to receive
            input r7 as u64.public;
            cast r6 r7 into r8 as reserves;
            call.dynamic r0 r2 r3 with r5 aleo1rrj2mgall8mw57lcpkkvkxwqkawpc5rjarqm57w8gux2ahnt9sxqf0md56 r6 (as dynamic.record address.public u64.public) into r9 r10 (as dynamic.record dynamic.future);
            call.dynamic r1 r2 r4 with self.signer r6 (as address.private u64.public) into r11 r12 (as dynamic.record dynamic.future);
            async buy_token_b r6 r7 r10 r12 into r13;
            // token_a change record
            output r9 as dynamic.record;
            // token_b receiver record
            output r11 as dynamic.record;
            output r13 as amm.aleo/buy_token_b.future;

        finalize buy_token_b:
            // token_a amount
            input r0 as u64.public;
            // token_b amount
            input r1 as u64.public;
            input r2 as dynamic.future;
            input r3 as dynamic.future;
            await r2;
            await r3;
            // Note: Reserve update logic is omitted intentionally — this test program only
            // exercises the dynamic dispatch and future-await mechanics, not AMM state changes.

        constructor:
            assert.eq true true;
        ",
    ).unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program - one at a time so as not to surpass public payer limits.
    for program in [credits_a_program, credits_b_program, amm_program] {
        let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 1);
        assert_eq!(block.transactions().num_rejected(), 0);
        assert_eq!(block.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block).unwrap();
    }

    // Execute credits_a.aleo/mint_private to mint a few credits_a records.
    let execute_mint_a = vm
        .execute(
            &caller_private_key,
            ("credits_a.aleo", "mint_private"),
            vec![Value::from_str("100u64")].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    // Execute credits_b.aleo/mint_private to mint a few credits_b records.
    let execute_mint_b = vm
        .execute(
            &caller_private_key,
            ("credits_b.aleo", "mint_private"),
            vec![Value::from_str("100u64")].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execute_mint_a, execute_mint_b], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Obtain the credits records.
    let records =
        block.records().map(|(_, record)| record.decrypt(&caller_view_key)).collect::<Result<Vec<_>>>().unwrap();
    // Split the records into credits_a and credits_b records.
    let (records_a, records_b) = records.split_at(2);

    // Create the AMM program address.
    let amm_address: Address<CurrentNetwork> = ProgramID::from_str("amm.aleo").unwrap().to_address().unwrap();
    let amm_address_value = Value::from_str(&amm_address.to_string()).unwrap();

    // Execute credits_a.aleo/transfer_private_to_public to give amm.aleo an initial balance of credits_a.
    let execute_transfer_a = vm
        .execute(
            &caller_private_key,
            ("credits_a.aleo", "transfer_private_to_public"),
            vec![Value::Record(records_a[0].clone()), amm_address_value.clone(), Value::from_str("100u64").unwrap()]
                .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    // Execute credits_b.aleo/transfer_private_to_public to give amm.aleo an initial balance of credits_b.
    let execute_transfer_b = vm
        .execute(
            &caller_private_key,
            ("credits_b.aleo", "transfer_private_to_public"),
            vec![Value::Record(records_b[0].clone()), amm_address_value.clone(), Value::from_str("100u64").unwrap()]
                .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execute_transfer_a, execute_transfer_b], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    let dynamic_record_a = DynamicRecord::<CurrentNetwork>::from_record(&records_a[1].clone()).unwrap();
    let credits_a_field = Identifier::<CurrentNetwork>::from_str("credits_a").unwrap().to_field().unwrap();
    let credits_b_field = Identifier::<CurrentNetwork>::from_str("credits_b").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let transfer_private_to_public_field =
        Identifier::<CurrentNetwork>::from_str("transfer_private_to_public").unwrap().to_field().unwrap();
    let transfer_public_to_private_field =
        Identifier::<CurrentNetwork>::from_str("transfer_public_to_private").unwrap().to_field().unwrap();

    // Execute amm.aleo/buy_token_b to buy token_b.
    let execute_buy_token_b = vm
        .execute(
            &caller_private_key,
            ("amm.aleo", "buy_token_b"),
            vec![
                Value::from_str(&format!("{credits_a_field}")).unwrap(),
                Value::from_str(&format!("{credits_b_field}")).unwrap(),
                Value::from_str(&format!("{aleo_field}")).unwrap(),
                Value::from_str(&format!("{transfer_private_to_public_field}")).unwrap(),
                Value::from_str(&format!("{transfer_public_to_private_field}")).unwrap(),
                Value::<CurrentNetwork>::DynamicRecord(dynamic_record_a),
                Value::from_str("100u64").unwrap(),
                Value::from_str("100u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[execute_buy_token_b], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Obtain the credits_a change and credits_b receiver records.
    let (_change_record, _receiver_record) = block
        .records()
        .map(|(_, record)| record.decrypt(&caller_view_key))
        .collect::<Result<Vec<_>>>()
        .unwrap()
        .split_at(1);
}

// Tests runtime selection of `call.dynamic` targets using ternary operations to conditionally determine the program and function.
#[test]
fn test_conditional_execution() {
    let constants_program_name = Identifier::<CurrentNetwork>::from_str("constants").unwrap();
    let constants_program_field = constants_program_name.to_field().unwrap();

    let other_constants_program_name = Identifier::<CurrentNetwork>::from_str("other_constants").unwrap();
    let other_constants_program_field = other_constants_program_name.to_field().unwrap();

    let three_function_name = Identifier::<CurrentNetwork>::from_str("three").unwrap();
    let three_function_field = three_function_name.to_field().unwrap();

    let four_function_name = Identifier::<CurrentNetwork>::from_str("four").unwrap();
    let four_function_field = four_function_name.to_field().unwrap();

    let five_function_name = Identifier::<CurrentNetwork>::from_str("five").unwrap();
    let five_function_field = five_function_name.to_field().unwrap();

    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    // Define the swap program.
    let constants_program_str = format!(
        r"
        program constants.aleo;

        function {three_function_name}:
            output 3u128 as u128.private;

        function {four_function_name}:
            output 4u128 as u128.private;

        constructor:
            assert.eq true true;
        ",
    );

    // Define the swap program.
    let other_constants_program_str = format!(
        r"
        program other_constants.aleo;

        function {five_function_name}:
            output 5u128 as u128.private;

        constructor:
            assert.eq true true;
        ",
    );

    // Define the swap program.
    let conditional_program_str = format!(
        r"
        import constants.aleo;

        program conditional_program.aleo;

        function conditional_function:
            input r0 as boolean.private; // flag
            input r1 as field.public;    // custom program
            input r2 as field.public;    // custom function
            
            ternary r0 r1 {other_constants_program_field} into r3;
            ternary r0 r2 {five_function_field} into r4;

            call.dynamic r3 {aleo_field} r4 into r5 (as u128.private);

            add r5 1u128 into r6;
            
            output r6 as u128.public;

        constructor:
            assert.eq true true;
        ",
    );

    // Parse programs
    let constants_program = Program::<CurrentNetwork>::from_str(&constants_program_str).unwrap();
    let other_constants_program = Program::<CurrentNetwork>::from_str(&other_constants_program_str).unwrap();
    let conditional_program = Program::<CurrentNetwork>::from_str(&conditional_program_str).unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program - one at a time so as not to surpass public payer limits.
    for program in [
        ("constants.aleo", constants_program),
        ("other_constants.aleo", other_constants_program),
        ("conditional_program.aleo", conditional_program),
    ] {
        println!("Deploying program {}...", program.0);

        let deployment = vm.deploy(&caller_private_key, &program.1, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deployment], rng);
    }

    println!("Executing (custom) conditional_program.aleo/conditional_function -> constants/three.aleo...");
    let inputs_1 = vec![
        Value::from_str("true").unwrap(),
        Value::from_str(&format!("{constants_program_field}")).unwrap(),
        Value::from_str(&format!("{three_function_field}")).unwrap(),
    ];
    let execute_1 = vm
        .execute(
            &caller_private_key,
            ("conditional_program.aleo", "conditional_function"),
            inputs_1.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    println!("Executing (custom) conditional_program.aleo/conditional_function -> constants/four.aleo...");
    let inputs_2 = vec![
        Value::from_str("true").unwrap(),
        Value::from_str(&format!("{constants_program_field}")).unwrap(),
        Value::from_str(&format!("{four_function_field}")).unwrap(),
    ];
    let execute_2 = vm
        .execute(
            &caller_private_key,
            ("conditional_program.aleo", "conditional_function"),
            inputs_2.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    println!("Executing (fallback) conditional_program.aleo/conditional_function -> other_constants/five.aleo...");
    let inputs_3 = vec![
        Value::from_str("false").unwrap(),
        Value::from_str(&format!("{constants_program_field}")).unwrap(),
        Value::from_str(&format!("{four_function_field}")).unwrap(),
    ];
    let execute_3 = vm
        .execute(
            &caller_private_key,
            ("conditional_program.aleo", "conditional_function"),
            inputs_3.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(
        &vm,
        &caller_private_key,
        Some(&[&inputs_1, &inputs_2, &inputs_3]),
        &[execute_1, execute_2, execute_3],
        rng,
    );
}

// Tests that execution graphs with mixed static/dynamic calls are correctly constructed.
// Each call instruction can be static or dynamic depending on the boolean inputs to the test function.
// Call tree:
//   `four::a`
//     -> `two::b`
//          -> `zero::c`
//          -> `one::d`
//     -> `three::e`
//          -> `two::b`
//               -> `zero::c`
//               -> `one::d`
//          -> `one::d`
//          -> `zero::c`
// Linearized order: [a, b, c, d, e, b, c, d, d, c].
// Transitions must be included in the `Execution` in the order they finish: [c, d, b, c, d, b, d, c, e, a].
fn test_complex_dynamic_graph_construction_internal(
    // In each of the arguments, call_X_Y_dynamic indicates whether the call to
    // function Y inside function X should be static or dynamic.
    call_a_b_dynamic: bool,
    call_a_e_dynamic: bool,
    call_b_c_dynamic: bool,
    call_b_d_dynamic: bool,
    call_e_b_dynamic: bool,
    call_e_d_dynamic: bool,
    call_e_c_dynamic: bool,
) {
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    let program_0_name_str = "zero";
    let program_1_name_str = "one";
    let program_2_name_str = "two";
    let program_3_name_str = "three";
    let program_4_name_str = "four";

    let program_0_name_field = Identifier::<CurrentNetwork>::from_str(program_0_name_str).unwrap().to_field().unwrap();
    let program_1_name_field = Identifier::<CurrentNetwork>::from_str(program_1_name_str).unwrap().to_field().unwrap();
    let program_2_name_field = Identifier::<CurrentNetwork>::from_str(program_2_name_str).unwrap().to_field().unwrap();
    let program_3_name_field = Identifier::<CurrentNetwork>::from_str(program_3_name_str).unwrap().to_field().unwrap();

    let function_b_name_id = Identifier::<CurrentNetwork>::from_str("b").unwrap();
    let function_c_name_id = Identifier::<CurrentNetwork>::from_str("c").unwrap();
    let function_d_name_id = Identifier::<CurrentNetwork>::from_str("d").unwrap();
    let function_e_name_id = Identifier::<CurrentNetwork>::from_str("e").unwrap();

    let function_b_name_field = function_b_name_id.to_field().unwrap();
    let function_c_name_field = function_c_name_id.to_field().unwrap();
    let function_d_name_field = function_d_name_id.to_field().unwrap();
    let function_e_name_field = function_e_name_id.to_field().unwrap();

    /******************************* program 0 *******************************/
    let (string, program0) = Program::<CurrentNetwork>::parse(
        r"
    program zero.aleo;

    function c:
        input r0 as u8.private;
        input r1 as u8.private;
        add r0 r1 into r2;
        output r2 as u8.private;
        
    constructor:
        assert.eq true true;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    /******************************* program 1 *******************************/
    let (string, program1) = Program::<CurrentNetwork>::parse(
        r"
    program one.aleo;

    function d:
        input r0 as u8.private;
        input r1 as u8.private;
        add r0 r1 into r2;
        output r2 as u8.private;
        
    constructor:
        assert.eq true true;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    /******************************* program 2 *******************************/
    let call_b_c_str = if call_b_c_dynamic {
        format!(
            "call.dynamic {program_0_name_field} {network_field} {function_c_name_field} with r0 r1 (as u8.private u8.private) into r2 (as u8.private);"
        )
    } else {
        "call zero.aleo/c r0 r1 into r2;".to_string()
    };

    let call_b_d_str = if call_b_d_dynamic {
        format!(
            "call.dynamic {program_1_name_field} {network_field} {function_d_name_field} with r1 r2 (as u8.private u8.private) into r3 (as u8.private);"
        )
    } else {
        "call one.aleo/d r1 r2 into r3;".to_string()
    };

    let program2_str = format!(
        r"
        import zero.aleo;
        import one.aleo;

        program two.aleo;

        function b:
            input r0 as u8.private;
            input r1 as u8.private;
            {call_b_c_str}
            {call_b_d_str}
            output r3 as u8.private;
            
        constructor:
            assert.eq true true;",
    );
    let (string, program2) = Program::<CurrentNetwork>::parse(program2_str.as_str()).unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    /******************************* program 3 *******************************/

    let call_e_b_str = if call_e_b_dynamic {
        format!(
            "call.dynamic {program_2_name_field} {network_field} {function_b_name_field} with r0 r1 (as u8.private u8.private) into r2 (as u8.private);"
        )
    } else {
        "call two.aleo/b r0 r1 into r2;".to_string()
    };

    let call_e_d_str = if call_e_d_dynamic {
        format!(
            "call.dynamic {program_1_name_field} {network_field} {function_d_name_field} with r1 r2 (as u8.private u8.private) into r3 (as u8.private);"
        )
    } else {
        "call one.aleo/d r1 r2 into r3;".to_string()
    };

    let call_e_c_str = if call_e_c_dynamic {
        format!(
            "call.dynamic {program_0_name_field} {network_field} {function_c_name_field} with r1 r2 (as u8.private u8.private) into r4 (as u8.private);"
        )
    } else {
        "call zero.aleo/c r1 r2 into r4;".to_string()
    };

    let program3_str = format!(
        r"
        import zero.aleo;
        import one.aleo;
        import two.aleo;

        program three.aleo;

        function e:
            input r0 as u8.private;
            input r1 as u8.private;
            {call_e_b_str}
            {call_e_d_str}
            {call_e_c_str}
            output r4 as u8.private;
            
        constructor:
            assert.eq true true;",
    );

    let (string, program3) = Program::<CurrentNetwork>::parse(program3_str.as_str()).unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    /******************************* program 4 *******************************/

    let call_a_b_str = if call_a_b_dynamic {
        format!(
            "call.dynamic {program_2_name_field} {network_field} {function_b_name_field} with r0 r1 (as u8.private u8.private) into r2 (as u8.private);"
        )
    } else {
        "call two.aleo/b r0 r1 into r2;".to_string()
    };

    let call_a_e_str = if call_a_e_dynamic {
        format!(
            "call.dynamic {program_3_name_field} {network_field} {function_e_name_field} with r1 r2 (as u8.private u8.private) into r3 (as u8.private);"
        )
    } else {
        "call three.aleo/e r1 r2 into r3;".to_string()
    };

    let program4_str = format!(
        r"
    import two.aleo;
    import three.aleo;

    program four.aleo;

    function a:
        input r0 as u8.private;
        input r1 as u8.private;
        {call_a_b_str}
        {call_a_e_str}
        output r3 as u8.private;
        
    constructor:
        assert.eq true true;",
    );

    let (string, program4) = Program::<CurrentNetwork>::parse(program4_str.as_str()).unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Initialize caller.
    let caller_private_key = sample_genesis_private_key(rng);

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    for (program, program_name_str) in [
        (program0, program_0_name_str),
        (program1, program_1_name_str),
        (program2, program_2_name_str),
        (program3, program_3_name_str),
        (program4, program_4_name_str),
    ] {
        // Deploy the program.
        println!("Deploying program {program_name_str}...");
        let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);
    }

    println!("Executing program four::a...");

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("1u8").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("2u8").unwrap();
    let inputs = [r0, r1];

    // Execute the "dynamic" function.
    let transaction = vm.execute(&caller_private_key, ("four.aleo", "a"), inputs.iter(), None, 0, None, rng).unwrap();

    println!("Reconstructing call graph...");

    let transitions = transaction.execution().unwrap().transitions().collect_vec();
    let tids = transitions.iter().map(|transition| transition.id()).collect_vec();

    // Call tree                    transition index
    // "four::a"                    (9)
    //   --> "two::b"               (2)
    //        --> "zero::c"         (0)
    //        --> "one::d"          (1)
    //   --> "three::e"             (8)
    //        --> "two::b"          (5)
    //             --> "zero::c"    (3)
    //             --> "one::d"     (4)
    //        --> "one::d"          (6)
    //        --> "zero::c"         (7)
    //
    // The expected call graph is:
    // 9 -> [2, 8]
    // 8 -> [5, 6, 7]
    // 5 -> [3, 4]
    // 2 -> [0, 1]
    // 0 -> []
    // 1 -> []
    // 3 -> []
    // 4 -> []
    // 6 -> []
    // 7 -> []

    let mut execution_stacks = indexmap::IndexMap::new();
    for transition in &transitions {
        execution_stacks.insert(*transition.program_id(), vm.process().get_stack(transition.program_id()).unwrap());
    }
    let graph = Process::construct_call_graph(transitions.into_iter(), &execution_stacks).unwrap();
    assert_eq!(graph[tids[9]], &[*tids[2], *tids[8]]);
    assert_eq!(graph[tids[8]], &[*tids[5], *tids[6], *tids[7]]);
    assert_eq!(graph[tids[5]], &[*tids[3], *tids[4]]);
    assert_eq!(graph[tids[2]], &[*tids[0], *tids[1]]);
    assert_eq!(graph[tids[0]], &[]);
    assert_eq!(graph[tids[1]], &[]);
    assert_eq!(graph[tids[3]], &[]);
    assert_eq!(graph[tids[4]], &[]);
    assert_eq!(graph[tids[6]], &[]);
    assert_eq!(graph[tids[7]], &[]);

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), std::slice::from_ref(&transaction), rng);
}

// Tests execution graph construction with all-static, all-dynamic, and random combinations of call types.
#[test]
fn test_complex_dynamic_graph_construction() {
    let num_random_mixes = 3;

    // All static calls
    test_complex_dynamic_graph_construction_internal(false, false, false, false, false, false, false);
    // All dynamic calls
    test_complex_dynamic_graph_construction_internal(true, true, true, true, true, true, true);

    // Random static-/dynamic-call mixes
    let rng = &mut TestRng::default();
    for _ in 0..num_random_mixes {
        let mix: [bool; 7] = rng.random();
        test_complex_dynamic_graph_construction_internal(mix[0], mix[1], mix[2], mix[3], mix[4], mix[5], mix[6]);
    }
}

// Tests that `call.dynamic` to a non-existent program fails with an appropriate error.
#[test]
fn test_call_nonexistent_program() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Use a program name that doesn't exist
    let nonexistent_program_field =
        Identifier::<CurrentNetwork>::from_str("nonexistent_program").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let some_function_field = Identifier::<CurrentNetwork>::from_str("some_function").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program call_nonexistent.aleo;

        function call_missing_program:
            call.dynamic {nonexistent_program_field} {aleo_field} {some_function_field}
                into r0 (as u64.public);
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the caller program
    let deploy_tx = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Execution should fail because the target program doesn't exist
    let exec_result = vm.execute(
        &caller_private_key,
        ("call_nonexistent.aleo", "call_missing_program"),
        Vec::<Value<CurrentNetwork>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(exec_result.is_err(), "Calling a non-existent program should fail");
}

// Tests that `call.dynamic` to a non-existent function in an existing program fails with an appropriate error.
#[test]
fn test_call_nonexistent_function() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // First deploy a target program with a known function
    let target_program = Program::<CurrentNetwork>::from_str(
        r"
        program target_program.aleo;

        function existing_function:
            output 42u64 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Use the existing program but a non-existent function
    let target_program_field = Identifier::<CurrentNetwork>::from_str("target_program").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let nonexistent_function_field =
        Identifier::<CurrentNetwork>::from_str("nonexistent_function").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program call_nonexistent_fn.aleo;

        function call_missing_function:
            call.dynamic {target_program_field} {aleo_field} {nonexistent_function_field}
                into r0 (as u64.public);
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy both programs
    let deploy_target = vm.deploy(&caller_private_key, &target_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_target], rng);

    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execution should fail because the target function doesn't exist
    let exec_result = vm.execute(
        &caller_private_key,
        ("call_nonexistent_fn.aleo", "call_missing_function"),
        Vec::<Value<CurrentNetwork>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(exec_result.is_err(), "Calling a non-existent function should fail");
}

// Tests circular `call.dynamic` patterns where program A calls B which calls back to A.
#[test]
fn test_circular_dynamic_calls() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let program_a_field = Identifier::<CurrentNetwork>::from_str("circular_a").unwrap().to_field().unwrap();
    let program_b_field = Identifier::<CurrentNetwork>::from_str("circular_b").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let call_b_field = Identifier::<CurrentNetwork>::from_str("call_b").unwrap().to_field().unwrap();
    let call_a_field = Identifier::<CurrentNetwork>::from_str("call_a").unwrap().to_field().unwrap();

    // Program A calls B, which calls back to A (with a base case to prevent infinite recursion)
    let program_a_str = format!(
        r"
        program circular_a.aleo;

        function entry:
            input r0 as u8.public;
            call.dynamic {program_b_field} {aleo_field} {call_b_field} with r0 (as u8.public)
                into r1 (as u64.public);
            output r1 as u64.public;

        function call_a:
            input r0 as u8.public;
            // Base case: if counter is 0, return 1
            is.eq r0 0u8 into r1;
            ternary r1 1u64 0u64 into r2;
            // Recursive case would need to decrement and call B again
            // For simplicity, we just return based on the counter
            add r2 1u64 into r3;
            output r3 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program_b_str = format!(
        r"
        program circular_b.aleo;

        function call_b:
            input r0 as u8.public;
            // Decrement counter
            sub.w r0 1u8 into r1;
            // If counter > 0, call back to A
            gt r0 0u8 into r2;
            ternary r2 r1 0u8 into r3;
            call.dynamic {program_a_field} {aleo_field} {call_a_field} with r3 (as u8.public)
                into r4 (as u64.public);
            output r4 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program_a = Program::<CurrentNetwork>::from_str(&program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy both programs
    let deploy_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_a], rng);

    let deploy_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_b], rng);

    // Execute with a small counter to test the circular pattern
    let inputs = vec![Value::from_str("2u8").unwrap()];
    let transaction =
        vm.execute(&caller_private_key, ("circular_a.aleo", "entry"), inputs.iter(), None, 0, None, rng).unwrap();

    // The transaction should succeed - circular calls are valid as long as they terminate
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests a deep `call.dynamic` hierarchy with 8 levels of nested calls.
#[test]
fn test_deep_call_hierarchy() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    // Create 8 programs, each calling the next one
    let program_names: Vec<String> = (0..8).map(|i| format!("deep_level_{i}")).collect();
    let program_fields: Vec<_> = program_names
        .iter()
        .map(|name| Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap())
        .collect();

    let call_next_field = Identifier::<CurrentNetwork>::from_str("call_next").unwrap().to_field().unwrap();

    let mut programs = Vec::new();

    // Create the deepest program (level 7) - just returns a value
    let deepest_program_str = format!(
        r"
        program {}.aleo;

        function call_next:
            input r0 as u64.public;
            add r0 1u64 into r1;
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        ",
        program_names[7]
    );
    programs.push(Program::<CurrentNetwork>::from_str(&deepest_program_str).unwrap());

    // Create intermediate programs (levels 1-6) - each calls the next level
    for i in (1..7).rev() {
        let program_str = format!(
            r"
            program {}.aleo;

            function call_next:
                input r0 as u64.public;
                add r0 1u64 into r1;
                call.dynamic {} {} {} with r1 (as u64.public)
                    into r2 (as u64.public);
                output r2 as u64.public;

            constructor:
                assert.eq true true;
            ",
            program_names[i],
            program_fields[i + 1],
            aleo_field,
            call_next_field
        );
        programs.push(Program::<CurrentNetwork>::from_str(&program_str).unwrap());
    }

    // Create the entry program (level 0)
    let entry_program_str = format!(
        r"
        program {}.aleo;

        function entry:
            input r0 as u64.public;
            call.dynamic {} {} {} with r0 (as u64.public)
                into r1 (as u64.public);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        ",
        program_names[0], program_fields[1], aleo_field, call_next_field
    );
    programs.push(Program::<CurrentNetwork>::from_str(&entry_program_str).unwrap());

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy all programs in reverse order (deepest first)
    for program in programs.iter() {
        println!("Deploying program {}...", program.id());
        let deploy_tx = vm.deploy(&caller_private_key, program, None, 0, None, rng).unwrap();
        add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);
    }

    // Execute from the entry point
    // Starting with 0, each level adds 1, so with 8 levels we should get 7 (levels 1-7 each add 1)
    let inputs = vec![Value::from_str("0u64").unwrap()];
    let transaction = vm
        .execute(
            &caller_private_key,
            (&format!("{}.aleo", program_names[0]), "entry"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Just verify it executes successfully
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests that `call.dynamic` to `credits.aleo/fee_private` and `fee_public` fails at deployment time.
#[test]
fn test_dynamic_call_credits_fee_functions_forbidden() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let credits_field = Identifier::<CurrentNetwork>::from_str("credits").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let fee_private_field = Identifier::<CurrentNetwork>::from_str("fee_private").unwrap().to_field().unwrap();
    let fee_public_field = Identifier::<CurrentNetwork>::from_str("fee_public").unwrap().to_field().unwrap();

    // Test fee_private - the restriction is enforced at deployment time
    let caller_program_fee_private_str = format!(
        r"
        program call_fee_private.aleo;

        function attempt_fee_private:
            input r0 as u64.public;
            call.dynamic {credits_field} {aleo_field} {fee_private_field}
                with r0 (as u64.public)
                into r1 (as dynamic.record);
            output r1 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program_fee_private = Program::<CurrentNetwork>::from_str(&caller_program_fee_private_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deployment should fail because fee_private cannot be called dynamically
    let deploy_result = vm.deploy(&caller_private_key, &caller_program_fee_private, None, 0, None, rng);

    assert!(deploy_result.is_err(), "Deployment should fail for program calling fee_private");
    let error_msg = deploy_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("fee_private") || error_msg.contains("fee_public"),
        "Error should mention fee_private or fee_public restriction, got: {error_msg}"
    );

    // Test fee_public - also enforced at deployment time
    let caller_program_fee_public_str = format!(
        r"
        program call_fee_public.aleo;

        function attempt_fee_public:
            input r0 as u64.public;
            call.dynamic {credits_field} {aleo_field} {fee_public_field}
                with r0 (as u64.public)
                into r1 (as dynamic.future);
            async attempt_fee_public r1 into r2;
            output r2 as call_fee_public.aleo/attempt_fee_public.future;

        finalize attempt_fee_public:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program_fee_public = Program::<CurrentNetwork>::from_str(&caller_program_fee_public_str).unwrap();

    // Deployment should fail because fee_public cannot be called dynamically
    let deploy_result2 = vm.deploy(&caller_private_key, &caller_program_fee_public, None, 0, None, rng);

    assert!(deploy_result2.is_err(), "Deployment should fail for program calling fee_public");
    let error_msg2 = deploy_result2.unwrap_err().to_string();
    assert!(
        error_msg2.contains("fee_private") || error_msg2.contains("fee_public"),
        "Error should mention fee_private or fee_public restriction, got: {error_msg2}"
    );
}

// Tests that `call.dynamic` to closures fails at deployment time since closures cannot be called dynamically.
#[test]
fn test_dynamic_call_closure_forbidden() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // First create a program with a closure
    let target_program = Program::<CurrentNetwork>::from_str(
        r"
        program has_closure.aleo;

        closure add_numbers:
            input r0 as u64;
            input r1 as u64;
            add r0 r1 into r2;
            output r2 as u64;

        function use_closure:
            input r0 as u64.public;
            input r1 as u64.public;
            call add_numbers r0 r1 into r2;
            output r2 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let target_field = Identifier::<CurrentNetwork>::from_str("has_closure").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let closure_field = Identifier::<CurrentNetwork>::from_str("add_numbers").unwrap().to_field().unwrap();

    // Attempt to call the closure dynamically
    let caller_program_str = format!(
        r"
        program call_closure.aleo;

        function attempt_closure_call:
            input r0 as u64.public;
            input r1 as u64.public;
            call.dynamic {target_field} {aleo_field} {closure_field}
                with r0 r1 (as u64.public u64.public)
                into r2 (as u64.public);
            output r2 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the target program with the closure
    let deploy_target = vm.deploy(&caller_private_key, &target_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_target], rng);

    // Deployment should fail because closures cannot be called dynamically
    let deploy_result = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng);

    assert!(deploy_result.is_err(), "Deployment should fail for program calling a closure dynamically");
    let error_msg = deploy_result.unwrap_err().to_string();
    assert!(
        error_msg.contains("closure") || error_msg.contains("dynamically"),
        "Error should mention closure restriction, got: {error_msg}"
    );
}

// Tests that a program can use `call.dynamic` to call its own functions.
#[test]
fn test_self_referential_dynamic_call() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let self_ref_field = Identifier::<CurrentNetwork>::from_str("self_referential").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let helper_field = Identifier::<CurrentNetwork>::from_str("helper").unwrap().to_field().unwrap();

    // Program that calls itself dynamically
    let program_str = format!(
        r"
        program self_referential.aleo;

        function entry:
            input r0 as u64.public;
            // Dynamically call our own helper function
            call.dynamic {self_ref_field} {aleo_field} {helper_field}
                with r0 (as u64.public)
                into r1 (as u64.public);
            output r1 as u64.public;

        function helper:
            input r0 as u64.public;
            mul r0 2u64 into r1;
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    let deploy_tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Execute the self-referential call
    let inputs = vec![Value::from_str("21u64").unwrap()];
    let transaction =
        vm.execute(&caller_private_key, ("self_referential.aleo", "entry"), inputs.iter(), None, 0, None, rng).unwrap();

    // Verify the output is correct (21 * 2 = 42)
    let num_transitions = transaction.transitions().count();
    let root_transition = transaction.transitions().nth(num_transitions - 2).unwrap();

    let has_expected_output =
        root_transition.outputs().iter().any(|o| matches!(o, Output::Public(_, Some(p)) if p.to_string() == "42u64"));

    assert!(has_expected_output, "Self-referential dynamic call should produce correct output");

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests that malformed identifier fields in `call.dynamic` are properly rejected at deployment time.
#[test]
fn test_malformed_identifier_in_call_dynamic() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    // Use a field value that cannot be decoded to a valid identifier
    // Field::from(u128::MAX) is unlikely to decode to a valid identifier string
    let invalid_program_field = "340282366920938463463374607431768211455field"; // u128::MAX as field
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let some_function_field = Identifier::<CurrentNetwork>::from_str("some_function").unwrap().to_field().unwrap();

    let caller_program_str = format!(
        r"
        program malformed_id.aleo;

        function call_with_bad_program_name:
            call.dynamic {invalid_program_field} {aleo_field} {some_function_field}
                into r0 (as u64.public);
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    let deploy_tx = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Execution should fail due to invalid program name
    let exec_result = vm.execute(
        &caller_private_key,
        ("malformed_id.aleo", "call_with_bad_program_name"),
        Vec::<Value<CurrentNetwork>>::new().into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(exec_result.is_err(), "Dynamic call with malformed program identifier should fail");
}

// Tests that `call.dynamic` inside a finalize block fails at parse time.
#[test]
fn test_call_dynamic_in_finalize_forbidden() {
    let target_field = Identifier::<CurrentNetwork>::from_str("some_program").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let func_field = Identifier::<CurrentNetwork>::from_str("some_func").unwrap().to_field().unwrap();

    let program_str = format!(
        r"
        program dynamic_in_finalize.aleo;

        function entry:
            input r0 as u64.public;
            async entry r0 into r1;
            output r1 as dynamic_in_finalize.aleo/entry.future;

        finalize entry:
            input r0 as u64.public;
            call.dynamic {target_field} {aleo_field} {func_field}
                with r0 (as u64.public)
                into r1 (as u64.public);

        constructor:
            assert.eq true true;
        "
    );

    let parse_result = Program::<CurrentNetwork>::from_str(&program_str);
    assert!(parse_result.is_err(), "call.dynamic in finalize should fail to parse");
}

// Tests that outputting a `dynamic.future` directly fails at deployment time.
// A `dynamic.future` must be passed to `async` and awaited, not returned directly.
#[test]
fn test_dynamic_future_direct_output_forbidden() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let target_field = Identifier::<CurrentNetwork>::from_str("some_program").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let func_field = Identifier::<CurrentNetwork>::from_str("some_func").unwrap().to_field().unwrap();

    let program_str = format!(
        r"
        program direct_future_output.aleo;

        function entry:
            input r0 as u64.public;
            call.dynamic {target_field} {aleo_field} {func_field}
                with r0 (as u64.public)
                into r1 (as dynamic.future);
            output r1 as dynamic.future;

        constructor:
            assert.eq true true;
        "
    );

    // Parsing succeeds but deployment should fail
    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let deploy_result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(deploy_result.is_err(), "dynamic.future direct output should fail deployment");
}

// Tests `call.dynamic` with local struct parameters (defined in the same program).
#[test]
fn test_dynamic_call_with_local_struct_parameters() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let program_field = Identifier::<CurrentNetwork>::from_str("struct_ops").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let process_point_field = Identifier::<CurrentNetwork>::from_str("process_point").unwrap().to_field().unwrap();
    let create_point_field = Identifier::<CurrentNetwork>::from_str("create_point").unwrap().to_field().unwrap();
    let transform_point_field = Identifier::<CurrentNetwork>::from_str("transform_point").unwrap().to_field().unwrap();

    // Program with struct defined locally, used in dynamic calls
    let program_str = format!(
        r"
        program struct_ops.aleo;

        struct point:
            x as u64;
            y as u64;

        struct nested_point:
            p as point;
            label as u8;

        // Function that takes a local struct as input
        function process_point:
            input r0 as point.public;
            add r0.x r0.y into r1;
            output r1 as u64.public;

        // Function that returns a local struct as output
        function create_point:
            input r0 as u64.public;
            input r1 as u64.public;
            cast r0 r1 into r2 as point;
            output r2 as point.public;

        // Function that takes and returns a local struct
        function transform_point:
            input r0 as point.public;
            mul r0.x 2u64 into r1;
            mul r0.y 2u64 into r2;
            cast r1 r2 into r3 as point;
            output r3 as point.public;

        // Dynamic caller that passes local struct as input
        function dynamic_process_point:
            input r0 as point.public;
            call.dynamic {program_field} {aleo_field} {process_point_field}
                with r0 (as point.public)
                into r1 (as u64.public);
            output r1 as u64.public;

        // Dynamic caller that receives local struct as output
        function dynamic_create_point:
            input r0 as u64.public;
            input r1 as u64.public;
            call.dynamic {program_field} {aleo_field} {create_point_field}
                with r0 r1 (as u64.public u64.public)
                into r2 (as point.public);
            output r2 as point.public;

        // Dynamic caller that passes and receives local struct
        function dynamic_transform_point:
            input r0 as point.public;
            call.dynamic {program_field} {aleo_field} {transform_point_field}
                with r0 (as point.public)
                into r1 (as point.public);
            output r1 as point.public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    let deploy_tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Test 1: Local struct as input
    println!("Testing local struct as input to call.dynamic...");
    let inputs = vec![Value::from_str("{ x: 10u64, y: 20u64 }").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_ops.aleo", "dynamic_process_point"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 2: Local struct as output
    println!("Testing local struct as output from call.dynamic...");
    let inputs = vec![Value::from_str("5u64").unwrap(), Value::from_str("15u64").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_ops.aleo", "dynamic_create_point"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 3: Local struct as both input and output
    println!("Testing local struct as input and output in call.dynamic...");
    let inputs = vec![Value::from_str("{ x: 7u64, y: 3u64 }").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_ops.aleo", "dynamic_transform_point"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests `call.dynamic` with external struct parameters (defined in an imported program).
#[test]
fn test_dynamic_call_with_external_struct_parameters() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let provider_field = Identifier::<CurrentNetwork>::from_str("struct_provider").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let get_sum_field = Identifier::<CurrentNetwork>::from_str("get_sum").unwrap().to_field().unwrap();
    let make_pair_field = Identifier::<CurrentNetwork>::from_str("make_pair").unwrap().to_field().unwrap();
    let double_pair_field = Identifier::<CurrentNetwork>::from_str("double_pair").unwrap().to_field().unwrap();

    // Provider program that defines the struct
    let provider_program_str = r"
        program struct_provider.aleo;

        struct pair:
            a as u64;
            b as u64;

        // Takes pair as input
        function get_sum:
            input r0 as pair.public;
            add r0.a r0.b into r1;
            output r1 as u64.public;

        // Returns pair as output
        function make_pair:
            input r0 as u64.public;
            input r1 as u64.public;
            cast r0 r1 into r2 as pair;
            output r2 as pair.public;

        // Takes and returns pair
        function double_pair:
            input r0 as pair.public;
            mul r0.a 2u64 into r1;
            mul r0.b 2u64 into r2;
            cast r1 r2 into r3 as pair;
            output r3 as pair.public;

        constructor:
            assert.eq true true;
    ";

    // Consumer program that uses external struct via call.dynamic
    let consumer_program_str = format!(
        r"
        import struct_provider.aleo;

        program struct_consumer.aleo;

        // Dynamic call with external struct as input
        function call_get_sum:
            input r0 as struct_provider.aleo/pair.public;
            call.dynamic {provider_field} {aleo_field} {get_sum_field}
                with r0 (as struct_provider.aleo/pair.public)
                into r1 (as u64.public);
            output r1 as u64.public;

        // Dynamic call with external struct as output
        function call_make_pair:
            input r0 as u64.public;
            input r1 as u64.public;
            call.dynamic {provider_field} {aleo_field} {make_pair_field}
                with r0 r1 (as u64.public u64.public)
                into r2 (as struct_provider.aleo/pair.public);
            output r2 as struct_provider.aleo/pair.public;

        // Dynamic call with external struct as input and output
        function call_double_pair:
            input r0 as struct_provider.aleo/pair.public;
            call.dynamic {provider_field} {aleo_field} {double_pair_field}
                with r0 (as struct_provider.aleo/pair.public)
                into r1 (as struct_provider.aleo/pair.public);
            output r1 as struct_provider.aleo/pair.public;

        constructor:
            assert.eq true true;
        "
    );

    let provider_program = Program::<CurrentNetwork>::from_str(provider_program_str).unwrap();
    let consumer_program = Program::<CurrentNetwork>::from_str(&consumer_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy provider program first
    println!("Deploying struct_provider.aleo...");
    let deploy_provider = vm.deploy(&caller_private_key, &provider_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_provider], rng);

    // Deploy consumer program
    println!("Deploying struct_consumer.aleo...");
    let deploy_consumer = vm.deploy(&caller_private_key, &consumer_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_consumer], rng);

    // Test 1: External struct as input
    println!("Testing external struct as input to call.dynamic...");
    let inputs = vec![Value::from_str("{ a: 100u64, b: 200u64 }").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_consumer.aleo", "call_get_sum"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 2: External struct as output
    println!("Testing external struct as output from call.dynamic...");
    let inputs = vec![Value::from_str("42u64").unwrap(), Value::from_str("58u64").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_consumer.aleo", "call_make_pair"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 3: External struct as both input and output
    println!("Testing external struct as input and output in call.dynamic...");
    let inputs = vec![Value::from_str("{ a: 25u64, b: 75u64 }").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("struct_consumer.aleo", "call_double_pair"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests `call.dynamic` with array parameters.
#[test]
fn test_dynamic_call_with_array_parameters() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let program_field = Identifier::<CurrentNetwork>::from_str("array_ops").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let sum_array_field = Identifier::<CurrentNetwork>::from_str("sum_array").unwrap().to_field().unwrap();
    let create_array_field = Identifier::<CurrentNetwork>::from_str("create_array").unwrap().to_field().unwrap();
    let double_array_field = Identifier::<CurrentNetwork>::from_str("double_array").unwrap().to_field().unwrap();

    let program_str = format!(
        r"
        program array_ops.aleo;

        // Function that takes an array as input
        function sum_array:
            input r0 as [u64; 4u32].public;
            add r0[0u32] r0[1u32] into r1;
            add r1 r0[2u32] into r2;
            add r2 r0[3u32] into r3;
            output r3 as u64.public;

        // Function that returns an array as output
        function create_array:
            input r0 as u64.public;
            mul r0 1u64 into r1;
            mul r0 2u64 into r2;
            mul r0 3u64 into r3;
            mul r0 4u64 into r4;
            cast r1 r2 r3 r4 into r5 as [u64; 4u32];
            output r5 as [u64; 4u32].public;

        // Function that takes and returns an array
        function double_array:
            input r0 as [u64; 4u32].public;
            mul r0[0u32] 2u64 into r1;
            mul r0[1u32] 2u64 into r2;
            mul r0[2u32] 2u64 into r3;
            mul r0[3u32] 2u64 into r4;
            cast r1 r2 r3 r4 into r5 as [u64; 4u32];
            output r5 as [u64; 4u32].public;

        // Dynamic caller that passes array as input
        function dynamic_sum_array:
            input r0 as [u64; 4u32].public;
            call.dynamic {program_field} {aleo_field} {sum_array_field}
                with r0 (as [u64; 4u32].public)
                into r1 (as u64.public);
            output r1 as u64.public;

        // Dynamic caller that receives array as output
        function dynamic_create_array:
            input r0 as u64.public;
            call.dynamic {program_field} {aleo_field} {create_array_field}
                with r0 (as u64.public)
                into r1 (as [u64; 4u32].public);
            output r1 as [u64; 4u32].public;

        // Dynamic caller that passes and receives array
        function dynamic_double_array:
            input r0 as [u64; 4u32].public;
            call.dynamic {program_field} {aleo_field} {double_array_field}
                with r0 (as [u64; 4u32].public)
                into r1 (as [u64; 4u32].public);
            output r1 as [u64; 4u32].public;

        constructor:
            assert.eq true true;
        "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    let deploy_tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Test 1: Array as input
    println!("Testing array as input to call.dynamic...");
    let inputs = vec![Value::from_str("[1u64, 2u64, 3u64, 4u64]").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("array_ops.aleo", "dynamic_sum_array"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 2: Array as output
    println!("Testing array as output from call.dynamic...");
    let inputs = vec![Value::from_str("10u64").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("array_ops.aleo", "dynamic_create_array"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Test 3: Array as both input and output
    println!("Testing array as input and output in call.dynamic...");
    let inputs = vec![Value::from_str("[5u64, 10u64, 15u64, 20u64]").unwrap()];
    let transaction = vm
        .execute(&caller_private_key, ("array_ops.aleo", "dynamic_double_array"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests double-spend detection behavior when passing dynamic records through `call.dynamic`.
// - When a `dynamic.record` is passed to a function expecting a static record, translation occurs
//   and the record is consumed. Passing the same record again causes double-spend.
// - When a `dynamic.record` is passed to a function expecting `dynamic.record`, no translation
//   occurs and the record is not consumed. The same record can be passed multiple times.
#[test]
fn test_dynamic_record_double_spend_detection() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Define the base program with record operations
    let base_program_name = Identifier::<CurrentNetwork>::from_str("record_ops").unwrap();
    let base_program_field = base_program_name.to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    let consume_static_name = Identifier::<CurrentNetwork>::from_str("consume_static").unwrap();
    let consume_static_field = consume_static_name.to_field().unwrap();

    let consume_dynamic_name = Identifier::<CurrentNetwork>::from_str("consume_dynamic").unwrap();
    let consume_dynamic_field = consume_dynamic_name.to_field().unwrap();

    let base_program_str = format!(
        r"
        program {base_program_name}.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function mint:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as token.record;
            output r2 as token.record;

        // Takes a static record as input - triggers translation when called with dynamic record
        function {consume_static_name}:
            input r0 as token.record;

        // Takes a dynamic record as input - no translation, record is not consumed
        function {consume_dynamic_name}:
            input r0 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    );

    // Define the caller program that tests double-spend scenarios
    let caller_program_str = format!(
        r"
        import {base_program_name}.aleo;

        program double_spend_test.aleo;

        // Calls consume_static twice with the same dynamic record
        // This SHOULD FAIL due to double-spend (translation consumes the record)
        function call_static_twice:
            input r0 as dynamic.record;
            call.dynamic {base_program_field} {aleo_field} {consume_static_field} with r0 (as dynamic.record);
            call.dynamic {base_program_field} {aleo_field} {consume_static_field} with r0 (as dynamic.record);

        // Calls consume_dynamic twice with the same dynamic record
        // This SHOULD SUCCEED (dynamic.record input doesn't consume the record)
        function call_dynamic_twice:
            input r0 as dynamic.record;
            call.dynamic {base_program_field} {aleo_field} {consume_dynamic_field} with r0 (as dynamic.record);
            call.dynamic {base_program_field} {aleo_field} {consume_dynamic_field} with r0 (as dynamic.record);

            // Needed to pass the record-existence check (r0 must materialize)
            call.dynamic {base_program_field} {aleo_field} {consume_static_field} with r0 (as dynamic.record);

        constructor:
            assert.eq true true;
        "
    );

    let base_program = Program::<CurrentNetwork>::from_str(&base_program_str).unwrap();
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    // Deploy both programs
    println!("Deploying {base_program_name}.aleo...");
    let deploy_base = vm.deploy(&caller_private_key, &base_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_base], rng);

    println!("Deploying double_spend_test.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Helper to mint a record and convert to dynamic
    let mint_dynamic_record = |rng: &mut TestRng| {
        println!("Minting record...");
        let inputs = vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("100u64").unwrap()];
        let mint_tx = vm
            .execute(
                &caller_private_key,
                (format!("{base_program_name}.aleo"), "mint"),
                inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let execution = mint_tx.execution().unwrap();
        let record = execution
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
        add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[mint_tx], rng);
        DynamicRecord::<CurrentNetwork>::from_record(&record).unwrap()
    };

    // Test 1: Passing same dynamic record to static-input function twice should fail (double-spend)
    println!("\nTest 1: Calling static-input function twice with same dynamic record (should fail)...");
    let dynamic_record = mint_dynamic_record(rng);
    let result = vm.execute(
        &caller_private_key,
        ("double_spend_test.aleo", "call_static_twice"),
        vec![Value::DynamicRecord(dynamic_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    if let Ok(transaction) = result {
        // If execution succeeds, the transaction should be aborted when added to block
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
        assert_eq!(block.transactions().num_accepted(), 0, "Transaction should not be accepted");
        assert_eq!(block.aborted_transaction_ids().len(), 1, "Transaction should be aborted due to double-spend");
        vm.add_next_block(&block).unwrap();
        println!("Double-spend correctly detected and transaction aborted.");
    } else {
        println!("Double-spend correctly detected during execution: {}", result.unwrap_err());
    }

    // Test 2: Passing same dynamic record to dynamic-input function twice should succeed
    println!("\nTest 2: Calling dynamic-input function twice with same dynamic record (should succeed)...");
    let dynamic_record = mint_dynamic_record(rng);
    let inputs = vec![Value::DynamicRecord(dynamic_record)];
    let transaction = vm
        .execute(
            &caller_private_key,
            ("double_spend_test.aleo", "call_dynamic_twice"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .expect("Passing dynamic record to dynamic-input function multiple times should succeed");

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
    println!("Successfully passed same dynamic record to dynamic-input function twice.");
}

// Tests dynamic calls to programs deployed before V14, then after a program upgrade.
// Verifies that:
// 1. Pre-V14 deployments do not include translation keys.
// 2. A verifier VM without translation keys rejects the prover's transaction.
// 3. After a program upgrade at V14, the verifier VM gains translation keys.
// 4. The verifier VM with translation keys (from upgrade) can verify and accept the transaction.
#[test]
fn test_dynamic_call_to_pre_v14_program() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let legacy_program = Program::<CurrentNetwork>::from_str(
        r"
        program legacy_token.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function mint:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as token.record;
            output r2 as token.record;

        function transfer:
            input r0 as token.record;
            input r1 as address.private;
            input r2 as u64.private;
            cast r1 r2 into r3 as token.record;
            output r3 as token.record;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let caller_program = Program::<CurrentNetwork>::from_str(
        r"
        program dynamic_caller.aleo;

        function call_legacy_transfer:
            input r0 as field.public;
            input r1 as field.public;
            input r2 as field.public;
            input r3 as dynamic.record;
            input r4 as address.private;
            input r5 as u64.private;
            call.dynamic r0 r1 r2 with r3 r4 r5 (as dynamic.record address.private u64.private) into r6 (as dynamic.record);
            async call_legacy_transfer into r7;
            output r6 as dynamic.record;
            output r7 as dynamic_caller.aleo/call_legacy_transfer.future;

        finalize call_legacy_transfer:
            assert.eq true true;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let legacy_program_field = Identifier::<CurrentNetwork>::from_str("legacy_token").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let transfer_field = Identifier::<CurrentNetwork>::from_str("transfer").unwrap().to_field().unwrap();

    // --- Set up verifier VM (pre-V14 deployment, no translation keys) ---
    let pre_v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap_or(1);
    let verifier_vm = sample_vm_at_height(pre_v14_height, rng);

    // Deploy legacy program before V14.
    let deploy_legacy_pre_v14 = verifier_vm.deploy(&caller_private_key, &legacy_program, None, 0, None, rng).unwrap();

    if let Transaction::Deploy(_, _, _, deployment, _) = &deploy_legacy_pre_v14 {
        assert!(
            deployment.translation_verifying_keys().is_none(),
            "Pre-V14 deployment should not have translation keys"
        );
    }

    add_and_test_with_costs(&verifier_vm, &caller_private_key, None, &[deploy_legacy_pre_v14], rng);

    // Mint a token on verifier VM.
    let inputs = vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let mint_tx = verifier_vm
        .execute(&caller_private_key, ("legacy_token.aleo", "mint"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&verifier_vm, &caller_private_key, Some(&[&inputs]), &[mint_tx], rng);

    // Advance verifier VM to V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    for _ in verifier_vm.block_store().current_block_height()..v14_height {
        let block = sample_next_block(&verifier_vm, &caller_private_key, &[], rng).unwrap();
        verifier_vm.add_next_block(&block).unwrap();
    }

    // Deploy caller program on verifier VM at V14.
    let deploy_caller_verifier = verifier_vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&verifier_vm, &caller_private_key, None, &[deploy_caller_verifier], rng);

    // Verify the verifier VM does NOT have translation keys for `legacy_token.aleo/token`.
    let legacy_program_id = console::program::ProgramID::<CurrentNetwork>::from_str("legacy_token.aleo").unwrap();
    let token_name = Identifier::<CurrentNetwork>::from_str("token").unwrap();

    {
        let vm_process = verifier_vm.process();
        let stack = vm_process.get_stack(legacy_program_id).unwrap();
        assert_eq!(*stack.program_edition(), 0, "Verifier should have edition 0 before upgrade");
        assert!(
            stack.get_verifying_key(&token_name).is_err(),
            "Verifier VM should NOT have translation key (pre-V14 deployment)"
        );
    }

    // --- Set up prover VM (V14 deployment, has translation keys) ---
    let prover_vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy legacy program at V14 (includes translation keys).
    let deploy_legacy_v14 = prover_vm.deploy(&caller_private_key, &legacy_program, None, 0, None, rng).unwrap();

    if let Transaction::Deploy(_, _, _, deployment, _) = &deploy_legacy_v14 {
        assert!(deployment.translation_verifying_keys().is_some(), "V14 deployment should include translation keys");
    }

    add_and_test_with_costs(&prover_vm, &caller_private_key, None, &[deploy_legacy_v14], rng);

    // Deploy caller program on prover VM.
    let deploy_caller_prover = prover_vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&prover_vm, &caller_private_key, None, &[deploy_caller_prover], rng);

    // Mint a token on prover VM.
    let inputs = vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let prover_mint_tx = prover_vm
        .execute(&caller_private_key, ("legacy_token.aleo", "mint"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    let prover_minted_record = prover_mint_tx
        .execution()
        .unwrap()
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
    add_and_test_with_costs(&prover_vm, &caller_private_key, Some(&[&inputs]), &[prover_mint_tx], rng);

    // Prover creates a transaction requiring translation.
    let dynamic_record = DynamicRecord::<CurrentNetwork>::from_record(&prover_minted_record).unwrap();

    let transaction = prover_vm
        .execute(
            &caller_private_key,
            ("dynamic_caller.aleo", "call_legacy_transfer"),
            vec![
                Value::from_str(&format!("{legacy_program_field}")).unwrap(),
                Value::from_str(&format!("{aleo_field}")).unwrap(),
                Value::from_str(&format!("{transfer_field}")).unwrap(),
                Value::DynamicRecord(dynamic_record),
                Value::from_str(&caller_address.to_string()).unwrap(),
                Value::from_str("500u64").unwrap(),
            ]
            .into_iter(),
            None,
            0,
            None,
            rng,
        )
        .expect("Prover with translation keys should create transaction");

    // Prover VM can verify its own transaction.
    prover_vm.check_transaction(&transaction, None, rng).expect("Prover VM should verify its own transaction");

    // Verifier VM (without translation keys) should abort the transaction.
    let block = sample_next_block(&verifier_vm, &caller_private_key, &[transaction], rng).unwrap();
    assert_eq!(block.aborted_transaction_ids().len(), 1, "Transaction should be aborted without translation keys");
    verifier_vm.add_next_block(&block).unwrap();

    // --- Upgrade verifier VM (program upgrade adds translation keys) ---

    // Re-deploy legacy program on verifier VM (program upgrade with new edition, includes translation keys).
    let upgrade_legacy = verifier_vm.deploy(&caller_private_key, &legacy_program, None, 0, None, rng).unwrap();

    if let Transaction::Deploy(_, _, _, deployment, _) = &upgrade_legacy {
        assert!(
            deployment.translation_verifying_keys().is_some(),
            "V14 program upgrade should include translation keys"
        );
    }

    add_and_test_with_costs(&verifier_vm, &caller_private_key, None, &[upgrade_legacy], rng);

    // Verify the verifier VM now HAS translation keys after upgrade, and the edition incremented.
    {
        let vm_process = verifier_vm.process();
        let stack = vm_process.get_stack(legacy_program_id).unwrap();
        assert_eq!(*stack.program_edition(), 1, "Verifier should have edition 1 after upgrade");
        assert!(
            stack.get_verifying_key(&token_name).is_ok(),
            "Verifier VM should have translation key after program upgrade"
        );
    }

    // Mint a fresh token on verifier VM and execute the dynamic call directly.
    // This verifies the verifier VM can create and accept dynamic call transactions
    // after getting translation keys via upgrade.
    let inputs = vec![Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let verifier_mint_tx_2 = verifier_vm
        .execute(&caller_private_key, ("legacy_token.aleo", "mint"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    let verifier_minted_record_2 = verifier_mint_tx_2
        .execution()
        .unwrap()
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
    add_and_test_with_costs(&verifier_vm, &caller_private_key, Some(&[&inputs]), &[verifier_mint_tx_2], rng);

    let dynamic_record_2 = DynamicRecord::<CurrentNetwork>::from_record(&verifier_minted_record_2).unwrap();

    let inputs = vec![
        Value::from_str(&format!("{legacy_program_field}")).unwrap(),
        Value::from_str(&format!("{aleo_field}")).unwrap(),
        Value::from_str(&format!("{transfer_field}")).unwrap(),
        Value::DynamicRecord(dynamic_record_2),
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str("500u64").unwrap(),
    ];
    let transaction_2 = verifier_vm
        .execute(
            &caller_private_key,
            ("dynamic_caller.aleo", "call_legacy_transfer"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .expect("Verifier VM should create transaction after getting translation keys via upgrade");

    // Verifier VM (with translation keys from upgrade) should accept the transaction.
    add_and_test_with_costs(&verifier_vm, &caller_private_key, Some(&[&inputs]), &[transaction_2], rng);
}

// Tests that a consumed record cannot be reused in a subsequent block.
#[test]
fn test_replay_attack_prevention_across_blocks() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    let base_program_field = Identifier::<CurrentNetwork>::from_str("replay_base").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_field = Identifier::<CurrentNetwork>::from_str("consume").unwrap().to_field().unwrap();

    // Define a base program with a record that can be consumed
    let base_program = Program::<CurrentNetwork>::from_str(
        r"
        program replay_base.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function mint:
            input r0 as u64.private;
            cast self.caller r0 into r1 as token.record;
            output r1 as token.record;

        function consume:
            input r0 as token.record;
            output r0.amount as u64.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    // Define a caller program that consumes records via dynamic call
    let caller_program_str = format!(
        r"
        program replay_caller.aleo;

        function dynamic_consume:
            input r0 as dynamic.record;
            call.dynamic {base_program_field} {aleo_field} {consume_field}
                with r0 (as dynamic.record)
                into r1 (as u64.public);
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        "
    );
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    // Deploy programs
    println!("Deploying replay_base.aleo...");
    let deploy_base = vm.deploy(&caller_private_key, &base_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_base], rng);

    println!("Deploying replay_caller.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Mint a record
    println!("\nMinting a token record...");
    let inputs = vec![Value::from_str("1000u64").unwrap()];
    let mint_tx =
        vm.execute(&caller_private_key, ("replay_base.aleo", "mint"), inputs.iter(), None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), std::slice::from_ref(&mint_tx), rng);

    // Extract the minted record
    let record = mint_tx
        .records()
        .filter_map(|(_, record)| record.decrypt(&caller_view_key).ok())
        .next()
        .expect("Should have a minted record");
    let dynamic_record = DynamicRecord::<CurrentNetwork>::from_record(&record).unwrap();
    println!("Minted record");

    // Block N: Consume the record via dynamic call (should succeed)
    println!("\nBlock N: Consuming record via dynamic call (should succeed)...");
    let inputs = vec![Value::DynamicRecord(dynamic_record.clone())];
    let consume_tx = vm
        .execute(&caller_private_key, ("replay_caller.aleo", "dynamic_consume"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[consume_tx], rng);
    println!("Record consumed successfully in block N");

    // Block N+1: Try to consume the same record again (replay attack - should fail)
    println!("\nBlock N+1: Attempting replay attack with same record (should fail)...");
    let replay_result = vm.execute(
        &caller_private_key,
        ("replay_caller.aleo", "dynamic_consume"),
        vec![Value::DynamicRecord(dynamic_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    match replay_result {
        Ok(replay_tx) => {
            // If execution succeeds, the transaction should be rejected when added to block
            let block = sample_next_block(&vm, &caller_private_key, &[replay_tx], rng).unwrap();
            assert_eq!(block.transactions().num_accepted(), 0, "Replay transaction should not be accepted");
            assert!(!block.aborted_transaction_ids().is_empty(), "Replay should be aborted");
            vm.add_next_block(&block).unwrap();
            println!("Replay correctly prevented - transaction aborted");
        }
        Err(e) => {
            println!("Replay attack correctly prevented during execution: {e}");
        }
    }

    println!("\nSUCCESS: Replay attack prevented");
}

// Tests that self.caller reflects the immediate caller in nested dynamic calls.
// A → B → C: C sees B as caller, not A.
#[test]
fn test_nested_caller_authorization() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Program that records who called it
    let recorder_program = Program::<CurrentNetwork>::from_str(
        r"
        program caller_recorder.aleo;

        mapping callers:
            key as u8.public;
            value as address.public;

        function record_caller:
            input r0 as u8.public;
            async record_caller r0 self.caller into r1;
            output r1 as caller_recorder.aleo/record_caller.future;

        finalize record_caller:
            input r0 as u8.public;
            input r1 as address.public;
            set r1 into callers[r0];

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let recorder_field = Identifier::<CurrentNetwork>::from_str("caller_recorder").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let record_caller_field = Identifier::<CurrentNetwork>::from_str("record_caller").unwrap().to_field().unwrap();

    // Middle program that calls recorder and passes self.caller
    let middle_program_str = format!(
        r"
        program middle_caller.aleo;

        function call_recorder:
            input r0 as u8.public;
            call.dynamic {recorder_field} {aleo_field} {record_caller_field}
                with r0 (as u8.public)
                into r1 (as dynamic.future);
            async call_recorder r1 into r2;
            output r2 as middle_caller.aleo/call_recorder.future;

        finalize call_recorder:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );
    let middle_program = Program::<CurrentNetwork>::from_str(&middle_program_str).unwrap();

    let middle_field = Identifier::<CurrentNetwork>::from_str("middle_caller").unwrap().to_field().unwrap();
    let call_recorder_field = Identifier::<CurrentNetwork>::from_str("call_recorder").unwrap().to_field().unwrap();

    // Outer program that calls middle
    let outer_program_str = format!(
        r"
        program outer_caller.aleo;

        function call_middle:
            input r0 as u8.public;
            call.dynamic {middle_field} {aleo_field} {call_recorder_field}
                with r0 (as u8.public)
                into r1 (as dynamic.future);
            async call_middle r1 into r2;
            output r2 as outer_caller.aleo/call_middle.future;

        finalize call_middle:
            input r0 as dynamic.future;
            await r0;

        constructor:
            assert.eq true true;
        "
    );
    let outer_program = Program::<CurrentNetwork>::from_str(&outer_program_str).unwrap();

    // Deploy all programs
    println!("Deploying caller_recorder.aleo...");
    let deploy_recorder = vm.deploy(&caller_private_key, &recorder_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_recorder], rng);

    println!("Deploying middle_caller.aleo...");
    let deploy_middle = vm.deploy(&caller_private_key, &middle_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_middle], rng);

    println!("Deploying outer_caller.aleo...");
    let deploy_outer = vm.deploy(&caller_private_key, &outer_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_outer], rng);

    // Test 1: Direct call to recorder - self.caller should be the user's address
    println!("\nTest 1: Direct call to recorder (self.caller = user address)...");
    let inputs = vec![Value::from_str("0u8").unwrap()];
    let direct_tx = vm
        .execute(&caller_private_key, ("caller_recorder.aleo", "record_caller"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[direct_tx], rng);

    // Verify the mapping value
    let recorded_caller_0 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("caller_recorder.aleo").unwrap(),
            Identifier::from_str("callers").unwrap(),
            &Plaintext::from_str("0u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    println!("Direct call recorded caller: {recorded_caller_0}");
    assert_eq!(
        recorded_caller_0.to_string(),
        caller_address.to_string(),
        "Direct call should record user's address as caller"
    );

    // Test 2: Call through middle program - self.caller should be middle program's address
    println!("\nTest 2: Call through middle_caller (self.caller = middle program address)...");
    let middle_program_address =
        ProgramID::<CurrentNetwork>::from_str("middle_caller.aleo").unwrap().to_address().unwrap();
    let inputs = vec![Value::from_str("1u8").unwrap()];
    let through_middle_tx = vm
        .execute(&caller_private_key, ("middle_caller.aleo", "call_recorder"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[through_middle_tx], rng);

    let recorded_caller_1 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("caller_recorder.aleo").unwrap(),
            Identifier::from_str("callers").unwrap(),
            &Plaintext::from_str("1u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    println!("Through middle recorded caller: {recorded_caller_1}");
    println!("Expected middle program address: {middle_program_address}");
    assert_eq!(
        recorded_caller_1.to_string(),
        middle_program_address.to_string(),
        "Call through middle should record middle program's address as caller"
    );

    // Test 3: Call through outer->middle - self.caller should still be middle program's address
    println!("\nTest 3: Call through outer->middle->recorder (self.caller = middle program address)...");
    let inputs = vec![Value::from_str("2u8").unwrap()];
    let through_outer_tx = vm
        .execute(&caller_private_key, ("outer_caller.aleo", "call_middle"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[through_outer_tx], rng);

    let recorded_caller_2 = vm
        .finalize_store()
        .get_value_confirmed(
            ProgramID::from_str("caller_recorder.aleo").unwrap(),
            Identifier::from_str("callers").unwrap(),
            &Plaintext::from_str("2u8").unwrap(),
        )
        .unwrap()
        .unwrap();
    println!("Through outer->middle recorded caller: {recorded_caller_2}");
    // The caller to recorder is middle_caller, even when called through outer_caller
    assert_eq!(
        recorded_caller_2.to_string(),
        middle_program_address.to_string(),
        "Call through outer->middle should record middle program's address as caller (immediate caller)"
    );

    println!("\nSUCCESS: Nested caller authorization correctly identifies immediate caller in dynamic call chains");
}

/// Tests that a V2 deployment (without record verifying keys)
/// is rejected when verified at V14.
#[test]
fn test_v2_deployment_transaction_rejected_at_v14() {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Create a VM at V13 to construct a V2 deployment.
    let vm_v13 = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V13).unwrap(), rng);

    // Deploy a program with a record at V13. The record means the V14 check will
    // require record verifying keys, which the pre-V14 deployment won't have.
    let program = Program::from_str(
        r"
program v2_rejected_at_v14_test.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function compute:
    input r0 as u64.private;
    add r0 1u64 into r1;
    output r1 as u64.private;

constructor:
    assert.eq true true;
",
    )
    .unwrap();

    // Create a V2 deployment transaction at V13.
    let v2_deployment = vm_v13.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();

    // Verify it's a pre-V14 deployment (no record verifying keys).
    match &v2_deployment {
        Transaction::Deploy(_, _, _, deploy, _) => {
            assert!(
                deploy.translation_verifying_keys().is_none(),
                "Pre-V14 deployment should have no record verifying keys"
            );
        }
        _ => panic!("Expected deploy transaction"),
    }

    // Now create a VM at V14 and try to verify/include the V2 deployment.
    let vm_v14 = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // The V2 deployment should be rejected at V14.
    let block = sample_next_block(&vm_v14, &caller_private_key, &[v2_deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 0, "V2 deployment should be rejected at V14");
    assert_eq!(block.aborted_transaction_ids().len(), 1, "V2 deployment should be aborted at V14");
}

// Tests that an execution generating more than `MAX_BATCH_PROOF_INSTANCES` (128) proof instances
// is rejected. The prover-side instance count (transitions + translation proofs) is checked in
// `prove_batch` before any proof is computed. The instance breakdown for this test is:
// - Transitions: 1 (caller) + 4×1 (mint_batch) + 4×1 (consume_batch) = 9
// - Translation proofs: 4×16 (A output static→dynamic) + 4×16 (B input dynamic→static) = 128
// - Total: 9 + 128 = 137 > MAX_BATCH_PROOF_INSTANCES (128)
//
// Two programs are used:
// - `instance_limit_a.aleo`: defines a `token` record and a `mint_batch` function that creates
//   16 tokens via `cast` per call (16 outputs).
// - `instance_limit_b.aleo`: defines a `consume_batch` function that takes 16 external tokens
//   from A (16 dynamic inputs, translated to static on entry).
// The caller chains 4 rounds of (call A → call B), each round contributing 32 translation
// proof instances, for a total that exceeds the 128-instance limit.
#[test]
fn test_batch_proof_instance_limit_exceeded() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;

    // Compute field operands for the dynamic calls.
    let a_field = Identifier::<CurrentNetwork>::from_str("instance_limit_a")?.to_field()?;
    let b_field = Identifier::<CurrentNetwork>::from_str("instance_limit_b")?.to_field()?;
    let net_field = Identifier::<CurrentNetwork>::from_str("aleo")?.to_field()?;
    let mint_field = Identifier::<CurrentNetwork>::from_str("mint_batch")?.to_field()?;
    let consume_field = Identifier::<CurrentNetwork>::from_str("consume_batch")?.to_field()?;

    // Program A: mints 16 token records per call via `cast`.
    let program_a = Program::<CurrentNetwork>::from_str(
        r"
        program instance_limit_a.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function mint_batch:
            input r0 as address.private;
            cast r0 1u64 into r1 as token.record;
            cast r0 2u64 into r2 as token.record;
            cast r0 3u64 into r3 as token.record;
            cast r0 4u64 into r4 as token.record;
            cast r0 5u64 into r5 as token.record;
            cast r0 6u64 into r6 as token.record;
            cast r0 7u64 into r7 as token.record;
            cast r0 8u64 into r8 as token.record;
            cast r0 9u64 into r9 as token.record;
            cast r0 10u64 into r10 as token.record;
            cast r0 11u64 into r11 as token.record;
            cast r0 12u64 into r12 as token.record;
            cast r0 13u64 into r13 as token.record;
            cast r0 14u64 into r14 as token.record;
            cast r0 15u64 into r15 as token.record;
            cast r0 16u64 into r16 as token.record;
            output r1 as token.record;
            output r2 as token.record;
            output r3 as token.record;
            output r4 as token.record;
            output r5 as token.record;
            output r6 as token.record;
            output r7 as token.record;
            output r8 as token.record;
            output r9 as token.record;
            output r10 as token.record;
            output r11 as token.record;
            output r12 as token.record;
            output r13 as token.record;
            output r14 as token.record;
            output r15 as token.record;
            output r16 as token.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Program B: spends 16 external token records from A per call.
    let program_b = Program::<CurrentNetwork>::from_str(
        r"
        import instance_limit_a.aleo;

        program instance_limit_b.aleo;

        function consume_batch:
            input r0 as instance_limit_a.aleo/token.record;
            input r1 as instance_limit_a.aleo/token.record;
            input r2 as instance_limit_a.aleo/token.record;
            input r3 as instance_limit_a.aleo/token.record;
            input r4 as instance_limit_a.aleo/token.record;
            input r5 as instance_limit_a.aleo/token.record;
            input r6 as instance_limit_a.aleo/token.record;
            input r7 as instance_limit_a.aleo/token.record;
            input r8 as instance_limit_a.aleo/token.record;
            input r9 as instance_limit_a.aleo/token.record;
            input r10 as instance_limit_a.aleo/token.record;
            input r11 as instance_limit_a.aleo/token.record;
            input r12 as instance_limit_a.aleo/token.record;
            input r13 as instance_limit_a.aleo/token.record;
            input r14 as instance_limit_a.aleo/token.record;
            input r15 as instance_limit_a.aleo/token.record;
            output r0.owner as address.private;

        constructor:
            assert.eq true true;
        ",
    )?;

    // The caller chains 3 rounds of (call A to mint 16 tokens, call B to spend them).
    let caller_program = Program::<CurrentNetwork>::from_str(&format!(
        r"
        import instance_limit_a.aleo;

        program instance_limit_caller.aleo;

        function run:
            input r0 as address.private;

            call.dynamic {a_field} {net_field} {mint_field}
                with r0 (as address.private)
                into r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record);
            call.dynamic {b_field} {net_field} {consume_field}
                with r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record)
                into r17 (as address.private);

            call.dynamic {a_field} {net_field} {mint_field}
                with r0 (as address.private)
                into r18 r19 r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 r32 r33
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record);
            call.dynamic {b_field} {net_field} {consume_field}
                with r18 r19 r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 r32 r33
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record)
                into r34 (as address.private);

            call.dynamic {a_field} {net_field} {mint_field}
                with r0 (as address.private)
                into r35 r36 r37 r38 r39 r40 r41 r42 r43 r44 r45 r46 r47 r48 r49 r50
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record);
            call.dynamic {b_field} {net_field} {consume_field}
                with r35 r36 r37 r38 r39 r40 r41 r42 r43 r44 r45 r46 r47 r48 r49 r50
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record)
                into r51 (as address.private);

            call.dynamic {a_field} {net_field} {mint_field}
                with r0 (as address.private)
                into r52 r53 r54 r55 r56 r57 r58 r59 r60 r61 r62 r63 r64 r65 r66 r67
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record);
            call.dynamic {b_field} {net_field} {consume_field}
                with r52 r53 r54 r55 r56 r57 r58 r59 r60 r61 r62 r63 r64 r65 r66 r67
                (as dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record
                    dynamic.record dynamic.record dynamic.record dynamic.record)
                into r68 (as address.private);

            output r17 as address.private;

        constructor:
            assert.eq true true;
        "
    ))?;

    // Initialize the VM at V14.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?, rng);

    // Deploy program A.
    let tx = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Deploy program B.
    let tx = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Deploy the caller program.
    let tx = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[tx], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Attempt execution. This should fail because 137 > MAX_BATCH_PROOF_INSTANCES (128).
    let result = vm.execute(
        &caller_private_key,
        ("instance_limit_caller.aleo", "run"),
        vec![Value::from_str(&format!("{caller_address}"))?].into_iter(),
        None,
        0,
        None,
        rng,
    );
    assert!(result.is_err(), "Expected execution to fail due to exceeding MAX_BATCH_PROOF_INSTANCES");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("exceed the maximum allowed"), "Expected instance limit error, got: {err}",);

    Ok(())
}

// Tests that programs containing dynamic calls with declared output types of the form "as <TYPE>.constant" are disallowed.
#[test]
fn test_constant_dynamic_call_input_output() {
    // In this program, the dynamic call attempts to return a single constant output.
    let program_a = |is_constant: bool| {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
    program program_a.aleo;

    function dynamic_constant_output:
        input r0 as u16.public;

        call.dynamic 0field 1field 2field
            with r0 (as u16.public)
            into r1 (as u16.{});

        output r1 as u16.constant;
    constructor:
        assert.eq true true;
    ",
            if is_constant { "constant" } else { "public" }
        ))
    };

    assert!(program_a(false).is_ok());
    assert!(program_a(true).is_err());

    // In this program, the invalid constant-output declaration is sandwiched in between two valid ones
    let program_b = |is_constant: bool| {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
    program program_c.aleo;

    function dynamic_constant_output:

        call.dynamic 0field 1field 2field
            into r0 r1 r2 (as bool.private bool.{} u16.public);

    constructor:
        assert.eq true true;
    ",
            if is_constant { "constant" } else { "private" }
        ))
    };

    assert!(program_b(false).is_ok());
    assert!(program_b(true).is_err());

    // In this program, the dynamic call attempts to receive a single constant input, whose value
    // is furthermore hardcoded (instead of being passed in a register)
    let program_c = |is_constant: bool| {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
    program program_c.aleo;

    function dynamic_constant_input:

        call.dynamic 0field 1field 2field
            with 0field (as field.{})
            into r1 (as u16.private);

        output r1 as u16.constant;
    constructor:
        assert.eq true true;
    ",
            if is_constant { "constant" } else { "public" }
        ))
    };

    assert!(program_c(false).is_ok());
    assert!(program_c(true).is_err());

    // In this program, the invalid constant-input declaration is sandwiched between several valid ones.
    let program_d = |is_constant: bool| {
        Program::<CurrentNetwork>::from_str(&format!(
            r"
    program program_d.aleo;

    function dynamic_constant_output:

        call.dynamic 0field 1field 2field
            with r0 r1 r2 r3 (as bool.private bool.{} u16.public field.public);

    constructor:
        assert.eq true true;
    ",
            if is_constant { "constant" } else { "private" }
        ))
    };

    assert!(program_d(false).is_ok());
    assert!(program_d(true).is_err());
}
