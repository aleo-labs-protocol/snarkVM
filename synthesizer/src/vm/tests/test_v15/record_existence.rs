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

// Tests that the record-existence check passes or fails as expected in a number
// of scenarios. In particular, all cases documented in process_transition
// (auxiliary function to ensure_records_exist) are explored.
#[test]
fn test_existence_check() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(&caller_private_key).unwrap();

    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let program_base_field = Identifier::<CurrentNetwork>::from_str("base").unwrap().to_field().unwrap();
    let program_extension_field = Identifier::<CurrentNetwork>::from_str("extension").unwrap().to_field().unwrap();
    let decommission_function_field =
        Identifier::<CurrentNetwork>::from_str("decommission").unwrap().to_field().unwrap();
    let decommission_reversed_function_field =
        Identifier::<CurrentNetwork>::from_str("decommission_reversed").unwrap().to_field().unwrap();
    let decommission_two_function_field =
        Identifier::<CurrentNetwork>::from_str("decommission_two").unwrap().to_field().unwrap();
    let mint_rover_function_field = Identifier::<CurrentNetwork>::from_str("mint_rover").unwrap().to_field().unwrap();
    let program_frontier_field = Identifier::<CurrentNetwork>::from_str("frontier").unwrap().to_field().unwrap();
    let program_remapper_field = Identifier::<CurrentNetwork>::from_str("remapper").unwrap().to_field().unwrap();
    let consume_map_function_field = Identifier::<CurrentNetwork>::from_str("consume_map").unwrap().to_field().unwrap();
    let consume_dynamic_map_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_dynamic_map").unwrap().to_field().unwrap();
    let remap_dynamic_function_field =
        Identifier::<CurrentNetwork>::from_str("remap_dynamic_function").unwrap().to_field().unwrap();
    let do_not_consume_function_field =
        Identifier::<CurrentNetwork>::from_str("do_not_consume").unwrap().to_field().unwrap();
    let consume_external_map_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_external_map").unwrap().to_field().unwrap();
    let dynamic_pass_through_function_field =
        Identifier::<CurrentNetwork>::from_str("dynamic_pass_through_function").unwrap().to_field().unwrap();

    let program_base = Program::<CurrentNetwork>::from_str(
        r"
        program base.aleo;

        record rover:
            owner as address.private;
            planet_code as u8.private;
            active as boolean.private;

        function mint_rover:
            input r0 as u8.private;
            input r1 as boolean.private;

            cast self.signer r0 r1 into r2 as rover.record;
            output r2 as rover.record;

        // This function breaks the local check (output)
        function dynamic_mint:
            input r0 as u8.private;
            input r1 as boolean.private;

            cast self.signer r0 r1 into r2 as rover.record;
            cast r2 into r3 as dynamic.record;

            output r3 as dynamic.record;

        // Consumes a rover Record and outputs whether its planet was the same as that of a DynamicRecord received separately
        function decommission:
            input r0 as rover.record;
            input r1 as dynamic.record;

            get.record.dynamic r1.planet_code into r2 as u8.private;

            is.eq r2 r0.planet_code into r3;

            output r3 as boolean.public;

        // Does the same as decommission but receives the DynamicRecord and Record in the opposite order
        function decommission_reversed:
            input r0 as dynamic.record;
            input r1 as rover.record;

            get.record.dynamic r0.planet_code into r2 as u8.private;

            is.eq r2 r1.planet_code into r3;

            output r3 as boolean.public;

        // Consumes two rover Records and outputs whether their planets coincide
        function decommission_two:
            input r0 as rover.record;
            input r1 as rover.record;

            is.eq r0.planet_code r1.planet_code into r2;

            output r2 as boolean.public;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let program_extension = Program::<CurrentNetwork>::from_str(&format!(
        r"
        import base.aleo;

        program extension.aleo;

        // This function passes the local check: if dynamic_mint does not output non-existent records, neither does call_base
        function call_base:
            input r0 as boolean.private;
            call base.aleo/dynamic_mint 3u8 r0 into r1;
            output r1 as dynamic.record;

        function check_decommission_same:
            input r0 as base.aleo/rover.record;

            assert.eq r0.active true;
            cast r0 into r1 as dynamic.record;
            cast r0 into r2 as dynamic.record;

            call.dynamic {program_base_field} {network_field} {decommission_function_field}
                with r1 r2 (as dynamic.record dynamic.record)
                into r3 (as boolean.public);

            output r3 as boolean.public;

        function dynamic_pass_through_function:
            input r0 as u64.private;
            input r1 as dynamic.record;

            assert.eq r0 r0;

            output r1 as dynamic.record;
            output r0 as u64.private;

        // Calls a function to mint a Record (received as a DynamicRecord), casts the input ExternalRecord
        // to a DynamicRecord and passes both DynamicRecords to a callee controlled by the input flags
        function mint_own_and_decom_int:
            input r0 as base.aleo/rover.record;
            input r1 as u8.private;
            input r2 as boolean.private;
            // Flag controlling whether the base.aleo function called takes two static Records (true) or one static Record and one DynamicRecord (false)
            input r3 as boolean.private;
            // Flag controlling whether the function called at the end takes in a (Record, DynamicRecord) (true) or (DynamicRecord, Record) (false) assuming r3 = false.
            input r4 as boolean.private;

            call.dynamic {program_base_field} {network_field} {mint_rover_function_field}
                with r1 r2 (as u8.private boolean.private)
                into r5 (as dynamic.record);

            cast r0 into r6 as dynamic.record;

            // Shuffling DynamicRecords for good measure
            call.dynamic {program_extension_field} {network_field} {dynamic_pass_through_function_field}
                with 11u64 r5 (as u64.private dynamic.record)
                into r7 r8 (as dynamic.record u64.private);
            call.dynamic {program_extension_field} {network_field} {dynamic_pass_through_function_field}
                with 1u64 r6 (as u64.private dynamic.record)
                into r9 r10 (as dynamic.record u64.private);

            ternary r4 {decommission_function_field} {decommission_reversed_function_field} into r11;
            ternary r3 {decommission_two_function_field} r11 into r12;

            call.dynamic {program_base_field} {network_field} r12
                with r7 r9 (as dynamic.record dynamic.record)
                into r13 (as boolean.public);

            output r13 as boolean.public;

        constructor:
            assert.eq true true;
        ",
    )).unwrap();

    let program_frontier = Program::<CurrentNetwork>::from_str(
        r"
        program frontier.aleo;

        record map:
            owner as address.private;
            capital_coordinate_x as u16.private;
            capital_coordinate_y as u16.private;
            orography as boolean.private;

        function mint_map:
            cast self.signer 111u16 222u16 true into r0 as map.record;
            output r0 as map.record;

        function consume_map:
            input r0 as map.record;

        function consume_map_read_x:
            input r0 as map.record;

            output r0.capital_coordinate_x as u16.public;
        
        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let program_mini_remapper = Program::<CurrentNetwork>::from_str(
        r"
        import frontier.aleo;
        program mini_remapper.aleo;

        function remap_external_function:
            input r0 as frontier.aleo/map.record;

            assert.eq true true;

            output r0 as frontier.aleo/map.record;
        
        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let program_remapper = Program::<CurrentNetwork>::from_str(&format!(
        r"
        import base.aleo;
        import mini_remapper.aleo;
        import frontier.aleo;

        program remapper.aleo;
    
        function remap_dynamic_function:
            input r0 as dynamic.record;

            assert.eq true true;

            output r0 as dynamic.record;

        function do_not_consume:
            input r0 as dynamic.record;

            get.record.dynamic r0.orography into r1 as boolean.private;
        
        function growing_family:
            input r0 as frontier.aleo/map.record;
            // Flag which determines whether the last function called will mark the family as existing or not
            input r1 as boolean.private;

            call mini_remapper.aleo/remap_external_function r0 into r2;
            
            cast r2 into r3 as dynamic.record;
            call mini_remapper.aleo/remap_external_function r2 into r4;

            cast r4 into r5 as dynamic.record;
            
            call.dynamic {program_remapper_field} {network_field} {consume_dynamic_map_function_field}
                with r5 r1 (as dynamic.record boolean.private);
                
        function consume_dynamic_map:
            input r0 as dynamic.record;
            input r1 as boolean.private;

            ternary r1 {program_frontier_field} {program_remapper_field} into r2;
            ternary r1 {consume_map_function_field} {do_not_consume_function_field} into r3;

            call.dynamic {program_remapper_field} {network_field} {remap_dynamic_function_field}
                with r0 (as dynamic.record)
                into r4 (as dynamic.record);

            call.dynamic {program_remapper_field} {network_field} {remap_dynamic_function_field}
                with r4 (as dynamic.record)
                into r5 (as dynamic.record);

            // This call materialises r5 only if r1 is true. By the time the global check gets here, the family contains nine members
            call.dynamic r2 {network_field} r3
                with r5 (as dynamic.record);

        function convert_dynamic_and_consume:
            input r0 as boolean.private;
            input r1 as u16.public;
            input r2 as u8.private;
            input r3 as dynamic.record;

            call.dynamic {program_remapper_field} {network_field} {remap_dynamic_function_field}
                with r3 (as dynamic.record)
                into r4 (as dynamic.record);

            call.dynamic {program_remapper_field} {network_field} {consume_external_map_function_field}
                with 1u8 r2 2u8 r2 r4 (as u8.public u8.public u8.private u8.private dynamic.record)
                into r5 (as u16.public);

            output r5 as u16.public;

        function consume_external_map:
            input r0 as u8.public;
            input r1 as u8.public;
            input r2 as u8.private;
            input r3 as u8.private;
            input r4 as frontier.aleo/map.record;

            call frontier.aleo/consume_map_read_x r4 into r5;

            output r5 as u16.public;

        function read_x:
            input r0 as frontier.aleo/map.record;

            output r0.capital_coordinate_x as u16.public;
        
        function read_x_dynamic:
            input r0 as dynamic.record;

            get.record.dynamic r0.capital_coordinate_x into r1 as u16.private;

            output r1 as u16.public;

        function cast_translate_consume:
            input r0 as boolean.private;
            input r1 as frontier.aleo/map.record;

            cast r1 into r2 as dynamic.record;

            call.dynamic {program_remapper_field} {network_field} {consume_external_map_function_field}
                with 3u8 14u8 15u8 92u8 r2 (as u8.public u8.public u8.private u8.private dynamic.record)
                into r3 (as u16.public);
    
        constructor:
            assert.eq true true;
        "),
    ).unwrap();

    let program_frontier_upgraded = Program::<CurrentNetwork>::from_str(
        r"
        import extension.aleo;
        import remapper.aleo;

        program frontier.aleo;

        record map:
            owner as address.private;
            capital_coordinate_x as u16.private;
            capital_coordinate_y as u16.private;
            orography as boolean.private;

        function mint_map:
            cast self.signer 111u16 222u16 true into r0 as map.record;
            output r0 as map.record;

        function consume_map:
            input r0 as map.record;

        function consume_map_read_x:
            input r0 as map.record;

            output r0.capital_coordinate_x as u16.public;

        function simple_cast_function:
            input r0 as boolean.private;
            
            cast self.signer 1u16 2u16 r0 into r1 as map.record;

            cast r1 into r2 as dynamic.record;

            // This is not okay: the locally minted DynamicRecord is not known to materialize and it is passed to an actual function
            call extension.aleo/dynamic_pass_through_function 3u64 r2 into r3 r4;

        // This function breaks the local check (input to call)
        function mint_and_read:
            input r0 as u16.private;
            input r1 as u16.private;

            cast self.signer r0 r1 false into r2 as map.record;
            
            call remapper.aleo/read_x r2 into r3;
                
            output r3 as u16.public;

        // This function does not break the local check
        function mint_and_read_then_output:
            input r0 as u16.private;
            input r1 as u16.private;

            cast self.signer r0 r1 false into r2 as map.record;
            
            call remapper.aleo/read_x r2 into r3;
                
            output r2 as map.record;

        // This function breaks the local check (input to call)
        function mint_cast_and_read:
            input r0 as u16.private;
            input r1 as u16.private;

            cast self.signer r0 r1 false into r2 as map.record;
            cast r2 into r3 as dynamic.record;
            
            call remapper.aleo/read_x_dynamic r3 into r4;
                
            output r4 as u16.public;

        // This function doesnt break the local check
        function mint_cast_and_read_then_output:
            input r0 as u16.private;
            input r1 as u16.private;

            cast self.signer r0 r1 false into r2 as map.record;
            cast r2 into r3 as dynamic.record;
            
            call remapper.aleo/read_x_dynamic r3 into r4;

            add r4 1u16 into r5;
            add r5 2u16 into r6;
                
            output r4 as u16.public;
            output r5 as u16.private;
            output r2 as map.record;
            output r6 as u16.public;

        function mint_cast_read_double_output:
            input r0 as u16.private;
            input r1 as u16.private;

            cast self.signer r0 r1 false into r2 as map.record;
            cast r2 into r3 as dynamic.record;
            
            call remapper.aleo/read_x r2 into r4;
            call remapper.aleo/read_x_dynamic r3 into r5;

            add r5 2u16 into r6;
                
            output r4 as u16.public;
            output r5 as u16.private;
            output r2 as map.record;
            output r6 as u16.public;
            output r3 as dynamic.record;

        constructor:
            assert.eq true true;
        "
    ).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap(), rng);

    println!("Deploying program base...");
    let deploy_base = vm.deploy(&caller_private_key, &program_base, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_base], rng);

    println!("Deploying program extension...");
    let deploy_extension = vm.deploy(&caller_private_key, &program_extension, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_extension], rng);

    println!("Deploying program frontier...");
    let deploy_frontier = vm.deploy(&caller_private_key, &program_frontier, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_frontier], rng);

    println!("Deploying program mini_remapper...");
    let deploy_mini_remapper = vm.deploy(&caller_private_key, &program_mini_remapper, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_mini_remapper], rng);

    println!("Deploying program remapper...");
    let deploy_remapper = vm.deploy(&caller_private_key, &program_remapper, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_remapper], rng);

    println!("Upgrading program frontier...");
    let deploy_frontier_upgraded =
        vm.deploy(&caller_private_key, &program_frontier_upgraded, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_frontier_upgraded], rng);

    // Test 1: A child function of the root transition breaks the (function version of the) local check
    // Involves process_transition cases 3, 5, 7
    println!("Test 1: Calling extension.aleo/call_base...");

    let tx_base_function = vm.execute(
        &caller_private_key,
        ("extension.aleo", "call_base"),
        [Value::from_str("true").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );

    let err = tx_base_function.unwrap_err().to_string();
    assert!(err.contains("base.aleo/dynamic_mint"));
    assert!(err.contains("output DynamicRecord at r3 is cast from a locally minted Record at r2 which is not output"));

    // Test 2: Breaking the local check due to locally minted Records passed or
    // DynamicRecord cast from them being passed to a function call
    println!("Test 2: Local check at call sites");

    // Involves process_transition cases 3, 6a
    println!("    2.1) Locally minted Record passed to a function call and not output");

    let tx_base_function_2_1 = vm.execute(
        &caller_private_key,
        ("frontier.aleo", "mint_and_read"),
        [Value::from_str("1u16").unwrap(), Value::from_str("2u16").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );

    let err = tx_base_function_2_1.unwrap_err().to_string();
    assert!(err.contains("frontier.aleo/mint_and_read"));
    assert!(err.contains("locally minted Record at r2 is passed to a function call but not output"));

    // Involves process_transition case 3
    println!("    2.2) Locally minted Record passed to a function call and output");

    let inputs = [Value::from_str("3u16").unwrap(), Value::from_str("4u16").unwrap()];

    let tx_base_function_2_2 = vm
        .execute(&caller_private_key, ("frontier.aleo", "mint_and_read_then_output"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx_base_function_2_2], rng);

    // Involves process_transition cases 3, 5, 6b
    println!(
        "    2.3) DynamicRecord cast from locally minted static Record passed to a function call, static not output"
    );

    let tx_base_function_2_3 = vm.execute(
        &caller_private_key,
        ("frontier.aleo", "mint_cast_and_read"),
        [Value::from_str("5u16").unwrap(), Value::from_str("6u16").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );

    let err = tx_base_function_2_3.unwrap_err().to_string();
    assert!(err.contains("frontier.aleo/mint_cast_and_read"));
    assert!(err.contains(
        "DynamicRecord at r3 passed to a function call is cast from a locally minted Record at r2 which is not output"
    ));

    // Involves process_transition cases 3, 5
    println!("    2.4) DynamicRecord cast from locally minted static Record passed to a function call, static output");

    let inputs = [Value::from_str("5u16").unwrap(), Value::from_str("6u16").unwrap()];

    let tx_base_function_2_4 = vm
        .execute(
            &caller_private_key,
            ("frontier.aleo", "mint_cast_and_read_then_output"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx_base_function_2_4], rng);

    println!("    2.5) Both static Record and DynamicRecord passed to a function call; both also output");

    let inputs = [Value::from_str("5u16").unwrap(), Value::from_str("6u16").unwrap()];

    // Involves process_transition cases 1, 3, 4, 5
    let tx_base_function_2_5 = vm
        .execute(
            &caller_private_key,
            ("frontier.aleo", "mint_cast_and_read_then_output"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx_base_function_2_5], rng);

    // Test 3: A static record cast to dynamic twice and passed to a callee once
    // translated and once as dynamic does not break the global or local checks.
    // Involves process_transition cases 1, 3, 4
    println!("Test 3: extension.aleo/check_decommission_same...");

    let inputs = [Value::from_str("4u8").unwrap(), Value::from_str("true").unwrap()];

    let mint_planet_4_tx =
        vm.execute(&caller_private_key, ("base.aleo", "mint_rover"), inputs.iter(), None, 0, None, rng).unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), std::slice::from_ref(&mint_planet_4_tx), rng);

    let mint_planet_4_output = mint_planet_4_tx.transitions().next().unwrap().outputs().first().unwrap();
    let mint_planet_4_record = match mint_planet_4_output {
        Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
        _ => panic!("expected record output from mint_rover"),
    };

    let inputs = [Value::<CurrentNetwork>::Record(mint_planet_4_record)];

    let check_decommission_same_tx = vm
        .execute(&caller_private_key, ("extension.aleo", "check_decommission_same"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[check_decommission_same_tx], rng);

    // Test 4: a root function receives a DynamicRecord R_d1 and calls a
    // function that mints a static Record, receiving it as a DynamicRecord
    // R_d2. The two records are eventually passed
    //  - 4.1) to a function receiving a DynamicRecord and a static Record. This
    //    fails since R_d1 is not known to materialize.
    //  - 4.2) to a function receiving a static Record and a DynamicRecord. This
    //         passes since R_d1 is known to materialize by the call and R_d2 is
    //         known to materialize by the local-check guarantee.
    //  - 4.3) to a function receiving two static Records. This passes for the
    // same reason as above Although both 4.2 and 4.3 pass, 4.2 nets 0 unspent
    // Records and 4.3 nets -1 unspent Records on the ledger.
    println!("Test 4: mint_own_and_decom_wrapper...");

    let mint_inputs = [Value::from_str("5u8").unwrap(), Value::from_str("true").unwrap()];
    let three_mint_txs = (0..3)
        .map(|_| {
            vm.execute(&caller_private_key, ("base.aleo", "mint_rover"), mint_inputs.iter(), None, 0, None, rng)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let three_records = three_mint_txs
        .iter()
        .map(|tx| match tx.transitions().next().unwrap().outputs().first().unwrap() {
            Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
            _ => panic!("expected record output from mint_rover"),
        })
        .collect::<Vec<_>>();

    add_and_test_with_costs(
        &vm,
        &caller_private_key,
        Some(&[&mint_inputs, &mint_inputs, &mint_inputs]),
        &three_mint_txs,
        rng,
    );

    // Involves process_transition cases 1, 2, 3, 4, 8
    println!("    4.1) Final function receives (DynamicRecord, Record)...");

    let mint_own_and_decom_4_1_tx = vm.execute(
        &caller_private_key,
        ("extension.aleo", "mint_own_and_decom_int"),
        [
            Value::<CurrentNetwork>::Record(three_records[0].clone()),
            Value::from_str("6u8").unwrap(),
            Value::from_str("true").unwrap(),
            Value::from_str("false").unwrap(),
            Value::from_str("true").unwrap(), // Together with the previous flag: select the function that receives (Record, DynamicRecord)
        ]
        .into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(mint_own_and_decom_4_1_tx.unwrap_err().to_string().contains(
        "record input at r0 of the root function extension.aleo/mint_own_and_decom_int is not known to correspond"
    ));

    let num_unspent_records_1 =
        vm.transition_store().records().count() - vm.transition_store().serial_numbers().count();

    // Involves process_transition cases 1, 2, 3, 4, 8
    println!("    4.2) Final function receives (Record, DynamicRecord)...");

    let inputs = [
        Value::<CurrentNetwork>::Record(three_records[1].clone()),
        Value::from_str("6u8").unwrap(),
        Value::from_str("true").unwrap(),
        Value::from_str("false").unwrap(),
        Value::from_str("false").unwrap(), // Together with the previous flag: select the function that receives (DynamicRecord, Record)
    ];

    let mint_own_and_decom_4_2_tx = vm
        .execute(&caller_private_key, ("extension.aleo", "mint_own_and_decom_int"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[mint_own_and_decom_4_2_tx], rng);

    let num_unspent_records_2 =
        vm.transition_store().records().count() - vm.transition_store().serial_numbers().count();

    assert_eq!(num_unspent_records_2, num_unspent_records_1);

    // Involves process_transition cases 1, 2, 3, 4, 8
    println!("    4.3) Final function receives (Record, Record)...");

    let inputs = [
        Value::<CurrentNetwork>::Record(three_records[2].clone()),
        Value::from_str("6u8").unwrap(),
        Value::from_str("true").unwrap(),
        Value::from_str("true").unwrap(), // Select the function that receives (Record, Record)
        Value::from_str("false").unwrap(),
    ];

    let mint_own_and_decom_4_3_tx = vm
        .execute(&caller_private_key, ("extension.aleo", "mint_own_and_decom_int"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[mint_own_and_decom_4_3_tx], rng);

    let num_unspent_records_3 =
        vm.transition_store().records().count() - vm.transition_store().serial_numbers().count();

    assert_eq!(num_unspent_records_3, num_unspent_records_2 - 1);

    // Test 5: four tests on the local check involving cast-to-dynamic
    // Involves process_transition cases 1, 2, 3, 4, 8
    println!("Test 5: Attempting to pass a locally minted DynamicRecord to a function...");

    let test_case_5_tx = vm.execute(
        &caller_private_key,
        ("frontier.aleo", "simple_cast_function"),
        [Value::from_str("true").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );

    let err = test_case_5_tx.unwrap_err().to_string();
    assert!(err.contains("frontier.aleo/simple_cast_function"));
    assert!(err.contains("DynamicRecord at r2 passed to a function call is cast from a locally minted Record at r1"));

    // Test 6: global check where a large family is constructed. It checks
    // families are updated correctly throughout function calls.
    println!("Test 6: growing_family...");

    let map_record_tx = vm
        .execute(
            &caller_private_key,
            ("frontier.aleo", "mint_map"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let map_record = match map_record_tx.transitions().next().unwrap().outputs().first().unwrap() {
        Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
        _ => panic!("expected record output from mint_map"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[map_record_tx], rng);

    let other_map_record_tx = vm
        .execute(
            &caller_private_key,
            ("frontier.aleo", "mint_map"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let other_map_record = match other_map_record_tx.transitions().next().unwrap().outputs().first().unwrap() {
        Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
        _ => panic!("expected record output from mint_map"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[other_map_record_tx], rng);

    // Involves process_transition cases 1, 2, 4, 8
    println!("    6.1) Calling remapper.aleo/growing_family and making the family materialize at the end...");

    let inputs = [Value::<CurrentNetwork>::Record(map_record.clone()), Value::from_str("true").unwrap()];

    let growing_family_tx = vm
        .execute(&caller_private_key, ("remapper.aleo", "growing_family"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[growing_family_tx], rng);

    // Involves process_transition cases 2, 4, 8
    println!("    6.2) Calling remapper.aleo/growing_family and not making the family materialize at the end...");

    let growing_family_tx = vm.execute(
        &caller_private_key,
        ("remapper.aleo", "growing_family"),
        [Value::<CurrentNetwork>::Record(other_map_record.clone()), Value::from_str("false").unwrap()].into_iter(),
        None,
        0,
        None,
        rng,
    );

    let err = growing_family_tx.unwrap_err().to_string();
    assert!(err.contains("Non-static record input at r0"));
    assert!(err.contains("not known to correspond to a record on the ledger"));

    // Test 7: check the global check passes when materialisation occurs in the
    // form of an ExternalRecord (at caller) -> Record (at callee) input
    // Involves process_transition case 1
    println!("Test 7: materialise a family via ExternalRecord -> Record input...");

    let map_records = (0..3)
        .map(|_| {
            let mint_map_tx = vm
                .execute(
                    &caller_private_key,
                    ("frontier.aleo", "mint_map"),
                    Vec::<Value<CurrentNetwork>>::new().into_iter(),
                    None,
                    0,
                    None,
                    rng,
                )
                .unwrap();

            let map_record = match mint_map_tx.transitions().next().unwrap().outputs().first().unwrap() {
                Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(&caller_view_key).unwrap(),
                _ => panic!("expected record output from mint_map"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[mint_map_tx], rng);

            map_record
        })
        .collect_vec();

    // Case 7.1) ExternalRecord is passed directly from the root call to the
    // callee which consumes it
    println!("    7.1) ExternalRecord consumption without casts or remappings...");

    let inputs = [
        Value::from_str("4u8").unwrap(),
        Value::from_str("3u8").unwrap(),
        Value::from_str("2u8").unwrap(),
        Value::from_str("1u8").unwrap(),
        Value::<CurrentNetwork>::Record(map_records[0].clone()),
    ];

    let consume_external_map_tx = vm
        .execute(&caller_private_key, ("remapper.aleo", "consume_external_map"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[consume_external_map_tx], rng);

    // Case 7.2) ExternalRecord is remapped once via a function call and then consumed by a callee
    // Involves process_transition cases 1, 2, 8
    println!("    7.2) ExternalRecord consumption after single remapping in function...");

    let inputs = [
        Value::from_str("true").unwrap(),
        Value::from_str("1000u16").unwrap(),
        Value::from_str("1u8").unwrap(),
        Value::<CurrentNetwork>::Record(map_records[1].clone()),
    ];

    let convert_dynamic_and_consume_tx = vm
        .execute(
            &caller_private_key,
            ("remapper.aleo", "convert_dynamic_and_consume"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[convert_dynamic_and_consume_tx], rng);

    // Case 7.3) ExternalRecord is cast to DynamicRecord, translated to an
    // ExternalRecord via a function call and then consumed by a callee
    // Involves process_transition cases 1, 2, 4
    println!(
        "    7.3) Consumption after casting External -> Dynamic, translating Dynamic -> External and passing to a callee..."
    );

    let inputs = [Value::from_str("true").unwrap(), Value::<CurrentNetwork>::Record(map_records[2].clone())];

    let cast_translate_consume_tx = vm
        .execute(
            &caller_private_key,
            ("remapper.aleo", "cast_translate_consume"),
            [Value::from_str("true").unwrap(), Value::<CurrentNetwork>::Record(map_records[2].clone())].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[cast_translate_consume_tx], rng);
}
