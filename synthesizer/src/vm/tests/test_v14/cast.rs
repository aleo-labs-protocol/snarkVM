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

// Tests related to the cast variant that casts a static record (whether external or not) into a dynamic one.

// Tests that `circuit::DynamicRecord::from_record` is consistent with `console::DynamicRecord::from_record`.
#[test]
fn test_circuit_dynamic_record_from_record() {
    let mut rng = TestRng::default();

    let n_iterations = 20;

    for _ in 0..n_iterations {
        let owner = Address::<CurrentNetwork>::rand(&mut rng);
        let owner_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let coordinates_x = format!("{}u64", <u64 as Uniform>::rand(&mut rng));
        let coordinates_y = format!("{}u64", <u64 as Uniform>::rand(&mut rng));
        let coordinates_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let treasure_amount = format!("{}u128", <u128 as Uniform>::rand(&mut rng));
        let treasure_amount_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let contains_gold = format!("{}", <bool as Uniform>::rand(&mut rng));
        let contains_gold_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let plundered = format!("{}", <bool as Uniform>::rand(&mut rng));
        let plundered_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let full_pointless_group_element = <Group<CurrentNetwork> as Uniform>::rand(&mut rng);
        let pointless_group_element_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let reported_on_day = format!("{}u8", <u8 as Uniform>::rand(&mut rng));
        let reported_on_month = format!("{}u8", <u8 as Uniform>::rand(&mut rng));
        let reported_on_year = format!("{}u16", <u16 as Uniform>::rand(&mut rng));
        let reported_on_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        // Cap the array length to stay within MAX_DATA_SIZE_IN_FIELDS when serialized.
        let jewels_len = rng.random_range(1..512);
        let jewel_privacy = if Uniform::rand(&mut rng) { "public" } else { "private" };
        let jewel_iter = (0..jewels_len)
            .map(|_| {
                format!(
                    "{{mineral_id: {}.{}, carets: {}u8.{}}}",
                    <Field<CurrentNetwork> as Uniform>::rand(&mut rng),
                    jewel_privacy,
                    <u8 as Uniform>::rand(&mut rng),
                    jewel_privacy,
                )
            })
            .collect::<Vec<_>>();
        let jewels = jewel_iter.join(", ");
        let nonce = <Group<CurrentNetwork> as Uniform>::rand(&mut rng);
        let version = format!("{}u8", rng.random_range(0..=1));

        let record_str = format!(
            r"{{
            owner: {owner}.{owner_privacy},
            coordinates: {{ x: {coordinates_x}.{coordinates_privacy}, y: {coordinates_y}.{coordinates_privacy} }},
            treasure_amount: {treasure_amount}.{treasure_amount_privacy},
            contains_gold: {contains_gold}.{contains_gold_privacy},
            plundered: {plundered}.{plundered_privacy},
            pointless_group_element: {full_pointless_group_element}.{pointless_group_element_privacy},
            reported_on: {{
                day: {reported_on_day}.{reported_on_privacy},
                month: {reported_on_month}.{reported_on_privacy},
                year: {reported_on_year}.{reported_on_privacy}
            }},
            jewels: [{jewels}],
            _nonce: {nonce}.public,
            _version: {version}.public
        }}"
        );

        let console_static_record =
            console::program::Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_str).unwrap();
        let console_dynamic_record =
            console::program::DynamicRecord::<CurrentNetwork>::from_record(&console_static_record).unwrap();

        let circuit_static_record = circuit::program::Record::new(Mode::Private, console_static_record.clone());
        let circuit_dynamic_record =
            circuit::program::DynamicRecord::<CurrentAleo>::from_record(&circuit_static_record).unwrap();

        assert_eq!(circuit_dynamic_record.owner().eject_value(), *console_dynamic_record.owner());
        // Crucial check: the circuit and console roots of the Merkleized data should coincide
        assert_eq!(circuit_dynamic_record.root().eject_value(), *console_dynamic_record.root());
        assert_eq!(circuit_dynamic_record.nonce().eject_value(), *console_dynamic_record.nonce());
        assert_eq!(circuit_dynamic_record.version().eject_value(), *console_dynamic_record.version());
        assert_eq!(circuit_dynamic_record.data().unwrap(), console_dynamic_record.data().as_ref().unwrap());
    }
}

// Tests casting external and non-external records to `dynamic.record` using `get.record.dynamic` to access entries.
// Also verifies that double-spend errors occur when the static record is consumed by both caller and callee (via translation).
#[test]
fn test_cast_simple() {
    let mut rng = TestRng::default();

    let caller_private_key = sample_genesis_private_key(&mut rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

    let program_b_name = Identifier::<CurrentNetwork>::from_str("hatchery").unwrap();
    let network_name = Identifier::<CurrentNetwork>::from_str("aleo").unwrap();
    let function_get_age_in_years_stat_callee_name =
        Identifier::<CurrentNetwork>::from_str("get_age_in_years_stat_callee").unwrap();

    let program_b_field = program_b_name.to_field().unwrap();
    let network_field = network_name.to_field().unwrap();
    let function_get_age_in_years_stat_callee_field = function_get_age_in_years_stat_callee_name.to_field().unwrap();

    let program_a_str = r"
        program garden_center.aleo;

        record plant:
            owner as address.public;
            species_id as u32.private;
            age_in_years as u16.public;
            is_pteridophyta as boolean.public;

        function sow:
            input r0 as address.public;
            input r1 as u32.private;
            input r2 as boolean.public;

            cast r0 r1 0u16 r2 into r3 as plant.record;

            output r3 as plant.record;

        function consume_plant:
            input r0 as plant.record;

        constructor:
            assert.eq true true;
        ";

    let program_b_str = format!(
        r"
        import garden_center.aleo;

        program hatchery.aleo;

        record fish:
            owner as address.private;
            species_id as u32.private;
            age_in_years as u16.public;

        function import_fish:
            input r0 as address.private;
            input r1 as u32.private;
            input r2 as u16.private;

            cast r0 r1 r2 into r3 as fish.record;

            output r3 as fish.record;

        function get_age_in_years_by_casting:
            input r0 as fish.record;
            
            cast r0 into r1 as dynamic.record;
            get.record.dynamic r1.age_in_years into r2 as u16;

            output r2 as u16.public;

        // This function should fail as the input record is consumed twice: once
        // as an input to the caller and once as an input to the callee (after
        // translation).
        function get_age_in_years_stat_caller:
            input r0 as fish.record;
            
            cast r0 into r1 as dynamic.record;
            call.dynamic {program_b_field} {network_field} {function_get_age_in_years_stat_callee_field} with r1 (as dynamic.record) into r2 (as u16.public);

            output r2 as u16.public;

        function {function_get_age_in_years_stat_callee_name}:
            input r0 as fish.record;

            output r0.age_in_years as u16.public;

        function get_plant_age_by_casting:
            input r0 as garden_center.aleo/plant.record;
            
            cast r0 into r1 as dynamic.record;
            get.record.dynamic r1.age_in_years into r2 as u16;

            // Needed to pass the record-existence check (r0 must materialize)
            call garden_center.aleo/consume_plant r0;

            output r2 as u16.public;

        constructor:
            assert.eq true true;
        "
    );

    // Initialize a new program.
    let program_a = Program::<CurrentNetwork>::from_str(program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), &mut rng);

    // Deploy the programs.
    println!("Deploying program garden_center.aleo...");
    let transaction_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, &mut rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_a], &mut rng);

    println!("Deploying program hatchery.aleo...");
    let transaction_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, &mut rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_b], &mut rng);

    let fish_record_data = [("9183u32", "3u16"), ("221u32", "2u16")];

    let mut fish_records = fish_record_data
        .into_iter()
        .rev()
        .enumerate()
        .map(|(i, (species_id, age_in_years))| {
            println!("Calling hatchery.aleo/import_fish ({i})...");

            let inputs = [
                Value::from_str(&caller_address.to_string()).unwrap(),
                Value::from_str(species_id).unwrap(),
                Value::from_str(age_in_years).unwrap(),
            ];
            let transaction_import = vm
                .execute(&caller_private_key, ("hatchery.aleo", "import_fish"), inputs.iter(), None, 0, None, &mut rng)
                .unwrap();

            let record = match &transaction_import.transitions().next().unwrap().outputs()[0] {
                Output::Record(_, _, record_ciphertext, _) => {
                    record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
                }
                _ => panic!("Expected output record is not a record"),
            };

            add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction_import], &mut rng);

            record
        })
        .collect_vec();

    /*** Case 1: Correct cast of non-external record + dynamic.get.record ***/
    println!("Calling hatchery.aleo/get_age_in_years_by_casting...");
    let fish_record = fish_records.pop().unwrap();
    let inputs_get_age = [Value::<CurrentNetwork>::Record(fish_record)];
    let transaction_get_age = vm
        .execute(
            &caller_private_key,
            ("hatchery.aleo", "get_age_in_years_by_casting"),
            inputs_get_age.iter(),
            None,
            0,
            None,
            &mut rng,
        )
        .unwrap();

    let expected_output = Plaintext::from_str("3u16").unwrap();
    match &transaction_get_age.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => {
            assert_eq!(*plaintext, expected_output);
        }
        _ => panic!("Expected output plaintext is not a plaintext"),
    }

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_get_age]), &[transaction_get_age], &mut rng);

    /*********** Case 2: Incorrect cast usage (double consumption) ***********/
    println!("Calling hatchery.aleo/get_age_in_years_stat_caller...");
    let transaction_get_age_stat_caller = vm
        .execute(
            &caller_private_key,
            ("hatchery.aleo", "get_age_in_years_stat_caller"),
            [Value::<CurrentNetwork>::Record(fish_records.pop().unwrap())].into_iter(),
            None,
            0,
            None,
            &mut rng,
        )
        .unwrap();

    let rejected_id = transaction_get_age_stat_caller.id();
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_get_age_stat_caller], &mut rng).unwrap();

    // The transaction should fail due to attempted double spend
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.aborted_transaction_ids(), &[rejected_id]);

    /****** Case 3: Correct cast of external record + static.get.record ******/
    println!("Calling garden_center.aleo/sow...");

    let inputs_sow = [
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str("12u32").unwrap(),
        Value::from_str("true").unwrap(),
    ];
    let transaction_sow = vm
        .execute(&caller_private_key, ("garden_center.aleo", "sow"), inputs_sow.iter(), None, 0, None, &mut rng)
        .unwrap();

    let plant_record = match &transaction_sow.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
        }
        _ => panic!("Expected output record is not a record"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs_sow]), &[transaction_sow], &mut rng);

    println!("Calling hatchery.aleo/get_plant_age_by_casting...");
    let inputs_get_plant_age = [Value::<CurrentNetwork>::Record(plant_record)];
    let transaction_get_plant_age = vm
        .execute(
            &caller_private_key,
            ("hatchery.aleo", "get_plant_age_by_casting"),
            inputs_get_plant_age.iter(),
            None,
            0,
            None,
            &mut rng,
        )
        .unwrap();

    let expected_output = Plaintext::from_str("0u16").unwrap();
    match &transaction_get_plant_age.transitions().nth(1).unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => {
            assert_eq!(*plaintext, expected_output);
        }
        _ => panic!("Expected output plaintext is not a plaintext"),
    }

    add_and_test_with_costs(
        &vm,
        &caller_private_key,
        Some(&[&inputs_get_plant_age]),
        &[transaction_get_plant_age],
        &mut rng,
    );
}
