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

fn test_translation(
    caller_private_key: &PrivateKey<CurrentNetwork>,
    // Program and function to call
    root_program_name: &str,
    root_function_name: &str,
    // Inputs to the root call; if None gas_to_mint is used as explained below.
    input_values: Option<Vec<Value<CurrentNetwork>>>,
    // If Some, precedes the root call with a transaction that mints the given
    // gas_container record and uses the corresponding dynamic record as input
    // to the root call.
    gas_to_mint: Option<Record<CurrentNetwork, Plaintext<CurrentNetwork>>>,
    // The expected outputs.
    expected_public_outputs: Option<Vec<Plaintext<CurrentNetwork>>>,
    rng: &mut TestRng,
) {
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    // Various parameters for call.dynamic instructions.
    let program_a_name_str = "flow";
    let program_a_name_field = Identifier::<CurrentNetwork>::from_str(program_a_name_str).unwrap().to_field().unwrap();
    let program_b_name_str = "gas_manager";
    let program_b_name_field = Identifier::<CurrentNetwork>::from_str(program_b_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    let get_liquid_liters_function_name = Identifier::<CurrentNetwork>::from_str("get_liquid_liters").unwrap();
    let get_gas_liters_function_name = Identifier::<CurrentNetwork>::from_str("get_gas_liters").unwrap();
    let nitrogen_pump_function_name = Identifier::<CurrentNetwork>::from_str("nitrogen_pump").unwrap();
    let get_external_liters_function_name = Identifier::<CurrentNetwork>::from_str("get_external_liters").unwrap();
    let gas_pipe_function_name = Identifier::<CurrentNetwork>::from_str("gas_pipe").unwrap();
    let static_gas_leak_function_name = Identifier::<CurrentNetwork>::from_str("static_gas_leak").unwrap();
    let get_dynamic_liters_from_gas_function_name =
        Identifier::<CurrentNetwork>::from_str("get_dynamic_liters_from_gas").unwrap();

    let get_liquid_liters_function_field = get_liquid_liters_function_name.to_field().unwrap();
    let get_gas_liters_function_field = get_gas_liters_function_name.to_field().unwrap();
    let nitrogen_pump_function_field = nitrogen_pump_function_name.to_field().unwrap();
    let get_external_liters_function_field = get_external_liters_function_name.to_field().unwrap();
    let gas_pipe_function_field = gas_pipe_function_name.to_field().unwrap();
    let static_gas_leak_function_field = static_gas_leak_function_name.to_field().unwrap();
    let get_dynamic_liters_from_gas_function_field = get_dynamic_liters_from_gas_function_name.to_field().unwrap();

    let program_a_str = format!(
        r"
    import {program_b_name_str}.aleo;

    program {program_a_name_str}.aleo;

    // Tries to consume a container passed as dynamic as a specifically liquid one
    function get_dynamic_liters_from_liquid:
        input r0 as dynamic.record;
        
        call.dynamic {program_b_name_field} {network_field} {get_liquid_liters_function_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);

        output r1 as u64.public;
    
    function {get_dynamic_liters_from_gas_function_name}:
        input r0 as dynamic.record;
        
        call.dynamic {program_b_name_field} {network_field} {get_gas_liters_function_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);

        output r1 as u64.public;

    function consume_dynamic_blob:
        input r0 as dynamic.record;
        output true as boolean.private;

    function dynamic_pump:
        call.dynamic {program_b_name_field} {network_field} {nitrogen_pump_function_field}
            with 1u64 (as u64.public)
            into r0 (as dynamic.record);
        
        output r0 as dynamic.record;

    // Get the liters in an external liquid record
    function {get_external_liters_function_name}:
        input r0 as {program_b_name_str}.aleo/gas_container.record;
        output r0.liters as u64.public;

    // Input and output the same gas record
    function {gas_pipe_function_name}:
        input r0 as {program_b_name_str}.aleo/gas_container.record;
        output r0 as {program_b_name_str}.aleo/gas_container.record;

    // Receive a dynamic blob of gas and pass it to another function for leaking,
    // then receive it and measure its liters with yet another function
    function dynamic_gas_leak:
        input r0 as dynamic.record;
        
        call.dynamic {program_b_name_field} {network_field} {static_gas_leak_function_field}
            with r0 (as dynamic.record)
            into r1 (as dynamic.record);
        call.dynamic {program_a_name_field} {network_field} {get_dynamic_liters_from_gas_function_field}
            with r1 (as dynamic.record)
            into r2 (as u64.public);

        output r2 as u64.public;

    constructor:
        assert.eq true true;
    "
    );

    // Preparing the record values for the hardcoded gas_record minter
    let (gas_owner, gas_liters, gas_flammable) = if let Some(gas_to_mint_record) = &gas_to_mint {
        let liters_entry =
            gas_to_mint_record.data().get(&Identifier::<CurrentNetwork>::from_str("liters").unwrap()).unwrap();
        let flammable_entry =
            gas_to_mint_record.data().get(&Identifier::<CurrentNetwork>::from_str("flammable").unwrap()).unwrap();
        let liters_value = match liters_entry {
            Entry::Public(plaintext) => plaintext.to_string(),
            _ => panic!("`liters` entry should be public"),
        };
        let flammable_value = match flammable_entry {
            Entry::Private(plaintext) => plaintext.to_string(),
            _ => panic!("`flammable` entry should be private"),
        };
        (caller_address.to_string(), liters_value, flammable_value)
    } else {
        (caller_address.to_string(), "100u64".to_string(), "false".to_string())
    };

    let program_b_str = format!(
        r"
    program {program_b_name_str}.aleo;

    record liquid_container:
        owner as address.private;
        liters as u64.public;

    record gas_container:
        owner as address.private;
        liters as u64.public;
        flammable as boolean.private;

    function {get_liquid_liters_function_name}:
        input r0 as liquid_container.record;
        
        output r0.liters as u64.public;

    function get_gas_liters_externally:
        input r0 as dynamic.record;
        
        call.dynamic {program_a_name_field} {network_field} {get_external_liters_function_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);

        call.dynamic {program_b_name_field} {network_field} {static_gas_leak_function_field} with r0 (as dynamic.record) into r2 (as dynamic.record);
        
        output r1 as u64.public;

    function {get_gas_liters_function_name}:
        input r0 as gas_container.record;
        
        output r0.liters as u64.public;

    function {nitrogen_pump_function_name}:
        input r0 as u64.public;
        
        cast self.caller r0 false into r1 as gas_container.record;
        
        output r1 as gas_container.record;

    function hardcoded_gas_pump:
        cast {gas_owner} {gas_liters} {gas_flammable} into r0 as gas_container.record;
        
        output r0 as gas_container.record;

    function pump_and_send_through_pipe:
        input r0 as dynamic.record;
        
        call.dynamic {program_a_name_field} {network_field} {gas_pipe_function_field}
            with r0 (as dynamic.record)
            into r1 (as dynamic.record);

        // Needed to pass the record-existence check (r0 must materialize)
        call.dynamic {program_b_name_field} {network_field} {static_gas_leak_function_field}
            with r0 (as dynamic.record)
            into r2 (as dynamic.record);
    
    // Consume a gas record and produce a new one containing 10 fewer liters
    function static_gas_leak:
        input r0 as gas_container.record;
        
        sub r0.liters 10u64 into r1;
        cast r0.owner r1 r0.flammable into r2 as gas_container.record;
        
        output r2 as gas_container.record;

    constructor:
        assert.eq true true;
    "
    );

    // Initialize a new program.
    let program_a = Program::<CurrentNetwork>::from_str(&program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the programs.
    println!("Deploying program {program_b_name_str}...");
    let transaction_b = vm.deploy(caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, caller_private_key, None, &[transaction_b], rng);

    println!("Deploying program {program_a_name_str}...");
    let transaction_a = vm.deploy(caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, caller_private_key, None, &[transaction_a], rng);

    assert!(
        input_values.is_none() || gas_to_mint.is_none(),
        "When gas_to_mint is provided, the resulting static input is converted to dynamic record is used instead of input_values, which should be None",
    );

    assert!(
        input_values.is_some() || gas_to_mint.is_some(),
        "Exactly one of input_values or gas_to_mint must be provided",
    );

    let computed_input_values = input_values.unwrap_or_else(|| {
        println!("Minting gas_container record...");
        let transaction_mint = vm
            .execute(
                caller_private_key,
                (format!("{program_b_name_str}.aleo"), "hardcoded_gas_pump"),
                Vec::<Value<CurrentNetwork>>::new().iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();

        let output_gas_record = match mint_output {
            Output::Record(_, _, record_ciphertext, _) => {
                record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
            }
            _ => panic!("Minted record is not a record"),
        };

        let block_mint = sample_next_block(&vm, caller_private_key, &[transaction_mint], rng).unwrap();
        assert_eq!(block_mint.transactions().num_accepted(), 1);
        assert_eq!(block_mint.transactions().num_rejected(), 0);
        assert_eq!(block_mint.aborted_transaction_ids().len(), 0);
        vm.add_next_block(&block_mint).unwrap();

        let dynamic_record = DynamicRecord::from_record(&output_gas_record).unwrap();
        vec![Value::<CurrentNetwork>::DynamicRecord(dynamic_record)]
    });

    println!("Executing root function {root_program_name}/{root_function_name}...");

    // Execute the root function.
    let transaction = vm
        .execute(
            caller_private_key,
            (root_program_name, root_function_name),
            computed_input_values.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    println!("Verifying transaction...");
    add_and_test_with_costs(
        &vm,
        caller_private_key,
        Some(&[&computed_input_values]),
        std::slice::from_ref(&transaction),
        rng,
    );

    if let Some(expected_public_outputs) = expected_public_outputs {
        println!("Asserting output correctness on {} expected public outputs...", expected_public_outputs.len());

        // Note the last transition is the fee transition
        let num_transitions = transaction.transitions().count();
        let root_transition = transaction.transitions().nth(num_transitions - 2).unwrap();

        let public_outputs = root_transition
            .outputs()
            .iter()
            .filter_map(|output| match output {
                Output::Public(_, Some(plaintext)) => Some(plaintext),
                _ => None,
            })
            .collect_vec();

        assert_eq!(public_outputs.into_iter().cloned().collect_vec(), expected_public_outputs);
    }
}

// Verifies that the static→dynamic output translation preserves record content.
// When a callee outputs a non-external static record and the caller receives it as
// `dynamic.record`, the Merkle tree encoding must faithfully represent the original
// field values so that `get.record.dynamic` can recover them.
#[test]
fn test_translation_output_non_external_dynamic_content() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let provider_name_str = "gas_pump_provider";
    let caller_name_str = "gas_pump_caller";

    let provider_field = Identifier::<CurrentNetwork>::from_str(provider_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let pump_field = Identifier::<CurrentNetwork>::from_str("pump").unwrap().to_field().unwrap();

    let expected_liters = 42u64;
    let expected_flammable = true;

    // provider.aleo mints a gas_container record with known liters and flammable values,
    // covering both public and private fields in the Merkle tree encoding.
    let provider_program_str = format!(
        r"
    program {provider_name_str}.aleo;

    record gas_container:
        owner as address.private;
        liters as u64.public;
        flammable as boolean.private;

    function pump:
        cast self.signer {expected_liters}u64 {expected_flammable} into r0 as gas_container.record;
        output r0 as gas_container.record;

    constructor:
        assert.eq true true;
    "
    );

    // caller.aleo calls pump dynamically, receives the output as dynamic.record, then reads
    // both fields to verify the static→dynamic translation preserves mixed-visibility content.
    let caller_program_str = format!(
        r"
    program {caller_name_str}.aleo;

    function pump_and_read:
        call.dynamic {provider_field} {network_field} {pump_field}
            into r0 (as dynamic.record);
        get.record.dynamic r0.liters into r1 as u64;
        get.record.dynamic r0.flammable into r2 as boolean;
        output r1 as u64.public;
        output r2 as boolean.public;

    constructor:
        assert.eq true true;
    "
    );

    let provider_program = Program::<CurrentNetwork>::from_str(&provider_program_str).unwrap();
    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    println!("Deploying {provider_name_str}.aleo...");
    let deploy_provider = vm.deploy(&caller_private_key, &provider_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_provider], rng);

    println!("Deploying {caller_name_str}.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    // Execute pump_and_read; it creates a record internally so no pre-minted record is needed.
    println!("Executing {caller_name_str}.aleo/pump_and_read...");
    let transaction = vm
        .execute(
            &caller_private_key,
            (format!("{caller_name_str}.aleo"), "pump_and_read"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // The root transition is second-to-last; the last is the fee transition.
    let num_transitions = transaction.transitions().count();
    let root_transition = transaction.transitions().nth(num_transitions - 2).unwrap();

    // Verify both the public liters field and the private flammable field are preserved.
    let expected_liters_output = Plaintext::<CurrentNetwork>::from_str(&format!("{expected_liters}u64")).unwrap();
    let expected_flammable_output = Plaintext::<CurrentNetwork>::from_str(&format!("{expected_flammable}")).unwrap();
    assert!(
        matches!(root_transition.outputs(), [Output::Public(_, Some(p1)), Output::Public(_, Some(p2))]
            if *p1 == expected_liters_output && *p2 == expected_flammable_output),
        "Expected liters = {expected_liters}u64 and flammable = {expected_flammable}, got: {:?}",
        root_transition.outputs()
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction], rng);
}

// Verifies that the dynamic→external-static input translation preserves record content.
// When caller.aleo passes a `dynamic.record` to provider.aleo, and provider.aleo expects a
// `caller_ext_dyn.aleo/container.record` (external record), the translation correctly
// reconstructs the original static record so field access returns the original values.
#[test]
fn test_translation_input_external_dynamic_content() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    let caller_name_str = "ext_dyn_caller";
    let provider_name_str = "ext_dyn_provider";

    let provider_field = Identifier::<CurrentNetwork>::from_str(provider_name_str).unwrap().to_field().unwrap();
    let caller_name_field = Identifier::<CurrentNetwork>::from_str(caller_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let get_liters_field = Identifier::<CurrentNetwork>::from_str("get_liters").unwrap().to_field().unwrap();
    let consume_container_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_container").unwrap().to_field().unwrap();

    let expected_liters = 77u64;
    let expected_active = true;

    // caller.aleo defines the container record (with mixed-visibility fields) and
    // pipe_and_read, which forwards a dynamic record to provider.aleo/get_liters.
    let caller_program_str = format!(
        r"
    program {caller_name_str}.aleo;

    record container:
        owner as address.private;
        liters as u64.public;
        active as boolean.private;

    function consume_container:
        input r0 as container.record;

    function mint_container:
        input r0 as address.private;
        input r1 as u64.public;
        input r2 as boolean.private;
        
        cast r0 r1 r2 into r3 as container.record;
        
        output r3 as container.record;

    function pipe_and_read:
        input r0 as dynamic.record;
        
        call.dynamic {provider_field} {network_field} {get_liters_field}
            with r0 (as dynamic.record)
            into r1 r2 (as u64.public boolean.public);

        call.dynamic {caller_name_field} {network_field} {consume_container_function_field} with r0 (as dynamic.record);
        
        output r1 as u64.public;
        output r2 as boolean.public;

    constructor:
        assert.eq true true;
    "
    );

    // provider.aleo imports caller.aleo to reference its external record type.
    // get_liters expects a caller.aleo/container.record; the dynamic→external-static
    // translation reconstructs this from the dynamic record passed by pipe_and_read.
    // Both liters (public) and active (private) are returned to verify mixed-visibility
    // field preservation across the translation.
    let provider_program_str = format!(
        r"
    import {caller_name_str}.aleo;

    program {provider_name_str}.aleo;

    function get_liters:
        input r0 as {caller_name_str}.aleo/container.record;
        output r0.liters as u64.public;
        output r0.active as boolean.public;

    constructor:
        assert.eq true true;
    "
    );

    let caller_program = Program::<CurrentNetwork>::from_str(&caller_program_str).unwrap();
    let provider_program = Program::<CurrentNetwork>::from_str(&provider_program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy caller first because provider imports it.
    println!("Deploying {caller_name_str}.aleo...");
    let deploy_caller = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_caller], rng);

    println!("Deploying {provider_name_str}.aleo...");
    let deploy_provider = vm.deploy(&caller_private_key, &provider_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_provider], rng);

    let inputs = vec![
        Value::from_str(&caller_address.to_string()).unwrap(),
        Value::from_str(&format!("{expected_liters}u64")).unwrap(),
        Value::from_str(&format!("{expected_active}")).unwrap(),
    ];
    // Mint a container record with known liters and active values and add it to the ledger.
    println!("Minting container record with {expected_liters} liters and active = {expected_active}...");
    let mint_tx = vm
        .execute(
            &caller_private_key,
            (format!("{caller_name_str}.aleo"), "mint_container"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let minted_record = mint_tx
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

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[mint_tx], rng);

    // Convert the minted record to a dynamic record for the call.
    let dynamic_record = DynamicRecord::from_record(&minted_record).unwrap();

    let inputs = vec![Value::DynamicRecord(dynamic_record)];

    // Execute pipe_and_read; the dynamic record is translated to an external static record
    // inside provider.aleo/get_liters, and both liters and active fields are returned.
    println!("Executing {caller_name_str}.aleo/pipe_and_read...");
    let transaction = vm
        .execute(
            &caller_private_key,
            (format!("{caller_name_str}.aleo"), "pipe_and_read"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // The root transition is second-to-last; the last is the fee transition.
    let num_transitions = transaction.transitions().count();
    let root_transition = transaction.transitions().nth(num_transitions - 2).unwrap();

    // Verify both the public liters field and the private active field are preserved.
    let expected_liters_output = Plaintext::<CurrentNetwork>::from_str(&format!("{expected_liters}u64")).unwrap();
    let expected_active_output = Plaintext::<CurrentNetwork>::from_str(&format!("{expected_active}")).unwrap();
    assert!(
        matches!(root_transition.outputs(), [Output::Public(_, Some(p1)), Output::Public(_, Some(p2))]
            if *p1 == expected_liters_output && *p2 == expected_active_output),
        "Expected liters = {expected_liters}u64 and active = {expected_active}, got: {:?}",
        root_transition.outputs()
    );

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests translation of a dynamic record input to a non-external static record.
#[test]
fn test_translation_input_dynamic_non_external() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let record_static_str = format!(
        r#"{{
        owner: {caller_address}.private,
        liters: 1888u64.public,
        flammable: false.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }}"#
    );

    let r0_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_static_str).unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("1888u64").unwrap();

    test_translation(
        &caller_private_key,
        "flow.aleo",
        "get_dynamic_liters_from_gas",
        None,
        Some(r0_static),
        Some(vec![expected_output]),
        rng,
    );
}

// Tests translation of a non-external static record output to a dynamic record.
#[test]
fn test_translation_output_non_external_dynamic() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    test_translation(&caller_private_key, "flow.aleo", "dynamic_pump", Some(vec![]), None, None, rng);
}

// Tests translation of a dynamic record input to an external static record.
#[test]
fn test_translation_input_dynamic_external() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let record_static_str = format!(
        r#"{{
        owner: {caller_address}.private,
        liters: 292u64.public,
        flammable: true.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }}"#
    );

    let r0_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_static_str).unwrap();

    let expected_output = Plaintext::<CurrentNetwork>::from_str("292u64").unwrap();

    test_translation(
        &caller_private_key,
        "gas_manager.aleo",
        "get_gas_liters_externally",
        None,
        Some(r0_static),
        Some(vec![expected_output]),
        rng,
    );
}

// Tests translation of an external static record output to a dynamic record.
#[test]
fn test_translation_output_external_dynamic() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let record_static_str = format!(
        r#"{{
        owner: {caller_address}.private,
        liters: 292u64.public,
        flammable: true.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }}"#
    );

    // Construct the static and dynamic records.
    let r0_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_static_str).unwrap();

    test_translation(
        &caller_private_key,
        "gas_manager.aleo",
        "pump_and_send_through_pipe",
        None,
        Some(r0_static),
        None,
        rng,
    );
}

// Tests three consecutive translations in a single execution path with consistent prover/verifier traversal order.
#[test]
fn test_translation_triple() {
    // Before root call: pump a gas_container.record
    // Root call:
    //    - Receive as input a dynamic record corresponding to the above static one
    //    - Pass it to static_gas_leak, which consumes a static gas_container.record (first translation) and produces a new one with 10 fewer liters.
    //    - Receive as output the new static record as dynamic (second translation)
    //    - Call get_dynamic_liters_from_gas, which receives a dynamic record (no translation) and calls get_gas_liters, which in turn expects a static record (third translation)
    //
    // This also checks consistency in the traversal order of translation tasks for the prover and verifier.

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let record_static_str = format!(
        r#"{{
        owner: {caller_address}.private,
        liters: 333u64.public,
        flammable: true.private,
        _nonce: 0group.public,
        _version: 1u8.public
    }}"#
    );

    // Construct the static and dynamic records.
    let r0_static = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&record_static_str).unwrap();

    // Expected output (10 liters have leaked)
    let expected_output = Plaintext::<CurrentNetwork>::from_str("323u64").unwrap();

    test_translation(
        &caller_private_key,
        "flow.aleo",
        "dynamic_gas_leak",
        None,
        Some(r0_static),
        Some(vec![expected_output]),
        rng,
    );
}

// Tests that prover and verifier traverse translation tasks in the same order using a complex execution graph.
#[test]
fn test_translation_traversal_consistency() {
    // This tests checks the prover and verifier order all translation tasks associated to a
    // transaction the same way by asserting correct verification of the following execution
    // graph (capital leters denote record types):
    // quadruple_caller (receives two dynamic records of types A B)
    //   -> leaf_two_one (two input translations A B, one output translation B)
    //   -> leaf_one_two (one input translation B, two output translations, B C)
    //   -> double_caller_one_zero (one input translation C)
    //        -> leaf_one_one (one input translation B, one output translation A)
    //        -> leaf_two_one (two input translations A B, one output translation B)
    //   -> leaf_zero_one (one output translation B)

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    // Various parameters for call.dynamic instructions.
    let program_name_str = "quotes";
    let program_name_field = Identifier::<CurrentNetwork>::from_str(program_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();

    let double_caller_one_zero_function_name =
        Identifier::<CurrentNetwork>::from_str("double_caller_one_zero").unwrap();
    let leaf_two_one_function_name = Identifier::<CurrentNetwork>::from_str("leaf_two_one").unwrap();
    let leaf_one_two_function_name = Identifier::<CurrentNetwork>::from_str("leaf_one_two").unwrap();
    let leaf_one_one_function_name = Identifier::<CurrentNetwork>::from_str("leaf_one_one").unwrap();
    let leaf_zero_one_function_name = Identifier::<CurrentNetwork>::from_str("leaf_zero_one").unwrap();

    let double_caller_one_zero_function_field = double_caller_one_zero_function_name.to_field().unwrap();
    let leaf_two_one_function_field = leaf_two_one_function_name.to_field().unwrap();
    let leaf_one_two_function_field = leaf_one_two_function_name.to_field().unwrap();
    let leaf_one_one_function_field = leaf_one_one_function_name.to_field().unwrap();
    let leaf_zero_one_function_field = leaf_zero_one_function_name.to_field().unwrap();

    let quixote_quote = vec![
        69u8, 110, 32, 117, 110, 32, 108, 117, 103, 97, 114, 32, 100, 101, 32, 108, 97, 32, 77, 97, 110, 99, 104, 97,
    ];
    let hamlet_quote = vec![84u8, 111, 32, 98, 101, 32, 111, 114, 32, 110, 111, 116, 32, 116, 111, 32, 98, 101];
    let lotr_quote = vec![
        73u8, 116, 39, 115, 32, 97, 32, 100, 97, 110, 103, 101, 114, 111, 117, 115, 32, 98, 117, 115, 105, 110, 101,
        115, 115, 44, 32, 70, 114, 111, 100, 111,
    ];

    fn process_quote(mut quote: Vec<u8>) -> String {
        quote.resize(50, 0);
        quote.into_iter().map(|c| format!("{c}u8")).join(" ").to_string()
    }

    let processed_quixote_quote = process_quote(quixote_quote);
    let processed_hamlet_quote = process_quote(hamlet_quote);
    let processed_lotr_quote = process_quote(lotr_quote);

    let program_str = format!(
        r"
    program {program_name_str}.aleo;

    record a:
        owner as address.private;
        quixote_tweet as [u8; 50u32].public;

    record b:
        owner as address.private;
        hamlet_tweet as [u8; 50u32].public;
        understandable as boolean.public;

    record c:
        owner as address.private;
        lotr_tweet as [u8; 50u32].public;
        book_number as u8.public;
        canon as boolean.private;

    function quadruple_caller:
        input r0 as dynamic.record; // type A
        input r1 as dynamic.record; // type B
        input r2 as dynamic.record; // type B
        
        // underlying input types: A B
        // underlying output types: B
        call.dynamic {program_name_field} {network_field} {leaf_two_one_function_field}
            with r0 r1 (as dynamic.record dynamic.record)
            into r3 (as dynamic.record);

        // underlying input types: B
        // underlying output types: B C
        call.dynamic {program_name_field} {network_field} {leaf_one_two_function_field}
            with r3 (as dynamic.record)
            into r4 r5 (as dynamic.record dynamic.record);

        // underlying input types: C B B (the last two are not translated)
        call.dynamic {program_name_field} {network_field} {double_caller_one_zero_function_field}
            with r5 r4 r2 (as dynamic.record dynamic.record dynamic.record);

        // underlying output types: B
        call.dynamic {program_name_field} {network_field} {leaf_zero_one_function_field}
            into r6 (as dynamic.record);

    function double_caller_one_zero:
        input r0 as c.record;
        input r1 as dynamic.record; // type B
        input r2 as dynamic.record; // type B

        // underlying input types: B
        // underlying output types: A
        call.dynamic {program_name_field} {network_field} {leaf_one_one_function_field}
            with r1 (as dynamic.record)
            into r3 (as dynamic.record);

        // underlying input types: A B
        // underlying output types: B
        call.dynamic {program_name_field} {network_field} {leaf_two_one_function_field}
            with r3 r2 (as dynamic.record dynamic.record)
            into r4 (as dynamic.record);

    function leaf_two_one:
        input r0 as a.record;
        input r1 as b.record;

        cast {processed_hamlet_quote} into r2 as [u8; 50u32];
        cast {caller_address} r2 false into r3 as b.record;

        output r3 as b.record;

    function leaf_one_two:
        input r0 as b.record;

        cast {processed_hamlet_quote} into r1 as [u8; 50u32];
        cast {caller_address} r1 false into r2 as b.record;

        cast {processed_lotr_quote} into r3 as [u8; 50u32];
        cast {caller_address} r3 1u8 false into r4 as c.record;

        output r2 as b.record;
        output r4 as c.record;

    function leaf_zero_one:
        cast {processed_hamlet_quote} into r0 as [u8; 50u32];
        cast {caller_address} r0 false into r1 as b.record;

        output r1 as b.record;

    function leaf_one_one:
        input r0 as b.record;

        cast {processed_quixote_quote} into r1 as [u8; 50u32];
        cast {caller_address} r1 into r2 as a.record;

        output r2 as a.record;

    function mint_a:
        cast {processed_quixote_quote} into r0 as [u8; 50u32];
        cast {caller_address} r0 into r1 as a.record;
        output r1 as a.record;
    
    function mint_b:
        cast {processed_hamlet_quote} into r0 as [u8; 50u32];
        cast {caller_address} r0 false into r1 as b.record;
        output r1 as b.record;

    function mint_c:
        cast {processed_lotr_quote} into r0 as [u8; 50u32];
        cast {caller_address} r0 1u8 false into r1 as c.record;
        output r1 as c.record;

    constructor:
        assert.eq true true;
    "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program.
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    let mut mint_record = |function_name: &str| {
        println!("Executing {function_name}...");

        let transaction_mint = vm
            .execute(
                &caller_private_key,
                ("quotes.aleo", function_name),
                Vec::<Value<CurrentNetwork>>::new().into_iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();

        let output_record = match mint_output {
            Output::Record(_, _, record_ciphertext, _) => {
                record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
            }
            _ => panic!("Minted record is not a record"),
        };

        let dynamic_record = DynamicRecord::from_record(&output_record).unwrap();

        (transaction_mint, dynamic_record)
    };

    let (transaction_mint_a, dynamic_record_a) = mint_record("mint_a");
    let (transaction_mint_b_1, dynamic_record_b_1) = mint_record("mint_b");
    let (transaction_mint_b_2, dynamic_record_b_2) = mint_record("mint_b");

    add_and_test_with_costs(
        &vm,
        &caller_private_key,
        Some(&[&[], &[], &[]]),
        &[transaction_mint_a, transaction_mint_b_1, transaction_mint_b_2],
        rng,
    );

    let inputs = vec![
        Value::DynamicRecord(dynamic_record_a),
        Value::DynamicRecord(dynamic_record_b_1),
        Value::DynamicRecord(dynamic_record_b_2),
    ];

    let transaction = vm
        .execute(&caller_private_key, ("quotes.aleo", "quadruple_caller"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // This indeed results of three batches for translation proving/verification:
    // one of size 3 for a.record, one of size 8 for b.record, and one of size 2 for c.record.
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);
}

// Tests that stripping or altering `dynamic_id` from `RecordWithDynamicID` inputs causes verification failure.
#[test]
fn test_malicious_dynamic_id_tampering() {
    use snarkvm_ledger_block::{Execution, Input, Output, Transition};

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(&caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Parameters for dynamic calls.
    let program_a_name_str = "flow";
    let program_b_name_str = "gas_manager";
    let program_b_name_field = Identifier::<CurrentNetwork>::from_str(program_b_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let get_gas_liters_function_field =
        Identifier::<CurrentNetwork>::from_str("get_gas_liters").unwrap().to_field().unwrap();

    // Define the programs (same as test_translation helper).
    let program_a_str = format!(
        r"
    import {program_b_name_str}.aleo;

    program {program_a_name_str}.aleo;

    function get_dynamic_liters_from_gas:
        input r0 as dynamic.record;

        call.dynamic {program_b_name_field} {network_field} {get_gas_liters_function_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);

        output r1 as u64.public;

    constructor:
        assert.eq true true;
    "
    );

    let gas_owner = caller_address.to_string();
    let program_b_str = format!(
        r"
    program {program_b_name_str}.aleo;

    record gas_container:
        owner as address.private;
        liters as u64.public;
        flammable as boolean.private;

    function get_gas_liters:
        input r0 as gas_container.record;
        output r0.liters as u64.public;

    function hardcoded_gas_pump:
        cast {gas_owner} 100u64 false into r0 as gas_container.record;
        output r0 as gas_container.record;

    constructor:
        assert.eq true true;
    "
    );

    let program_a = Program::<CurrentNetwork>::from_str(&program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the programs.
    let transaction_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_b], rng);

    let transaction_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_a], rng);

    // Mint a gas_container record.
    let transaction_mint = vm
        .execute(
            &caller_private_key,
            (format!("{program_b_name_str}.aleo"), "hardcoded_gas_pump"),
            Vec::<Value<CurrentNetwork>>::new().iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
    let output_gas_record = match mint_output {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
        }
        _ => panic!("Minted record is not a record"),
    };

    let block_mint = sample_next_block(&vm, &caller_private_key, &[transaction_mint], rng).unwrap();
    assert_eq!(block_mint.transactions().num_accepted(), 1);
    vm.add_next_block(&block_mint).unwrap();

    // Convert the static record to a dynamic record.
    let dynamic_record = DynamicRecord::from_record(&output_gas_record).unwrap();

    // Execute a dynamic call (flow.aleo/get_dynamic_liters_from_gas).
    let transaction = vm
        .execute(
            &caller_private_key,
            ("flow.aleo", "get_dynamic_liters_from_gas"),
            [Value::<CurrentNetwork>::DynamicRecord(dynamic_record)].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Verify the valid transaction passes.
    vm.check_transaction(&transaction, None, rng).unwrap();

    // Extract the execution.
    let (execution, fee) = match &transaction {
        Transaction::Execute(_, _, execution, fee) => (execution.as_ref().clone(), fee.clone()),
        _ => panic!("Expected an execution transaction"),
    };

    // Find a child transition containing RecordWithDynamicID inputs.
    let transitions: Vec<_> = execution.transitions().cloned().collect();
    let global_state_root = execution.global_state_root();
    let proof = execution.proof().cloned();

    let mut found_dynamic_input = false;
    let mut tampered_transitions = Vec::new();

    for transition in &transitions {
        // Check if this transition has a RecordWithDynamicID input.
        let has_dynamic_input = transition.inputs().iter().any(|input| input.dynamic_id().is_some());

        if has_dynamic_input && !found_dynamic_input {
            found_dynamic_input = true;

            // Tamper: strip the dynamic ID from `RecordWithDynamicID` inputs.
            let tampered_inputs: Vec<Input<CurrentNetwork>> = transition
                .inputs()
                .iter()
                .map(|input| match input {
                    Input::RecordWithDynamicID(sn, tag, _dynamic_id) => {
                        // Strip dynamic_id by converting to a plain Record.
                        Input::Record(*sn, *tag)
                    }
                    Input::ExternalRecordWithDynamicID(hash, _dynamic_id) => {
                        // Strip dynamic_id by converting to a plain ExternalRecord.
                        Input::ExternalRecord(*hash)
                    }
                    other => other.clone(),
                })
                .collect();

            // Reconstruct the transition with tampered inputs.
            // RecordWithDynamicID and Record produce different transition leaves (version 2 vs 1),
            // so tampering changes the transition ID and causes verification to fail.
            let tampered_transition = Transition::new(
                *transition.program_id(),
                *transition.function_name(),
                tampered_inputs,
                transition.outputs().to_vec(),
                *transition.tpk(),
                *transition.tcm(),
                *transition.scm(),
            )
            .unwrap();

            tampered_transitions.push(tampered_transition);
        } else {
            tampered_transitions.push(transition.clone());
        }
    }

    // Ensure we found and tampered with at least one transition.
    assert!(found_dynamic_input, "Expected at least one transition with RecordWithDynamicID input");

    // Reconstruct the execution and transaction.
    let tampered_execution = Execution::from(tampered_transitions.into_iter(), global_state_root, proof).unwrap();
    let tampered_transaction = Transaction::from_execution(tampered_execution, fee).unwrap();

    // The tampered transaction should fail verification.
    assert!(
        vm.check_transaction(&tampered_transaction, None, rng).is_err(),
        "Stripping dynamic_id from RecordWithDynamicID should cause verification failure"
    );
}

// Tests that stripping or altering `dynamic_id` from `ExternalRecordWithDynamicID` inputs causes verification failure.
#[test]
fn test_malicious_external_record_dynamic_id_tampering() {
    use snarkvm_ledger_block::{Execution, Input, Output, Transition};

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(&caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    // Parameters for dynamic calls.
    let program_a_name_str = "flow_external";
    let program_b_name_str = "gas_manager_external";
    let program_a_name_field = Identifier::<CurrentNetwork>::from_str(program_a_name_str).unwrap().to_field().unwrap();
    let program_b_name_field = Identifier::<CurrentNetwork>::from_str(program_b_name_str).unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let get_external_liters_function_field =
        Identifier::<CurrentNetwork>::from_str("get_external_liters").unwrap().to_field().unwrap();
    let consume_gas_container_function_field =
        Identifier::<CurrentNetwork>::from_str("consume_gas_container").unwrap().to_field().unwrap();

    // Define program_a which accepts an external record from program_b.
    let program_a_str = format!(
        r"
    import {program_b_name_str}.aleo;

    program {program_a_name_str}.aleo;

    // Get the liters in an external gas_container record from program_b.
    function get_external_liters:
        input r0 as {program_b_name_str}.aleo/gas_container.record;
        output r0.liters as u64.public;

    constructor:
        assert.eq true true;
    "
    );

    // Define program_b which mints records and calls program_a dynamically with an external record.
    let gas_owner = caller_address.to_string();
    let program_b_str = format!(
        r"
    program {program_b_name_str}.aleo;

    record gas_container:
        owner as address.private;
        liters as u64.public;
        flammable as boolean.private;

    function consume_gas_container:
        input r0 as gas_container.record;

    function hardcoded_gas_pump:
        cast {gas_owner} 100u64 false into r0 as gas_container.record;
        output r0 as gas_container.record;

    // Calls get_external_liters dynamically, passing the gas record as an external record.
    function call_external_liters:
        input r0 as dynamic.record;

        call.dynamic {program_a_name_field} {network_field} {get_external_liters_function_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);

        // Needed to pass the record-existence check (r0 must materialize)
        call.dynamic {program_b_name_field} {network_field} {consume_gas_container_function_field} with r0 (as dynamic.record);

        output r1 as u64.public;

    constructor:
        assert.eq true true;
    "
    );

    let program_a = Program::<CurrentNetwork>::from_str(&program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy both programs (program_b first since program_a imports it).
    let transaction_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_b], rng);

    let transaction_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_a], rng);

    // Mint a gas_container record.
    let transaction_mint = vm
        .execute(
            &caller_private_key,
            (format!("{program_b_name_str}.aleo"), "hardcoded_gas_pump"),
            Vec::<Value<CurrentNetwork>>::new().iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let mint_output = transaction_mint.transitions().next().unwrap().outputs().iter().next().unwrap();
    let output_gas_record = match mint_output {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
        }
        _ => panic!("Minted record is not a record"),
    };

    let block_mint = sample_next_block(&vm, &caller_private_key, &[transaction_mint], rng).unwrap();
    assert_eq!(block_mint.transactions().num_accepted(), 1);
    vm.add_next_block(&block_mint).unwrap();

    // Convert the static record to a dynamic record.
    let dynamic_record = DynamicRecord::from_record(&output_gas_record).unwrap();

    // Execute a dynamic call that uses an external record (program_b calls program_a with external record).
    let transaction = vm
        .execute(
            &caller_private_key,
            (format!("{program_b_name_str}.aleo"), "call_external_liters"),
            [Value::<CurrentNetwork>::DynamicRecord(dynamic_record)].into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Verify the valid transaction passes.
    vm.check_transaction(&transaction, None, rng).unwrap();

    // Extract the execution.
    let (execution, fee) = match &transaction {
        Transaction::Execute(_, _, execution, fee) => (execution.as_ref().clone(), fee.clone()),
        _ => panic!("Expected an execution transaction"),
    };

    // Find a transition containing ExternalRecordWithDynamicID inputs.
    let transitions: Vec<_> = execution.transitions().cloned().collect();
    let global_state_root = execution.global_state_root();
    let proof = execution.proof().cloned();

    let mut found_external_dynamic_input = false;
    let mut tampered_transitions = Vec::new();

    for transition in &transitions {
        // Check if this transition has an ExternalRecordWithDynamicID input.
        let has_external_dynamic_input =
            transition.inputs().iter().any(|input| matches!(input, Input::ExternalRecordWithDynamicID(..)));

        if has_external_dynamic_input && !found_external_dynamic_input {
            found_external_dynamic_input = true;

            // Tamper: strip the dynamic ID from `ExternalRecordWithDynamicID` inputs.
            let tampered_inputs: Vec<Input<CurrentNetwork>> = transition
                .inputs()
                .iter()
                .map(|input| match input {
                    Input::ExternalRecordWithDynamicID(hash, _dynamic_id) => {
                        // Strip dynamic_id by converting to a plain ExternalRecord.
                        Input::ExternalRecord(*hash)
                    }
                    other => other.clone(),
                })
                .collect();

            // Reconstruct the transition with tampered inputs.
            let tampered_transition = Transition::new(
                *transition.program_id(),
                *transition.function_name(),
                tampered_inputs,
                transition.outputs().to_vec(),
                *transition.tpk(),
                *transition.tcm(),
                *transition.scm(),
            )
            .unwrap();

            tampered_transitions.push(tampered_transition);
        } else {
            tampered_transitions.push(transition.clone());
        }
    }

    // Ensure we found and tampered with at least one transition.
    assert!(found_external_dynamic_input, "Expected at least one transition with ExternalRecordWithDynamicID input");

    // Reconstruct the execution and transaction.
    let tampered_execution = Execution::from(tampered_transitions.into_iter(), global_state_root, proof).unwrap();
    let tampered_transaction = Transaction::from_execution(tampered_execution, fee).unwrap();

    // The tampered transaction should fail verification.
    assert!(
        vm.check_transaction(&tampered_transaction, None, rng).is_err(),
        "Stripping dynamic_id from ExternalRecordWithDynamicID should cause verification failure"
    );
}

// Checks that translation keys for the same record name but different programs are different and vice versa.
// Run with `snark-print` feature to explore Varuna batch sizes and locate translation keys in verification batches.
#[test]
fn test_differing_keys() {
    // Parameters for dynamic calls
    let program_a_name = Identifier::<CurrentNetwork>::from_str("program_a").unwrap();
    let program_b_name = Identifier::<CurrentNetwork>::from_str("program_b").unwrap();
    let network_name = Identifier::<CurrentNetwork>::from_str("aleo").unwrap();
    let mint_record_a_function_name = Identifier::<CurrentNetwork>::from_str("mint_record_a").unwrap();
    let mint_record_b_function_name = Identifier::<CurrentNetwork>::from_str("mint_record_b").unwrap();
    let program_a_field = program_a_name.to_field().unwrap();
    let program_b_field = program_b_name.to_field().unwrap();
    let network_field = network_name.to_field().unwrap();
    let mint_record_a_function_field = mint_record_a_function_name.to_field().unwrap();
    let mint_record_b_function_field = mint_record_b_function_name.to_field().unwrap();

    let program_a_str = r"
        program program_a.aleo;

        record record_a:
            owner as address.private;

        record record_b:
            owner as address.private;
        
        function mint_record_a:
            cast self.signer into r0 as record_a.record;
            output r0 as record_a.record;

        function mint_record_b:
            cast self.signer into r0 as record_b.record;
            output r0 as record_b.record;

        constructor:
            assert.eq true true;";

    let program_b_str = format!(
        r"
        import program_a.aleo;

        program program_b.aleo;

        record record_a:
            owner as address.private;

        record record_b:
            owner as address.private;
        
        function mint_record_a:
            cast self.signer into r0 as record_a.record;
            output r0 as record_a.record;

        function mint_record_b:
            cast self.signer into r0 as record_b.record;
            output r0 as record_b.record;

        function mint_all:
            call.dynamic {program_a_field} {network_field} {mint_record_a_function_field}
                into r0 (as dynamic.record);

            call.dynamic {program_a_field} {network_field} {mint_record_b_function_field}
                into r1 (as dynamic.record);

            call.dynamic {program_b_field} {network_field} {mint_record_a_function_field}
                into r2 (as dynamic.record);

            call.dynamic {program_b_field} {network_field} {mint_record_b_function_field}
                into r3 (as dynamic.record);

        constructor:
            assert.eq true true;
    "
    );

    let program_a = Program::<CurrentNetwork>::from_str(program_a_str).unwrap();
    let program_b = Program::<CurrentNetwork>::from_str(&program_b_str).unwrap();

    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the programs.
    let transaction_a = vm.deploy(&caller_private_key, &program_a, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_a], rng);

    let transaction_b = vm.deploy(&caller_private_key, &program_b, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction_b], rng);

    // Displaying the keys associated to each translation circuit for easier
    // identification with snark-print
    for program_name in ["program_a.aleo", "program_b.aleo"] {
        let stack = vm.process().get_stack(program_name).unwrap();
        println!("{program_name} translation keys:");
        for record_name in ["record_a", "record_b"] {
            let record_identifier = Identifier::<CurrentNetwork>::from_str(record_name).unwrap();
            let verifying_key = stack.get_verifying_key(&record_identifier).unwrap();
            println!(" - {record_name}: {}", verifying_key.id);
        }
    }

    // Executing one translation task for each of the four record definitions
    println!("Minting and translating all records...");

    let transaction_mint_all = vm
        .execute(
            &caller_private_key,
            ("program_b.aleo", "mint_all"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[transaction_mint_all], rng);
}

// Tests translation with a record containing exactly 32 entries (MAX_DATA_ENTRIES boundary).
// This verifies that the Merkle tree of depth 5 can handle the maximum number of entries.
#[test]
fn test_translation_max_entries_record() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();

    let program_name_field = Identifier::<CurrentNetwork>::from_str("max_entries").unwrap().to_field().unwrap();
    let network_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let consume_max_field = Identifier::<CurrentNetwork>::from_str("consume_max_record").unwrap().to_field().unwrap();

    // Generate 32 field names (f0 through f31) for the record entries
    let field_names: Vec<String> = (0..32).map(|i| format!("f{i}")).collect();
    let field_declarations: String =
        field_names.iter().map(|name| format!("        {name} as u64.public;\n")).collect();

    // Generate cast arguments for minting
    let cast_args: String = (0..32).map(|i| format!("{i}u64 ")).collect::<String>().trim().to_string();

    // Generate sum computation for consuming (sum all 32 fields)
    let mut sum_computation = String::new();
    sum_computation.push_str("        add r0.f0 r0.f1 into r1;\n");
    for i in 2..32 {
        let prev = if i == 2 { 1 } else { i - 1 };
        sum_computation.push_str(&format!("        add r{prev} r0.f{i} into r{i};\n"));
    }

    let program_str = format!(
        r"
    program max_entries.aleo;

    // Record with exactly 32 entries (MAX_DATA_ENTRIES)
    record max_record:
        owner as address.private;
{field_declarations}
    // Mint a max_record with all fields set to their index value
    function mint_max_record:
        cast self.signer {cast_args} into r0 as max_record.record;
        output r0 as max_record.record;

    // Consume a max_record and return the sum of all fields
    function consume_max_record:
        input r0 as max_record.record;
{sum_computation}        output r31 as u64.public;

    // Dynamic caller that passes max_record through translation
    function dynamic_consume_max:
        input r0 as dynamic.record;
        call.dynamic {program_name_field} {network_field} {consume_max_field}
            with r0 (as dynamic.record)
            into r1 (as u64.public);
        output r1 as u64.public;

    constructor:
        assert.eq true true;
    "
    );

    let program = Program::<CurrentNetwork>::from_str(&program_str).unwrap();

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap(), rng);

    // Deploy the program
    println!("Deploying max_entries.aleo with 32-entry record...");
    let deploy_tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&vm, &caller_private_key, None, &[deploy_tx], rng);

    // Mint a max_record
    println!("Minting max_record with 32 entries...");
    let mint_tx = vm
        .execute(
            &caller_private_key,
            ("max_entries.aleo", "mint_max_record"),
            Vec::<Value<CurrentNetwork>>::new().into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let mint_output = mint_tx.transitions().next().unwrap().outputs().iter().next().unwrap();
    let max_record = match mint_output {
        Output::Record(_, _, record_ciphertext, _) => {
            record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap()
        }
        _ => panic!("Expected a record output"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&[]]), &[mint_tx], rng);

    // Convert to dynamic record and test translation
    println!("Testing translation of 32-entry record...");
    let dynamic_record = DynamicRecord::from_record(&max_record).unwrap();

    let inputs = vec![Value::DynamicRecord(dynamic_record)];

    let consume_tx = vm
        .execute(&caller_private_key, ("max_entries.aleo", "dynamic_consume_max"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Verify the transaction succeeds (sum of 0+1+2+...+31 = 496)
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[consume_tx], rng);
    println!("Successfully translated 32-entry record (MAX_DATA_ENTRIES boundary)");
}
