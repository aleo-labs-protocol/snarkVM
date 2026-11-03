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

/// Advances the VM to V15 consensus height by adding empty blocks.
fn advance_to_v15(
    vm: &VM<CurrentNetwork, LedgerType>,
    caller_private_key: &PrivateKey<CurrentNetwork>,
    rng: &mut TestRng,
) -> Result<()> {
    let v15_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?;
    for _ in vm.block_store().current_block_height()..v15_height {
        let block = sample_next_block(vm, caller_private_key, &[], rng)?;
        vm.add_next_block(&block)?;
    }
    Ok(())
}

/// Decrypts the first record output from the first transition in a transaction.
fn decrypt_first_record(
    tx: &Transaction<CurrentNetwork>,
    view_key: &ViewKey<CurrentNetwork>,
) -> Record<CurrentNetwork, Plaintext<CurrentNetwork>> {
    match &tx.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, ct, _) => ct.as_ref().unwrap().decrypt(view_key).unwrap(),
        other => panic!("Expected record output, got: {other:?}"),
    }
}

// Tests that a closure can accept a record as input and read its fields.
#[test]
fn test_closure_record_input() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;

    // Define a program with a closure that reads a record field.
    let program = Program::from_str(
        r"
        program closure_rec_input.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        closure extract_amount:
            input r0 as token.record;
            add r0.amount 0u64 into r1;
            output r1 as u64;

        function mint_and_extract:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as token.record;
            call extract_amount r2 into r3;
            output r2 as token.record;
            output r3 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Initialize the VM at V15.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    // Deploy the program.
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Execute the function to mint a record and extract its amount via the closure.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("42u64")?];
    let transaction = vm.execute(
        &caller_private_key,
        ("closure_rec_input.aleo", "mint_and_extract"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;

    // Verify the public output matches the expected amount.
    let expected = Plaintext::from_str("42u64")?;
    match &transaction.transitions().next().unwrap().outputs()[1] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected),
        other => panic!("Expected public output, got: {other:?}"),
    }

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    Ok(())
}

// Tests that a closure cannot output a record type (rejected at parse time).
#[test]
fn test_closure_record_output_rejected() {
    // Attempt to parse a program with a closure that outputs a record.
    let result = Program::<CurrentNetwork>::from_str(
        r"
        program closure_rec_out_bad.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        closure bad_output:
            input r0 as address;
            input r1 as u64;
            cast r0 r1 into r2 as token.record;
            output r2 as token.record;

        function unused:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    );

    // Parsing should fail because closures cannot output records.
    assert!(result.is_err(), "Program with record output from closure should fail to parse");
}

// Tests that a closure can accept an external record as input and read its fields.
#[test]
fn test_closure_external_record_input() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Parent program defines a record and a consume function.
    let parent_program = Program::from_str(
        r"
        program closure_ext_parent.aleo;

        record item:
            owner as address.private;
            worth as u32.private;

        function mint_item:
            input r0 as address.private;
            input r1 as u32.private;
            cast r0 r1 into r2 as item.record;
            output r2 as item.record;

        function consume_item:
            input r0 as item.record;
            output r0.worth as u32.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child program imports parent and has a closure taking the external record.
    // The function also calls consume_item to resolve the record family.
    let child_program = Program::from_str(
        r"
        import closure_ext_parent.aleo;

        program closure_ext_child.aleo;

        closure read_external_item:
            input r0 as closure_ext_parent.aleo/item.record;
            add r0.worth 0u32 into r1;
            output r1 as u32;

        function extract_external_value:
            input r0 as closure_ext_parent.aleo/item.record;
            call read_external_item r0 into r1;
            call closure_ext_parent.aleo/consume_item r0 into r2;
            output r1 as u32.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Initialize the VM at V15.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    // Deploy the parent program.
    let transaction = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Deploy the child program.
    let transaction = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Mint an item via the parent program.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("99u32")?];
    let transaction =
        vm.execute(&caller_private_key, ("closure_ext_parent.aleo", "mint_item"), inputs.iter(), None, 0, None, rng)?;

    // Decrypt the minted record.
    let item_record = match &transaction.transitions().next().unwrap().outputs()[0] {
        Output::Record(_, _, record_ciphertext, _) => record_ciphertext.as_ref().unwrap().decrypt(&caller_view_key)?,
        _ => panic!("Expected record output"),
    };

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Execute the child function with the external record.
    let inputs = [Value::<CurrentNetwork>::Record(item_record)];
    let transaction = vm.execute(
        &caller_private_key,
        ("closure_ext_child.aleo", "extract_external_value"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;

    // Verify the public output matches the expected value.
    let expected = Plaintext::from_str("99u32")?;
    match &transaction.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected),
        other => panic!("Expected public output, got: {other:?}"),
    }

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    Ok(())
}

// Tests that a closure outputting an ExternalRecord is rejected at V15+ deployment.
// The program parses successfully, but transaction verification (`VM::check_transaction`)
// rejects it at V15+ because closures cannot output ExternalRecord or DynamicRecord types.
#[test]
fn test_closure_external_record_output() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    let parent_program = Program::from_str(
        r"
        program ext_rec_out_parent.aleo;

        record item:
            owner as address.private;
            amount as u64.private;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    let child_program = Program::from_str(
        r"
        import ext_rec_out_parent.aleo;

        program ext_rec_out_child.aleo;

        closure passthrough_external:
            input r0 as ext_rec_out_parent.aleo/item.record;
            assert.eq true true;
            output r0 as ext_rec_out_parent.aleo/item.record;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // The deployment transaction is created successfully, but rejected by verification because
    // closures cannot output ExternalRecord at V15+.
    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    assert!(vm.check_transaction(&tx, None, rng).is_err(), "ExternalRecord closure output should be rejected at V15+");

    Ok(())
}

// Tests that a closure can accept a dynamic record as input and read it with `get.record.dynamic`.
#[test]
fn test_closure_dynamic_record_input() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Program with a closure that reads a dynamic record.
    let program = Program::from_str(
        r"
        program closure_dyn_input.aleo;

        record asset:
            owner as address.private;
            quantity as u64.private;

        closure read_dynamic_quantity:
            input r0 as dynamic.record;
            get.record.dynamic r0.quantity into r1 as u64;
            output r1 as u64;

        function mint_asset:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as asset.record;
            output r2 as asset.record;

        function read_via_closure:
            input r0 as asset.record;
            cast r0 into r1 as dynamic.record;
            call read_dynamic_quantity r1 into r2;
            output r2 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Initialize the VM at V15.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    // Deploy the program.
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[transaction], rng);

    // Mint an asset record.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("500u64")?];
    let transaction =
        vm.execute(&caller_private_key, ("closure_dyn_input.aleo", "mint_asset"), inputs.iter(), None, 0, None, rng)?;

    // Decrypt the minted record.
    let asset_record = decrypt_first_record(&transaction, &caller_view_key);

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    // Execute the function that reads the dynamic record via the closure.
    let inputs = [Value::<CurrentNetwork>::Record(asset_record)];
    let transaction = vm.execute(
        &caller_private_key,
        ("closure_dyn_input.aleo", "read_via_closure"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;

    // Verify the public output matches the expected quantity.
    let expected = Plaintext::from_str("500u64")?;
    match &transaction.transitions().next().unwrap().outputs()[0] {
        Output::Public(_, Some(plaintext)) => assert_eq!(*plaintext, expected),
        other => panic!("Expected public output, got: {other:?}"),
    }

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    Ok(())
}

// Tests that closures cannot use `call` instructions (closures are leaf computations).
// This documents a language constraint: record inputs in closures are read-only —
// a closure cannot forward a record to another closure or function via `call`.
#[test]
fn test_closure_cannot_contain_call() {
    let rng = &mut TestRng::default();

    // A program whose closure body contains a `call` instruction. The program
    // parses successfully but must be rejected at stack initialization.
    let program = Program::<CurrentNetwork>::from_str(
        r"
        program closure_call_bad.aleo;

        record coin:
            owner as address.private;
            amount as u64.private;

        closure inner_read:
            input r0 as coin.record;
            add r0.amount 0u64 into r1;
            output r1 as u64;

        closure outer_read:
            input r0 as coin.record;
            call inner_read r0 into r1;
            output r1 as u64;

        function use_outer:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as coin.record;
            call outer_read r2 into r3;
            output r3 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )
    .expect("program should parse");

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15).unwrap(), rng);
    // `add_program` runs `Stack::new`, the same well-formedness check that `deploy` performs,
    // without the cost of synthesizing verifying keys.
    let result = vm.process().lock().add_program(&program);

    assert!(result.is_err(), "A closure containing a `call` instruction should be rejected at stack initialization");
}

// Tests that the existence check rejects an ExternalRecord cast to DynamicRecord and then
// only used in a closure. The family is never resolved through a function call boundary.
#[test]
fn test_external_record_cast_to_dynamic_then_closure_fails_existence_check() -> Result<()> {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Parent program defines the record.
    let parent_program = Program::from_str(
        r"
        program cast_dyn_parent.aleo;

        record gem:
            owner as address.private;
            karat as u32.private;

        function mint_gem:
            input r0 as address.private;
            input r1 as u32.private;
            cast r0 r1 into r2 as gem.record;
            output r2 as gem.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child program imports parent, casts the ExternalRecord to DynamicRecord, then
    // passes the DynamicRecord ONLY to a closure (no function call to verify it).
    let child_program = Program::from_str(
        r"
        import cast_dyn_parent.aleo;

        program cast_dyn_child.aleo;

        closure read_dynamic_karat:
            input r0 as dynamic.record;
            get.record.dynamic r0.karat into r1 as u32;
            output r1 as u32;

        // Receives an ExternalRecord, casts it to DynamicRecord, and passes it only
        // to a closure. The family is never resolved through a function call.
        function read_gem_via_cast_and_closure:
            input r0 as cast_dyn_parent.aleo/gem.record;
            cast r0 into r1 as dynamic.record;
            call read_dynamic_karat r1 into r2;
            output r2 as u32.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a gem.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("24u32")?];
    let tx =
        vm.execute(&caller_private_key, ("cast_dyn_parent.aleo", "mint_gem"), inputs.iter(), None, 0, None, rng)?;

    let gem_record = decrypt_first_record(&tx, &caller_view_key);

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);

    // Execute the child function. The ExternalRecord is cast to DynamicRecord and passed only
    // to a closure. The existence check rejects this because the family is never resolved
    // through a function call boundary.
    let result = vm.execute(
        &caller_private_key,
        ("cast_dyn_child.aleo", "read_gem_via_cast_and_closure"),
        [Value::<CurrentNetwork>::Record(gem_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(
        result.is_err(),
        "Execution should fail: ExternalRecord cast to DynamicRecord and only passed to closure has no existence verification"
    );

    Ok(())
}

// Tests that a pre-V15 program whose closure accepts an ExternalRecord as input (but does NOT
// output it) is rejected at V15+ by the record-existence check. The ExternalRecord creates an
// unresolved family because closures cannot provide existence verification.
#[test]
fn test_pre_v15_closure_external_record_input_only_rejected_at_v15() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Start at V9 (height 12), before the V15 closure-output restriction (height 18).
    let vm = sample_vm_at_height(12, rng);

    // Parent defines the record.
    let parent_program = Program::from_str(
        r"
        program closure_legacy_parent.aleo;

        record gem:
            owner as address.private;
            amount as u64.private;

        function mint_gem:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as gem.record;
            output r2 as gem.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child has a closure that accepts an ExternalRecord as input and extracts a field value.
    // The function only passes the ExternalRecord to the closure — never to a function call.
    let child_program = Program::from_str(
        r"
        import closure_legacy_parent.aleo;

        program closure_legacy_child.aleo;

        closure extract_gem_amount:
            input r0 as closure_legacy_parent.aleo/gem.record;
            add r0.amount 0u64 into r1;
            output r1 as u64;

        function use_gem_closure:
            input r0 as closure_legacy_parent.aleo/gem.record;
            call extract_gem_amount r0 into r1;
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Deploy both programs before V15. The deployments must be accepted.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a gem to use as input to the child function.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("77u64")?];
    let mint_tx =
        vm.execute(&caller_private_key, ("closure_legacy_parent.aleo", "mint_gem"), inputs.iter(), None, 0, None, rng)?;
    let gem_record = decrypt_first_record(&mint_tx, &caller_view_key);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[mint_tx], rng);

    // Advance to V15.
    advance_to_v15(&vm, &caller_private_key, rng)?;

    // Execute the function. The record-existence check rejects the execution because the
    // ExternalRecord input creates an unresolved family (closures cannot verify existence).
    let result = vm.execute(
        &caller_private_key,
        ("closure_legacy_child.aleo", "use_gem_closure"),
        [Value::<CurrentNetwork>::Record(gem_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(result.is_err(), "ExternalRecord used only in closure should fail existence check at V15+");

    Ok(())
}

// Tests that executing a pre-V15 program whose closure outputs ExternalRecord is rejected at V15+.
// This covers the runtime `has_forbidden_output` check, which is the only code path exercising
// that check — deployment-time rejection prevents new programs from reaching execution.
#[test]
fn test_pre_v15_closure_external_record_output_rejected_at_v15_runtime() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Start at V9 (height 12), before the V15 closure-output restriction (height 18).
    let vm = sample_vm_at_height(12, rng);

    // Parent defines the record.
    let parent_program = Program::from_str(
        r"
        program pre_v15_ext_out_parent.aleo;

        record widget:
            owner as address.private;
            worth as u64.private;

        function mint_widget:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as widget.record;
            output r2 as widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child has a closure that passes an ExternalRecord through as an output.
    // This is allowed at pre-V15 but forbidden at V15+.
    let child_program = Program::from_str(
        r"
        import pre_v15_ext_out_parent.aleo;

        program pre_v15_ext_out_child.aleo;

        closure passthrough_widget:
            input r0 as pre_v15_ext_out_parent.aleo/widget.record;
            assert.eq true true;
            output r0 as pre_v15_ext_out_parent.aleo/widget.record;

        function use_closure:
            input r0 as pre_v15_ext_out_parent.aleo/widget.record;
            call passthrough_widget r0 into r1;
            output r1 as pre_v15_ext_out_parent.aleo/widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Deploy both programs before V15. Both deployments must be accepted.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a widget to use as input.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("42u64")?];
    let tx = vm.execute(
        &caller_private_key,
        ("pre_v15_ext_out_parent.aleo", "mint_widget"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;
    let widget_record = decrypt_first_record(&tx, &caller_view_key);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);

    // Advance to V15 (height 18) by adding empty blocks.
    advance_to_v15(&vm, &caller_private_key, rng)?;

    // At V15+, executing `use_closure` must fail: the runtime `has_forbidden_output` check
    // detects that `passthrough_widget` outputs ExternalRecord and rejects the execution.
    let result = vm.execute(
        &caller_private_key,
        ("pre_v15_ext_out_child.aleo", "use_closure"),
        [Value::<CurrentNetwork>::Record(widget_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(result.is_err(), "Execution must fail: pre-V15 closure outputting ExternalRecord is disallowed at V15+");

    Ok(())
}

// Tests that when a function contains multiple closures — one with a forbidden output and one
// without — execution is rejected. Verifies that the check is per-closure and not accidentally
// bypassed when benign closures are present.
#[test]
fn test_mixed_closures_forbidden_output_rejected_at_v15_runtime() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Start at V9 (height 12), before the V15 closure-output restriction (height 18).
    let vm = sample_vm_at_height(12, rng);

    let parent_program = Program::from_str(
        r"
        program mixed_closures_parent.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function mint_token:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as token.record;
            output r2 as token.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child has two closures: one benign (reads a field), one forbidden (outputs ExternalRecord).
    // The function calls the benign closure first, then the forbidden one.
    let child_program = Program::from_str(
        r"
        import mixed_closures_parent.aleo;

        program mixed_closures_child.aleo;

        closure extract_amount:
            input r0 as mixed_closures_parent.aleo/token.record;
            add r0.amount 0u64 into r1;
            output r1 as u64;

        closure passthrough:
            input r0 as mixed_closures_parent.aleo/token.record;
            assert.eq true true;
            output r0 as mixed_closures_parent.aleo/token.record;

        function use_both_closures:
            input r0 as mixed_closures_parent.aleo/token.record;
            call extract_amount r0 into r1;
            call passthrough r0 into r2;
            output r1 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Deploy both programs before V15. Both deployments must be accepted.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a token.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("50u64")?];
    let tx = vm.execute(
        &caller_private_key,
        ("mixed_closures_parent.aleo", "mint_token"),
        inputs.iter(),
        None,
        0,
        None,
        rng,
    )?;
    let token_record = decrypt_first_record(&tx, &caller_view_key);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);

    // Advance to V15.
    advance_to_v15(&vm, &caller_private_key, rng)?;

    // At V15+, the function calls both a safe closure and a forbidden one. Execution must be
    // rejected because `passthrough` outputs ExternalRecord.
    let result = vm.execute(
        &caller_private_key,
        ("mixed_closures_child.aleo", "use_both_closures"),
        [Value::<CurrentNetwork>::Record(token_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(result.is_err(), "Execution must fail: function contains a closure with forbidden ExternalRecord output");

    Ok(())
}

// Tests that executing a pre-V15 cross-program closure call (`CallOperator::Locator`) whose
// closure outputs ExternalRecord is rejected at V15+ runtime. This covers the Locator branch of
// `has_forbidden_output`, where the closure lives in a different program and is referenced by
// `call other_program.aleo/closure_name` syntax.
#[test]
fn test_pre_v15_cross_program_closure_forbidden_output_rejected_at_v15_runtime() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Start at V9 (height 12), before the V15 closure-output restriction (height 18).
    let vm = sample_vm_at_height(12, rng);

    // Parent program defines the record.
    let parent_program = Program::from_str(
        r"
        program locator_parent.aleo;

        record widget:
            owner as address.private;
            amount as u64.private;

        function mint_widget:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as widget.record;
            output r2 as widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Lib program imports parent and defines a closure that passes an ExternalRecord through as
    // an output. This is allowed at pre-V15 but forbidden at V15+. A dummy function is required
    // because programs must have at least one function.
    let lib_program = Program::from_str(
        r"
        import locator_parent.aleo;

        program locator_lib.aleo;

        closure passthrough_widget:
            input r0 as locator_parent.aleo/widget.record;
            assert.eq true true;
            output r0 as locator_parent.aleo/widget.record;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Caller program imports both and calls the closure from locator_lib.aleo via a Locator
    // (`call locator_lib.aleo/passthrough_widget`), creating a `CallOperator::Locator`.
    let caller_program = Program::from_str(
        r"
        import locator_parent.aleo;
        import locator_lib.aleo;

        program locator_caller.aleo;

        function use_external_closure:
            input r0 as locator_parent.aleo/widget.record;
            call locator_lib.aleo/passthrough_widget r0 into r1;
            output r1 as locator_parent.aleo/widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Deploy all three programs before V15. All deployments must be accepted.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &lib_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a widget to use as input.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("42u64")?];
    let tx =
        vm.execute(&caller_private_key, ("locator_parent.aleo", "mint_widget"), inputs.iter(), None, 0, None, rng)?;
    let widget_record = decrypt_first_record(&tx, &caller_view_key);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);

    // Advance to V15 (height 18) by adding empty blocks.
    advance_to_v15(&vm, &caller_private_key, rng)?;

    // At V15+, executing `use_external_closure` must fail: the runtime `has_forbidden_output`
    // check (Locator branch) detects that `locator_lib.aleo/passthrough_widget` outputs
    // ExternalRecord and rejects the execution.
    let result = vm.execute(
        &caller_private_key,
        ("locator_caller.aleo", "use_external_closure"),
        [Value::<CurrentNetwork>::Record(widget_record)].into_iter(),
        None,
        0,
        None,
        rng,
    );

    assert!(
        result.is_err(),
        "Execution must fail: pre-V15 cross-program closure (Locator) outputting ExternalRecord is disallowed at V15+"
    );

    Ok(())
}

// Tests that a closure outputting a DynamicRecord is rejected at V15+ deployment.
// The program parses successfully, but transaction verification (`VM::check_transaction`)
// rejects it at V15+ because closures cannot output ExternalRecord or DynamicRecord types.
#[test]
fn test_closure_dynamic_record_output() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // A program whose closure casts a record to DynamicRecord and outputs it. This is
    // rejected at V15+ because `ensure_records_exist` assumes closures cannot extend
    // record families.
    let program = Program::from_str(
        r"
        program closure_dyn_output_bad.aleo;

        record asset:
            owner as address.private;
            quantity as u64.private;

        closure cast_to_dynamic:
            input r0 as asset.record;
            cast r0 into r1 as dynamic.record;
            output r1 as dynamic.record;

        function unused:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // The deployment transaction is created successfully, but rejected by verification because
    // closures cannot output DynamicRecord at V15+.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);
    let tx = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    assert!(vm.check_transaction(&tx, None, rng).is_err(), "DynamicRecord closure output should be rejected at V15+");

    Ok(())
}

// Tests that a pre-V15 program whose closure outputs ExternalRecord executes successfully
// *before* V15. This is the backward-compatibility counterpart to
// `test_pre_v15_closure_external_record_output_rejected_at_v15_runtime`: both deploy at pre-V15,
// but this test executes before V15 (where the restriction does not apply) and confirms the
// output is accepted.
#[test]
fn test_pre_v15_closure_external_record_output_works_before_v15() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_address = Address::try_from(&caller_private_key)?;
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;

    // Start at V9 (height 12), before the V15 closure-output restriction (height 18).
    let vm = sample_vm_at_height(12, rng);

    // Parent defines the record.
    let parent_program = Program::from_str(
        r"
        program pre_v15_ok_parent.aleo;

        record widget:
            owner as address.private;
            worth as u64.private;

        function mint_widget:
            input r0 as address.private;
            input r1 as u64.private;
            cast r0 r1 into r2 as widget.record;
            output r2 as widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child has a closure that passes an ExternalRecord through as an output.
    let child_program = Program::from_str(
        r"
        import pre_v15_ok_parent.aleo;

        program pre_v15_ok_child.aleo;

        closure passthrough_widget:
            input r0 as pre_v15_ok_parent.aleo/widget.record;
            assert.eq true true;
            output r0 as pre_v15_ok_parent.aleo/widget.record;

        function use_closure:
            input r0 as pre_v15_ok_parent.aleo/widget.record;
            call passthrough_widget r0 into r1;
            output r1 as pre_v15_ok_parent.aleo/widget.record;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Deploy both programs before V15.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Mint a widget.
    let inputs = [Value::from_str(&caller_address.to_string())?, Value::from_str("42u64")?];
    let tx =
        vm.execute(&caller_private_key, ("pre_v15_ok_parent.aleo", "mint_widget"), inputs.iter(), None, 0, None, rng)?;
    let widget_record = decrypt_first_record(&tx, &caller_view_key);
    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[tx], rng);

    // Execute at pre-V15. The closure outputs ExternalRecord, which must be accepted.
    let inputs = [Value::<CurrentNetwork>::Record(widget_record)];
    let transaction =
        vm.execute(&caller_private_key, ("pre_v15_ok_child.aleo", "use_closure"), inputs.iter(), None, 0, None, rng)?;

    add_and_test_with_costs(&vm, &caller_private_key, Some(&[&inputs]), &[transaction], rng);

    Ok(())
}

// Tests that deploying a program at V15+ with mixed closures — one safe (outputs scalar) and one
// forbidden (outputs ExternalRecord) — is rejected. Ensures the deploy-time check iterates all
// closures and does not short-circuit after the first safe one.
#[test]
fn test_mixed_closures_deploy_rejected_at_v15() -> Result<()> {
    let rng = &mut TestRng::default();
    let caller_private_key = sample_genesis_private_key(rng);

    // Parent defines the record.
    let parent_program = Program::from_str(
        r"
        program mixed_deploy_parent.aleo;

        record token:
            owner as address.private;
            amount as u64.private;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    // Child has two closures: one safe (outputs u64), one forbidden (outputs ExternalRecord).
    let child_program = Program::from_str(
        r"
        import mixed_deploy_parent.aleo;

        program mixed_deploy_child.aleo;

        closure safe_extract:
            input r0 as mixed_deploy_parent.aleo/token.record;
            add r0.amount 0u64 into r1;
            output r1 as u64;

        closure bad_passthrough:
            input r0 as mixed_deploy_parent.aleo/token.record;
            assert.eq true true;
            output r0 as mixed_deploy_parent.aleo/token.record;

        function noop:
            input r0 as u64.public;
            output r0 as u64.public;

        constructor:
            assert.eq true true;
        ",
    )?;

    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V15)?, rng);

    // Deploy the parent program.
    let tx = vm.deploy(&caller_private_key, &parent_program, None, 0, None, rng)?;
    add_and_test_with_costs(&vm, &caller_private_key, None, &[tx], rng);

    // Deploy the child program. The transaction is created, but rejected by verification because
    // `bad_passthrough` outputs ExternalRecord.
    let tx = vm.deploy(&caller_private_key, &child_program, None, 0, None, rng)?;
    assert!(
        vm.check_transaction(&tx, None, rng).is_err(),
        "Mixed closures with one forbidden output should be rejected at V15+"
    );

    Ok(())
}
