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

use console::{
    program::{Identifier, ProgramOwner},
    types::U8,
};
use snarkvm_ledger_block::{Output, Transaction};
use snarkvm_synthesizer_program::StackTrait;

/// Helper to create a V3 deployment transaction (amendment) with a properly connected fee.
/// V3 deployments have checksum but no owner. They retain translation VKs if the program has records.
fn create_v3_deployment_transaction<C: ConsensusStorage<CurrentNetwork>, R: Rng + CryptoRng>(
    vm: &VM<CurrentNetwork, C>,
    private_key: &PrivateKey<CurrentNetwork>,
    program: &Program<CurrentNetwork>,
    edition: u16,
    rng: &mut R,
) -> Result<Transaction<CurrentNetwork>> {
    // Create a deployment for the program.
    let mut v3_deployment = vm.process().deploy::<CurrentAleo, _>(program, rng)?;

    // Set the V3 deployment fields (amendment: checksum but no owner).
    // Translation VKs are retained if the program has records.
    v3_deployment.set_edition_raw(edition);
    v3_deployment.set_program_checksum_raw(Some(program.to_checksum()));
    v3_deployment.set_program_owner_raw(None);

    // Compute the deployment ID.
    let deployment_id = v3_deployment.to_deployment_id()?;

    // Create the owner signature.
    let owner = ProgramOwner::new(private_key, deployment_id, rng)?;

    // Compute the deployment cost.
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(vm.block_store().current_block_height())?;
    let (minimum_cost, _) = deployment_cost(vm.process(), &v3_deployment, consensus_version)?;

    // Authorize and execute the fee.
    let fee_authorization = vm.authorize_fee_public(private_key, minimum_cost, 0, deployment_id, rng)?;
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng)?;

    // Return the V3 deployment transaction.
    Transaction::from_deployment(owner, v3_deployment, fee)
}

// This test verifies that:
// - V3 deployments (amendments) are rejected before ConsensusVersion::V14
// - V3 deployments (amendments) are accepted at ConsensusVersion::V14
//
// Test flow:
// 1. V9: Deploy a program with records as V2 (checksum + owner, NO translation VKs)
// 2. V14: Create an amendment (checksum, no owner, WITH translation VKs for records)
// 3. Validation passes because translation VKs were added (didn't exist in original V2)
#[test]
fn test_v3_deployment_requires_v14() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Get the V9 and V14 heights.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?;
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?;

    // Initialize the VM at V9 height (where V2 deployments are allowed).
    let vm = sample_vm_at_height(v9_height, rng);

    // Define a program with records (so translation VKs will be generated at V14+).
    // At V9, this program is deployed as V2 (no translation VKs).
    // At V14, the amendment adds translation VKs, satisfying the "at least one VK changed" check.
    let program = Program::from_str(
        r"
program amendment_test.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function compute:
    input r0 as u32.public;
    add r0 r0 into r1;
    output r1 as u32.public;

constructor:
    assert.eq true true;
",
    )?;

    // Deploy the program as V2.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify the program is deployed with edition 0.
    let stack = vm.process().get_stack("amendment_test.aleo")?;
    assert_eq!(*stack.program_edition(), 0);

    // Create a V3 deployment (amendment).
    let deployed_program = stack.program().clone();

    // Create a V3 deployment transaction with proper fee.
    let v3_transaction = create_v3_deployment_transaction(&vm, &caller_private_key, &deployed_program, 0, rng)?;

    // Attempt to add the V3 deployment before V14 - it should be aborted.
    let block = sample_next_block(&vm, &caller_private_key, std::slice::from_ref(&v3_transaction), rng)?;
    assert_eq!(block.transactions().num_accepted(), 0, "V3 should be rejected before V14");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1, "V3 should be aborted before V14");
    vm.add_next_block(&block)?;

    // Advance the VM to V14 height.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &transactions, rng)?;
        vm.add_next_block(&block)?;
    }

    // Verify we're at V14.
    assert!(vm.block_store().current_block_height() >= v14_height);

    // Create a new V3 deployment transaction (need fresh fee).
    let v3_transaction = create_v3_deployment_transaction(&vm, &caller_private_key, &deployed_program, 0, rng)?;

    // Attempt to add the V3 deployment at V14 - it should succeed.
    let block = sample_next_block(&vm, &caller_private_key, &[v3_transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1, "V3 should be accepted at V14");
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify the edition hasn't changed (V3 doesn't change edition).
    let stack = vm.process().get_stack("amendment_test.aleo")?;
    assert_eq!(*stack.program_edition(), 0, "Edition should remain 0 after an amendment");

    Ok(())
}

// This test verifies the complete amendment lifecycle:
// - An amendment adds translation VKs to a pre-V14 deployment.
// - The program executes correctly before and after the amendment.
// - A duplicate amendment (no VK changes) is rejected.
//
// Test flow:
// 1. V9: Deploy a program with records (V2: checksum + owner, NO translation VKs)
// 2. Execute the program pre-amendment
// 3. Advance to V14
// 4. First amendment succeeds (adds translation VKs)
// 5. Verify VKs added and edition unchanged
// 6. Execute the program post-amendment
// 7. Second amendment fails (no VK changes since circuits are deterministic)
#[test]
fn test_amendment_updates_vks() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Get the V9 and V14 heights.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?;
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?;

    // Initialize the VM at V9 height.
    let vm = sample_vm_at_height(v9_height, rng);

    // Define a program with records.
    let program = Program::from_str(
        r"
program vk_test.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function add_numbers:
    input r0 as u32.public;
    input r1 as u32.public;
    add r0 r1 into r2;
    output r2 as u32.public;

constructor:
    assert.eq true true;
",
    )?;

    // Deploy the program at V9 (V2 deployment: checksum + owner, NO translation VKs).
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Verify the program was deployed without translation VKs.
    let stack = vm.process().get_stack("vk_test.aleo")?;
    assert!(
        stack.get_verifying_key(&Identifier::from_str("token")?).is_err(),
        "V2 deployment at V9 should NOT have translation VKs"
    );

    // Execute the program to verify it works before the amendment.
    let execution = vm.execute(
        &caller_private_key,
        ("vk_test.aleo", "add_numbers"),
        vec![Value::from_str("5u32")?, Value::from_str("3u32")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    assert!(vm.check_transaction(&execution, None, rng).is_ok());
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Advance the VM to V14 height.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &transactions, rng)?;
        vm.add_next_block(&block)?;
    }

    // Get the deployed program.
    let stack = vm.process().get_stack("vk_test.aleo")?;
    let deployed_program = stack.program().clone();

    // First amendment: Adds translation VKs - should succeed.
    let v3_transaction = create_v3_deployment_transaction(&vm, &caller_private_key, &deployed_program, 0, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[v3_transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1, "First amendment should be accepted (adds translation VKs)");
    vm.add_next_block(&block)?;

    // Verify the translation VK was added by the amendment.
    let stack = vm.process().get_stack("vk_test.aleo")?;
    assert!(
        stack.get_verifying_key(&Identifier::from_str("token")?).is_ok(),
        "Amendment should have added translation VKs"
    );

    // Verify the edition is still 0.
    assert_eq!(*stack.program_edition(), 0, "Edition should remain 0 after amendment");

    // Execute the program again - should still work with the new translation VKs.
    let execution = vm.execute(
        &caller_private_key,
        ("vk_test.aleo", "add_numbers"),
        vec![Value::from_str("10u32")?, Value::from_str("20u32")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    assert!(vm.check_transaction(&execution, None, rng).is_ok());
    let block = sample_next_block(&vm, &caller_private_key, &[execution], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Second amendment: No VK changes (deterministic circuits) - should fail.
    let v3_transaction_2 = create_v3_deployment_transaction(&vm, &caller_private_key, &deployed_program, 0, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[v3_transaction_2], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0, "Second amendment should be rejected (no VK changes)");
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test verifies that:
// - Amendments must match the existing program exactly.
// - Amendments must have the correct checksum.
// - Amendments must target an existing program.
//
// Test flow:
// 1. Deploy a program with records at V9 (no translation VKs)
// 2. Advance to V14
// 3. Test various invalid amendments (wrong checksum, non-existent program)
// 4. Test valid amendment that adds translation VKs
#[test]
fn test_amendment_validation() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Get the V9 and V14 heights.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?;
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?;

    // Initialize the VM at V9 height.
    let vm = sample_vm_at_height(v9_height, rng);

    // Define a program with records (so translation VKs can be added by the amendment).
    let program = Program::from_str(
        r"
program validation_test.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function dummy:
    input r0 as u32.public;
    output r0 as u32.public;

constructor:
    assert.eq true true;
",
    )?;

    // Deploy the program at V9 (no translation VKs).
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Get the deployed program info.
    let stack = vm.process().get_stack("validation_test.aleo")?;
    let deployed_program = stack.program().clone();

    // Advance the VM to V14 height.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &caller_private_key, &transactions, rng)?;
        vm.add_next_block(&block)?;
    }

    // Test 1: An amendment with wrong checksum should be rejected by the VM.
    // Note: Raw setters bypass construction validation, so the transaction is created,
    // but the VM will reject it during check_transaction because the checksum doesn't match.
    let mut wrong_checksum_deployment = vm.process().deploy::<CurrentAleo, _>(&deployed_program, rng)?;
    wrong_checksum_deployment.set_edition_raw(0);
    wrong_checksum_deployment.set_program_checksum_raw(Some([0u8; 32].map(U8::new))); // Wrong checksum
    wrong_checksum_deployment.set_program_owner_raw(None);

    let deployment_id = wrong_checksum_deployment.to_deployment_id()?;
    let owner = ProgramOwner::new(&caller_private_key, deployment_id, rng)?;
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(vm.block_store().current_block_height())?;
    let (minimum_cost, _) = deployment_cost(vm.process(), &wrong_checksum_deployment, consensus_version)?;
    let fee_authorization = vm.authorize_fee_public(&caller_private_key, minimum_cost, 0, deployment_id, rng)?;
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng)?;
    let wrong_checksum_tx = Transaction::from_deployment(owner, wrong_checksum_deployment, fee)?;

    // The transaction is created, but should be aborted due to checksum mismatch.
    let block = sample_next_block(&vm, &caller_private_key, &[wrong_checksum_tx], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0, "V3 with wrong checksum should be rejected");
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Test 2: An amendment for non-existent program should fail.
    let nonexistent_program = Program::from_str(
        r"
program nonexistent.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function dummy:

constructor:
    assert.eq true true;
",
    )?;

    let mut nonexistent_deployment = vm.process().deploy::<CurrentAleo, _>(&nonexistent_program, rng)?;
    nonexistent_deployment.set_edition_raw(0);
    nonexistent_deployment.set_program_checksum_raw(Some(nonexistent_program.to_checksum()));
    nonexistent_deployment.set_program_owner_raw(None);

    let deployment_id = nonexistent_deployment.to_deployment_id()?;
    let owner = ProgramOwner::new(&caller_private_key, deployment_id, rng)?;
    let (minimum_cost, _) = deployment_cost(vm.process(), &nonexistent_deployment, consensus_version)?;
    let fee_authorization = vm.authorize_fee_public(&caller_private_key, minimum_cost, 0, deployment_id, rng)?;
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng)?;
    let nonexistent_tx = Transaction::from_deployment(owner, nonexistent_deployment, fee)?;

    let block = sample_next_block(&vm, &caller_private_key, &[nonexistent_tx], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0, "V3 for non-existent program should be rejected");
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Test 3: Valid amendment should succeed (adds translation VKs).
    let v3_transaction = create_v3_deployment_transaction(&vm, &caller_private_key, &deployed_program, 0, rng)?;

    let block = sample_next_block(&vm, &caller_private_key, &[v3_transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1, "Valid V3 should be accepted");
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test verifies that:
// - Anyone can submit an amendment.
// - The amendment submitter is recorded but doesn't affect the program owner.
//
// Test flow:
// 1. Deploy a program with records at V9 as the original owner
// 2. Advance to V14
// 3. Another user submits a amendment (adds translation VKs)
// 4. Verify the program owner hasn't changed
#[test]
fn test_amendment_permissionless() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize the original deployer.
    let original_owner = sample_genesis_private_key(rng);

    // Initialize a different user.
    let other_user = PrivateKey::new(rng)?;
    let other_address = Address::try_from(&other_user)?;

    // Get the V9 and V14 heights.
    let v9_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9)?;
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?;

    // Initialize the VM at V9 height.
    let vm = sample_vm_at_height(v9_height, rng);

    // Fund the other user.
    let transfer = vm.execute(
        &original_owner,
        ("credits.aleo", "transfer_public"),
        vec![Value::from_str(&format!("{other_address}"))?, Value::from_str("1_000_000_000_000u64")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &original_owner, &[transfer], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Deploy a program with records as the original owner at V9 (no translation VKs).
    let program = Program::from_str(
        r"
program permissionless_test.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function dummy:
    input r0 as u32.public;
    output r0 as u32.public;

constructor:
    assert.eq true true;
",
    )?;

    let deployment = vm.deploy(&original_owner, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &original_owner, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block)?;

    // Get the deployed program info.
    let stack = vm.process().get_stack("permissionless_test.aleo")?;
    let deployed_program = stack.program().clone();
    let original_program_owner = *stack.program_owner();

    // Advance the VM to V14 height.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < v14_height {
        let block = sample_next_block(&vm, &original_owner, &transactions, rng)?;
        vm.add_next_block(&block)?;
    }

    // Submit an amendment as the OTHER user (not the original owner).
    // This will add translation VKs since the original deployment didn't have them.
    let v3_transaction = create_v3_deployment_transaction(&vm, &other_user, &deployed_program, 0, rng)?;

    // The amendment should be accepted even though submitted by a different user.
    let block = sample_next_block(&vm, &original_owner, &[v3_transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1, "V3 from different user should be accepted");
    vm.add_next_block(&block)?;

    // Verify the program owner hasn't changed.
    let stack = vm.process().get_stack("permissionless_test.aleo")?;
    assert_eq!(
        *stack.program_owner(),
        original_program_owner,
        "Program owner should remain unchanged after an amendment"
    );

    Ok(())
}

// This test verifies that:
// - credits.aleo cannot be amended with V3.
// Note: credits.aleo is protected at multiple levels:
//   1. Process::deploy blocks re-initialization of credits.aleo
//   2. The verification logic also checks for credits.aleo amendments
// This test verifies level 1 - the deployment creation itself is blocked.
#[test]
fn test_credits_cannot_be_amended() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize the VM at V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14)?;
    let vm = sample_vm_at_height(v14_height, rng);

    // Get the credits program.
    let credits_program = Program::credits()?;

    // Attempt to create a V3 deployment for credits.aleo - this should fail.
    let result = vm.process().deploy::<CurrentAleo, _>(&credits_program, rng);

    // Verify that creating a deployment for credits.aleo fails.
    assert!(result.is_err(), "Creating a deployment for credits.aleo should fail");
    let error = result.unwrap_err().to_string();
    assert!(error.contains("credits.aleo"), "Error should mention credits.aleo: {error}");

    Ok(())
}

// Tests dynamic calls to programs deployed before V14, then after a V3 amendment.
// Verifies that:
// 1. Pre-V14 deployments do not include translation keys.
// 2. A verifier VM without translation keys rejects the prover's transaction.
// 3. After a V3 amendment at V14, the verifier VM gains translation keys.
// 4. The verifier VM with translation keys (from amendment) can verify and accept the transaction.
#[test]
fn test_dynamic_call_after_amendment() {
    let rng = &mut TestRng::default();

    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    let legacy_program = Program::<CurrentNetwork>::from_str(
        r"
        program legacy_token_amend.aleo;

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
        program dynamic_caller_amend.aleo;

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
            output r7 as dynamic_caller_amend.aleo/call_legacy_transfer.future;

        finalize call_legacy_transfer:
            assert.eq true true;

        constructor:
            assert.eq true true;
        ",
    )
    .unwrap();

    let legacy_program_field =
        Identifier::<CurrentNetwork>::from_str("legacy_token_amend").unwrap().to_field().unwrap();
    let aleo_field = Identifier::<CurrentNetwork>::from_str("aleo").unwrap().to_field().unwrap();
    let transfer_field = Identifier::<CurrentNetwork>::from_str("transfer").unwrap().to_field().unwrap();

    // --- Set up verifier VM (pre-V14 deployment, then V3 amendment for translation keys) ---
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
    let mint_inputs = [Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let mint_tx = verifier_vm
        .execute(&caller_private_key, ("legacy_token_amend.aleo", "mint"), mint_inputs.iter(), None, 0, None, rng)
        .unwrap();

    add_and_test_with_costs(&verifier_vm, &caller_private_key, Some(&[&mint_inputs]), &[mint_tx], rng);

    // Advance verifier VM to V14.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    for _ in verifier_vm.block_store().current_block_height()..v14_height {
        let block = sample_next_block(&verifier_vm, &caller_private_key, &[], rng).unwrap();
        verifier_vm.add_next_block(&block).unwrap();
    }

    // Deploy caller program on verifier VM at V14.
    let deploy_caller_verifier = verifier_vm.deploy(&caller_private_key, &caller_program, None, 0, None, rng).unwrap();
    add_and_test_with_costs(&verifier_vm, &caller_private_key, None, &[deploy_caller_verifier], rng);

    // Verify the verifier VM does NOT have translation keys for `legacy_token_amend.aleo/token`.
    let legacy_program_id = console::program::ProgramID::<CurrentNetwork>::from_str("legacy_token_amend.aleo").unwrap();
    let token_name = Identifier::<CurrentNetwork>::from_str("token").unwrap();

    {
        let vm_process = verifier_vm.process();
        let stack = vm_process.get_stack(legacy_program_id).unwrap();
        assert_eq!(*stack.program_edition(), 0, "Verifier should have edition 0 before amendment");
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
    let prover_mint_inputs =
        [Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let prover_mint_tx = prover_vm
        .execute(
            &caller_private_key,
            ("legacy_token_amend.aleo", "mint"),
            prover_mint_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
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
    add_and_test_with_costs(&prover_vm, &caller_private_key, Some(&[&prover_mint_inputs]), &[prover_mint_tx], rng);

    // Prover creates a transaction requiring translation.
    let dynamic_record = DynamicRecord::<CurrentNetwork>::from_record(&prover_minted_record).unwrap();

    let transaction = prover_vm
        .execute(
            &caller_private_key,
            ("dynamic_caller_amend.aleo", "call_legacy_transfer"),
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

    // --- Amend verifier VM (V3 amendment adds translation keys) ---

    // Create a V3 amendment on verifier VM to add translation keys.
    let stack = verifier_vm.process().get_stack("legacy_token_amend.aleo").unwrap();
    let deployed_program = stack.program().clone();
    let edition = *stack.program_edition();
    drop(stack);

    let v3_transaction =
        create_v3_deployment_transaction(&verifier_vm, &caller_private_key, &deployed_program, edition, rng).unwrap();
    add_and_test_with_costs(&verifier_vm, &caller_private_key, None, &[v3_transaction], rng);

    // Verify the verifier VM now HAS translation keys after amendment, and edition is unchanged.
    {
        let vm_process = verifier_vm.process();
        let stack = vm_process.get_stack(legacy_program_id).unwrap();
        assert_eq!(*stack.program_edition(), 0, "Edition should remain 0 after amendment");
        assert!(
            stack.get_verifying_key(&token_name).is_ok(),
            "Verifier VM should have translation key after amendment"
        );
    }

    // Mint a fresh token on verifier VM and execute the dynamic call directly.
    // This verifies the verifier VM can create and accept dynamic call transactions
    // after getting translation keys via V3 amendment.
    let verifier_mint_inputs_2 =
        [Value::from_str(&caller_address.to_string()).unwrap(), Value::from_str("1000u64").unwrap()];
    let verifier_mint_tx_2 = verifier_vm
        .execute(
            &caller_private_key,
            ("legacy_token_amend.aleo", "mint"),
            verifier_mint_inputs_2.iter(),
            None,
            0,
            None,
            rng,
        )
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
    add_and_test_with_costs(
        &verifier_vm,
        &caller_private_key,
        Some(&[&verifier_mint_inputs_2]),
        &[verifier_mint_tx_2],
        rng,
    );

    let dynamic_record_2 = DynamicRecord::<CurrentNetwork>::from_record(&verifier_minted_record_2).unwrap();

    let dynamic_call_inputs = [
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
            ("dynamic_caller_amend.aleo", "call_legacy_transfer"),
            dynamic_call_inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .expect("Verifier VM should create transaction after getting translation keys via amendment");

    // Verifier VM (with translation keys from amendment) should accept the transaction.
    add_and_test_with_costs(&verifier_vm, &caller_private_key, Some(&[&dynamic_call_inputs]), &[transaction_2], rng);
}
