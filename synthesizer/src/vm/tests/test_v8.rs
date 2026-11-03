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

use crate::prelude::deployment_cost_v1;

use console::{account::ViewKey, network::ConsensusVersion, program::ProgramOwner};
use snarkvm_ledger_block::{Deployment, Transaction};
use snarkvm_ledger_store::ConsensusStore;
use snarkvm_synthesizer_program::{Program, StackTrait as _};

use aleo_std::StorageMode;

// This test checks that:
//  - an existing program cannot be redeployed before `ConsensusVersion::V8`
//  - an existing program cannot be redeployed with different code after `ConsensusVersion::V8`
//  - an existing program can be redeployed with the same code after `ConsensusVersion::V8` (even after `V9`)
//  - an existing program can only be redeployed once after `ConsensusVersion::V8` (even after `V9`)
//  - a program with a mapping can be redeployed after `ConsensusVersion::V8` (even after `V9`)
//  - after `ConsensusVersion::V8`, existing programs cannot be executed until they are redeployed.
//  - the VM can be loaded from a store at the very end.
#[test]
#[ignore]
fn test_redeployment() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the storage.
    let store = ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap();

    // Initialize the VM.
    let mut vm = VM::<CurrentNetwork, LedgerType>::from(store.clone())?;
    let genesis = sample_genesis_block(rng);
    vm.add_next_block(&genesis)?;

    // Get the genesis private key.
    let genesis_private_key = sample_genesis_private_key(rng);

    // Advance the VM to 3 blocks before `ConsensusVersion::V8`.
    advance_vm_to_height(
        &mut vm,
        genesis_private_key,
        CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V8)? - 3,
        rng,
    );

    // Initialize the programs
    let program = Program::from_str(
        r"
program test_redeployment.aleo;
mapping foo:
    key as address.public;
    value as u64.public;
function dummy:
    ",
    )?;
    let program_diff = Program::from_str(
        r"
program test_redeployment.aleo;
mapping foo:
    key as address.public;
    value as u64.public;
function dummy:
function dummy2:
    ",
    )?;

    // Attempt to deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Execute the program.
    let execute = vm.execute(
        &caller_private_key,
        ("test_redeployment.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to redeploy the program before `ConsensusVersion::V8`.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Check that the consensus version is `V8`.
    let block_height = vm.store.block_store().current_block_height();
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(block_height)?;
    assert_eq!(consensus_version, ConsensusVersion::V8);

    // Attempt to execute the program after `ConsensusVersion::V8`.
    let execute = vm.execute(
        &caller_private_key,
        ("test_redeployment.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Attempt to redeploy the program with different code after `ConsensusVersion::V8`.
    let result = vm.deploy(&caller_private_key, &program_diff, None, 0, None, rng);
    assert!(result.is_err());

    // Redeploy the program with the same code after `ConsensusVersion::V8`.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the program can be executed after redeployment.
    let execute = vm.execute(
        &caller_private_key,
        ("test_redeployment.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Attempt to redeploy the program again after `ConsensusVersion::V8`.
    let transaction = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Drop the VM.
    drop(vm);

    // Load the VM from the store.
    let vm = VM::<CurrentNetwork, LedgerType>::from(store)?;

    // Check that the latest block.
    let latest_block = vm.store.block_store().current_block_height();
    assert_eq!(latest_block, CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V8)? + 4);

    // Check that the program can still be executed.
    let execute = vm.execute(
        &caller_private_key,
        ("test_redeployment.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    Ok(())
}

// This test checks that the `credits.aleo` program cannot be redeployed.
#[test]
#[ignore]
fn test_credits_cannot_be_redeployed() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V8)?, rng);

    // Initialize the `credits.aleo` program.
    let program = Program::credits()?;

    // Attempt to redeploy the `credits.aleo` program.
    let result = vm.deploy(&caller_private_key, &program, None, 0, None, rng);
    assert!(result.is_err());

    Ok(())
}

// This test:
// - verifies that a program calling `credits.aleo/upgrade` cannot be deployed before `ConsensusVersion::V8`
// - verifies that a program calling `credits.aleo/upgrade` cannot be deployed after `ConsensusVersion::V8`.
// - verifies that `credits.aleo/upgrade` cannot be executed before `ConsensusVersion::V8`
// - verifies that `credits.aleo/upgrade` can be executed after `ConsensusVersion::V8`.
#[test]
#[ignore]
fn test_credits_upgrade() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V8)? - 3, rng);

    // A helper closure to create a program with an upgrade call.
    let sample_program = |i: usize| {
        Program::from_str(&format!(
            r"
import credits.aleo;

program test_upgrade_call_{i}.aleo;

function run:
    input r0 as credits.aleo/credits.record;
    call credits.aleo/upgrade r0 into r1 r2;
    async run r2 into r3;
    output r1 as credits.aleo/credits.record;
    output r3 as test_upgrade_call_{i}.aleo/run.future;
    
finalize run:
    input r0 as credits.aleo/upgrade.future;
    await r0;
    ",
        ))
    };

    // Deploy the program before `ConsensusVersion::V8`.
    let deployment = vm.deploy(&caller_private_key, &sample_program(0)?, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Extract a record from the genesis block and `split` it into two smaller records.
    let genesis_hash = vm.store.block_store().get_block_hash(0)?.unwrap();
    let genesis_block = vm.store.block_store().get_block(&genesis_hash)?.unwrap();
    let caller_view_key = ViewKey::try_from(&caller_private_key)?;
    let mut records = genesis_block
        .transactions()
        .records()
        .map(|(_, record)| record.decrypt(&caller_view_key))
        .collect::<Result<Vec<_>>>()?;
    let record = records.pop().unwrap();
    let execute = vm.execute(
        &caller_private_key,
        ("credits.aleo", "split"),
        vec![Value::Record(record), Value::from_str("12345u64")?].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Extract the split record.
    let record = block.transactions().records().next().unwrap().1.decrypt(&caller_view_key)?;

    // Attempt to execute the `upgrade` function directly before `ConsensusVersion::V8`.
    let execute = vm.execute(
        &caller_private_key,
        ("credits.aleo", "upgrade"),
        vec![Value::Record(record.clone())].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Check that the consensus version is `V8`.
    let block_height = vm.store.block_store().current_block_height();
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(block_height)?;
    assert_eq!(consensus_version, ConsensusVersion::V8);

    // Attempt to deploy the program after `ConsensusVersion::V8`.
    let deployment = vm.deploy(&caller_private_key, &sample_program(1)?, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Execute the `upgrade` function directly.
    let execute = vm.execute(
        &caller_private_key,
        ("credits.aleo", "upgrade"),
        vec![Value::Record(record)].into_iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    Ok(())
}

// This test verifies that:
//   - a program cannot be redeployed in the same block as its deployment
//   - an edition 0 program cannot be executed if it is deployed after `ConsensusVersion::V8`
//   - a program can be redeployed using the exact same deployment, different fee, and in a different block, after `ConsensusVersion::V8` (even after `ConsensusVersion::V9`)
// Note: It is important that this invariant holds, otherwise block rollbacks in the DB can be inconsistent.
#[test]
#[ignore]
fn test_deploy_and_redeploy() -> Result<()> {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = sample_genesis_private_key(rng);

    // Initialize a second caller.
    let other_private_key = sample_genesis_private_key(rng);
    let address = Address::try_from(&other_private_key)?;

    // Initialize the VM.
    let vm = sample_vm_at_height(CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V8)? - 1, rng);

    // Send some credits to the second caller.
    let transfer = vm.execute(
        &caller_private_key,
        ("credits.aleo", "transfer_public"),
        [Value::from_str(&address.to_string())?, Value::from_str("1000000u64")?].iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[transfer], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Initialize the program.
    let program = Program::from_str(
        r"
program test_deploy_and_redeploy.aleo;

function dummy:
    ",
    )?;

    // Deploy the program.
    let transaction_0 = vm.deploy(&caller_private_key, &program, None, 0, None, rng)?;
    let deployment_0 = transaction_0.deployment().expect("Expected a deployment transaction");
    // Generate a second deployment transaction with an incremented edition and a different fee.
    let deployment_1 = Deployment::new(
        deployment_0.edition() + 1,
        deployment_0.program().clone(),
        deployment_0.verifying_keys().clone(),
        deployment_0.program_checksum(),
        deployment_0.program_owner(),
    )?;
    let fee_authorization = vm.authorize_fee_public(
        &other_private_key,
        *transaction_0.base_fee_amount()?,
        *transaction_0.priority_fee_amount()?,
        deployment_1.to_deployment_id()?,
        rng,
    )?;
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng)?;
    let owner = ProgramOwner::new(&other_private_key, deployment_1.to_deployment_id()?, rng)?;
    let transaction_1 = Transaction::from_deployment(owner, deployment_1, fee)?;
    // Attempt to deploy both programs in the same block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction_0.clone(), transaction_1], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Check the edition of the deployed program.
    let edition = *vm.process().get_stack("test_deploy_and_redeploy.aleo")?.program_edition();
    assert_eq!(edition, 0);

    // Attempt to execute the program immediately after deployment.
    let execute = vm.execute(
        &caller_private_key,
        ("test_deploy_and_redeploy.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);
    vm.add_next_block(&block)?;

    // Redeploy the program with the other private key, using the original deployment.
    let deployment = Deployment::new(
        1,
        program.clone(),
        deployment_0.verifying_keys().clone(),
        Some(deployment_0.program().to_checksum()),
        Some(address),
    )?;

    // Note: This needs to be recalculated since the new deployment contains a checksum and owner.
    let (base_fee_amount, _) = deployment_cost_v1(vm.process(), &deployment)?;
    let fee_authorization = vm.authorize_fee_public(
        &other_private_key,
        base_fee_amount,
        *transaction_0.priority_fee_amount()?,
        deployment.to_deployment_id()?,
        rng,
    )?;
    let fee = vm.execute_fee_authorization(fee_authorization, None, rng)?;
    let owner = ProgramOwner::new(&other_private_key, deployment.to_deployment_id()?, rng)?;
    let transaction = Transaction::from_deployment(owner, deployment, fee)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Check that the program can now be executed.
    let execute = vm.execute(
        &caller_private_key,
        ("test_deploy_and_redeploy.aleo", "dummy"),
        Vec::<Value<CurrentNetwork>>::new().iter(),
        None,
        0,
        None,
        rng,
    )?;
    let block = sample_next_block(&vm, &caller_private_key, &[execute], rng)?;
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block)?;

    // Verify that the program cannot be redeployed further.
    let transaction = vm.deploy(&other_private_key, &program, None, 0, None, rng)?;
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng)?;
    assert_eq!(block.transactions().num_accepted(), 0);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 1);

    Ok(())
}
