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

use crate::{
    Ledger,
    RecordsFilter,
    advance::split_candidate_solutions,
    test_helpers::{CurrentAleo, CurrentLedger, CurrentNetwork, chain_builder::GenerateBlockOptions},
};

use aleo_std::StorageMode;
use console::{
    account::{Address, PrivateKey},
    network::{MainnetV0, prelude::*},
    program::{Entry, Identifier, Literal, Plaintext, ProgramID, Value},
    types::U16,
};
use snarkvm_ledger_authority::Authority;
use snarkvm_ledger_block::{Block, ConfirmedTransaction, Execution, Ratify, Rejected, Transaction};
use snarkvm_ledger_committee::{Committee, MIN_VALIDATOR_STAKE};
use snarkvm_ledger_narwhal::{BatchHeader, Data, Subdag, Transmission, TransmissionID};
use snarkvm_ledger_store::ConsensusStore;

use snarkvm_synthesizer::{
    program::Program,
    vm::{TransactionCacheKey, VM},
};
use snarkvm_utilities::try_vm_runtime;

use anyhow::Context;
use indexmap::IndexMap;
use rand::seq::SliceRandom;

use crate::test_helpers::{LedgerType, TestChainBuilder, chain_builder::GenerateBlocksOptions};

/// Initializes a sample VM.
fn sample_vm() -> VM<CurrentNetwork, LedgerType> {
    VM::from(ConsensusStore::<CurrentNetwork, LedgerType>::open(StorageMode::new_test(None)).unwrap()).unwrap()
}

/// Extract the transmissions from a block.
fn extract_transmissions(
    block: &Block<CurrentNetwork>,
) -> IndexMap<TransmissionID<CurrentNetwork>, Transmission<CurrentNetwork>> {
    let mut transmissions = IndexMap::new();
    for tx in block.transactions().iter() {
        let checksum = Data::Object(tx.transaction().clone()).to_checksum::<CurrentNetwork>().unwrap();
        transmissions.insert(TransmissionID::from((&tx.id(), &checksum)), tx.transaction().clone().into());
    }
    if let Some(coinbase_solution) = block.solutions().as_ref() {
        for (_, solution) in coinbase_solution.iter() {
            let checksum = Data::Object(*solution).to_checksum::<CurrentNetwork>().unwrap();
            transmissions.insert(TransmissionID::from((solution.id(), checksum)), (*solution).into());
        }
    }
    transmissions
}

/// Creates the cache key for a transaction in the partially-verified transactions cache.
fn create_cache_key(
    vm: &VM<CurrentNetwork, LedgerType>,
    transaction: &Transaction<CurrentNetwork>,
) -> Result<TransactionCacheKey<CurrentNetwork>> {
    let mut execution_stacks = IndexMap::new();
    for transition in transaction.transitions() {
        execution_stacks.insert(*transition.program_id(), vm.process().get_stack(transition.program_id())?);
    }
    let current_block_height = vm.block_store().current_block_height();
    let consensus_version = CurrentNetwork::CONSENSUS_VERSION(current_block_height)?;
    VM::<CurrentNetwork, LedgerType>::create_cache_key_with_stacks(transaction, &execution_stacks, consensus_version)
}

#[test]
fn test_load() {
    let rng = &mut TestRng::default();

    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    // Initialize the store.
    let store = ConsensusStore::<_, LedgerType>::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    // Initialize the ledger with the genesis block.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    assert_eq!(ledger.latest_hash(), genesis.hash());
    assert_eq!(ledger.latest_height(), genesis.height());
    assert_eq!(ledger.latest_round(), genesis.round());
    assert_eq!(ledger.latest_block(), genesis);
}

#[test]
fn test_load_unchecked() {
    let rng = &mut TestRng::default();

    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    // Initialize the store.
    let store = ConsensusStore::<_, LedgerType>::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    // Initialize the ledger without checks.
    let ledger = CurrentLedger::load_unchecked(genesis.clone(), StorageMode::new_test(None)).unwrap();
    assert_eq!(ledger.latest_hash(), genesis.hash());
    assert_eq!(ledger.latest_height(), genesis.height());
    assert_eq!(ledger.latest_round(), genesis.round());
    assert_eq!(ledger.latest_block(), genesis);

    // Initialize the ledger with the genesis block.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    assert_eq!(ledger.latest_hash(), genesis.hash());
    assert_eq!(ledger.latest_height(), genesis.height());
    assert_eq!(ledger.latest_round(), genesis.round());
    assert_eq!(ledger.latest_block(), genesis);
}

/// Loads a ledger whose genesis state root is `Field::one()`.
#[cfg(feature = "dev_genesis_state_root")]
#[test]
fn test_load_dev_genesis_state_root() {
    let rng = &mut TestRng::default();

    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    // Initialize the store.
    let store = ConsensusStore::<_, LedgerType>::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    // Initialize the ledger with the genesis block.
    let storage_mode = StorageMode::new_test(None);
    let ledger = CurrentLedger::load(genesis.clone(), storage_mode.clone()).unwrap();
    assert_eq!(ledger.latest_height(), 0);
    assert_eq!(ledger.latest_block(), genesis);
    assert_eq!(ledger.get_state_root(0).unwrap().unwrap(), console::types::Field::<CurrentNetwork>::one().into());
    // Block 1 speculation treats genesis as inserted when this lookup finds a height.
    assert_eq!(ledger.find_block_height_from_state_root(ledger.latest_state_root()).unwrap(), Some(0));
    drop(ledger);

    // Load the same storage mode again while the chain is still at height 0.
    let ledger = CurrentLedger::load(genesis.clone(), storage_mode).unwrap();
    assert_eq!(ledger.latest_height(), 0);
    assert_eq!(ledger.latest_block(), genesis);
    assert_eq!(ledger.get_state_root(0).unwrap().unwrap(), console::types::Field::<CurrentNetwork>::one().into());
}

#[test]
fn test_get_block() {
    let rng = &mut TestRng::default();

    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    // Initialize the store.
    let store = ConsensusStore::<_, LedgerType>::open(StorageMode::new_test(None)).unwrap();
    // Create a genesis block.
    let genesis = VM::from(store).unwrap().genesis_beacon(&private_key, rng).unwrap();

    // Initialize a new ledger.
    let ledger = CurrentLedger::load(genesis.clone(), StorageMode::new_test(None)).unwrap();
    // Retrieve the genesis block.
    let candidate = ledger.get_block(0).unwrap();
    // Ensure the genesis block matches.
    assert_eq!(genesis, candidate);
}

#[test]
fn test_get_bonded_balances() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, .. } = crate::test_helpers::sample_test_env(rng);

    // Fetch the bonded mapping.
    let credits_program_id = ProgramID::from_str("credits.aleo").unwrap();
    let bonded_mapping = Identifier::from_str("bonded").unwrap();
    let bonded_mapping =
        ledger.vm().finalize_store().get_mapping_confirmed(credits_program_id, bonded_mapping).unwrap();
    // Deserialize the bonded stakers.
    let stakers = snarkvm_synthesizer::vm::bonded_map_into_stakers(bonded_mapping).unwrap();
    // Check that the bonded amounts match the bonded mapping.
    for (staker, (_, amount)) in stakers {
        assert_eq!(amount, ledger.get_bonded_amount(&staker).unwrap());
    }
}

#[test]
fn test_state_path() {
    let rng = &mut TestRng::default();

    // Initialize the ledger.
    let ledger = crate::test_helpers::sample_ledger(PrivateKey::<CurrentNetwork>::new(rng).unwrap(), rng);
    // Retrieve the genesis block.
    let block = ledger.get_block(0).unwrap();

    // Construct the state path.
    let commitments = block.transactions().commitments().collect::<Vec<_>>();
    let commitment = commitments[0];

    let _state_path = ledger.get_state_path_for_commitment(commitment).unwrap();
}

#[test]
fn test_state_paths() {
    let rng = &mut TestRng::default();

    // Initialize the ledger.
    let ledger = crate::test_helpers::sample_ledger(PrivateKey::<CurrentNetwork>::new(rng).unwrap(), rng);
    // Retrieve the genesis block.
    let block = ledger.get_block(0).unwrap();

    // Construct the state path.
    let commitments = block.transactions().commitments().copied().collect::<Vec<_>>();

    let _state_paths = ledger.get_state_paths_for_commitments(&commitments).unwrap();
}

#[test]
fn test_insufficient_private_fees() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, address, .. } =
        crate::test_helpers::sample_test_env(rng);

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    let record_1 = records[0].clone();
    let record_2 = records[1].clone();

    // Check fee amount requirements for `split` calls.
    {
        // Prepare a `split` execution without a fee.
        let inputs = [Value::Record(record_1.clone()), Value::from_str("100u64").unwrap()];
        let authorization = ledger.vm.authorize(&private_key, "credits.aleo", "split", inputs, rng).unwrap();
        let split_transaction_without_fee = ledger.vm.execute_authorization(authorization, None, None, rng).unwrap();
        assert!(ledger.check_transaction_basic(&split_transaction_without_fee, None, rng).is_ok());
    }

    // Check fee amount requirements for executions.
    {
        // Prepare an execution without a fee.
        let inputs = [
            Value::Record(record_1),
            Value::from_str(&format!("{address}")).unwrap(),
            Value::from_str("100u64").unwrap(),
        ];
        let authorization = ledger.vm.authorize(&private_key, "credits.aleo", "transfer_private", inputs, rng).unwrap();
        let transaction_without_fee = ledger.vm.execute_authorization(authorization, None, None, rng).unwrap();
        let execution = transaction_without_fee.execution().unwrap();

        // Check that a transaction with sufficient fee will succeed.
        let fee_authorization = ledger
            .vm
            .authorize_fee_private(
                &private_key,
                record_2.clone(),
                10_000_000,
                1_000,
                execution.to_execution_id().unwrap(),
                rng,
            )
            .unwrap();
        let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();
        let sufficient_fee_transaction = Transaction::from_execution(execution.clone(), Some(fee)).unwrap();
        assert!(ledger.check_transaction_basic(&sufficient_fee_transaction, None, rng).is_ok());

        // Check that a transaction with insufficient fee will fail.
        let insufficient_fee_authorization = ledger
            .vm
            .authorize_fee_private(&private_key, record_2.clone(), 1, 0, execution.to_execution_id().unwrap(), rng)
            .unwrap();
        let insufficient_fee = ledger.vm.execute_fee_authorization(insufficient_fee_authorization, None, rng).unwrap();
        let insufficient_fee_transaction =
            Transaction::from_execution(execution.clone(), Some(insufficient_fee)).unwrap();
        assert!(ledger.check_transaction_basic(&insufficient_fee_transaction, None, rng).is_err());
    }

    // Check fee amount requirements for deployment.

    {
        // Deploy a test program to the ledger.
        let program = Program::<CurrentNetwork>::from_str(
            r"
program dummy.aleo;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
        )
        .unwrap();

        // Check that a deployment transaction with sufficient fee will succeed.
        let transaction = ledger.vm.deploy(&private_key, &program, Some(record_2.clone()), 0, None, rng).unwrap();
        assert!(ledger.check_transaction_basic(&transaction, None, rng).is_ok());

        // Check that a deployment transaction with insufficient fee will fail.
        let deployment = transaction.deployment().unwrap();
        let insufficient_fee_authorization = ledger
            .vm
            .authorize_fee_private(&private_key, record_2, 1, 0, deployment.to_deployment_id().unwrap(), rng)
            .unwrap();
        let insufficient_fee = ledger.vm.execute_fee_authorization(insufficient_fee_authorization, None, rng).unwrap();
        let insufficient_fee_transaction =
            Transaction::from_deployment(*transaction.owner().unwrap(), deployment.clone(), insufficient_fee).unwrap();
        assert!(ledger.check_transaction_basic(&insufficient_fee_transaction, None, rng).is_err());
    }
}

#[test]
fn test_insufficient_public_fees() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Sample recipient.
    let recipient_private_key = PrivateKey::new(rng).unwrap();
    let recipient_address = Address::try_from(&recipient_private_key).unwrap();
    let withdrawal_private_key = PrivateKey::<MainnetV0>::new(rng).unwrap();
    let withdrawal_address = Address::try_from(&withdrawal_private_key).unwrap();

    // Fund the recipient with 1 million credits.
    {
        let inputs =
            [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("1000000000000u64").unwrap()];
        let transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
            .unwrap();

        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();
        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();
    }

    // Attempt to bond the node with insufficient public fees.
    {
        let inputs = [
            Value::from_str(&format!("{withdrawal_address}")).unwrap(),
            Value::from_str("1000000000000u64").unwrap(),
            Value::from_str("10u8").unwrap(),
        ];
        let transaction = ledger
            .vm
            .execute(&recipient_private_key, ("credits.aleo", "bond_validator"), inputs.into_iter(), None, 0, None, rng)
            .unwrap();

        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();
        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();
    }
}

#[test]
fn test_insufficient_finalize_fees() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, address, .. } =
        crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program dummy.aleo;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    // Prepare the additional fee.
    let credits = Some(records.values().next().unwrap().clone());

    // Deploy.
    let transaction = ledger.vm.deploy(&private_key, &program, credits, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&transaction, None, rng).unwrap();

    // Construct the next block.
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block).unwrap();
    assert_eq!(ledger.latest_height(), 1);
    assert_eq!(ledger.latest_hash(), block.hash());

    // Create a transfer transaction to produce a record with insufficient balance to pay for fees.
    let transfer_transaction = ledger.create_transfer(&private_key, address, 100, 0, None, rng).unwrap();

    // Construct the next block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transfer_transaction.clone()], rng)
        .unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block).unwrap();
    assert_eq!(ledger.latest_height(), 2);
    assert_eq!(ledger.latest_hash(), block.hash());

    // Execute the test program, without providing enough fees for finalize, and ensure that the ledger deems the transaction invalid.

    // Find records from the transfer transaction.
    let records = transfer_transaction
        .records()
        .map(|(_, record)| record.decrypt(&view_key))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // Prepare the inputs.
    let inputs = [Value::<CurrentNetwork>::from_str("1u8").unwrap()].into_iter();

    // Check that the record has the correct balance.
    let insufficient_record = records[0].clone();
    if let Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) =
        &insufficient_record.data().get(&Identifier::from_str("microcredits").unwrap())
    {
        assert_eq!(**amount, 100)
    }
    // Ensure that we can't produce a transaction with a record that has insufficient balance to pay for fees.
    assert!(
        ledger
            .vm
            .execute(&private_key, ("dummy.aleo", "foo"), inputs.clone(), Some(insufficient_record), 0, None, rng)
            .is_err()
    );

    let sufficient_record = records[1].clone();
    // Execute with enough fees.
    let transaction =
        ledger.vm.execute(&private_key, ("dummy.aleo", "foo"), inputs, Some(sufficient_record), 0, None, rng).unwrap();
    // Verify.
    ledger.vm.check_transaction(&transaction, None, rng).unwrap();
    // Ensure that the ledger deems the transaction valid.
    assert!(ledger.check_transaction_basic(&transaction, None, rng).is_ok());
}

#[test]
fn test_rejected_execution() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program_id = "test_rejected_execute.aleo";
    let program = Program::<CurrentNetwork>::from_str(&format!(
        "
program {program_id};

function failed_assert:
    async failed_assert into r0;
    output r0 as {program_id}/failed_assert.future;

finalize failed_assert:
    assert.eq false true;"
    ))
    .unwrap();

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    let record_1 = records[0].clone();
    let record_2 = records[1].clone();

    // Deploy the program.
    let deployment_transaction = ledger.vm().deploy(&private_key, &program, Some(record_1), 0, None, rng).unwrap();

    // Construct the deployment block.
    let deployment_block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&deployment_block, rng).unwrap();

    // Add the deployment block to the ledger.
    ledger.advance_to_next_block(&deployment_block).unwrap();

    // Construct a transaction that will cause error from an assert call in `finalize`.
    let failed_assert_transaction = ledger
        .vm()
        .execute(
            &private_key,
            (program_id, "failed_assert"),
            Vec::<Value<_>>::new().into_iter(),
            Some(record_2),
            0,
            None,
            rng,
        )
        .unwrap();
    let failed_assert_transaction_id = failed_assert_transaction.id();

    // Construct the next block containing the new transaction.
    let next_block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![failed_assert_transaction.clone()],
            rng,
        )
        .unwrap();

    // Check that the block contains 1 rejected execution.
    assert_eq!(next_block.transactions().len(), 1);
    let confirmed_transaction = next_block.transactions().iter().next().unwrap();
    assert!(confirmed_transaction.is_rejected());
    if let Transaction::Execute(_, _, execution, fee) = failed_assert_transaction {
        let fee_transaction = Transaction::from_fee(fee.unwrap()).unwrap();
        let expected_confirmed_transaction =
            ConfirmedTransaction::RejectedExecute(0, fee_transaction, Rejected::new_execution(*execution), vec![]);

        assert_eq!(confirmed_transaction, &expected_confirmed_transaction);
    }

    // Check that the unconfirmed transaction ID of the rejected execution is correct.
    assert_eq!(confirmed_transaction.to_unconfirmed_transaction_id().unwrap(), failed_assert_transaction_id);

    // Check that the next block is valid.
    ledger.check_next_block(&next_block, rng).unwrap();

    // Add the block with the rejected transaction to the ledger.
    ledger.advance_to_next_block(&next_block).unwrap();
}

#[test]
fn test_deploy_with_public_fees() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program_id = ProgramID::<CurrentNetwork>::from_str("dummy_program.aleo").unwrap();
    let program = Program::<CurrentNetwork>::from_str(&format!(
        "
program {program_id};
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as {program_id}/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    ))
    .unwrap();

    // Deploy.
    let transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&transaction, None, rng).unwrap();

    // Construct the next block.
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block).unwrap();
    assert_eq!(ledger.latest_height(), 1);
    assert_eq!(ledger.latest_hash(), block.hash());

    assert_eq!(program, ledger.get_program(program_id).unwrap())
}

#[test]
fn test_bond_and_unbond_validator() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Sample new account for the new committee member.
    let new_member_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let new_member_address = Address::try_from(&new_member_private_key).unwrap();
    let new_member_withdrawal_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let new_member_withdrawal_address = Address::try_from(&new_member_withdrawal_private_key).unwrap();

    // Fund the new committee member and their withdrawal address.
    let inputs = [
        Value::from_str(&format!("{new_member_address}")).unwrap(),
        Value::from_str("20000000000000u64").unwrap(), // 20 million credits.
    ];
    let transfer_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    let inputs = [
        Value::from_str(&format!("{new_member_withdrawal_address}")).unwrap(),
        Value::from_str("20000000u64").unwrap(), // 20 credits.
    ];
    let transfer_to_withdrawal_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Construct the next block.
    let transfer_block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transfer_transaction, transfer_to_withdrawal_transaction],
            rng,
        )
        .unwrap();

    // Procure mapping-related objects.
    let program_id = ProgramID::<CurrentNetwork>::from_str("credits.aleo").unwrap();
    let metadata_mapping_name = Identifier::from_str("metadata").unwrap();
    let metadata_mapping_key =
        Plaintext::<CurrentNetwork>::from_str("aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc")
            .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&transfer_block, rng).unwrap();

    // Add the deployment block to the ledger.
    ledger.advance_to_next_block(&transfer_block).unwrap();

    // Construct the bond public
    let bond_amount = MIN_VALIDATOR_STAKE;
    let commission = 10u8;
    let inputs = [
        Value::from_str(&format!("{new_member_withdrawal_address}")).unwrap(),
        Value::from_str(&format!("{bond_amount}u64")).unwrap(),
        Value::from_str(&format!("{commission}u8")).unwrap(),
    ];
    let bond_validator_transaction = ledger
        .vm
        .execute(&new_member_private_key, ("credits.aleo", "bond_validator"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Construct the next block.
    let bond_validator_block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![bond_validator_transaction], rng)
        .unwrap();

    // Check that the committee does not include the new member.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(new_member_address));

    // Check that the next block is valid.
    ledger.check_next_block(&bond_validator_block, rng).unwrap();

    // Add the bond public block to the ledger.
    ledger.advance_to_next_block(&bond_validator_block).unwrap();

    // Check that the committee is updated with the new member.
    let committee = ledger.latest_committee().unwrap();
    assert!(committee.is_committee_member(new_member_address));

    // Check that number of validators in the `metadata` mapping in `credits.aleo` is updated.
    let num_validators = match ledger
        .vm()
        .finalize_store()
        .get_value_confirmed(program_id, metadata_mapping_name, &metadata_mapping_key)
        .unwrap()
        .unwrap()
    {
        Value::Plaintext(Plaintext::Literal(Literal::U32(num_validators), _)) => *num_validators as usize,
        _ => panic!("Unexpected value type"),
    };
    assert_eq!(num_validators, committee.num_members());

    // Construct the unbond public
    let unbond_amount = committee.get_stake(new_member_address);
    let inputs = [
        Value::from_str(&format!("{new_member_address}")).unwrap(),
        Value::from_str(&format!("{unbond_amount}u64")).unwrap(),
    ];
    let unbond_public_transaction = ledger
        .vm
        .execute(
            &new_member_withdrawal_private_key,
            ("credits.aleo", "unbond_public"),
            inputs.iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Construct the next block.
    let unbond_public_block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![unbond_public_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&unbond_public_block, rng).unwrap();

    // Add the bond public block to the ledger.
    ledger.advance_to_next_block(&unbond_public_block).unwrap();

    // Check that the committee does not include the new member.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(new_member_address));

    // Check that number of validators in the `metadata` mapping in `credits.aleo` is updated.
    let num_validators = match ledger
        .vm()
        .finalize_store()
        .get_value_confirmed(program_id, metadata_mapping_name, &metadata_mapping_key)
        .unwrap()
        .unwrap()
    {
        Value::Plaintext(Plaintext::Literal(Literal::U32(num_validators), _)) => *num_validators as usize,
        _ => panic!("Unexpected value type"),
    };
    assert_eq!(num_validators, committee.num_members());
}

#[test]
fn test_aborted_transaction_indexing() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Sample a recipient account.
    let recipient_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let recipient_address = Address::try_from(&recipient_private_key).unwrap();

    // Sample another recipient account.
    let recipient_private_key_2 = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let recipient_address_2 = Address::try_from(&recipient_private_key_2).unwrap();

    // Fund a new address.
    let inputs = [Value::from_str(&format!("{recipient_address}")).unwrap(), Value::from_str("185000u64").unwrap()];
    let transfer_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Construct the next block.
    let transfer_block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transfer_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&transfer_block, rng).unwrap();

    // Add the deployment block to the ledger.
    ledger.advance_to_next_block(&transfer_block).unwrap();

    // Send a transaction that will be aborted due to insufficient fee.
    let inputs = [Value::from_str(&format!("{recipient_address_2}")).unwrap(), Value::from_str("1u64").unwrap()];
    let transfer_transaction = ledger
        .vm
        .execute(&recipient_private_key_2, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    let aborted_transaction_id = transfer_transaction.id();

    // Create another arbitrary transaction.
    let inputs = [Value::from_str(&format!("{recipient_address_2}")).unwrap(), Value::from_str("1u64").unwrap()];
    let transfer_transaction_2 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transfer_transaction, transfer_transaction_2],
            rng,
        )
        .unwrap();

    // Check that the block contains the aborted transaction.
    assert_eq!(block.aborted_transaction_ids(), &[aborted_transaction_id]);

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the deployment block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();
}

#[test]
fn test_aborted_solution_ids() -> Result<()> {
    let rng = &mut TestRng::default();
    let mut builder = TestChainBuilder::<CurrentNetwork>::new(rng)?;
    let ledger = builder.instantiate_ledger();
    let private_key = builder.validator_key(0);
    let address = builder.validator_address(0);

    // Retrieve the puzzle parameters.
    let puzzle = ledger.puzzle();
    let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
    let minimum_proof_target = ledger.latest_proof_target();

    // Create a solution that is less than the minimum proof target.
    let mut invalid_solution = puzzle.prove(latest_epoch_hash, address, rng.random(), None).unwrap();
    while puzzle.get_proof_target(&invalid_solution).unwrap() >= minimum_proof_target {
        invalid_solution = puzzle.prove(latest_epoch_hash, address, rng.random(), None).unwrap();
    }

    // Create a valid transaction for the block.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("10u64").unwrap()];
    let transfer_transaction =
        ledger.vm.execute(private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng).unwrap();

    let block = builder.generate_block_with_opts(
        GenerateBlockOptions {
            solutions: vec![invalid_solution],
            transactions: vec![transfer_transaction],
            ..Default::default()
        },
        rng,
    )?;

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).with_context(|| "Failed to check next block")?;

    // Add the deployment block to the ledger.
    ledger.advance_to_next_block(&block).with_context(|| "Failed to advance to next block")?;

    // Enforce that the block solution was aborted properly.
    assert!(block.solutions().is_empty());
    assert_eq!(block.aborted_solution_ids(), &vec![invalid_solution.id()]);

    Ok(())
}

#[test]
fn test_execute_duplicate_input_ids() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, address, .. } =
        crate::test_helpers::sample_test_env(rng);

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    let record_execution = records[0].clone();
    let record_deployment = records[1].clone();

    // Prepare a transfer that spends a record.
    let inputs = [
        Value::Record(record_execution.clone()),
        Value::from_str(&format!("{address}")).unwrap(),
        Value::from_str("100u64").unwrap(),
    ];

    let num_duplicate_deployments = 3;
    let mut executions = Vec::with_capacity(num_duplicate_deployments + 1);
    let mut execution_ids = Vec::with_capacity(num_duplicate_deployments + 1);
    let mut execution_cache_keys = Vec::with_capacity(num_duplicate_deployments + 1);
    let mut deployments = Vec::with_capacity(num_duplicate_deployments);
    let mut deployment_ids = Vec::with_capacity(num_duplicate_deployments);
    let mut deployment_cache_keys = Vec::with_capacity(num_duplicate_deployments);

    // Create Executions and Deployments, spending the same record.
    for i in 0..num_duplicate_deployments {
        // Execute.
        let execution = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_private"), inputs.clone().iter(), None, 0, None, rng)
            .unwrap();
        execution_ids.push(execution.id());
        execution_cache_keys.push(create_cache_key(ledger.vm(), &execution).unwrap());
        executions.push(execution);
        // Deploy.
        let program_id = ProgramID::<CurrentNetwork>::from_str(&format!("dummy_program_{i}.aleo")).unwrap();
        let program = Program::<CurrentNetwork>::from_str(&format!(
            "
program {program_id};
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as {program_id}/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
        ))
        .unwrap();
        let deployment =
            ledger.vm.deploy(&private_key, &program, Some(record_deployment.clone()), 0, None, rng).unwrap();
        deployment_ids.push(deployment.id());
        deployment_cache_keys.push(create_cache_key(ledger.vm(), &deployment).unwrap());
        deployments.push(deployment);
    }

    // Create one more execution which spends the record as a fee.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("100u64").unwrap()];
    let execution = ledger
        .vm
        .execute(
            &private_key,
            ("credits.aleo", "transfer_public"),
            inputs.clone().iter(),
            Some(record_execution.clone()),
            0,
            None,
            rng,
        )
        .unwrap();
    execution_ids.push(execution.id());
    execution_cache_keys.push(create_cache_key(ledger.vm(), &execution).unwrap());
    executions.push(execution);

    // Select a transaction to mutate by a malicious validator.
    let transaction_to_mutate = executions.last().unwrap().clone();

    // Create a mutated execution which adds one transition, resulting in a different transaction id.
    // This simulates a malicious validator re-using execution content.
    let execution_to_mutate = transaction_to_mutate.execution().unwrap();
    // Sample a transition.
    let sample = snarkvm_ledger_test_helpers::sample_transition(rng);
    // Extend the transitions.
    let mutated_transitions = std::iter::once(sample).chain(execution_to_mutate.transitions().cloned());
    // Create a mutated execution.
    let mutated_execution = Execution::from(
        mutated_transitions,
        execution_to_mutate.global_state_root(),
        execution_to_mutate.proof().cloned(),
    )
    .unwrap();
    // Create a new fee for the execution.
    let fee_authorization = ledger
        .vm
        .authorize_fee_public(
            &private_key,
            *executions.last().unwrap().fee_amount().unwrap(),
            0,
            mutated_execution.to_execution_id().unwrap(),
            rng,
        )
        .unwrap();
    let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();
    // Create a mutated transaction.
    let mutated_transaction = Transaction::from_execution(mutated_execution, Some(fee)).unwrap();
    execution_ids.push(mutated_transaction.id());
    execution_cache_keys.push(create_cache_key(ledger.vm(), &mutated_transaction).unwrap());
    executions.push(mutated_transaction);

    // Create a mutated execution which just takes the fee transition, resulting in a different transaction id.
    // This simulates a malicious validator transforming a transaction to a fee transaction.
    let mutated_transaction = Transaction::from_fee(transaction_to_mutate.fee_transition().unwrap()).unwrap();
    execution_ids.push(mutated_transaction.id());
    execution_cache_keys.push(create_cache_key(ledger.vm(), &mutated_transaction).unwrap());
    executions.push(mutated_transaction);

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![
                executions.pop().unwrap(),
                executions.pop().unwrap(),
                executions.pop().unwrap(),
                executions.pop().unwrap(),
                executions.pop().unwrap(),
                deployments.pop().unwrap(),
                deployments.pop().unwrap(),
            ],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&execution_ids[2], &deployment_ids[2]]);
    assert_eq!(block.aborted_transaction_ids(), &vec![
        execution_ids[5],
        execution_ids[4],
        execution_ids[3],
        execution_ids[1],
        deployment_ids[1]
    ]);

    // Ensure that verification was not run on aborted deployments.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();

    assert!(partially_verified_transaction.contains(&execution_cache_keys[2]));
    assert!(partially_verified_transaction.contains(&deployment_cache_keys[2]));
    assert!(!partially_verified_transaction.contains(&execution_cache_keys[1]));
    assert!(!partially_verified_transaction.contains(&deployment_cache_keys[1]));
    assert!(!partially_verified_transaction.contains(&execution_cache_keys[3]));
    assert!(!partially_verified_transaction.contains(&execution_cache_keys[4])); // Verification was run, but the execution was invalid.
    assert!(!partially_verified_transaction.contains(&execution_cache_keys[5]));

    // Prepare a transfer that will succeed for the subsequent block.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let transfer = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let transfer_id = transfer.id();
    let transfer_cache_key = create_cache_key(ledger.vm(), &transfer).unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![executions.pop().unwrap(), deployments.pop().unwrap(), transfer],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transfer_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![execution_ids[0], deployment_ids[0]]);

    // Ensure that verification was not run on transactions aborted in a previous block.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transfer_cache_key));
    assert!(!partially_verified_transaction.contains(&execution_cache_keys[0]));
    assert!(!partially_verified_transaction.contains(&deployment_cache_keys[0]));
}

#[test]
fn test_execute_duplicate_output_ids() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, address, .. } =
        crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program = Program::<CurrentNetwork>::from_str(
        "
program dummy_program.aleo;

record dummy_program:
    owner as address.private;
    rand_var as u64.private;

function create_duplicate_record:
    input r0 as u64.private;
    cast self.caller 1u64 into r1 as dummy_program.record;
    output r1 as dummy_program.record;",
    )
    .unwrap();

    // Deploy.
    let deployment_transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&deployment_transaction, None, rng).unwrap();

    // Construct the next block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();
    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    let record_1 = records[0].clone();

    // Create an execution with different transition ids, but with a fixed output record (output ID).
    let mut create_execution_with_duplicate_output_id = |x: u64| -> Transaction<CurrentNetwork> {
        // Use a fixed seed RNG.
        let fixed_rng = &mut TestRng::from_seed(1);

        // Create a transaction with a fixed rng.
        let inputs = [Value::from_str(&format!("{x}u64")).unwrap()];
        let transaction = ledger
            .vm
            .execute(
                &private_key,
                ("dummy_program.aleo", "create_duplicate_record"),
                inputs.into_iter(),
                None,
                0,
                None,
                fixed_rng,
            )
            .unwrap();
        // Extract the execution.
        let execution = transaction.execution().unwrap().clone();

        // Create a new fee for the execution.
        let fee_authorization = ledger
            .vm
            .authorize_fee_public(
                &private_key,
                *transaction.fee_amount().unwrap(),
                0,
                execution.to_execution_id().unwrap(),
                rng,
            )
            .unwrap();
        let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();

        Transaction::from_execution(execution, Some(fee)).unwrap()
    };

    // Create an deployment with different transition ids, but with a fixed output record (output ID).
    let create_deployment_with_duplicate_output_id = |x: u64| -> Transaction<CurrentNetwork> {
        // Use a fixed seed RNG.
        let fixed_rng = &mut TestRng::from_seed(1);

        // Deploy a test program to the ledger.
        let program = Program::<CurrentNetwork>::from_str(&format!(
            "
program dummy_program_{x}.aleo;

record dummy_program:
    owner as address.private;
    rand_var as u64.private;

function create_duplicate_record:
    input r0 as u64.private;
    cast self.caller 1u64 into r1 as dummy_program.record;
    output r1 as dummy_program.record;"
        ))
        .unwrap();

        // Create a transaction with a fixed rng.
        let transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, fixed_rng).unwrap();

        // Extract the deployment and owner.
        let deployment = transaction.deployment().unwrap().clone();
        let owner = *transaction.owner().unwrap();

        // Create a new fee for the execution.
        let fee_authorization = ledger
            .vm
            .authorize_fee_private(
                &private_key,
                record_1.clone(),
                *transaction.fee_amount().unwrap(),
                0,
                deployment.to_deployment_id().unwrap(),
                fixed_rng,
            )
            .unwrap();
        let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, fixed_rng).unwrap();

        Transaction::from_deployment(owner, deployment, fee).unwrap()
    };

    // Create the first transfer.
    let transfer_1 = create_execution_with_duplicate_output_id(1);
    let transfer_1_id = transfer_1.id();
    let transfer_1_cache_key = create_cache_key(ledger.vm(), &transfer_1).unwrap();

    // Create a second transfer with the same output id.
    let transfer_2 = create_execution_with_duplicate_output_id(2);
    let transfer_2_id = transfer_2.id();
    let transfer_2_cache_key = create_cache_key(ledger.vm(), &transfer_2).unwrap();

    // Create a third transfer with the same output id.
    let transfer_3 = create_execution_with_duplicate_output_id(3);
    let transfer_3_id = transfer_3.id();
    let transfer_3_cache_key = create_cache_key(ledger.vm(), &transfer_3).unwrap();

    // Ensure that each transaction has a duplicate output id.
    let tx_1_output_id = transfer_1.output_ids().next().unwrap();
    let tx_2_output_id = transfer_2.output_ids().next().unwrap();
    let tx_3_output_id = transfer_3.output_ids().next().unwrap();
    assert_eq!(tx_1_output_id, tx_2_output_id);
    assert_eq!(tx_1_output_id, tx_3_output_id);

    // Create the first deployment.
    let deployment_1 = create_deployment_with_duplicate_output_id(1);
    let deployment_1_id = deployment_1.id();
    let deployment_1_cache_key = create_cache_key(ledger.vm(), &deployment_1).unwrap();

    // Create a second deployment with the same output id.
    let deployment_2 = create_deployment_with_duplicate_output_id(2);
    let deployment_2_id = deployment_2.id();
    let deployment_2_cache_key = create_cache_key(ledger.vm(), &deployment_2).unwrap();

    // Create a third deployment with the same output id.
    let deployment_3 = create_deployment_with_duplicate_output_id(3);
    let deployment_3_id = deployment_3.id();
    let deployment_3_cache_key = create_cache_key(ledger.vm(), &deployment_3).unwrap();

    // Ensure that each transaction has a duplicate output id.
    let deployment_1_output_id = deployment_1.output_ids().next().unwrap();
    let deployment_2_output_id = deployment_2.output_ids().next().unwrap();
    let deployment_3_output_id = deployment_3.output_ids().next().unwrap();
    assert_eq!(deployment_1_output_id, deployment_2_output_id);
    assert_eq!(deployment_1_output_id, deployment_3_output_id);

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transfer_1, transfer_2, deployment_1, deployment_2],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 2);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transfer_1_id, &deployment_1_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transfer_2_id, deployment_2_id]);

    // Ensure that verification was not run on aborted deployments.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transfer_1_cache_key));
    assert!(partially_verified_transaction.contains(&deployment_1_cache_key));
    assert!(!partially_verified_transaction.contains(&transfer_2_cache_key));
    assert!(!partially_verified_transaction.contains(&deployment_2_cache_key));

    // Prepare a transfer that will succeed for the subsequent block.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let transfer_4 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let transfer_4_id = transfer_4.id();
    let transfer_4_cache_key = create_cache_key(ledger.vm(), &transfer_4).unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transfer_3, transfer_4, deployment_3],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transfer_4_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transfer_3_id, deployment_3_id]);

    // Ensure that verification was not run on transactions aborted in a previous block.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transfer_4_cache_key));
    assert!(!partially_verified_transaction.contains(&transfer_3_cache_key));
    assert!(!partially_verified_transaction.contains(&deployment_3_cache_key));
}

// Tests that `try_get_*' returns `None` if the tranmissions does not exist.
#[test]
fn test_get_transaction() {
    let rng = &mut TestRng::default();
    let ledger = crate::test_helpers::sample_test_env(rng).ledger;

    // Generate a random transaction ID.
    let transaction = crate::test_helpers::sample_deployment_transaction(1, 0, false, true, rng);
    let transaction_id = transaction.id();

    assert_eq!(ledger.try_get_transaction(&transaction_id).unwrap(), None);
    assert_eq!(ledger.try_get_confirmed_transaction(&transaction_id).unwrap(), None);
    assert_eq!(ledger.try_get_unconfirmed_transaction(&transaction_id).unwrap(), None);

    assert!(ledger.get_transaction(transaction_id).is_err());
    assert!(ledger.get_confirmed_transaction(transaction_id).is_err());
    assert!(ledger.get_unconfirmed_transaction(&transaction_id).is_err());

    // Insert the transaction as unconfirmed into the ledger.
    ledger.vm().transaction_store().insert(&transaction).unwrap();

    assert!(ledger.try_get_transaction(&transaction_id).unwrap().is_some());
    assert_eq!(ledger.try_get_confirmed_transaction(&transaction_id).unwrap(), None);
    assert!(ledger.try_get_unconfirmed_transaction(&transaction_id).unwrap().is_some());

    assert!(ledger.get_transaction(transaction_id).is_ok());
    assert!(ledger.get_confirmed_transaction(transaction_id).is_err());
    assert!(ledger.get_unconfirmed_transaction(&transaction_id).is_ok());
}

#[test]
fn test_execute_duplicate_transition_ids() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, address, .. } = crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program = Program::<CurrentNetwork>::from_str(
        "
program dummy_program.aleo;

function empty_function:
    ",
    )
    .unwrap();

    // Deploy.
    let deployment_transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&deployment_transaction, None, rng).unwrap();

    // Construct the next block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();
    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Create a transaction with different transaction IDs, but with a fixed transition ID.
    // NOTE: there's no use creating deployments with duplicate (fee) transition ids,
    //       as this is only possible if they have duplicate programs, duplicate transaction_ids,
    //       which will not abort but fail on check_next_block.
    let mut create_transaction_with_duplicate_transition_id = || -> Transaction<CurrentNetwork> {
        // Use a fixed seed RNG.
        let fixed_rng = &mut TestRng::from_seed(1);

        // Create a transaction with a fixed rng.
        let inputs: [Value<_>; 0] = [];
        let transaction = ledger
            .vm
            .execute(
                &private_key,
                ("dummy_program.aleo", "empty_function"),
                inputs.into_iter(),
                None,
                0,
                None,
                fixed_rng,
            )
            .unwrap();
        // Extract the execution.
        let execution = transaction.execution().unwrap().clone();

        // Create a new fee for the execution.
        let fee_authorization = ledger
            .vm
            .authorize_fee_public(
                &private_key,
                *transaction.fee_amount().unwrap(),
                0,
                execution.to_execution_id().unwrap(),
                rng,
            )
            .unwrap();
        let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();

        Transaction::from_execution(execution, Some(fee)).unwrap()
    };

    // Create the first transaction.
    let transaction_1 = create_transaction_with_duplicate_transition_id();
    let transaction_1_id = transaction_1.id();
    let transaction_1_cache_key = create_cache_key(ledger.vm(), &transaction_1).unwrap();

    // Create a second transaction with the same transition id.
    let transaction_2 = create_transaction_with_duplicate_transition_id();
    let transaction_2_id = transaction_2.id();
    let transaction_2_cache_key = create_cache_key(ledger.vm(), &transaction_2).unwrap();

    // Create a third transaction with the same transition_id
    let transaction_3 = create_transaction_with_duplicate_transition_id();
    let transaction_3_id = transaction_3.id();
    let transaction_3_cache_key = create_cache_key(ledger.vm(), &transaction_3).unwrap();

    // Ensure that each transaction has a duplicate transition id.
    let tx_1_transition_id = transaction_1.transition_ids().next().unwrap();
    let tx_2_transition_id = transaction_2.transition_ids().next().unwrap();
    let tx_3_transition_id = transaction_3.transition_ids().next().unwrap();
    assert_eq!(tx_1_transition_id, tx_2_transition_id);
    assert_eq!(tx_1_transition_id, tx_3_transition_id);

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction_1, transaction_2], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transaction_1_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transaction_2_id]);

    // Ensure that verification was not run on aborted transactions.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transaction_1_cache_key));
    assert!(!partially_verified_transaction.contains(&transaction_2_cache_key));

    // Prepare a transfer that will succeed for the subsequent block.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let transfer_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let transfer_transaction_id = transfer_transaction.id();
    let transfer_cache_key = create_cache_key(ledger.vm(), &transfer_transaction).unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transaction_3, transfer_transaction],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transfer_transaction_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transaction_3_id]);

    // Ensure that verification was not run on transactions aborted in a previous block.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transfer_cache_key));
    assert!(!partially_verified_transaction.contains(&transaction_3_cache_key));
}

#[test]
fn test_execute_duplicate_transition_public_keys() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, address, .. } = crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program = Program::<CurrentNetwork>::from_str(
        "
program dummy_program.aleo;

function empty_function:

function simple_output:
    output 1u64 as u64.public;
    ",
    )
    .unwrap();

    // Deploy.
    let deployment_transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&deployment_transaction, None, rng).unwrap();

    // Construct the next block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_transaction], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();
    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Create a transaction with different transaction ids, but with a duplicate TPK.
    // NOTE: there's no use creating deployments with duplicate (fee) TPKs,
    //       as this is only possible if they have duplicate programs, duplicate transaction_ids,
    //       which will not abort but fail on check_next_block.
    let mut create_transaction_with_duplicate_tpk = |function: &str| -> Transaction<CurrentNetwork> {
        // Use a fixed seed RNG.
        let fixed_rng = &mut TestRng::from_seed(1);

        // Create a transaction with a fixed rng.
        let inputs: [Value<_>; 0] = [];
        let transaction = ledger
            .vm
            .execute(&private_key, ("dummy_program.aleo", function), inputs.into_iter(), None, 0, None, fixed_rng)
            .unwrap();
        // Extract the execution.
        let execution = transaction.execution().unwrap().clone();

        // Create a new fee for the execution.
        let fee_authorization = ledger
            .vm
            .authorize_fee_public(
                &private_key,
                *transaction.fee_amount().unwrap(),
                0,
                execution.to_execution_id().unwrap(),
                rng,
            )
            .unwrap();
        let fee = ledger.vm.execute_fee_authorization(fee_authorization, None, rng).unwrap();

        Transaction::from_execution(execution, Some(fee)).unwrap()
    };

    // Create the first transaction.
    let transaction_1 = create_transaction_with_duplicate_tpk("empty_function");
    let transaction_1_id = transaction_1.id();
    let transaction_1_cache_key = create_cache_key(ledger.vm(), &transaction_1).unwrap();

    // Create a second transaction with the same tpk and tcm.
    let transaction_2 = create_transaction_with_duplicate_tpk("simple_output");
    let transaction_2_id = transaction_2.id();
    let transaction_2_cache_key = create_cache_key(ledger.vm(), &transaction_2).unwrap();

    // Create a third transaction with the same tpk and tcm.
    let transaction_3 = create_transaction_with_duplicate_tpk("simple_output");
    let transaction_3_id = transaction_3.id();
    let transaction_3_cache_key = create_cache_key(ledger.vm(), &transaction_3).unwrap();

    // Ensure that each transaction has a duplicate tcm and tpk.
    let tx_1_tpk = transaction_1.transitions().next().unwrap().tpk();
    let tx_2_tpk = transaction_2.transitions().next().unwrap().tpk();
    let tx_3_tpk = transaction_3.transitions().next().unwrap().tpk();
    assert_eq!(tx_1_tpk, tx_2_tpk);
    assert_eq!(tx_1_tpk, tx_3_tpk);

    let tx_1_tcm = transaction_1.transitions().next().unwrap().tcm();
    let tx_2_tcm = transaction_2.transitions().next().unwrap().tcm();
    let tx_3_tcm = transaction_3.transitions().next().unwrap().tcm();
    assert_eq!(tx_1_tcm, tx_2_tcm);
    assert_eq!(tx_1_tcm, tx_3_tcm);

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction_1, transaction_2], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transaction_1_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transaction_2_id]);

    // Ensure that verification was not run on aborted transactions.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transaction_1_cache_key));
    assert!(!partially_verified_transaction.contains(&transaction_2_cache_key));

    // Prepare a transfer that will succeed for the subsequent block.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let transfer_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let transfer_transaction_id = transfer_transaction.id();
    let transfer_transaction_cache_key = create_cache_key(ledger.vm(), &transfer_transaction).unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![transaction_3, transfer_transaction],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().transaction_ids().collect::<Vec<_>>(), vec![&transfer_transaction_id]);
    assert_eq!(block.aborted_transaction_ids(), &vec![transaction_3_id]);

    // Ensure that verification was not run on transactions aborted in a previous block.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&transfer_transaction_cache_key));
    assert!(!partially_verified_transaction.contains(&transaction_3_cache_key));
}

#[test]
fn test_abort_multiple_deployments_with_same_payer() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Create two distinct programs
    let program_1 = Program::<CurrentNetwork>::from_str(
        "
program dummy_program_1.aleo;

function empty_function:
    ",
    )
    .unwrap();

    let program_2 = Program::<CurrentNetwork>::from_str(
        "
program dummy_program_2.aleo;

function empty_function:
    ",
    )
    .unwrap();

    // Create a deployment transaction for the first program with the same public payer.
    let deployment_1 = ledger.vm.deploy(&private_key, &program_1, None, 0, None, rng).unwrap();
    let deployment_1_id = deployment_1.id();
    let deployment_1_cache_key = create_cache_key(ledger.vm(), &deployment_1).unwrap();

    // Create a deployment transaction for the second program with the same public payer.
    let deployment_2 = ledger.vm.deploy(&private_key, &program_2, None, 0, None, rng).unwrap();
    let deployment_2_id = deployment_2.id();
    let deployment_2_cache_key = create_cache_key(ledger.vm(), &deployment_2).unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_1, deployment_2], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.aborted_transaction_ids(), &vec![deployment_2_id]);

    // Enforce that the first program was deployed and the second was aborted.
    assert_eq!(ledger.get_program(*program_1.id()).unwrap(), program_1);
    assert!(ledger.vm.transaction_store().contains_transaction_id(&deployment_1_id).unwrap());
    assert!(ledger.vm.block_store().contains_rejected_or_aborted_transaction_id(&deployment_2_id).unwrap());

    // Ensure that verification was not run on aborted transactions.
    let partially_verified_transaction = ledger.vm().partially_verified_transactions().read().clone();
    assert!(partially_verified_transaction.contains(&deployment_1_cache_key));
    assert!(!partially_verified_transaction.contains(&deployment_2_cache_key));
}

#[test]
fn test_abort_fee_transaction() {
    let rng = &mut TestRng::default();
    let mut chain_builder = TestChainBuilder::new(rng).unwrap();

    let private_key = chain_builder.private_keys()[0];
    let address = Address::try_from(&private_key).unwrap();

    // Construct the ledger.
    let ledger =
        Ledger::<CurrentNetwork, LedgerType>::load(chain_builder.genesis_block().clone(), StorageMode::new_test(None))
            .unwrap();

    // Construct valid transaction for the ledger.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.clone().into_iter(), None, 0, None, rng)
        .unwrap();
    let transaction_id = transaction.id();

    // Convert a fee transaction.
    let transaction_to_convert_to_fee = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let fee_transaction = Transaction::from_fee(transaction_to_convert_to_fee.fee_transition().unwrap()).unwrap();
    let fee_transaction_id = fee_transaction.id();

    // Create a block using a fee transaction.
    let block = chain_builder
        .generate_block_with_opts(
            GenerateBlockOptions { transactions: vec![fee_transaction, transaction], ..Default::default() },
            rng,
        )
        .unwrap();

    // Check that the block aborts the invalid transaction.
    assert_eq!(block.aborted_transaction_ids(), &vec![fee_transaction_id]);
    assert_eq!(block.transaction_ids().collect::<Vec<_>>(), vec![&transaction_id]);

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();
}

#[test]
fn test_abort_invalid_transaction() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, address, .. } = crate::test_helpers::sample_test_env(rng);

    // Initialize a new VM.
    let vm = sample_vm();

    // Construct a custom genesis block.
    let custom_genesis = vm.genesis_beacon(&private_key, rng).unwrap();

    // Update the VM.
    vm.add_next_block(&custom_genesis).unwrap();

    // Generate a transaction that will be invalid on another network.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000u64").unwrap()];
    let invalid_transaction = vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.clone().into_iter(), None, 0, None, rng)
        .unwrap();
    let invalid_transaction_id = invalid_transaction.id();

    // Check that the ledger deems this transaction invalid.
    assert!(ledger.check_transaction_basic(&invalid_transaction, None, rng).is_err());

    // Construct valid transactions for the ledger.
    let valid_transaction_1 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.clone().into_iter(), None, 0, None, rng)
        .unwrap();
    let valid_transaction_2 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let valid_transaction_id_1 = valid_transaction_1.id();
    let valid_transaction_id_2 = valid_transaction_2.id();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![],
            vec![valid_transaction_1, invalid_transaction, valid_transaction_2],
            rng,
        )
        .unwrap();

    // Check that the block aborts the invalid transaction.
    assert_eq!(block.aborted_transaction_ids(), &vec![invalid_transaction_id]);
    assert_eq!(block.transaction_ids().collect::<Vec<_>>(), vec![&valid_transaction_id_1, &valid_transaction_id_2]);

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();
}

#[test]
fn test_deployment_duplicate_program_id() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, .. } = crate::test_helpers::sample_test_env(rng);

    // A helper function to find records.
    let find_records = || {
        let microcredits = Identifier::from_str("microcredits").unwrap();
        ledger
            .find_records(&view_key, RecordsFilter::SlowUnspent(private_key))
            .unwrap()
            .filter(|(_, record)| match record.data().get(&microcredits) {
                Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), _))) => !amount.is_zero(),
                _ => false,
            })
            .collect::<IndexMap<_, _>>()
    };

    // Fetch the unspent records.
    let records = find_records();
    let record_1 = records[0].clone();
    let record_2 = records[1].clone();

    // Create two programs with a duplicate program ID but different mappings
    let program_1 = Program::<CurrentNetwork>::from_str(
        r"
program dummy_program.aleo;
mapping abcd1:
    key as address.public;
    value as u64.public;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy_program.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    let program_2 = Program::<CurrentNetwork>::from_str(
        r"
program dummy_program.aleo;
mapping abcd2:
    key as address.public;
    value as u64.public;
function foo2:
    input r0 as u8.private;
    async foo2 r0 into r1;
    output r1 as dummy_program.aleo/foo2.future;
finalize foo2:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    // Create a deployment transaction for the first program.
    let deployment_1 = ledger.vm.deploy(&private_key, &program_1, Some(record_1), 0, None, rng).unwrap();
    let deployment_1_id = deployment_1.id();
    assert!(ledger.check_transaction_basic(&deployment_1, None, rng).is_ok());

    // Create a deployment transaction for the second program.
    let deployment_2 = ledger.vm.deploy(&private_key, &program_2, Some(record_2), 0, None, rng).unwrap();
    let deployment_2_id = deployment_2.id();
    assert!(ledger.check_transaction_basic(&deployment_2, None, rng).is_ok());

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_1, deployment_2], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Enforce that the block transactions were correct.
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);

    // Enforce that the first program was deployed and the second was rejected.
    assert_eq!(ledger.get_program(*program_1.id()).unwrap(), program_1);
    assert!(ledger.vm.transaction_store().contains_transaction_id(&deployment_1_id).unwrap());
    assert!(ledger.vm.block_store().contains_rejected_or_aborted_transaction_id(&deployment_2_id).unwrap());
}

#[test]
fn test_split_candidate_solutions() {
    let rng = &mut TestRng::default();

    let max_solutions = CurrentNetwork::MAX_SOLUTIONS;

    const ITERATIONS: usize = 1_000;

    for _ in 0..ITERATIONS {
        let num_candidates = rng.random_range(0..max_solutions * 2);
        let candidate_solutions: Vec<u8> = rng.sample_iter(StandardUniform).take(num_candidates).collect();

        let (_accepted, _aborted) =
            split_candidate_solutions(candidate_solutions, max_solutions, |candidate| *candidate % 2 == 0);
    }
}

#[test]
fn test_max_committee_limit_with_bonds() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();

    // Construct the validators, one less than the maximum committee size.
    let max_committee_size = consensus_config_value!(CurrentNetwork, MAX_CERTIFICATES, 0).unwrap();
    let validators = (0..max_committee_size - 1)
        .map(|_| {
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let amount = MIN_VALIDATOR_STAKE;
            let is_open = true;
            (private_key, (amount, is_open))
        })
        .collect::<IndexMap<_, _>>();

    // Track the allocated amount.
    let mut allocated_amount = 0;

    // Construct the committee.
    let mut committee_map = IndexMap::new();
    for (private_key, (amount, _)) in &validators {
        let address = Address::try_from(private_key).unwrap();
        committee_map.insert(address, (*amount, true, 0));
        allocated_amount += *amount;
    }

    // Initialize two new validators.
    let first_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let first_address = Address::try_from(&first_private_key).unwrap();
    let first_withdrawal_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let first_withdrawal_address = Address::try_from(&first_withdrawal_private_key).unwrap();
    let second_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let second_address = Address::try_from(&second_private_key).unwrap();
    let second_withdrawal_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let second_withdrawal_address = Address::try_from(&second_withdrawal_private_key).unwrap();

    // Construct the public balances, allocating the remaining supply to the first validator and two new validators.
    // The remaining validators will have a balance of 0.
    let mut public_balances = IndexMap::new();
    for (private_key, _) in &validators {
        public_balances.insert(Address::try_from(private_key).unwrap(), 0);
    }
    let remaining_supply = <CurrentNetwork as Network>::STARTING_SUPPLY - allocated_amount;
    let amount = remaining_supply / 5;
    public_balances.insert(Address::try_from(validators.keys().next().unwrap()).unwrap(), amount);
    public_balances.insert(first_address, amount);
    public_balances.insert(first_withdrawal_address, amount);
    public_balances.insert(second_address, amount);
    public_balances.insert(second_withdrawal_address, remaining_supply - 4 * amount);

    // Construct the bonded balances.
    let bonded_balances = validators
        .iter()
        .map(|(private_key, (amount, _))| {
            let address = Address::try_from(private_key).unwrap();
            (address, (address, address, *amount))
        })
        .collect();

    // Construct the genesis block, which should pass.
    let genesis_block = vm
        .genesis_quorum(
            validators.keys().next().unwrap(),
            Committee::new_genesis(committee_map).unwrap(),
            public_balances,
            bonded_balances,
            rng,
        )
        .unwrap();

    // Initialize a Ledger from the genesis block.
    let ledger = Ledger::<CurrentNetwork, LedgerType>::load(genesis_block, StorageMode::new_test(None)).unwrap();

    // Bond the first validator.
    let bond_first_transaction = ledger
        .vm()
        .execute(
            &first_private_key,
            ("credits.aleo", "bond_validator"),
            [
                Value::<CurrentNetwork>::from_str(&first_withdrawal_address.to_string()).unwrap(),
                Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),
                Value::<CurrentNetwork>::from_str("10u8").unwrap(),
            ]
            .iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            validators.keys().next().unwrap(),
            vec![],
            vec![],
            vec![bond_first_transaction],
            rng,
        )
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Check that the first validator is not in the committee.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(first_address));

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Check that the first validator was added to the committee.
    let committee = ledger.latest_committee().unwrap();
    assert!(committee.is_committee_member(first_address));

    // Attempt to bond the second validator.
    let bond_second_transaction = ledger
        .vm()
        .execute(
            &second_private_key,
            ("credits.aleo", "bond_validator"),
            [
                Value::<CurrentNetwork>::from_str(&second_withdrawal_address.to_string()).unwrap(),
                Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),
                Value::<CurrentNetwork>::from_str("10u8").unwrap(),
            ]
            .iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            validators.keys().next().unwrap(),
            vec![],
            vec![],
            vec![bond_second_transaction],
            rng,
        )
        .unwrap();

    // Ensure that the `bond_second_transaction` is rejected.
    assert_eq!(block.transactions().num_rejected(), 1);

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Check that the second validator is not in the committee.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(second_address));

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Check that the second validator was not added to the committee.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(second_address));

    // Check that unbonding a validator first allows the second validator to bond in.

    let unbond_first_validator = ledger
        .vm()
        .execute(
            &first_withdrawal_private_key,
            ("credits.aleo", "unbond_public"),
            [
                Value::<CurrentNetwork>::from_str(&first_address.to_string()).unwrap(),
                Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),
            ]
            .iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Attempt to bond the second validator.
    let bond_second_validator = ledger
        .vm()
        .execute(
            &second_private_key,
            ("credits.aleo", "bond_validator"),
            [
                Value::<CurrentNetwork>::from_str(&second_withdrawal_address.to_string()).unwrap(),
                Value::<CurrentNetwork>::from_str(&format!("{MIN_VALIDATOR_STAKE}u64")).unwrap(),
                Value::<CurrentNetwork>::from_str("10u8").unwrap(),
            ]
            .iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(
            validators.keys().next().unwrap(),
            vec![],
            vec![],
            vec![unbond_first_validator, bond_second_validator],
            rng,
        )
        .unwrap();

    // Ensure that no transactions are rejected.
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.transactions().num_accepted(), 2);

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Check that the first validator is in the committee and the second validator is not.
    let committee = ledger.latest_committee().unwrap();
    assert!(!committee.is_committee_member(second_address));
    assert!(committee.is_committee_member(first_address));

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Check that the first validator was removed and the second validator was added to the committee.
    let committee = ledger.latest_committee().unwrap();
    assert!(committee.is_committee_member(second_address));
    assert!(!committee.is_committee_member(first_address));
}

#[test]
fn test_transaction_ordering() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, address, .. } = crate::test_helpers::sample_test_env(rng);

    // Get the public balance of the address.
    let mut public_balance = match ledger.genesis_block.ratifications().iter().next().unwrap() {
        Ratify::Genesis(_, public_balance, _) => *public_balance.get(&address).unwrap(),
        _ => panic!("Expected a genesis ratification"),
    };

    // Sample multiple private keys and addresses.
    let private_key_2 = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let address_2 = Address::try_from(&private_key_2).unwrap();
    let private_key_3 = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let address_3 = Address::try_from(&private_key_3).unwrap();

    // Fund a new address.
    let amount_1 = 100000000u64;
    let inputs =
        [Value::from_str(&format!("{address_2}")).unwrap(), Value::from_str(&format!("{amount_1}u64")).unwrap()];
    let transfer_1 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    let amount_2 = 100000000u64;
    let inputs =
        [Value::from_str(&format!("{address_3}")).unwrap(), Value::from_str(&format!("{amount_2}u64")).unwrap()];
    let transfer_2 = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Update the public balance.
    public_balance -= *transfer_1.fee_amount().unwrap();
    public_balance -= *transfer_2.fee_amount().unwrap();

    // Create a block.
    let block = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transfer_1, transfer_2], rng)
        .unwrap();

    // Check that the next block is valid.
    ledger.check_next_block(&block, rng).unwrap();

    // Add the block to the ledger.
    ledger.advance_to_next_block(&block).unwrap();

    // Create multiple dummy programs.
    let program_1 = Program::<CurrentNetwork>::from_str(
        r"
program dummy_program.aleo;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy_program.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    let program_2 = Program::<CurrentNetwork>::from_str(
        r"
program dummy_program_2.aleo;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy_program_2.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    let program_3 = Program::<CurrentNetwork>::from_str(
        r"
program dummy_program_3.aleo;
function foo:
    input r0 as u8.private;
    async foo r0 into r1;
    output r1 as dummy_program_3.aleo/foo.future;
finalize foo:
    input r0 as u8.public;
    add r0 r0 into r1;",
    )
    .unwrap();

    // Create a transfer transaction.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000000u64").unwrap()];
    let initial_transfer = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();
    let initial_transfer_id = initial_transfer.id();

    // Create a deployment transaction.
    let deployment_transaction = ledger.vm.deploy(&private_key_2, &program_1, None, 0, None, rng).unwrap();

    // Create a deployment transaction.
    let deployment_transaction_2 = ledger.vm.deploy(&private_key_3, &program_2, None, 0, None, rng).unwrap();

    // Create a transfer transaction.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000000u64").unwrap()];
    let transfer_transaction = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Create a rejected transfer transaction.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("1000000000000000u64").unwrap()];
    let rejected_transfer = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
        .unwrap();

    // Create an aborted transfer transaction.
    let inputs = [Value::from_str(&format!("{address}")).unwrap(), Value::from_str("10u64").unwrap()];
    let aborted_transfer = ledger
        .vm
        .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, public_balance - 10, None, rng)
        .unwrap();

    // Create an aborted deployment transaction.
    let aborted_deployment = ledger.vm.deploy(&private_key, &program_3, None, public_balance - 10, None, rng).unwrap();

    const ITERATIONS: usize = 100;
    for _ in 0..ITERATIONS {
        // Create a random order for the transactions.
        let mut transactions = vec![
            deployment_transaction.clone(),
            deployment_transaction_2.clone(),
            transfer_transaction.clone(),
            rejected_transfer.clone(),
        ];
        transactions.shuffle(rng);

        // Get the confirmed transaction IDs.
        let mut confirmed_transaction_ids = transactions.iter().map(Transaction::id).collect::<Vec<_>>();

        // Randomly insert the aborted transactions.
        let mut aborted_transactions = [aborted_transfer.clone(), aborted_deployment.clone()];
        aborted_transactions.shuffle(rng);

        // Randomly insert the aborted transactions.
        let start_position = rng.random_range(0..=transactions.len());
        for (index, element) in aborted_transactions.iter().enumerate() {
            transactions.insert(start_position + index, element.clone());
        }

        // Get the aborted transaction IDs.
        let aborted_transaction_ids = aborted_transactions.iter().map(Transaction::id).collect::<Vec<_>>();

        // Add the initial transfer to the list of transactions.
        transactions.insert(0, initial_transfer.clone());
        confirmed_transaction_ids.insert(0, initial_transfer_id);

        // Create a block.
        let block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], transactions, rng).unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();

        // Enforce that the block transactions were correct.
        assert_eq!(block.transactions().num_accepted(), 4);
        assert_eq!(block.transactions().num_rejected(), 1);

        // Enforce that the ordering of the transactions is correct.
        let block_confirmed_transactions_ids: Vec<_> = block
            .transactions()
            .iter()
            .map(|transaction| transaction.to_unconfirmed_transaction_id().unwrap())
            .collect();
        assert_eq!(block_confirmed_transactions_ids, confirmed_transaction_ids);

        // Enforce that the aborted transactions is correct.
        assert_eq!(block.aborted_transaction_ids(), &aborted_transaction_ids);
    }
}

#[test]
fn test_metadata() {
    let rng = &mut TestRng::default();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Deploy a test program to the ledger.
    let program_id = ProgramID::<CurrentNetwork>::from_str("metadata.aleo").unwrap();
    let program = Program::<CurrentNetwork>::from_str(&format!(
        "
program {program_id};
function is_block:
    input r0 as u32.public;
    async is_block r0 into r1;
    output r1 as {program_id}/is_block.future;

finalize is_block:
    input r0 as u32.public;
    assert.eq r0 block.height;

function is_id:
    input r0 as u16.public;
    async is_id r0 into r1;
    output r1 as {program_id}/is_id.future;

finalize is_id:
    input r0 as u16.public;
    assert.eq r0 network.id;
    ",
    ))
    .unwrap();

    // Deploy.
    let transaction = ledger.vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
    // Verify.
    ledger.vm().check_transaction(&transaction, None, rng).unwrap();

    // Construct the next block.
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block).unwrap();
    assert_eq!(ledger.latest_height(), 1);
    assert_eq!(ledger.latest_hash(), block.hash());
    assert_eq!(program, ledger.get_program(program_id).unwrap());

    // Execute functions `is_block` and `is_id` to assert that the on-chain state is as expected.
    let inputs_block: [Value<CurrentNetwork>; 1] = [Value::from_str("2u32").unwrap()];
    let tx_block =
        ledger.vm.execute(&private_key, (&program_id, "is_block"), inputs_block.iter(), None, 0, None, rng).unwrap();
    let inputs_id: [Value<CurrentNetwork>; 1] = [Value::from(Literal::U16(U16::new(CurrentNetwork::ID)))];
    let tx_id = ledger.vm.execute(&private_key, (&program_id, "is_id"), inputs_id.iter(), None, 0, None, rng).unwrap();

    // Construct the next block.
    let block_2 =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![tx_id, tx_block], rng).unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block_2).unwrap();

    // Execute the program.
    let inputs_block_2: [Value<CurrentNetwork>; 1] = [Value::from_str("3u32").unwrap()];
    let tx_block_2 =
        ledger.vm.execute(&private_key, (&program_id, "is_block"), inputs_block_2.iter(), None, 0, None, rng).unwrap();
    let tx_id_2 =
        ledger.vm.execute(&private_key, (&program_id, "is_id"), inputs_id.iter(), None, 0, None, rng).unwrap();

    // Construct the next block.
    let block_3 = ledger
        .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![tx_block_2, tx_id_2], rng)
        .unwrap();
    // Advance to the next block.
    ledger.advance_to_next_block(&block_3).unwrap();
}

#[test]
fn test_deployment_with_cast_from_field_to_scalar() {
    // Initialize an RNG.
    let rng = &mut TestRng::default();

    const ITERATIONS: usize = 10;

    // Construct a program that casts a field to a scalar.
    let program = Program::<CurrentNetwork>::from_str(
        r"
program test_cast_field_to_scalar.aleo;
function foo:
    input r0 as field.public;
    cast r0 into r1 as scalar;",
    )
    .unwrap();

    // Constructs a program that has a struct with a field that is cast to a scalar.
    let program_2 = Program::<CurrentNetwork>::from_str(
        r"
program test_cast_f_to_s_struct.aleo;

struct message:
    first as scalar;

function foo:
    input r0 as field.public;
    cast r0 into r1 as scalar;
    cast r1 into r2 as message;",
    )
    .unwrap();

    // Constructs a program that has an array of scalars cast from fields.
    let program_3 = Program::<CurrentNetwork>::from_str(
        r"
program test_cast_f_to_s_array.aleo;

function foo:
    input r0 as field.public;
    cast r0 into r1 as scalar;
    cast r1 r1 r1 r1 into r2 as [scalar; 4u32];",
    )
    .unwrap();

    // Initialize the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Create a helper method to deploy the programs.
    let deploy_program = |program: &Program<CurrentNetwork>, rng: &mut TestRng| {
        let mut attempts = 0;
        loop {
            if attempts >= ITERATIONS {
                panic!("Failed to craft deployment after {ITERATIONS} attempts");
            }
            match try_vm_runtime(|| ledger.vm().deploy(&private_key, program, None, 0, None, rng)) {
                Ok(result) => break result.unwrap(),
                Err(_) => attempts += 1,
            }
        }
    };

    // Deploy the programs. Keep attempting to create a deployment until it is successful.
    let deployment_tx = deploy_program(&program, rng);
    let deployment_tx_2 = deploy_program(&program_2, rng);
    let deployment_tx_3 = deploy_program(&program_3, rng);

    // Verify the deployment under different RNGs to ensure the deployment is valid.
    for _ in 0..ITERATIONS {
        let process = ledger.vm().process().clone();
        // Create a helper method to verify the deployments.
        let verify_deployment = |deployment_tx: &Transaction<CurrentNetwork>, rng: &mut TestRng| {
            let expected_result = match try_vm_runtime(|| ledger.vm().check_transaction(deployment_tx, None, rng)) {
                Ok(result) => result.is_ok(),
                Err(_) => false,
            };
            let deployment = deployment_tx.deployment().unwrap().clone();
            for _ in 0..ITERATIONS {
                let result = match try_vm_runtime(|| {
                    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V8, &deployment, rng)
                }) {
                    Ok(result) => result.is_ok(),
                    Err(_) => false,
                };
                assert_eq!(result, expected_result);
            }
        };

        // Verify the deployments.
        verify_deployment(&deployment_tx, rng);
        verify_deployment(&deployment_tx_2, rng);
        verify_deployment(&deployment_tx_3, rng);
    }
}

// These tests require the proof targets to be low enough to be able to generate **valid** solutions.
// This requires the 'test' feature to be enabled for the `console` dependency.
#[cfg(feature = "test")]
mod valid_solutions {
    use super::*;
    use crate::is_solution_limit_reached::stake_requirements_per_solution;
    use rand::prelude::SliceRandom;
    use snarkvm_ledger_puzzle::Solution;
    use std::collections::HashSet;

    // Helper function to set up a prover's account with sufficient balance to generate solutions.
    fn setup_prover_account(
        ledger: &CurrentLedger,
        validator_private_key: &PrivateKey<CurrentNetwork>,
        prover_private_key: &PrivateKey<CurrentNetwork>,
        rng: &mut TestRng,
    ) {
        // Fetch the validator and prover addresses.
        let validator_address = Address::try_from(validator_private_key).unwrap();
        let prover_address = Address::try_from(prover_private_key).unwrap();

        // Transfer a large number of credits to a prover address to ensure the prover has sufficient balance to generate solutions.
        let inputs =
            [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("181000000000000u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(validator_private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        let block = ledger
            .prepare_advance_to_next_beacon_block(
                validator_private_key,
                vec![],
                vec![],
                vec![transfer_transaction],
                rng,
            )
            .unwrap();
        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();
        // Add the block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();

        // Bond the prover's account to ensure it can generate solutions.
        let inputs = [
            Value::from_str(&format!("{validator_address}")).unwrap(),
            Value::from_str(&format!("{prover_address}")).unwrap(),
            Value::from_str("180000000000000u64").unwrap(),
        ];
        let bond_transaction = ledger
            .vm
            .execute(prover_private_key, ("credits.aleo", "bond_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        let block = ledger
            .prepare_advance_to_next_beacon_block(validator_private_key, vec![], vec![], vec![bond_transaction], rng)
            .unwrap();
        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();
        // Add the block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();
    }

    #[test]
    fn test_duplicate_solution_ids() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Create a solution that is greater than the minimum proof target.
        let mut valid_solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
        while puzzle.get_proof_target(&valid_solution).unwrap() < minimum_proof_target {
            println!(
                "Solution is invalid: {} < {}",
                puzzle.get_proof_target(&valid_solution).unwrap(),
                minimum_proof_target
            );
            valid_solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
        }

        // Create a valid transaction for the block.
        let inputs = [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        // Check that block creation fails when duplicate solution IDs are provided.
        let result = ledger.prepare_advance_to_next_beacon_block(
            &private_key,
            vec![],
            vec![valid_solution, valid_solution],
            vec![transfer_transaction.clone()],
            rng,
        );
        assert!(result.is_err());

        // Create a block.
        let block = ledger
            .prepare_advance_to_next_beacon_block(
                &private_key,
                vec![],
                vec![valid_solution],
                vec![transfer_transaction],
                rng,
            )
            .unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();

        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();

        // Enforce that the block solution was accepted properly.
        assert_eq!(block.solutions().len(), 1);
        assert_eq!(block.aborted_solution_ids().len(), 0)
    }

    #[test]
    #[ignore]
    fn test_cumulative_proof_target_correctness() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // The number of blocks to test.
        let num_blocks = CurrentNetwork::NUM_BLOCKS_PER_EPOCH * 2;

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();

        // Initialize block height.
        let mut block_height = ledger.latest_height();

        // Start a local counter of proof targets.
        let mut combined_targets = 0;

        // Track the total number of solutions in the current epoch.
        let mut total_epoch_solutions = 0;

        // Run through `num_blocks` blocks of target adjustment.
        while block_height < num_blocks {
            // Get coinbase puzzle data from the latest block.
            let block = ledger.latest_block();
            let coinbase_target = block.coinbase_target();
            let coinbase_threshold = coinbase_target.saturating_div(2);
            let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
            let latest_proof_target = ledger.latest_proof_target();

            // Sample the number of solutions to generate.
            let num_solutions = rng.random_range(1..=CurrentNetwork::MAX_SOLUTIONS);

            // Initialize a vector for valid solutions for this block.
            let mut solutions = Vec::with_capacity(num_solutions);

            // Loop through proofs until two that meet the threshold are found.
            loop {
                if let Ok(solution) =
                    puzzle.prove(latest_epoch_hash, prover_address, rng.random(), Some(latest_proof_target))
                {
                    // Get the proof target.
                    let proof_target = puzzle.get_proof_target(&solution).unwrap();

                    // Update the local combined target counter and store the solution.
                    combined_targets += proof_target;
                    solutions.push(solution);

                    // If two have been found, exit the solver loop.
                    if solutions.len() >= num_solutions {
                        break;
                    }
                }
            }

            // If the combined target exceeds the coinbase threshold reset it.
            if combined_targets >= coinbase_threshold {
                combined_targets = 0;
            }

            // Generate the next prospective block.
            let next_block =
                ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], solutions, vec![], rng).unwrap();

            // Ensure the combined target matches the expected value.
            assert_eq!(combined_targets as u128, next_block.cumulative_proof_target());

            // Ensure the next block is correct.
            ledger.check_next_block(&next_block, rng).unwrap();

            // Advanced to the next block.
            ledger.advance_to_next_block(&next_block).unwrap();

            // Set the latest block height.
            block_height = ledger.latest_height();

            // Update the epoch solutions count.
            if block_height.is_multiple_of(CurrentNetwork::NUM_BLOCKS_PER_EPOCH) {
                // Reset the epoch solutions count at the epoch boundary.
                total_epoch_solutions = 0;
            } else {
                total_epoch_solutions += num_solutions;
            }

            // Fetch the epoch provers cache.
            let epoch_provers = ledger.epoch_provers_cache.read();
            // Load the epoch provers from the blocks in the current epoch.
            let expected_epoch_provers = ledger.load_epoch_provers();
            // Check that the epoch solutions are correct
            assert_eq!(epoch_provers.values().sum::<u32>(), u32::try_from(total_epoch_solutions).unwrap());
            assert_eq!(epoch_provers.len(), expected_epoch_provers.len());
            for ((expected_address, expected_count), (address, count)) in
                expected_epoch_provers.iter().zip(epoch_provers.iter())
            {
                assert_eq!(expected_address, address);
                assert_eq!(expected_count, count);
            }
        }
    }

    #[test]
    #[ignore]
    fn test_epoch_provers_cache_cleared_at_epoch_boundary() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();

        // Initialize block height.
        let mut block_height = ledger.latest_height();

        // Start a local counter of proof targets.
        let mut combined_targets = 0;

        // Track the total number of solutions in the current epoch.
        let mut total_epoch_solutions = 0;

        // Run through blocks until the end of the epoch.
        while block_height < CurrentNetwork::NUM_BLOCKS_PER_EPOCH {
            // Check the epoch provers cache.
            {
                // Fetch the epoch provers cache.
                let epoch_provers = ledger.epoch_provers_cache.read();
                // Load the epoch provers from the blocks in the current epoch.
                let expected_epoch_provers = ledger.load_epoch_provers();
                // Check that the epoch solutions are correct
                assert_eq!(epoch_provers.values().sum::<u32>(), u32::try_from(total_epoch_solutions).unwrap());
                assert_eq!(epoch_provers.len(), expected_epoch_provers.len());
                for ((expected_address, expected_count), (address, count)) in
                    expected_epoch_provers.iter().zip(epoch_provers.iter())
                {
                    assert_eq!(expected_address, address);
                    assert_eq!(expected_count, count);
                    assert_eq!(*expected_count, u32::try_from(total_epoch_solutions).unwrap());
                }
            }

            // Get coinbase puzzle data from the latest block.
            let block = ledger.latest_block();
            let coinbase_target = block.coinbase_target();
            let coinbase_threshold = coinbase_target.saturating_div(2);
            let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
            let latest_proof_target = ledger.latest_proof_target();

            // Sample the number of solutions to generate.
            let num_solutions = rng.random_range(1..=CurrentNetwork::MAX_SOLUTIONS);

            // Initialize a vector for valid solutions for this block.
            let mut solutions = Vec::with_capacity(num_solutions);

            // Loop through proofs until two that meet the threshold are found.
            loop {
                if let Ok(solution) =
                    puzzle.prove(latest_epoch_hash, prover_address, rng.random(), Some(latest_proof_target))
                {
                    // Get the proof target.
                    let proof_target = puzzle.get_proof_target(&solution).unwrap();

                    // Update the local combined target counter and store the solution.
                    combined_targets += proof_target;
                    solutions.push(solution);

                    // If two have been found, exit the solver loop.
                    if solutions.len() >= num_solutions {
                        break;
                    }
                }
            }

            // If the combined target exceeds the coinbase threshold reset it.
            if combined_targets >= coinbase_threshold {
                combined_targets = 0;
            }

            // Generate the next prospective block.
            let next_block =
                ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], solutions, vec![], rng).unwrap();

            // Ensure the next block is correct.
            ledger.check_next_block(&next_block, rng).unwrap();

            // Advanced to the next block.
            ledger.advance_to_next_block(&next_block).unwrap();

            // Set the latest block height.
            block_height = ledger.latest_height();

            // Update the epoch solutions count.
            total_epoch_solutions += num_solutions;
        }

        // Ensure that we are at the end of the epoch.
        assert!(block_height.is_multiple_of(CurrentNetwork::NUM_BLOCKS_PER_EPOCH));

        // Fetch the epoch provers cache.
        let epoch_provers = ledger.epoch_provers_cache.read();
        // Load the epoch provers from the blocks in the current epoch.
        let expected_epoch_provers = ledger.load_epoch_provers();
        // Check that the epoch solutions are both empty.
        assert_eq!(epoch_provers.len(), 0);
        assert_eq!(expected_epoch_provers.len(), 0);
    }

    #[test]
    fn test_solution_limits() -> Result<()> {
        let rng = &mut TestRng::default();
        let stake_requirements = stake_requirements_per_solution::<CurrentNetwork>();
        let mut chain_builder = TestChainBuilder::new(rng)?;

        let private_key = chain_builder.private_keys()[0];
        let validator_address = Address::try_from(&private_key).unwrap();

        // Construct the ledger.
        let ledger = Ledger::<CurrentNetwork, LedgerType>::load(
            chain_builder.genesis_block().clone(),
            StorageMode::new_test(None),
        )?;

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Create new prover account.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();

        // Create solutions that are greater than the minimum proof target.
        let valid_solution = loop {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() >= minimum_proof_target {
                break solution;
            }
        };

        // 1. Advance to the latest timestamp.
        assert!(!ledger.is_solution_limit_reached(&prover_address, 0));

        // Transfer a public balance to the prover address.
        let inputs =
            [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10_000_000_000_000u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        // Create a block that advances the ledger past the first solution limit timestamp.
        let timestamp_1 = stake_requirements[0].0;
        let next_block = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    timestamp: timestamp_1,
                    transactions: vec![transfer_transaction],
                    skip_votes: true,
                    ..Default::default()
                },
                rng,
            )
            .with_context(|| "Failed to generate first block")?;
        // Advance to the next block.
        ledger.advance_to_next_block(&next_block).with_context(|| "Failed to advance to first block")?;

        // 2. Check that the solution limit is reached because the prover does not have any stake.
        assert_eq!(ledger.num_remaining_solutions(&prover_address, 0), 0);
        assert!(ledger.is_solution_limit_reached(&prover_address, 0));

        // Create a block with a solution.
        let next_block = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    timestamp: timestamp_1,
                    solutions: vec![valid_solution],
                    skip_votes: true,
                    ..Default::default()
                },
                rng,
            )
            .with_context(|| "Failed to generate second block")?;

        // Check that the solution is aborted.
        assert!(next_block.solutions().is_empty());
        assert_eq!(next_block.aborted_solution_ids().len(), 1);
        // Advance to the next block.
        ledger.advance_to_next_block(&next_block).with_context(|| "Failed to advance to second block")?;

        // 3. Bond the required stake.

        // Bond the required stake.
        let inputs = [
            Value::<CurrentNetwork>::from_str(&validator_address.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str(&prover_address.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str(&format!("{}u64", stake_requirements[0].1)).unwrap(),
        ];
        let bond_transaction = ledger
            .vm
            .execute(&prover_private_key, ("credits.aleo", "bond_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();
        let next_block = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    timestamp: timestamp_1,
                    transactions: vec![bond_transaction],
                    skip_votes: true,
                    ..Default::default()
                },
                rng,
            )
            .with_context(|| "Failed to generate third block")?;

        // Advance to the next block.
        ledger.advance_to_next_block(&next_block).with_context(|| "Failed to advance to third block")?;

        // 4. Check that the solution is valid with sufficient stake.

        // Check that the prover can submit solutions.
        assert_eq!(ledger.num_remaining_solutions(&prover_address, 0), 1);
        assert!(!ledger.is_solution_limit_reached(&prover_address, 0));

        // 5. Check that the next block will accept the solution and abort any excess.

        // Generate new solutions to valid_solution_1 will not get rejected due to duplication.
        let mut valid_solutions = Vec::with_capacity(2);
        // Create solutions that are greater than the minimum proof target.
        while valid_solutions.len() < 2 {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() >= minimum_proof_target {
                valid_solutions.push(solution);
            }
        }
        let valid_solution_1 = valid_solutions.remove(0);
        let valid_solution_2 = valid_solutions.remove(0);

        let next_block = chain_builder
            .generate_block_with_opts(
                GenerateBlockOptions {
                    timestamp: timestamp_1,
                    solutions: vec![valid_solution_1, valid_solution_2],
                    skip_votes: true,
                    ..Default::default()
                },
                rng,
            )
            .with_context(|| "Failed to generate fourth block")?;

        // Check that the first solution is accepted and the second is aborted.
        assert!(next_block.solutions().solution_ids().contains(&valid_solution_1.id()));
        assert_eq!(next_block.aborted_solution_ids(), &vec![valid_solution_2.id()]);

        // Advance to the next block.
        ledger.advance_to_next_block(&next_block).with_context(|| "Failed to advance to fourth block")?;

        // Check that the prover can no longer submit solutions.
        assert_eq!(ledger.num_remaining_solutions(&prover_address, 0), 0);
        assert!(ledger.is_solution_limit_reached(&prover_address, 0));

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_excess_invalid_solution_ids() {
        // Note that the sum of `NUM_INVALID_SOLUTIONS` and `NUM_VALID_SOLUTIONS` should exceed the maximum number of solutions.
        const NUM_INVALID_SOLUTIONS: usize = CurrentNetwork::MAX_SOLUTIONS;
        const NUM_VALID_SOLUTIONS: usize = CurrentNetwork::MAX_SOLUTIONS;

        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Initialize storage for the valid and invalid solutions
        let mut valid_solutions = Vec::with_capacity(NUM_VALID_SOLUTIONS);
        let mut invalid_solutions = Vec::with_capacity(NUM_INVALID_SOLUTIONS);

        // Create solutions that are greater than the minimum proof target.
        while valid_solutions.len() < NUM_VALID_SOLUTIONS {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() < minimum_proof_target {
                if invalid_solutions.len() < NUM_INVALID_SOLUTIONS {
                    invalid_solutions.push(solution);
                }
            } else {
                valid_solutions.push(solution);
            }
        }
        // Create the remaining solutions that are less than the minimum proof target.
        while invalid_solutions.len() < NUM_INVALID_SOLUTIONS {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() < minimum_proof_target {
                invalid_solutions.push(solution);
            }
        }

        // Check the length of the valid and invalid solutions.
        assert_eq!(valid_solutions.len(), NUM_VALID_SOLUTIONS);
        assert_eq!(invalid_solutions.len(), NUM_INVALID_SOLUTIONS);

        // Concatenate and shuffle the solutions.
        let mut candidate_solutions = valid_solutions.clone();
        candidate_solutions.extend(invalid_solutions.clone());
        candidate_solutions.shuffle(rng);

        // Create a valid transaction for the block.
        let inputs = [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        // Create a block.
        let block = ledger
            .prepare_advance_to_next_beacon_block(
                &private_key,
                vec![],
                candidate_solutions,
                vec![transfer_transaction],
                rng,
            )
            .unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();

        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();

        // Check that the block's solutions are well-formed.
        assert_eq!(block.aborted_solution_ids().len(), NUM_INVALID_SOLUTIONS);
        assert_eq!(block.solutions().len(), NUM_VALID_SOLUTIONS);

        let block_solutions = block.solutions().solution_ids().cloned().collect::<HashSet<_>>();
        let valid_solutions = valid_solutions.iter().map(|s| s.id()).collect::<HashSet<_>>();
        assert_eq!(block_solutions, valid_solutions, "Valid solutions do not match");

        let block_aborted_solution_ids = block.aborted_solution_ids().iter().cloned().collect::<HashSet<_>>();
        let invalid_solutions = invalid_solutions.iter().map(|s| s.id()).collect::<HashSet<_>>();
        assert_eq!(block_aborted_solution_ids, invalid_solutions, "Invalid solutions do not match");
    }

    #[test]
    #[ignore]
    fn test_excess_valid_solution_ids() {
        // Note that this should be greater than the maximum number of solutions.
        const NUM_VALID_SOLUTIONS: usize = 2 * CurrentNetwork::MAX_SOLUTIONS;

        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Initialize storage for the valid solutions
        let mut valid_solutions = Vec::with_capacity(NUM_VALID_SOLUTIONS);

        // Create solutions that are greater than the minimum proof target.
        while valid_solutions.len() < NUM_VALID_SOLUTIONS {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() >= minimum_proof_target {
                valid_solutions.push(solution);
            }
        }

        // Check the length of the valid solutions.
        assert_eq!(valid_solutions.len(), NUM_VALID_SOLUTIONS);

        // Shuffle the solutions.
        let mut candidate_solutions = valid_solutions;
        candidate_solutions.shuffle(rng);

        // Create a valid transaction for the block.
        let inputs = [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        // Create a block.
        let block = ledger
            .prepare_advance_to_next_beacon_block(
                &private_key,
                vec![],
                candidate_solutions.clone(),
                vec![transfer_transaction],
                rng,
            )
            .unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();

        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();

        // Check that the block's solutions are well-formed.
        assert_eq!(block.solutions().len(), CurrentNetwork::MAX_SOLUTIONS);
        assert_eq!(block.aborted_solution_ids().len(), NUM_VALID_SOLUTIONS - CurrentNetwork::MAX_SOLUTIONS);

        let block_solutions = block.solutions().solution_ids().cloned().collect::<HashSet<_>>();
        let expected_accepted_solutions =
            candidate_solutions.iter().take(CurrentNetwork::MAX_SOLUTIONS).map(|s| s.id()).collect::<HashSet<_>>();
        assert_eq!(block_solutions, expected_accepted_solutions, "Accepted solutions do not match");

        let block_aborted_solution_ids = block.aborted_solution_ids().iter().cloned().collect::<HashSet<_>>();
        let expected_aborted_solutions =
            candidate_solutions.iter().skip(CurrentNetwork::MAX_SOLUTIONS).map(|s| s.id()).collect::<HashSet<_>>();
        assert_eq!(block_aborted_solution_ids, expected_aborted_solutions, "Aborted solutions do not match");
    }

    #[test]
    fn test_malicious_solution() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Initialize a valid solution object.
        let mut valid_solution = None;
        while valid_solution.is_none() {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() >= minimum_proof_target {
                valid_solution = Some(solution);
            }
        }
        // Unwrap the valid solution.
        let valid_solution = valid_solution.unwrap();

        // Construct a malicious solution with a different target.
        let different_target = valid_solution.target().wrapping_sub(1);
        let malicious_solution = Solution::new(*valid_solution.partial_solution(), different_target);

        assert_eq!(
            valid_solution.id(),
            malicious_solution.id(),
            "The malicious solution should have the same ID as the valid solution"
        );
        assert_ne!(
            valid_solution.target(),
            malicious_solution.target(),
            "The malicious solution should have a different target than the valid solution"
        );

        // Create a valid transaction for the block.
        let inputs = [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        // Check that the block creation fixes the malformed solution.
        let expected_solution_id = valid_solution.id();
        let expected_solution = valid_solution;
        let mut check_block = |candidate_solutions: Vec<Solution<CurrentNetwork>>| {
            // Create a block.
            let block = ledger
                .prepare_advance_to_next_beacon_block(
                    &private_key,
                    vec![],
                    candidate_solutions.clone(),
                    vec![transfer_transaction.clone()],
                    rng,
                )
                .unwrap();

            // Check that the next block is valid.
            ledger.check_next_block(&block, rng).unwrap();

            // Check that the block's solutions are well-formed.
            assert_eq!(block.solutions().len(), 1);
            assert_eq!(block.aborted_solution_ids().len(), 0);

            // Fetch the solution from the block.
            let (solution_id, solution) = block.solutions().as_ref().unwrap().first().unwrap();
            assert_eq!(*solution_id, expected_solution_id, "Check that the block has the correct solution ID");
            assert_eq!(*solution, expected_solution, "Check that the block has the correct solution");
        };

        // Case 1: The malicious solution is included in the block construction.
        let candidate_solutions = vec![malicious_solution];
        check_block(candidate_solutions);

        // Case 2: The valid solution is included in the block construction.
        let candidate_solutions = vec![valid_solution];
        check_block(candidate_solutions);
    }

    #[test]
    fn test_solution_with_insufficient_target() {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, .. } = crate::test_helpers::sample_test_env(rng);

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Set up the prover account with sufficient balance to generate solutions.
        let prover_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let prover_address = Address::try_from(&prover_private_key).unwrap();
        setup_prover_account(&ledger, &private_key, &prover_private_key, rng);

        // Initialize a valid solution object.
        let mut invalid_solution = None;
        while invalid_solution.is_none() {
            let solution = puzzle.prove(latest_epoch_hash, prover_address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() < minimum_proof_target {
                invalid_solution = Some(solution);
            }
        }
        // Unwrap the invalid solution.
        let invalid_solution = invalid_solution.unwrap();

        // Create a valid transaction for the block.
        let inputs = [Value::from_str(&format!("{prover_address}")).unwrap(), Value::from_str("10u64").unwrap()];
        let transfer_transaction = ledger
            .vm
            .execute(&private_key, ("credits.aleo", "transfer_public"), inputs.iter(), None, 0, None, rng)
            .unwrap();

        // Create a block.
        let block = ledger
            .prepare_advance_to_next_beacon_block(
                &private_key,
                vec![],
                vec![invalid_solution],
                vec![transfer_transaction],
                rng,
            )
            .unwrap();

        // Check that the next block is valid.
        ledger.check_next_block(&block, rng).unwrap();

        // Add the deployment block to the ledger.
        ledger.advance_to_next_block(&block).unwrap();

        // Check that the block's solutions are well-formed.
        assert_eq!(block.solutions().len(), 0);
        assert_eq!(block.aborted_solution_ids().len(), 1);

        // Check that the aborted solution is correct.
        let block_aborted_solution_id = block.aborted_solution_ids().first().unwrap();
        assert_eq!(*block_aborted_solution_id, invalid_solution.id(), "Aborted solutions do not match");
    }

    #[test]
    fn test_no_rewards_after_limit_height() {
        let rng = &mut TestRng::default();

        // Initialize the test environment.
        let crate::test_helpers::TestEnv { ledger, private_key, address, .. } =
            crate::test_helpers::sample_test_env(rng);

        // Advance the ledger to the reward limit height.
        let supply_limit_height = CurrentNetwork::MAX_SUPPLY_LIMIT_HEIGHT;

        // Advance until before the supply limit height.
        while ledger.latest_height() + 1 < supply_limit_height {
            let block = ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![], rng).unwrap();
            ledger.advance_to_next_block(&block).unwrap();

            // Check that there exists rewards in the block.
            assert!(!block.ratifications().is_empty());
            let ratifications: Vec<_> = block.ratifications().iter().collect();
            match ratifications[0] {
                Ratify::BlockReward(block_reward) => {
                    assert!(*block_reward > 0);
                }
                _ => panic!("Expected a block reward ratification"),
            }
        }

        // Create one additional block at the supply limit height.
        let next_block =
            ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![], rng).unwrap();
        ledger.advance_to_next_block(&next_block).unwrap();

        // Check that the block and puzzle rewards are 0.
        assert!(!next_block.ratifications().is_empty());
        let ratifications: Vec<_> = next_block.ratifications().iter().collect();
        match ratifications[0] {
            Ratify::BlockReward(block_reward) => {
                assert_eq!(*block_reward, 0);
            }
            _ => panic!("Expected a block reward ratification"),
        }
        match ratifications[1] {
            Ratify::PuzzleReward(puzzle_reward) => {
                assert_eq!(*puzzle_reward, 0);
            }
            _ => panic!("Expected a puzzle reward ratification"),
        }

        // Create another block with a valid solution that does not give any rewards.

        // Retrieve the puzzle parameters.
        let puzzle = ledger.puzzle();
        let latest_epoch_hash = ledger.latest_epoch_hash().unwrap();
        let minimum_proof_target = ledger.latest_proof_target();

        // Create solutions that are greater than the minimum proof target.
        let valid_solution = loop {
            let solution = puzzle.prove(latest_epoch_hash, address, rng.random(), None).unwrap();
            if puzzle.get_proof_target(&solution).unwrap() >= minimum_proof_target {
                break solution;
            }
        };

        // Create a block with the valid solution.
        let next_block_with_solution = ledger
            .prepare_advance_to_next_beacon_block(&private_key, vec![], vec![valid_solution], vec![], rng)
            .unwrap();
        ledger.advance_to_next_block(&next_block_with_solution).unwrap();

        // Check that the block and puzzle rewards are 0.
        assert!(!next_block.ratifications().is_empty());
        let ratifications: Vec<_> = next_block.ratifications().iter().collect();
        match ratifications[0] {
            Ratify::BlockReward(block_reward) => {
                assert_eq!(*block_reward, 0);
            }
            _ => panic!("Expected a block reward ratification"),
        }
        match ratifications[1] {
            Ratify::PuzzleReward(puzzle_reward) => {
                assert_eq!(*puzzle_reward, 0);
            }
            _ => panic!("Expected a puzzle reward ratification"),
        }

        // Check that the solution was accepted.
        assert_eq!(next_block_with_solution.solutions().len(), 1);
    }
}

/// Tests multiple attacks where the subDAG of a block is invalid
/// (for example, because it contains more than one anchor)
#[test]
fn test_forged_block_subdags() -> Result<()> {
    let rng = &mut TestRng::default();
    let mut chain_builder = TestChainBuilder::new_with_quorum_size(10, rng)?;
    // Construct 3 quorum blocks.
    let mut quorum_blocks = chain_builder.generate_blocks(3, rng)?;

    // Extract the individual blocks.
    let block_1 = quorum_blocks.remove(0);
    let block_2 = quorum_blocks.remove(0);
    let block_3 = quorum_blocks.remove(0);

    // Construct the ledger.
    let ledger =
        Ledger::<CurrentNetwork, LedgerType>::load(chain_builder.genesis_block().clone(), StorageMode::new_test(None))?;

    // Advance to block 1.
    ledger.advance_to_next_block(&block_1)?;

    // Check that the original block 2 is accepted.
    ledger.check_next_block(&block_2, rng).with_context(|| "Unmodified block 2 must be accepted by the ledger")?;

    // Fetch the unmodified/correct subdags.
    let Authority::Quorum(block_2_subdag) = block_2.authority() else { unreachable!("") };
    let Authority::Quorum(block_3_subdag) = block_3.authority() else { unreachable!("") };

    // Fetch the transmissions.
    let block_2_transmissions = extract_transmissions(&block_2);
    let block_3_transmissions = extract_transmissions(&block_3);

    ////////////////////////////////////////////////////////////////////////////
    // Attack 1: Forge block 2' with the subdag of block 3.
    ////////////////////////////////////////////////////////////////////////////
    {
        // Forge the block.
        let forged_block_2 = ledger
            .prepare_advance_to_next_quorum_block(
                block_3_subdag.clone(),
                block_3_transmissions.clone(),
                &mut rand::rng(),
            )
            .unwrap();

        assert_ne!(forged_block_2, block_2);

        // Attempt to verify the forged block.
        assert!(ledger.check_next_block(&forged_block_2, &mut rand::rng()).is_err());
    }

    ////////////////////////////////////////////////////////////////////////////
    // Attack 2: Forge block 2' with the combined subdag of block 2 and 3.
    ////////////////////////////////////////////////////////////////////////////
    {
        // Combined the subdags.
        let mut combined_subdag = block_2_subdag.deref().clone();
        for (round, certificates) in block_3_subdag.iter() {
            combined_subdag
                .entry(*round)
                .and_modify(|c| c.extend(certificates.clone()))
                .or_insert(certificates.clone());
        }

        // Combine the transmissions.
        let mut combined_transmissions = block_2_transmissions.clone();
        combined_transmissions.extend(block_3_transmissions);

        // Forge the block.
        let forged_block_2_from_both_subdags = ledger
            .prepare_advance_to_next_quorum_block(
                Subdag::from(combined_subdag).unwrap(),
                combined_transmissions,
                &mut rand::rng(),
            )
            .unwrap();

        assert_ne!(forged_block_2_from_both_subdags, block_1);

        // Attempt to verify the forged block.
        assert!(ledger.check_next_block(&forged_block_2_from_both_subdags, &mut rand::rng()).is_err());
    }

    ////////////////////////////////////////////////////////////////////////////
    // Attack 3:  Forge block 2' that misses some batches.
    ////////////////////////////////////////////////////////////////////////////
    {
        let mut subdag = block_2_subdag.deref().clone();

        // Get the lowest round which contains batches pointing to the previous
        // block's DAG
        let (_, first_dag_round) = subdag.iter_mut().next().unwrap();
        assert!(first_dag_round.len() > 1, "First round needs more than one batch for attack to work");
        // remove one "leaf" batch.
        let _removed_batch = first_dag_round.drain(..1).next().unwrap();

        // Build new set of transmissions that matches the modified DAG
        // (we cannot just remove it, because transmissions might be in other batches as well)
        let transmissions: IndexMap<_, _> = subdag
            .values()
            .flat_map(|batches| batches.iter())
            .flat_map(|batch| batch.transmission_ids().iter())
            .map(|tid| (*tid, block_2_transmissions.get(tid).unwrap().clone()))
            .collect();

        // Forge the block.
        let forged_block_2 = ledger
            .prepare_advance_to_next_quorum_block(Subdag::from(subdag).unwrap(), transmissions, &mut rand::rng())
            .unwrap();

        assert_ne!(forged_block_2, block_1);

        // Attempt to verify the forged block.
        assert!(ledger.check_next_block(&forged_block_2, &mut rand::rng()).is_err());
    }

    Ok(())
}

/// Test that a block that has a long branch for one validator
/// (long = half of GC)
#[test]
fn test_subdag_with_long_branch() -> Result<()> {
    let rng = &mut TestRng::default();
    let mut chain_builder = TestChainBuilder::new(rng)?;

    let blocks = chain_builder.generate_blocks_with_opts(
        BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS / 4,
        GenerateBlocksOptions { skip_nodes: [0].into(), ..Default::default() },
        rng,
    )?;

    // Construct the ledger.
    let ledger =
        Ledger::<CurrentNetwork, LedgerType>::load(chain_builder.genesis_block().clone(), StorageMode::new_test(None))?;

    for block in blocks {
        ledger.advance_to_next_block(&block)?;
    }

    // Now create a long block.
    let block = chain_builder.generate_block(rng)?;

    // Ensure it is still accepted
    ledger.advance_to_next_block(&block)?;

    Ok(())
}

/// Create a block that is exactly GC rounds long
#[test]
fn test_subdag_with_gc_length() -> Result<()> {
    let rng = &mut TestRng::default();
    let mut chain_builder = TestChainBuilder::new(rng).unwrap();

    let blocks = chain_builder.generate_blocks_with_opts(
        BatchHeader::<CurrentNetwork>::MAX_GC_ROUNDS / 2,
        GenerateBlocksOptions { skip_nodes: [0].into(), ..Default::default() },
        rng,
    )?;

    // Construct the ledger.
    let ledger =
        Ledger::<CurrentNetwork, LedgerType>::load(chain_builder.genesis_block().clone(), StorageMode::new_test(None))?;

    for block in blocks {
        ledger.advance_to_next_block(&block)?;
    }

    // Now create a long block.
    let block = chain_builder.generate_block(rng)?;

    {
        // First, let us ensure that the leaf check still works by removing the lowest round and trying to reinsert.
        let Authority::Quorum(block_subdag) = block.authority() else { unreachable!("") };
        let mut forged_subdag = block_subdag.deref().clone();
        let transmissions = extract_transmissions(&block);

        // Remove one round from the subDAG.
        let _ = forged_subdag.first_entry().unwrap().remove();

        // Build new set of transmissions that matches the modified DAG
        // (we cannot just remove it, because transmissions might be in other batches as well)
        let transmissions: IndexMap<_, _> = forged_subdag
            .values()
            .flat_map(|batches| batches.iter())
            .flat_map(|batch| batch.transmission_ids().iter())
            .map(|tid| (*tid, transmissions.get(tid).unwrap().clone()))
            .collect();

        // Forge the block.
        let forged_block = ledger.prepare_advance_to_next_quorum_block(
            Subdag::from(forged_subdag).unwrap(),
            transmissions,
            &mut rand::rng(),
        )?;

        assert_ne!(forged_block, block);

        // Attempt to verify the forged block.
        assert!(ledger.check_next_block(&forged_block, &mut rand::rng()).is_err());
    }

    // Ensure it is still accepted
    ledger.advance_to_next_block(&block)?;

    Ok(())
}

#[test]
fn test_record_creation_and_consumption_in_call() {
    let rng = &mut TestRng::default();

    // Sample the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, .. } = crate::test_helpers::sample_test_env(rng);

    // A helper function to get the record counts.
    let get_record_counts = || {
        let slow_spent_filter = RecordsFilter::SlowSpent(private_key);
        let slow_unspent_filter = RecordsFilter::SlowUnspent(private_key);
        let spent_records = ledger.find_records(&view_key, RecordsFilter::Spent).unwrap().collect_vec().len();
        let slow_spent_records = ledger.find_records(&view_key, slow_spent_filter).unwrap().collect_vec().len();
        let unspent_records = ledger.find_records(&view_key, RecordsFilter::Unspent).unwrap().collect_vec().len();
        let slow_unspent_records = ledger.find_records(&view_key, slow_unspent_filter).unwrap().collect_vec().len();
        let records = ledger.records().collect_vec().len();
        (spent_records, slow_spent_records, unspent_records, slow_unspent_records, records)
    };

    // Check the initial record counts.
    let (
        initial_spent_records,
        initial_slow_spent_records,
        initial_unspent_records,
        initial_slow_unspent_records,
        initial_records,
    ) = get_record_counts();
    assert_eq!(0, initial_spent_records);
    assert_eq!(0, initial_slow_spent_records);
    assert_eq!(4, initial_unspent_records);
    assert_eq!(4, initial_slow_unspent_records);
    assert_eq!(4, initial_records);

    // Initialize the two programs.
    let program_0 = Program::from_str(
        r"
program child.aleo;

record data:
    owner as address.private;
    val as u64.private;

function mint:
    cast self.signer 0u64 into r0 as data.record;
    output r0 as data.record;

function burn:
    input r0 as data.record;
    ",
    )
    .unwrap();

    let program_1 = Program::from_str(
        r"
import child.aleo;

program parent.aleo;

function create_without_output:
    call child.aleo/mint into r0;

function create:
    call child.aleo/mint into r0;
    output r0 as child.aleo/data.record;

function consume_without_call:
    input r0 as child.aleo/data.record;

function consume:
    input r0 as child.aleo/data.record;
    call child.aleo/burn r0;

function create_and_consume:
    call child.aleo/mint into r0;
    call child.aleo/burn r0;
    ",
    )
    .unwrap();

    // Deploy the programs.
    let deployment_0 = ledger.vm().deploy(&private_key, &program_0, None, 0, None, rng).unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_0], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    let deployment_1 = ledger.vm().deploy(&private_key, &program_1, None, 0, None, rng).unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![deployment_1], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Call the `mint` function.
    let transaction = ledger
        .vm()
        .execute(&private_key, ("child.aleo", "mint"), Vec::<Value<CurrentNetwork>>::new().iter(), None, 0, None, rng)
        .unwrap();
    let mint_record = transaction.records().last().unwrap().1.decrypt(&view_key).unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Check the record counts.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records);
    assert_eq!(num_unspent_records, initial_unspent_records + 1);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 1);
    assert_eq!(num_records, initial_records + 1);

    // Call the `create_without_output` function.
    let transaction = ledger
        .vm()
        .execute(
            &private_key,
            ("parent.aleo", "create_without_output"),
            Vec::<Value<CurrentNetwork>>::new().iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();

    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Check the record counts.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records);
    assert_eq!(num_unspent_records, initial_unspent_records + 2);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 2);
    assert_eq!(num_records, initial_records + 2);

    // Call the `burn` function on record created by `create_without_output`.
    let record = block.records().collect_vec().last().unwrap().1.decrypt(&view_key).unwrap();
    let transaction = ledger
        .vm()
        .execute(&private_key, ("child.aleo", "burn"), [Value::Record(record)].iter(), None, 0, None, rng)
        .unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Check the record counts.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records + 1);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records + 1);
    assert_eq!(num_unspent_records, initial_unspent_records + 1);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 1);
    assert_eq!(num_records, initial_records + 2);

    // Call the `create` function.
    let transaction = ledger
        .vm()
        .execute(
            &private_key,
            ("parent.aleo", "create"),
            Vec::<Value<CurrentNetwork>>::new().iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Ensure that a record was created and spent.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records + 1);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records + 1);
    assert_eq!(num_unspent_records, initial_unspent_records + 2);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 2);
    assert_eq!(num_records, initial_records + 3);

    // Call the `consume_without_call` function.
    let transaction = ledger
        .vm()
        .execute(
            &private_key,
            ("parent.aleo", "consume_without_call"),
            [Value::Record(mint_record.clone())].iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Ensure that no records were created or spent.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records + 1);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records + 1);
    assert_eq!(num_unspent_records, initial_unspent_records + 2);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 2);
    assert_eq!(num_records, initial_records + 3);

    // Call the `consume` function.
    let transaction = ledger
        .vm()
        .execute(&private_key, ("parent.aleo", "consume"), [Value::Record(mint_record)].iter(), None, 0, None, rng)
        .unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Ensure that the record was spent.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records + 2);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records + 2);
    assert_eq!(num_unspent_records, initial_unspent_records + 1);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 1);
    assert_eq!(num_records, initial_records + 3);

    // Call the `create_and_consume` function.
    let transaction = ledger
        .vm()
        .execute(
            &private_key,
            ("parent.aleo", "create_and_consume"),
            Vec::<Value<CurrentNetwork>>::new().iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap();
    let block =
        ledger.prepare_advance_to_next_beacon_block(&private_key, vec![], vec![], vec![transaction], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    ledger.advance_to_next_block(&block).unwrap();

    // Ensure that a record was created and spent.
    let (num_spent_records, num_slow_spent_records, num_unspent_records, num_slow_unspent_records, num_records) =
        get_record_counts();
    assert_eq!(num_spent_records, initial_spent_records + 3);
    assert_eq!(num_slow_spent_records, initial_slow_spent_records + 3);
    assert_eq!(num_unspent_records, initial_unspent_records + 1);
    assert_eq!(num_slow_unspent_records, initial_slow_unspent_records + 1);
    assert_eq!(num_records, initial_records + 4);
}

// Ensure that `find_records` only returns records owned by the given view key.
#[test]
fn test_find_records_filters_by_ownership() {
    let rng = &mut TestRng::default();

    // Sample the test environment.
    let crate::test_helpers::TestEnv { ledger, private_key, view_key, .. } = crate::test_helpers::sample_test_env(rng);

    // Fetch all unspent records for the primary view key.
    let owned_records =
        ledger.find_records(&view_key, RecordsFilter::SlowUnspent(private_key)).unwrap().collect::<Vec<_>>();

    // Ensure that we successfully fetched at least one record that is owned by the view key.
    assert!(!owned_records.is_empty(), "Expected at least one record owned by the view key");

    // Generate a new test environment to simulate an unrelated view key.
    let other_env = crate::test_helpers::sample_test_env(rng);
    let unrelated_view_key = other_env.view_key;

    // Attempt to fetch records using the unrelated view key.
    let unrelated_records = ledger.find_records(&unrelated_view_key, RecordsFilter::All).unwrap().collect::<Vec<_>>();

    // Ensure that no records were returned for the unrelated view key.
    // This validates that ownership filtering is enforced before decrypting or filtering records.
    assert!(unrelated_records.is_empty(), "Expected no records for unrelated view key");
}
