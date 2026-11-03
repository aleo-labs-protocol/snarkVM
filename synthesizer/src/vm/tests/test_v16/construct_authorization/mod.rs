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

mod construct_authorization_flow;
use construct_authorization_flow::*;

mod program_source;
use program_source::*;

use console::{account::ViewKey, program::Identifier};

use snarkvm_ledger_block::Output;
use snarkvm_synthesizer_process::execution_cost_for_authorization;
use snarkvm_synthesizer_program::Program;

// This helper function performs the following flow:
//   1. Sample a VM at the V16 height.
//   2. Deploy ldgbatcher_p28.aleo (which imports credits.aleo).
//   3. Shield funds into three private `credits.aleo` records via
//      transfer_public_to_private.
//   4.
//    - If `use_construct_authorization` is true:
//       - Manually construct the authorization from the root-call information using
//        `sample_authorization_with_record_tracking`, populating the requests and calling
//        `authorize_requests`.
//       - Estimate the fee and construct the fee transaction.
//       - Manually construct an execution transaction by proving the authorization.
//       - Post the transaction to the ledger and check it is accepted.
//    - If `use_construct_authorization` is false:
//       - Call ldgbatcher_p28.aleo/transfer_private_3 on the VM, executing the
//         transaction as usual.
fn transfer_private_3_flow(use_construct_authorization: bool) {
    let rng = &mut TestRng::default();

    // Use the genesis account as the caller, since it holds a public balance to shield.
    let caller_private_key = sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::<CurrentNetwork>::try_from(&caller_private_key).unwrap();
    let caller_address = Address::<CurrentNetwork>::try_from(&caller_private_key).unwrap();

    println!("Sampling VM at V16 height...");

    let v16_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V16).unwrap();
    let vm = sample_vm_at_height(v16_height, rng);

    println!("Deploying ldgbatcher_p28.aleo...");

    let program = Program::<CurrentNetwork>::from_str(SRC_LDGBATCHER_P28_ALEO).unwrap();
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    println!("Minting credits.aleo records...");

    let transfer_public_to_private = Identifier::<CurrentNetwork>::from_str("transfer_public_to_private").unwrap();
    let shield_amount = 1_000_000u64;
    let mut shield_transactions = Vec::with_capacity(3);
    let mut records = Vec::with_capacity(3);
    for _ in 0..3 {
        let inputs = [
            Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(),
            Value::<CurrentNetwork>::from_str(&format!("{shield_amount}u64")).unwrap(),
        ];
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "transfer_public_to_private"),
                inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // Extract the private record produced
        let record = transaction
            .transitions()
            .find(|transition| transition.function_name() == &transfer_public_to_private)
            .unwrap()
            .outputs()
            .iter()
            .find_map(|output| match output {
                Output::Record(_, _, ciphertext, _) => {
                    Some(ciphertext.as_ref().unwrap().decrypt(&caller_view_key).unwrap())
                }
                _ => None,
            })
            .unwrap();

        shield_transactions.push(transaction);
        records.push(record);
    }

    let block = sample_next_block(&vm, &caller_private_key, &shield_transactions, rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 3);
    assert_eq!(block.transactions().num_rejected(), 0);
    vm.add_next_block(&block).unwrap();

    // Create a recipient for the private transfer.
    let recipient_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let recipient_address = Address::<CurrentNetwork>::try_from(&recipient_private_key).unwrap();

    let transfer_amount = 2_000_000u64;
    let inputs = [
        Value::Record(records[0].clone()),
        Value::Record(records[1].clone()),
        Value::Record(records[2].clone()),
        Value::<CurrentNetwork>::from_str(&recipient_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{transfer_amount}u64")).unwrap(),
    ];

    let program_id = ProgramID::<CurrentNetwork>::from_str("ldgbatcher_p28.aleo").unwrap();
    let function_name = Identifier::<CurrentNetwork>::from_str("transfer_private_3").unwrap();

    let block = if use_construct_authorization {
        println!("Constructing authorization for {program_id}/{function_name} manually...");

        // Manually construct the authorization
        let authorization = construct_authorization(&vm, caller_private_key, program_id, function_name, &inputs, rng);
        let execution_id = authorization.to_execution_id().unwrap();

        println!("Constructing the transaction by proving the authorization and incorporating a fee...");

        // Estimate and pay the fee
        let (minimum_execution_cost, _) =
            execution_cost_for_authorization(vm.process(), &authorization, ConsensusVersion::V16).unwrap();
        let fee_authorization =
            vm.authorize_fee_public(&caller_private_key, minimum_execution_cost, 0, execution_id, rng).unwrap();

        // Prove the authorization and the fee to construct the execution transaction.
        let transaction = vm.execute_authorization(authorization, Some(fee_authorization), None, rng).unwrap();

        // The transaction must verify.
        vm.check_transaction(&transaction, None, rng).unwrap();

        sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap()
    } else {
        println!("Executing transaction for {program_id}/{function_name} with vm.execute()...");

        let transaction = vm
            .execute(
                &caller_private_key,
                ("ldgbatcher_p28.aleo", "transfer_private_3"),
                inputs.iter(),
                None,
                0,
                None,
                rng,
            )
            .unwrap();

        // The transaction must verify.
        vm.check_transaction(&transaction, None, rng).unwrap();

        // The transaction must be accepted when included in a block.
        sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap()
    };

    println!("Checking transaction is accepted and posting it to the ledger");

    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();
}

#[test]
fn test_transfer_private_3_flow() {
    transfer_private_3_flow(true);
    transfer_private_3_flow(false);
}
