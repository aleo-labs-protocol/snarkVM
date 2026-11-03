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

#[cfg(feature = "test")]
#[test]
fn test_aleo_generators_migration() {
    let rng = &mut TestRng::default();

    // Initialize the VM.
    let vm = sample_vm();
    // Initialize the genesis block.
    let genesis = sample_genesis_block(rng);
    // Update the VM.
    vm.add_next_block(&genesis).unwrap();

    // Fetch the private key.
    let private_key = sample_genesis_private_key(rng);
    let view_key = ViewKey::try_from(&private_key).unwrap();
    let address = Address::try_from(&view_key).unwrap();

    // Deploy a test program to the ledger.
    let program_id = ProgramID::<CurrentNetwork>::from_str("dummy_program.aleo").unwrap();
    let program = Program::<CurrentNetwork>::from_str(&format!(
        r"
    program {program_id};
    function foo:
        input r0 as scalar.public;
        input r1 as address.public;
        mul aleo::GENERATOR r0 into r2;
        mul aleo::GENERATOR_POWERS[0u32] r0 into r3;
        assert.eq aleo::GENERATOR aleo::GENERATOR_POWERS[0u32];
        assert.eq r2 r3;
        cast r2 into r4 as address;
        assert.eq r1 r4;
        async foo r0 r1 into r5;
        output r5 as {program_id}/foo.future;
    finalize foo:
        input r0 as scalar.public;
        input r1 as address.public;
        mul aleo::GENERATOR r0 into r2;
        mul aleo::GENERATOR_POWERS[0u32] r0 into r3;
        assert.eq r2 r3;
        assert.eq aleo::GENERATOR aleo::GENERATOR_POWERS[0u32];
        cast r2 into r4 as address;
        assert.eq r1 r4;

    function foo_2:
        input r0 as scalar.public;
        input r1 as address.public;
        async foo_2 r0 r1 into r2;
        output r2 as {program_id}/foo_2.future;
    finalize foo_2:
        input r0 as scalar.public;
        input r1 as address.public;
        mul aleo::GENERATOR r0 into r2;
        cast r2 into r3 as address;
        assert.eq r1 r3;

    function will_fail:
        input r0 as scalar.public;
        async will_fail r0 into r1;
        output r1 as {program_id}/will_fail.future;

    finalize will_fail:
        input r0 as scalar.public;
        mul aleo::GENERATOR_POWERS[256u32] r0 into r1;

    constructor:
        assert.eq edition 0u16;",
    ))
    .unwrap();

    // Advance the ledger past ConsensusV9 where the new varuna version and deployment version starts to take place.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V9).unwrap() {
        // Call the function
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Construct the deployment transaction.
    let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

    // Advance the ledger past ConsensusV14 where the new generator opcodes are enabled.
    let transactions: [Transaction<CurrentNetwork>; 0] = [];
    while vm.block_store().current_block_height() < CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap() {
        // Ensure that the deployment is invalid.
        assert!(vm.check_transaction(&deployment, None, rng).is_err());

        // Call the function
        let next_block = sample_next_block(&vm, &private_key, &transactions, rng).unwrap();
        vm.add_next_block(&next_block).unwrap();
    }

    // Ensure that the deployment is valid after ConsensusVersion::V14.
    assert!(vm.check_transaction(&deployment, None, rng).is_ok());

    // Deploy the program.
    let next_block = sample_next_block(&vm, &private_key, &[deployment], rng).unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Construct the input with the valid view key derivation.
    let inputs = [
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Scalar(*view_key))),
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Address(address))),
    ];
    // Create the execution transaction.
    let valid_transaction =
        vm.execute(&private_key, (&program_id.to_string(), "foo"), inputs.into_iter(), None, 0, None, rng).unwrap();
    let valid_tx_id = valid_transaction.id();

    // Create the execution transaction that will fail to execute.
    let new_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let new_address = Address::try_from(&new_private_key).unwrap();
    let inputs = [
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Scalar(*view_key))),
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Address(new_address))),
    ];
    assert!(
        vm.execute(&private_key, (&program_id.to_string(), "foo"), inputs.into_iter(), None, 0, None, rng).is_err()
    );

    // Create the execution transaction that will fail in finalize.
    let inputs = [
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Scalar(*view_key))),
        Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Address(new_address))),
    ];
    let invalid_transaction =
        vm.execute(&private_key, (&program_id.to_string(), "foo_2"), inputs.into_iter(), None, 0, None, rng).unwrap();
    let invalid_tx_id = invalid_transaction.id();

    // Construct another invalid transaction that will fail in finalize.
    let inputs = [Value::<CurrentNetwork>::Plaintext(Plaintext::from(Literal::Scalar(*view_key)))];
    let invalid_transaction_2 = vm
        .execute(&private_key, (&program_id.to_string(), "will_fail"), inputs.into_iter(), None, 0, None, rng)
        .unwrap();
    let invalid_tx_2_id = invalid_transaction_2.id();

    // Construct a block with both transactions.
    let next_block =
        sample_next_block(&vm, &private_key, &[valid_transaction, invalid_transaction, invalid_transaction_2], rng)
            .unwrap();
    vm.add_next_block(&next_block).unwrap();

    // Ensure that the valid transaction was accepted and the invalid ones were rejected.
    assert_eq!(next_block.transactions().num_accepted(), 1);
    assert_eq!(next_block.transactions().num_rejected(), 2);
    assert!(vm.block_store().get_confirmed_transaction(&valid_tx_id).unwrap().unwrap().is_accepted());
    assert!(vm.block_store().get_confirmed_transaction(&invalid_tx_id).unwrap().unwrap().is_rejected());
    assert!(vm.block_store().get_confirmed_transaction(&invalid_tx_2_id).unwrap().unwrap().is_rejected());
}
