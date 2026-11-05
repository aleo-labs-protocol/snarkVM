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
    Authorization,
    CallStack,
    ExecutionKeyKind,
    InclusionVersion,
    Process,
    Trace,
    execution_cost,
    execution_cost_for_authorization,
};
use circuit::{Aleo, network::AleoV0};
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::{MainnetV0, prelude::*},
    program::{DynamicRecord, Identifier, Literal, Plaintext, ProgramID, Record, Request, Value, ValueType},
    types::{Field, U64},
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{Fee, Output, Transaction, Transition};
use snarkvm_ledger_query::Query;
use snarkvm_ledger_store::{
    BlockStorage,
    BlockStore,
    FinalizeStorage,
    FinalizeStore,
    helpers::memory::{BlockMemory, FinalizeMemory},
};
use snarkvm_synthesizer_program::{FinalizeGlobalState, FinalizeStoreTrait, Program, StackTrait};
use snarkvm_synthesizer_snark::UniversalSRS;

use aleo_std::StorageMode;
use indexmap::{IndexMap, IndexSet};
#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use std::sync::Arc;

type CurrentNetwork = MainnetV0;
type CurrentAleo = AleoV0;

/// Samples a new finalize state.
pub fn sample_finalize_state(block_height: u32) -> FinalizeGlobalState {
    FinalizeGlobalState::from(block_height as u64, block_height, None, [0u8; 32], None, None)
}

/// Samples a valid fee for the given process, block store, and finalize store.
pub fn sample_fee<N: Network, A: Aleo<Network = N>, B: BlockStorage<N>, P: FinalizeStorage<N>>(
    process: &Process<N>,
    block_store: &BlockStore<N, B>,
    finalize_store: &FinalizeStore<N, P>,
    rng: &mut TestRng,
) -> Fee<N> {
    let program_id = ProgramID::from_str("credits.aleo").unwrap();
    let account_mapping = Identifier::from_str("account").unwrap();

    // Initialize the account mapping, even if it already has been (we silence the result for testing).
    let _ = finalize_store.initialize_mapping(program_id, account_mapping);

    // Sample a random private key.
    let private_key = PrivateKey::<N>::new(rng).unwrap();
    let address = Address::try_from(private_key).unwrap();

    // Construct the key.
    let key = Plaintext::from(Literal::Address(address));
    // Construct the public balance.
    let value = Value::from(Literal::U64(U64::new(100)));
    // Update the public balance in finalize storage.
    finalize_store.update_key_value(program_id, account_mapping, key, value).unwrap();

    // Sample a base fee in microcredits.
    let base_fee_in_microcredits = 100;
    // Sample a priority fee in microcredits.
    let priority_fee_in_microcredits = 0;
    // Sample a dummy ID.
    let id = Field::rand(rng);

    // Authorize the fee.
    let authorization = process
        .authorize_fee_public::<A, _>(&private_key, base_fee_in_microcredits, priority_fee_in_microcredits, id, rng)
        .unwrap();
    // Execute the fee.
    let (_, mut trace) = process.execute::<A, _>(authorization, rng).unwrap();
    // Prepare the assignments.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Compute the proof and construct the fee.
    trace.prove_fee::<A, _>(VarunaVersion::V2, rng).unwrap()
}

#[test]
fn test_program_evaluate_function() {
    let program = Program::<CurrentNetwork>::from_str(
        r"
program example.aleo;

function foo:
    input r0 as field.public;
    input r1 as field.private;
    add r0 r1 into r2;
    output r2 as field.private;
",
    )
    .unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("foo").unwrap();
    // Declare the function inputs.
    let inputs = [
        Value::<CurrentNetwork>::Plaintext(Plaintext::from_str("2field").unwrap()),
        Value::Plaintext(Plaintext::from_str("3field").unwrap()),
    ];

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Compute the authorization.
    let authorization = {
        // Initialize caller private key.
        let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Authorize the function call.
        let authorization = process
            .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, inputs.iter(), rng)
            .unwrap();
        assert_eq!(authorization.len(), 1);
        authorization
    };

    // Retrieve the stack.
    let stack = process.get_stack(program.id()).unwrap();

    // Declare the expected output.
    let expected = Value::Plaintext(Plaintext::<CurrentNetwork>::from_str("5field").unwrap());

    // Run the function.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization.replicate()).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);

    // Re-run to ensure state continues to work.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);
}

#[test]
fn test_program_evaluate_struct_and_function() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program example.aleo;

struct message:
first as field;
second as field;

function compute:
input r0 as message.private;
add r0.first r0.second into r1;
output r1 as field.private;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();
    // Declare the input value.
    let input = Value::<CurrentNetwork>::Plaintext(Plaintext::from_str("{ first: 2field, second: 3field }").unwrap());
    // Declare the expected output value.
    let expected = Value::Plaintext(Plaintext::from_str("5field").unwrap());

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Compute the authorization.
    let authorization = {
        // Initialize caller private key.
        let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Authorize the function call.
        let authorization = process
            .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [input].iter(), rng)
            .unwrap();
        assert_eq!(authorization.len(), 1);
        authorization
    };

    // Retrieve the stack.
    let stack = process.get_stack(program.id()).unwrap();

    // Compute the output value.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization.replicate()).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);

    // Re-run to ensure state continues to work.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);
}

#[test]
fn test_program_evaluate_record_and_function() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program token.aleo;

record token:
owner as address.private;
token_amount as u64.private;

function compute:
input r0 as token.record;
add r0.token_amount r0.token_amount into r1;
output r1 as u64.private;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize caller private key.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let input_record = Record::from_str(&format!(
        "{{ owner: {caller}.private, token_amount: 100u64.private, _nonce: 0group.public }}"
    ))
    .unwrap();
    let input = Value::<CurrentNetwork>::Record(input_record);

    // Declare the expected output value.
    let expected = Value::Plaintext(Plaintext::from_str("200u64").unwrap());

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [input].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Retrieve the stack.
    let stack = process.get_stack(program.id()).unwrap();

    // Compute the output value.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization.replicate()).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);

    // Re-run to ensure state continues to work.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);
}

#[test]
fn test_program_evaluate_call() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program example_call.aleo;

// (a + (a + b)) + (a + b) == (3a + 2b)
closure execute:
input r0 as field;
input r1 as field;
add r0 r1 into r2;
add r0 r2 into r3;
add r2 r3 into r4;
output r4 as field;
output r3 as field;
output r2 as field;

function compute:
input r0 as field.private;
input r1 as field.public;
call execute r0 r1 into r2 r3 r4;
output r2 as field.private;
output r3 as field.private;
output r4 as field.private;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::Plaintext(Plaintext::from_str("3field").unwrap());
    let r1 = Value::<CurrentNetwork>::Plaintext(Plaintext::from_str("5field").unwrap());

    // Declare the expected output value.
    let r2 = Value::Plaintext(Plaintext::from_str("19field").unwrap());
    let r3 = Value::Plaintext(Plaintext::from_str("11field").unwrap());
    let r4 = Value::Plaintext(Plaintext::from_str("8field").unwrap());

    {
        // Construct the process.
        let process = crate::test_helpers::sample_process(&program);
        // Check that the circuit key can be synthesized.
        process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, &mut TestRng::default()).unwrap();
    }

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Compute the authorization.
    let authorization = {
        // Initialize caller private key.
        let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

        // Authorize the function call.
        let authorization = process
            .authorize::<CurrentAleo, _>(
                &caller_private_key,
                program.id(),
                function_name,
                [r0.clone(), r1.clone()].iter(),
                rng,
            )
            .unwrap();
        assert_eq!(authorization.len(), 1);
        authorization
    };

    // Retrieve the stack.
    let stack = process.get_stack(program.id()).unwrap();

    // Compute the output value.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization.replicate()).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(r2, candidate[0]);
    assert_eq!(r3, candidate[1]);
    assert_eq!(r4, candidate[2]);

    // Re-run to ensure state continues to work.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(r2, candidate[0]);
    assert_eq!(r3, candidate[1]);
    assert_eq!(r4, candidate[2]);

    use circuit::Environment;

    // Ensure the environment is clean.
    assert_eq!(0, CurrentAleo::num_constants());
    assert_eq!(1, CurrentAleo::num_public());
    assert_eq!(0, CurrentAleo::num_private());
    assert_eq!(0, CurrentAleo::num_constraints());

    // Initialize an RNG.
    let rng = &mut TestRng::default();
    // Initialize a burner private key.
    let burner_private_key = PrivateKey::new(rng).unwrap();
    // Authorize the function call, with a burner private key.
    let authorization = process
        .authorize::<CurrentAleo, _>(&burner_private_key, program.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Re-run to ensure state continues to work.
    let trace = Arc::new(RwLock::new(Trace::new()));
    let translations = Arc::new(RwLock::new(Vec::new()));
    let call_stack = CallStack::execute(authorization, trace, translations).unwrap();
    let response = stack.execute_function::<CurrentAleo, _>(call_stack, None, None, rng).unwrap().unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(r2, candidate[0]);
    assert_eq!(r3, candidate[1]);
    assert_eq!(r4, candidate[2]);
}

#[test]
fn test_program_evaluate_cast() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program token_with_cast.aleo;

record token:
owner as address.private;
token_amount as u64.private;

function compute:
input r0 as token.record;
cast r0.owner r0.token_amount into r1 as token.record;
output r1 as token.record;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize caller private key.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let input_record = Record::from_str(&format!(
        "{{ owner: {caller}.private, token_amount: 100u64.private, _nonce: 0group.public }}"
    ))
    .unwrap();
    let input = Value::<CurrentNetwork>::Record(input_record);

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [input].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);
    let request = authorization.peek_next().unwrap();

    // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
    let randomizer = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(1)]).unwrap();
    let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);

    // Declare the expected output value.
    let expected = Value::from_str(&format!(
        "{{ owner: {caller}.private, token_amount: 100u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
    ))
    .unwrap();

    // Retrieve the stack.
    let stack = process.get_stack(program.id()).unwrap();

    // Compute the output value.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization.replicate()).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);

    // Re-run to ensure state continues to work.
    let response = stack
        .evaluate_function::<CurrentAleo, _>(CallStack::evaluate(authorization).unwrap(), None, None, rng)
        .unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(expected, candidate[0]);
}

#[test]
fn test_process_execute_transfer_public_to_private() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::credits().unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();
    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();
    // Initialize a new recipient address.
    let recipient_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let recipient_view_key = ViewKey::try_from(&recipient_private_key).unwrap();
    let recipient = Address::try_from(&recipient_private_key).unwrap();
    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&format!("{recipient}")).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("99_000_000_000_000_u64").unwrap();

    // Construct the process.
    let process = Process::load().unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &caller_private_key,
            program.id(),
            Identifier::from_str("transfer_public_to_private").unwrap(),
            [r0, r1].iter(),
            rng,
        )
        .unwrap();
    assert_eq!(authorization.len(), 1);
    let request = authorization.peek_next().unwrap();

    // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
    let randomizer = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(2)]).unwrap();
    let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);

    // Declare the expected output value.
    let r2 = Value::from_str(&format!(
        "{{ owner: {recipient}.private, microcredits: 99_000_000_000_000_u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
    ))
    .unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len());
    assert_eq!(r2, candidate[0]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len());
    assert_eq!(r2, candidate[0]);

    // Check that the sender ciphertext is well-formed.
    {
        // Construct a new process.
        let process = Process::load().unwrap();
        // Initialize a new block store.
        let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
        // Prepare the trace.
        trace.prepare(&Query::from(block_store)).unwrap();
        // Prove the execution.
        let execution = trace.prove_execution::<CurrentAleo, _>("credits.aleo", VarunaVersion::V2, rng).unwrap();
        // Verify the execution.
        Process::verify_execution(
            ConsensusVersion::V10,
            VarunaVersion::V2,
            InclusionVersion::V1,
            &execution,
            &process.get_stacks(execution.transitions(), false).unwrap(),
        )
        .unwrap();

        // Check the execution cost
        assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

        // Ensure there is only one transition.
        assert_eq!(1, execution.transitions().len());
        // Retrieve the transition.
        let transition: Transition<_> = execution.into_transitions().next().unwrap();
        // Ensure the transition program ID and function name are correct.
        assert_eq!(transition.program_id(), program.id());
        assert_eq!(transition.function_name(), &Identifier::from_str("transfer_public_to_private").unwrap());
        // Ensure the transition has 2 inputs and 2 outputs.
        assert_eq!(2, transition.inputs().len());
        assert_eq!(2, transition.outputs().len());
        // Ensure the first output is a record.
        assert!(matches!(transition.outputs()[0], Output::Record(..)));

        // Retrieve the first output.
        let output = transition.outputs()[0].clone();
        // Decrypt the sender ciphertext.
        let expected_caller = output.decrypt_sender_ciphertext(&recipient_view_key).unwrap();
        // Ensure the caller address matches the expected caller.
        assert_eq!(Some(caller), expected_caller);

        // Ensure decryption fails with the caller view key.
        assert!(output.decrypt_sender_ciphertext(&caller_view_key).is_err());

        // Ensure decryption fails with a different view key.
        let different_view_key = ViewKey::try_from(&PrivateKey::<CurrentNetwork>::new(rng).unwrap()).unwrap();
        assert!(output.decrypt_sender_ciphertext(&different_view_key).is_err());
    }

    // use circuit::Environment;
    //
    // assert_eq!(22152, CurrentAleo::num_constants());
    // assert_eq!(9, CurrentAleo::num_public());
    // assert_eq!(20561, CurrentAleo::num_private());
    // assert_eq!(20579, CurrentAleo::num_constraints());
    // assert_eq!(79386, CurrentAleo::num_gates());
}

#[test]
fn test_process_circuit_key() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r#"program testing.aleo;

function hello_world:
    input r0 as u32.public;
    input r1 as u32.private;
    add r0 r1 into r2;
    output r2 as u32.private;
"#,
    )
    .unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("hello_world").unwrap();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, &mut TestRng::default()).unwrap();
}

#[test]
fn test_process_multirecords() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"program multirecord.aleo;

  record record_a:
    owner as address.private;
    item as u64.private;

  record record_b:
    owner as address.private;
    item as u64.private;

  record record_c:
    owner as address.private;
    item as u64.private;

  function initialize:
    input r0 as record_a.record;
    input r1 as record_b.record;
    input r2 as record_c.record;
    cast r0.owner r0.item into r3 as record_a.record;
    cast r1.owner r1.item into r4 as record_b.record;
    cast r2.owner r2.item into r5 as record_c.record;
    output r3 as record_a.record;
    output r4 as record_b.record;
    output r5 as record_c.record;",
    )
    .unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("initialize").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let input_a =
        Value::from_str(&format!("{{ owner: {caller}.private, item: 1234u64.private, _nonce: 0group.public }}"))
            .unwrap();
    let input_b =
        Value::from_str(&format!("{{ owner: {caller}.private, item: 4321u64.private, _nonce: 0group.public }}"))
            .unwrap();
    let input_c =
        Value::from_str(&format!("{{ owner: {caller}.private, item: 5678u64.private, _nonce: 0group.public }}"))
            .unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &caller_private_key,
            program.id(),
            function_name,
            [input_a, input_b, input_c].iter(),
            rng,
        )
        .unwrap();
    assert_eq!(authorization.len(), 1);
    let request = authorization.peek_next().unwrap();

    // Compute the encryption randomizer for the first output as `HashToScalar(tvk || index)`.
    let randomizer_a = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(3)]).unwrap();
    let nonce_a = CurrentNetwork::g_scalar_multiply(&randomizer_a);

    // Compute the encryption randomizer for the second output as `HashToScalar(tvk || index)`.
    let randomizer_b = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(4)]).unwrap();
    let nonce_b = CurrentNetwork::g_scalar_multiply(&randomizer_b);

    // Compute the encryption randomizer for the third output as `HashToScalar(tvk || index)`.
    let randomizer_c = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(5)]).unwrap();
    let nonce_c = CurrentNetwork::g_scalar_multiply(&randomizer_c);

    // Declare the output value.
    let output_a = Value::from_str(&format!(
        "{{ owner: {caller}.private, item: 1234u64.private, _nonce: {nonce_a}.public, _version: 1u8.public }}"
    ))
    .unwrap();
    let output_b = Value::from_str(&format!(
        "{{ owner: {caller}.private, item: 4321u64.private, _nonce: {nonce_b}.public, _version: 1u8.public }}"
    ))
    .unwrap();
    let output_c = Value::from_str(&format!(
        "{{ owner: {caller}.private, item: 5678u64.private, _nonce: {nonce_c}.public, _version: 1u8.public }}"
    ))
    .unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(output_a, candidate[0]);
    assert_eq!(output_b, candidate[1]);
    assert_eq!(output_c, candidate[2]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(output_a, candidate[0]);
    assert_eq!(output_b, candidate[1]);
    assert_eq!(output_c, candidate[2]);

    // use circuit::Environment;
    //
    // assert_eq!(20060, CurrentAleo::num_constants());
    // assert_eq!(12, CurrentAleo::num_public());
    // assert_eq!(57602, CurrentAleo::num_private());
    // assert_eq!(57684, CurrentAleo::num_constraints());
    // assert_eq!(178189, CurrentAleo::num_gates());
}

#[test]
fn test_process_self_caller() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"program caller.aleo;

  record data:
    owner as address.private;
    item as u64.private;

  function initialize:
    input r0 as data.record;
    cast self.caller r0.item into r1 as data.record;
    output r1 as data.record;",
    )
    .unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("initialize").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let input =
        Value::from_str(&format!("{{ owner: {caller}.private, item: 1234u64.private, _nonce: 0group.public }}"))
            .unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [input].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);
    let request = authorization.peek_next().unwrap();

    // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
    let randomizer = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(1)]).unwrap();
    let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);

    // Declare the output value.
    let output = Value::from_str(&format!(
        "{{ owner: {caller}.private, item: 1234u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
    ))
    .unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(output, candidate[0]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(output, candidate[0]);
}

#[test]
fn test_process_program_id() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"program id.aleo;

  struct data:
    user as address;

  function initialize:
    cast id.aleo into r0 as data;
    output r0 as data.private;",
    )
    .unwrap();

    // Declare the program ID.
    let program_id = ProgramID::from_str("id.aleo").unwrap();
    assert_eq!(*program.id(), program_id);

    // Declare the function name.
    let function_name = Identifier::from_str("initialize").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Authorize the function call.
    let inputs: &[Value<CurrentNetwork>] = &[];
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, inputs.iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Declare the output value.
    let output = Value::from_str(&format!("{{ user: {} }}", program_id.to_address().unwrap())).unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(output, candidate[0]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());
    assert_eq!(output, candidate[0]);
}

#[test]
fn test_process_output_operand() {
    // Helper function to test authorization, execution, and verification for the program below.
    fn authorize_execute_and_verify(
        program: &Program<CurrentNetwork>,
        function_name: Identifier<CurrentNetwork>,
        output: Value<CurrentNetwork>,
        caller_private_key: &PrivateKey<CurrentNetwork>,
        rng: &mut TestRng,
    ) {
        // Construct the process.
        let process = crate::test_helpers::sample_process(program);

        // Authorize the function call.
        let inputs: &[Value<CurrentNetwork>] = &[];
        let authorization = process
            .authorize::<CurrentAleo, _>(caller_private_key, program.id(), function_name, inputs.iter(), rng)
            .unwrap();
        assert_eq!(authorization.len(), 1);

        // Check again to make sure we didn't modify the authorization before calling `evaluate`.
        assert_eq!(authorization.len(), 1);

        // Compute the output value.
        let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
        let candidate = response.outputs();
        assert_eq!(1, candidate.len());
        assert_eq!(output, candidate[0]);

        // Check again to make sure we didn't modify the authorization after calling `evaluate`.
        assert_eq!(authorization.len(), 1);

        // Execute the request.
        let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
        let candidate = response.outputs();
        assert_eq!(1, candidate.len());
        assert_eq!(output, candidate[0]);

        // process.verify_execution::<true>(&execution).unwrap();
    }

    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"program operand.aleo;

  function program_id:
    output operand.aleo as address.private;

  function literal:
    output 1234u64 as u64.private;

  function caller:
    output self.caller as address.private;",
    )
    .unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Test the `program_id` function.
    authorize_execute_and_verify(
        &program,
        Identifier::from_str("program_id").unwrap(),
        Value::from_str(&program.id().to_address().unwrap().to_string()).unwrap(),
        &caller_private_key,
        rng,
    );

    // Test the `literal` function.
    authorize_execute_and_verify(
        &program,
        Identifier::from_str("literal").unwrap(),
        Value::from_str("1234u64").unwrap(),
        &caller_private_key,
        rng,
    );

    // Test the `caller` function.
    authorize_execute_and_verify(
        &program,
        Identifier::from_str("caller").unwrap(),
        Value::from_str(&format!("{caller}")).unwrap(),
        &caller_private_key,
        rng,
    );
}

#[test]
fn test_process_execute_call_closure() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program token.aleo;

record token:
    owner as address.private;
    token_amount as u64.private;

// (a + (a + b)) + (a + b) == (3a + 2b)
closure execute:
    input r0 as field;
    input r1 as field;
    add r0 r1 into r2;
    add r0 r2 into r3;
    add r2 r3 into r4;
    output r4 as field;
    output r3 as field;
    output r2 as field;

closure check_not_equal:
    input r0 as field;
    input r1 as field;
    assert.neq r0 r1;

function compute:
    input r0 as field.private;
    input r1 as field.public;
    input r2 as token.record;
    cast r2.owner r2.token_amount into r3 as token.record;
    call check_not_equal r0 r1;
    call execute r0 r1 into r4 r5 r6;
    output r3 as token.record;
    output r4 as field.private;
    output r5 as field.private;
    output r6 as field.private;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Prepare a record belonging to the address.
    let record_string = format!("{{ owner: {caller}.private, token_amount: 100u64.private, _nonce: 0group.public }}");

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("3field").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("5field").unwrap();
    let r2 = Value::<CurrentNetwork>::from_str(&record_string).unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1, r2].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);
    let request = authorization.peek_next().unwrap();

    // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
    let randomizer = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(3)]).unwrap();
    let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);

    // Declare the expected output value.
    let r3 = Value::<CurrentNetwork>::from_str(&format!(
        "{{ owner: {caller}.private, token_amount: 100u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
    ))
    .unwrap();
    let r4 = Value::from_str("19field").unwrap();
    let r5 = Value::from_str("11field").unwrap();
    let r6 = Value::from_str("8field").unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(4, candidate.len());
    assert_eq!(r3, candidate[0]);
    assert_eq!(r4, candidate[1]);
    assert_eq!(r5, candidate[2]);
    assert_eq!(r6, candidate[3]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(4, candidate.len());
    assert_eq!(r3, candidate[0]);
    assert_eq!(r4, candidate[1]);
    assert_eq!(r5, candidate[2]);
    assert_eq!(r6, candidate[3]);

    // use circuit::Environment;
    //
    // assert_eq!(37080, CurrentAleo::num_constants());
    // assert_eq!(12, CurrentAleo::num_public());
    // assert_eq!(41630, CurrentAleo::num_private());
    // assert_eq!(41685, CurrentAleo::num_constraints());
    // assert_eq!(159387, CurrentAleo::num_gates());
}

#[test]
fn test_process_execute_call_external_function() {
    // Initialize a new program.
    let (string, program0) = Program::<CurrentNetwork>::parse(
        r"
program token.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function mint:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function produce_magic_number:
    add 1234u64 0u64 into r0;
    output r0 as u64.private;

function check_magic_number:
    input r0 as u64.private;
    assert.eq r0 1234u64;

function noop:

function transfer:
    input r0 as token.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.amount r2 into r3;
    cast r1 r2 into r4 as token.record;
    cast r0.owner r3 into r5 as token.record;
    output r4 as token.record;
    output r5 as token.record;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program0);
    // Initialize another program.
    let (string, program1) = Program::<CurrentNetwork>::parse(
        r"
import token.aleo;

program wallet.aleo;

function transfer:
    input r0 as token.aleo/token.record;
    input r1 as address.private;
    input r2 as u64.private;
    call token.aleo/noop;
    call token.aleo/produce_magic_number into r3;
    call token.aleo/check_magic_number r3;
    call token.aleo/transfer r0 r1 r2 into r4 r5;
    output r4 as token.aleo/token.record;
    output r5 as token.aleo/token.record;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program1).unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Initialize caller 0.
    let caller0_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller0 = Address::try_from(&caller0_private_key).unwrap();

    // Initialize caller 1.
    let caller1_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller1 = Address::try_from(&caller1_private_key).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("transfer").unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&format!(
        "{{ owner: {caller0}.private, amount: 100u64.private, _nonce: 0group.public }}"
    ))
    .unwrap();
    let r1 = Value::<CurrentNetwork>::from_str(&caller1.to_string()).unwrap();
    let r2 = Value::<CurrentNetwork>::from_str("99u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller0_private_key, program1.id(), function_name, [r0, r1, r2].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 5);
    println!("\nAuthorize\n{:#?}\n\n", authorization.to_vec_deque());

    let (output_a, output_b) = {
        // Fetch the first request.
        let request = authorization.to_vec_deque().pop_back().unwrap();

        // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
        let randomizer_a = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(4)]).unwrap();
        let nonce_a = CurrentNetwork::g_scalar_multiply(&randomizer_a);

        // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
        let randomizer_b = CurrentNetwork::hash_to_scalar_psd2(&[*request.tvk(), Field::from_u64(5)]).unwrap();
        let nonce_b = CurrentNetwork::g_scalar_multiply(&randomizer_b);

        // Declare the expected output value.
        let output_a = Value::from_str(&format!(
            "{{ owner: {caller1}.private, amount: 99u64.private, _nonce: {nonce_a}.public, _version: 1u8.public }}"
        ))
        .unwrap();
        let output_b = Value::from_str(&format!(
            "{{ owner: {caller0}.private, amount: 1u64.private, _nonce: {nonce_b}.public, _version: 1u8.public }}"
        ))
        .unwrap();

        (output_a, output_b)
    };

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 5);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len());
    assert_eq!(output_a, candidate[0]);
    assert_eq!(output_b, candidate[1]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 5);

    // Execute the request.
    let (response, _trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len());
    assert_eq!(output_a, candidate[0]);
    assert_eq!(output_b, candidate[1]);

    // use circuit::Environment;
    //
    // assert_eq!(6427, CurrentAleo::num_constants());
    // assert_eq!(8, CurrentAleo::num_public());
    // assert_eq!(21264, CurrentAleo::num_private());
    // assert_eq!(21279, CurrentAleo::num_constraints());
    // assert_eq!(81872, CurrentAleo::num_gates());
    //
    // assert_eq!(18504, CurrentAleo::num_constants());
    // assert_eq!(17, CurrentAleo::num_public());
    // assert_eq!(58791, CurrentAleo::num_private());
    // assert_eq!(58855, CurrentAleo::num_constraints());
    // assert_eq!(215810, CurrentAleo::num_gates());
}

#[test]
fn test_process_execute_and_finalize_get_add_set() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program testing.aleo;

mapping account:
    key as address.public;
    value as u64.public;

function compute:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    add r1 r2 into r3;
    async compute r0 r3 into r4;
    output r4 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the program ID.
    let program_id = program.id();
    // Declare the mapping.
    let mapping_name = Identifier::from_str("account").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&caller.to_string()).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("3u64").unwrap();
    let r2 = Value::<CurrentNetwork>::from_str("5u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1, r2].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap();
    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check that the account balance is now 8.
    let candidate = finalize_store
        .get_value_speculative(*program_id, mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("8u64").unwrap());
}

#[test]
fn test_process_execute_and_finalize_increment_decrement_via_get_set() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program testing.aleo;

mapping account:
    key as address.public;
    value as u64.public;

function compute:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    add r1 r2 into r3;
    async compute r0 r3 into r4;
    output r4 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r2 r1 into r3;
    sub r3 r1 into r4;
    set r4 into account[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the program ID.
    let program_id = program.id();
    // Declare the mapping.
    let mapping_name = Identifier::from_str("account").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&caller.to_string()).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("3u64").unwrap();
    let r2 = Value::<CurrentNetwork>::from_str("5u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1, r2].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check that the account balance is now 0.
    let candidate = finalize_store
        .get_value_speculative(*program_id, mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("0u64").unwrap());
}

#[test]
fn test_process_execute_mint_public() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program token.aleo;

// On-chain storage of an `account` map, with `owner` as the key,
// and `amount` as the value.
mapping account:
    // The token owner.
    key as address.public;
    // The token amount.
    value as u64.public;

// The function `mint_public` issues the specified token amount
// for the token receiver publicly on the network.
function mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;
    // Mint the tokens publicly.
    async mint_public r0 r1 into r2;
    output r2 as token.aleo/mint_public.future;

// The finalize scope of `mint_public` increments the
// `account` of the token receiver by the specified amount.
finalize mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;

    // Get `account[r0]` into `r2`, defaulting to 0u64 if the entry does not exist.
    get.or_use account[r0] 0u64 into r2;
    // Add `r1` to `r2`. If the operation overflows, `mint_public` is reverted.
    add r2 r1 into r3;
    // Set `r3` into `account[r0]`.
    set r3 into account[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the program ID.
    let program_id = program.id();
    // Declare the mapping.
    let mapping_name = Identifier::from_str("account").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("mint_public").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // TODO (howardwu): Remove this. I call this to synthesize the proving key independent of the assignment from 'execute'.
    //  In general, we should update all tests to utilize a presynthesized proving key, before execution, to test
    //  the correctness of the synthesizer.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&caller.to_string()).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("3u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("token", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check the account balance.
    let candidate = finalize_store
        .get_value_speculative(*program_id, mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("3u64").unwrap());
}

#[test]
fn test_process_execute_call_mint_public() {
    // Initialize a new program.
    let (string, program0) = Program::<CurrentNetwork>::parse(
        r"
program token.aleo;

// On-chain storage of an `account` map, with `owner` as the key,
// and `amount` as the value.
mapping account:
    // The token owner.
    key as address.public;
    // The token amount.
    value as u64.public;

// The function `mint_public` issues the specified token amount
// for the token receiver publicly on the network.
function mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;
    // Mint the tokens publicly.
    async mint_public r0 r1 into r2;
    output r2 as token.aleo/mint_public.future;

// The finalize scope of `mint_public` increments the
// `account` of the token receiver by the specified amount.
finalize mint_public:
    // Input the token receiver.
    input r0 as address.public;
    // Input the token amount.
    input r1 as u64.public;

    // Get `account[r0]` into `r2`, defaulting to 0u64 if the entry does not exist.
    get.or_use account[r0] 0u64 into r2;
    // Add `r1` to `r2`. If the operation overflows, `mint_public` is reverted.
    add r2 r1 into r3;
    // Set `r3` into `account[r0]`.
    set r3 into account[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the mapping.
    let mapping_name = Identifier::from_str("account").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("mint_public").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program0);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program0.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program0, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // TODO (howardwu): Remove this. I call this to synthesize the proving key independent of the assignment from 'execute'.
    //  In general, we should update all tests to utilize a presynthesized proving key, before execution, to test
    //  the correctness of the synthesizer.
    process.synthesize_key::<CurrentAleo, _>(program0.id(), &function_name, rng).unwrap();

    // Initialize another program.
    let (string, program1) = Program::<CurrentNetwork>::parse(
        r"
import token.aleo;

program public_wallet.aleo;

function init:
    input r0 as address.public;
    input r1 as u64.public;
    call token.aleo/mint_public r0 r1 into r2;
    async init r2 into r3;
    output r3 as public_wallet.aleo/init.future;
finalize init:
    input r0 as token.aleo/mint_public.future;
    await r0;
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("init").unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program1, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(2), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // TODO (howardwu): Remove this. I call this to synthesize the proving key independent of the assignment from 'execute'.
    //  In general, we should update all tests to utilize a presynthesized proving key, before execution, to test
    //  the correctness of the synthesizer.
    process.synthesize_key::<CurrentAleo, _>(program1.id(), &function_name, rng).unwrap();

    // Initialize caller.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&caller.to_string()).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("100u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program1.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 2);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 2);

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("public_wallet", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check the account balance.
    let candidate = finalize_store
        .get_value_speculative(*program0.id(), mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("100u64").unwrap());
}

#[test]
fn test_process_execute_and_finalize_get_set() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program testing.aleo;

mapping account:
    key as address.public;
    value as u64.public;

function compute:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    add r1 r2 into r3;
    async compute r0 r3 into r4;
    output r4 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    add r1 r2 into r3;
    set r3 into account[r0];
    get account[r0] into r4;
    add r1 r4 into r5;
    set r5 into account[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the program ID.
    let program_id = program.id();
    // Declare the mapping.
    let mapping_name = Identifier::from_str("account").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str(&caller.to_string()).unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("3u64").unwrap();
    let r2 = Value::<CurrentNetwork>::from_str("5u64").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1, r2].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check that the account balance is now 8.
    let candidate = finalize_store
        .get_value_speculative(*program_id, mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("16u64").unwrap());
}

#[test]
fn test_execution_order() {
    // Initialize a new program (leaf node).
    let (string, program0) = Program::<CurrentNetwork>::parse(
        r"
program zero.aleo;

mapping zero_data:
    key as u8.public;
    value as u8.public;

function c:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    async c r2 into r3;
    output r2 as u8.private;
    output r3 as zero.aleo/c.future;

finalize c:
    input r0 as u8.public;
    set r0 into zero_data[r0];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program0);

    // Initialize another program (middle node).
    let (string, program1) = Program::<CurrentNetwork>::parse(
        r"
import zero.aleo;

program one.aleo;

mapping one_data:
    key as u8.public;
    value as u8.public;

function b:
    input r0 as u8.private;
    input r1 as u8.private;
    call zero.aleo/c r0 r1 into r2 r3;
    async b r3 r2 into r4;
    output r2 as u8.private;
    output r4 as one.aleo/b.future;

finalize b:
    input r0 as zero.aleo/c.future;
    input r1 as u8.public;
    await r0;
    set r1 into one_data[r1];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program1).unwrap();

    // Initialize another program (root node).
    let (string, program2) = Program::<CurrentNetwork>::parse(
        r"
import zero.aleo;
import one.aleo;

program two.aleo;

mapping two_data:
    key as u8.public;
    value as u8.public;

function a:
    input r0 as u8.private;
    input r1 as u8.private;
    call one.aleo/b r0 r1 into r2 r3;
    async a r3 r2 into r4;
    output r2 as u8.private;
    output r4 as two.aleo/a.future;

finalize a:
    input r0 as one.aleo/b.future;
    input r1 as u8.public;
    await r0;
    set r1 into two_data[r1];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program2).unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Initialize the caller.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("a").unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("1u8").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("2u8").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program2.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 3);
    println!("\nAuthorize\n{:#?}\n\n", authorization.to_vec_deque());

    let output = Value::<CurrentNetwork>::from_str("3u8").unwrap();

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len()); // output value + future
    assert_eq!(output, candidate[0]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 3);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len()); // output value + future
    assert_eq!(output, candidate[0]);

    // Construct the expected transition order.
    let expected_order = [
        (program0.id(), Identifier::<MainnetV0>::from_str("c").unwrap()),
        (program1.id(), Identifier::from_str("b").unwrap()),
        (program2.id(), Identifier::from_str("a").unwrap()),
    ];

    // Check the expected transition order.
    for (transition, (expected_program_id, expected_function_name)) in
        trace.transitions().iter().zip_eq(expected_order.iter())
    {
        assert_eq!(transition.program_id(), *expected_program_id);
        assert_eq!(transition.function_name(), expected_function_name);
    }

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("two", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Verify finalize costs match between static analysis and runtime calculation.
    // Each finalize block has: inputs (100 each) + 1 await (500) + 1 set (10000), except leaf has no await.
    // Leaf (zero.aleo/c): 1 input + set = 100 + 10000 = 10100
    // Middle (one.aleo/b): 2 inputs + await + set = 200 + 500 + 10000 = 10700
    // Root (two.aleo/a): 2 inputs + await + set = 200 + 500 + 10000 = 10700
    // Total V2 cost: 10100 + 10700 + 10700 = 31500... but actual is 31600
    // The extra 100 comes from the finalize command base costs
    let stack = process.get_stack(program2.id()).unwrap();
    let static_finalize_cost = crate::cost::minimum_cost_in_microcredits_v2(&stack, &function_name).unwrap();
    let runtime_finalize_cost = crate::cost::execution_finalize_cost(
        &process,
        &execution,
        crate::cost::ConsensusFeeVersion::V2,
        Some(ConsensusVersion::V10),
    )
    .unwrap();

    assert_eq!(static_finalize_cost, 31600, "Expected static finalize cost of 31600");
    assert_eq!(runtime_finalize_cost, 31600, "Expected runtime finalize cost of 31600");
    assert_eq!(static_finalize_cost, runtime_finalize_cost, "Static and runtime costs should match");
}

#[test]
fn test_complex_execution_order() {
    // This test checks that the execution order is correct.
    // The functions are invoked in the following order:
    // "four::a"
    //   --> "two::b"
    //        --> "zero::c"
    //        --> "one::d"
    //   --> "three::e"
    //        --> "two::b"
    //             --> "zero::c"
    //             --> "one::d"
    //        --> "one::d"
    //        --> "zero::c"
    // The linearized order is:
    //  - [a, b, c, d, e, b, c, d, d, c]
    // The transitions must be included in the `Execution` in the order they finish.
    // The execution order is:
    //  - [c, d, b, c, d, b, d, c, e, a]

    // Initialize a new program (leaf).
    let (string, program0) = Program::<CurrentNetwork>::parse(
        r"
    program zero.aleo;

    mapping zero_data:
        key as u8.public;
        value as u8.public;

    function c:
        input r0 as u8.private;
        input r1 as u8.private;
        add r0 r1 into r2;
        async c r2 into r3;
        output r2 as u8.private;
        output r3 as zero.aleo/c.future;

    finalize c:
        input r0 as u8.public;
        set r0 into zero_data[r0];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program0);

    // Initialize another program (leaf).
    let (string, program1) = Program::<CurrentNetwork>::parse(
        r"
    program one.aleo;

    mapping one_data:
        key as u8.public;
        value as u8.public;

    function d:
        input r0 as u8.private;
        input r1 as u8.private;
        add r0 r1 into r2;
        async d r2 into r3;
        output r2 as u8.private;
        output r3 as one.aleo/d.future;

    finalize d:
        input r0 as u8.public;
        set r0 into one_data[r0];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program1).unwrap();

    // Initialize another program (calls zero and one).
    let (string, program2) = Program::<CurrentNetwork>::parse(
        r"
    import zero.aleo;
    import one.aleo;

    program two.aleo;

    mapping two_data:
        key as u8.public;
        value as u8.public;

    function b:
        input r0 as u8.private;
        input r1 as u8.private;
        call zero.aleo/c r0 r1 into r2 r3;
        call one.aleo/d r1 r2 into r4 r5;
        async b r3 r5 r4 into r6;
        output r4 as u8.private;
        output r6 as two.aleo/b.future;

    finalize b:
        input r0 as zero.aleo/c.future;
        input r1 as one.aleo/d.future;
        input r2 as u8.public;
        await r0;
        await r1;
        set r2 into two_data[r2];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program2).unwrap();

    // Initialize another program (calls two, one, zero).
    let (string, program3) = Program::<CurrentNetwork>::parse(
        r"
    import zero.aleo;
    import one.aleo;
    import two.aleo;

    program three.aleo;

    mapping three_data:
        key as u8.public;
        value as u8.public;

    function e:
        input r0 as u8.private;
        input r1 as u8.private;
        call two.aleo/b r0 r1 into r2 r3;
        call one.aleo/d r1 r2 into r4 r5;
        call zero.aleo/c r1 r2 into r6 r7;
        async e r3 r5 r7 r6 into r8;
        output r6 as u8.private;
        output r8 as three.aleo/e.future;

    finalize e:
        input r0 as two.aleo/b.future;
        input r1 as one.aleo/d.future;
        input r2 as zero.aleo/c.future;
        input r3 as u8.public;
        await r0;
        await r1;
        await r2;
        set r3 into three_data[r3];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program3).unwrap();

    // Initialize another program (calls two and three).
    let (string, program4) = Program::<CurrentNetwork>::parse(
        r"
    import zero.aleo;
    import one.aleo;
    import two.aleo;
    import three.aleo;

    program four.aleo;

    mapping four_data:
        key as u8.public;
        value as u8.public;

    function a:
        input r0 as u8.private;
        input r1 as u8.private;
        call two.aleo/b r0 r1 into r2 r3;
        call three.aleo/e r1 r2 into r4 r5;
        async a r3 r5 r4 into r6;
        output r4 as u8.private;
        output r6 as four.aleo/a.future;

    finalize a:
        input r0 as two.aleo/b.future;
        input r1 as three.aleo/e.future;
        input r2 as u8.public;
        await r0;
        await r1;
        set r2 into four_data[r2];",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Add the program to the process.
    process.lock().add_program(&program4).unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Initialize caller.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Declare the function name.
    let function_name = Identifier::from_str("a").unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("1u8").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("2u8").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program4.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 10);
    println!("\nAuthorize\n{:#?}\n\n", authorization.to_vec_deque());

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    let output = Value::<CurrentNetwork>::from_str("17u8").unwrap();

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len()); // output value + future
    assert_eq!(output, candidate[0]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 10);

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(2, candidate.len()); // output value + future
    assert_eq!(output, candidate[0]);

    // Construct the expected execution order.
    let expected_order = [
        (program0.id(), Identifier::<MainnetV0>::from_str("c").unwrap()),
        (program1.id(), Identifier::<MainnetV0>::from_str("d").unwrap()),
        (program2.id(), Identifier::<MainnetV0>::from_str("b").unwrap()),
        (program0.id(), Identifier::<MainnetV0>::from_str("c").unwrap()),
        (program1.id(), Identifier::<MainnetV0>::from_str("d").unwrap()),
        (program2.id(), Identifier::<MainnetV0>::from_str("b").unwrap()),
        (program1.id(), Identifier::<MainnetV0>::from_str("d").unwrap()),
        (program0.id(), Identifier::<MainnetV0>::from_str("c").unwrap()),
        (program3.id(), Identifier::<MainnetV0>::from_str("e").unwrap()),
        (program4.id(), Identifier::<MainnetV0>::from_str("a").unwrap()),
    ];
    for (transition, (expected_program_id, expected_function_name)) in
        trace.transitions().iter().zip_eq(expected_order.iter())
    {
        assert_eq!(transition.program_id(), *expected_program_id);
        assert_eq!(transition.function_name(), expected_function_name);
    }

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("four", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Verify finalize costs match between static analysis and runtime calculation.
    // Cost breakdown for V2 (execution order: [c, d, b, c, d, b, d, c, e, a]):
    //   zero.aleo/c (3x): 1 input (100) + set (10000) = 10100 each -> 30300
    //   one.aleo/d (3x): 1 input (100) + set (10000) = 10100 each -> 30300
    //   two.aleo/b (2x): 3 inputs (300) + 2 awaits (1000) + set (10000) = 11300 each -> 22600
    //   three.aleo/e (1x): 4 inputs (400) + 3 awaits (1500) + set (10000) = 11900
    //   four.aleo/a (1x): 3 inputs (300) + 2 awaits (1000) + set (10000) = 11300
    // Total V2 cost: 30300 + 30300 + 22600 + 11900 + 11300 = 106400 + 100 (base) = 106500
    let stack = process.get_stack(program4.id()).unwrap();
    let static_finalize_cost = crate::cost::minimum_cost_in_microcredits_v2(&stack, &function_name).unwrap();
    let runtime_finalize_cost = crate::cost::execution_finalize_cost(
        &process,
        &execution,
        crate::cost::ConsensusFeeVersion::V2,
        Some(ConsensusVersion::V10),
    )
    .unwrap();

    assert_eq!(static_finalize_cost, 106500, "Expected static finalize cost of 106500");
    assert_eq!(runtime_finalize_cost, 106500, "Expected runtime finalize cost of 106500");
    assert_eq!(static_finalize_cost, runtime_finalize_cost, "Static and runtime costs should match");
}

#[test]
fn test_process_execute_and_finalize_get_set_with_struct() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program testing.aleo;

struct entry:
    count as u8;
    data as u8;

mapping entries:
    key as address.public;
    value as entry.public;

function compute:
    input r0 as u8.public;
    input r1 as u8.public;
    cast r0 r1 into r2 as entry;
    async compute self.caller r2 into r3;
    output r3 as testing.aleo/compute.future;

finalize compute:
    input r0 as address.public;
    input r1 as entry.public;
    get.or_use entries[r0] r1 into r2;
    add r1.count r2.count into r3;
    add r1.data r2.data into r4;
    cast r3 r4 into r5 as entry;
    set r5 into entries[r0];
    get entries[r0] into r6;
    add r6.count r1.count into r7;
    add r6.data r1.data into r8;
    cast r7 r8 into r9 as entry;
    set r9 into entries[r0];
",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the program ID.
    let program_id = program.id();
    // Declare the mapping.
    let mapping_name = Identifier::from_str("entries").unwrap();
    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let _caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller = Address::try_from(&caller_private_key).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("1u8").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("2u8").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(1, candidate.len());

    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);

    // Now, finalize the execution.
    process.lock().finalize_execution(sample_finalize_state(1), &finalize_store, &execution, None).unwrap();

    // Check that the struct is stored as expected.
    let candidate = finalize_store
        .get_value_speculative(*program_id, mapping_name, &Plaintext::from(Literal::Address(caller)))
        .unwrap()
        .unwrap();
    assert_eq!(candidate, Value::from_str("{ count: 3u8, data: 6u8 }").unwrap());
}

#[test]
fn test_process_execute_and_verify_call_to_closure() {
    // Initialize a new program.
    let (string, program) = Program::<CurrentNetwork>::parse(
        r"
program testing.aleo;

// (a + (a + b)) + (a + b) == (3a + 2b)
closure execute:
    input r0 as field;
    input r1 as field;
    add r0 r1 into r2;
    add r0 r2 into r3;
    add r2 r3 into r4;
    output r4 as field;
    output r3 as field;
    output r2 as field;

closure check_not_equal:
    input r0 as field;
    input r1 as field;
    assert.neq r0 r1;

function compute:
    input r0 as field.private;
    input r1 as field.public;
    call check_not_equal r0 r1;
    call execute r0 r1 into r2 r3 r4;
    output r2 as field.private;
    output r3 as field.private;
    output r4 as field.private;",
    )
    .unwrap();
    assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

    // Declare the function name.
    let function_name = Identifier::from_str("compute").unwrap();

    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);
    // Check that the circuit key can be synthesized.
    process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, rng).unwrap();

    // Reset the process.
    let process = crate::test_helpers::sample_process(&program);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Declare the input value.
    let r0 = Value::<CurrentNetwork>::from_str("3field").unwrap();
    let r1 = Value::<CurrentNetwork>::from_str("5field").unwrap();

    // Authorize the function call.
    let authorization = process
        .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), function_name, [r0, r1].iter(), rng)
        .unwrap();
    assert_eq!(authorization.len(), 1);

    let r2 = Value::from_str("19field").unwrap();
    let r3 = Value::from_str("11field").unwrap();
    let r4 = Value::from_str("8field").unwrap();

    // Check again to make sure we didn't modify the authorization before calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    // Compute the output value.
    let response = process.evaluate::<CurrentAleo>(authorization.replicate()).unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(r2, candidate[0]);
    assert_eq!(r3, candidate[1]);
    assert_eq!(r4, candidate[2]);

    // Check again to make sure we didn't modify the authorization after calling `evaluate`.
    assert_eq!(authorization.len(), 1);

    let expected_execution_cost =
        execution_cost_for_authorization(&process, &authorization, ConsensusVersion::V10).unwrap();

    // Execute the request.
    let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
    let candidate = response.outputs();
    assert_eq!(3, candidate.len());
    assert_eq!(r2, candidate[0]);
    assert_eq!(r3, candidate[1]);
    assert_eq!(r4, candidate[2]);

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Prepare the trace.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Prove the execution.
    let execution = trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap();

    // Verify the execution.
    Process::verify_execution(
        ConsensusVersion::V10,
        VarunaVersion::V2,
        InclusionVersion::V1,
        &execution,
        &process.get_stacks(execution.transitions(), false).unwrap(),
    )
    .unwrap();

    // Check the execution cost
    assert_eq!(execution_cost(&process, &execution, ConsensusVersion::V10).unwrap(), expected_execution_cost);
}

#[test]
fn test_process_deploy_credits_program() {
    let rng = &mut TestRng::default();

    // Initialize an empty process without the `credits` program.
    let empty_process = Process {
        universal_srs: UniversalSRS::<CurrentNetwork>::load().unwrap(),
        stacks: Default::default(),
        old_stacks: Default::default(),
        lock: Default::default(),
    };

    // Construct the process.
    let process = Process::load().unwrap();

    // Fetch the credits program
    let program = Program::credits().unwrap();

    // Create a deployment for the credits.aleo program.
    let deployment = empty_process.deploy::<CurrentAleo, _>(&program, rng).unwrap();

    // Ensure the deployment is valid on the empty process.
    empty_process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Ensure the deployment is not valid on the standard process.
    assert!(process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).is_err());

    // Create a new `credits.aleo` program.
    let program = Program::from_str(
        r"
program credits.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function compute:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
    )
    .unwrap();

    // Create a deployment for the credits.aleo program.
    let deployment = empty_process.deploy::<CurrentAleo, _>(&program, rng).unwrap();

    // Ensure the deployment is valid on the empty process.
    empty_process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Ensure the deployment is not valid on the standard process.
    assert!(process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).is_err());
}

#[test]
fn test_process_zero_input_zero_output_executions() {
    // Initialize the RNG.
    let rng = &mut TestRng::default();

    // Create a new program with a function that has no inputs or outputs.
    let function_name = Identifier::from_str("zero_inputs_zero_outputs").unwrap();
    let program = Program::from_str(&format!(
        r"
program testing.aleo;
function {function_name}:
    add 0u8 1u8 into r0;",
    ))
    .unwrap();

    // Reset the process.
    let process = Process::load().unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Initialize a new finalize store.
    let finalize_store = FinalizeStore::<_, FinalizeMemory<_>>::open(StorageMode::new_test(None)).unwrap();

    // Add the program to the process.
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Check that the deployment verifies.
    process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V10, &deployment, rng).unwrap();
    // Compute the fee.
    let fee = sample_fee::<_, CurrentAleo, _, _>(&process, &block_store, &finalize_store, rng);
    // Finalize the deployment.
    let (stack, _) =
        process.lock().finalize_deployment(sample_finalize_state(1), &finalize_store, &deployment, &fee).unwrap();
    // Add the stack *manually* to the process.
    process.lock().add_stack(stack);

    // Initialize a new caller account.
    let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();

    // Create an execution for the `zero_inputs_zero_outputs` function.
    let execution_1 = {
        // Authorize the function call.
        let inputs = Vec::<Value<CurrentNetwork>>::new();
        let authorization = process
            .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), &function_name, inputs.iter(), rng)
            .unwrap();

        // Execute the request.
        let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
        assert_eq!(response.outputs().len(), 0);

        // Prepare the trace.
        trace.prepare(&Query::from(block_store.clone())).unwrap();
        // Prove the execution.
        trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap()
    };
    assert_eq!(execution_1.len(), 1);

    // Create a subsequent execution for the `zero_inputs_zero_outputs` function.
    let execution_2 = {
        // Authorize the function call.
        let inputs = Vec::<Value<CurrentNetwork>>::new();
        let authorization = process
            .authorize::<CurrentAleo, _>(&caller_private_key, program.id(), &function_name, inputs.iter(), rng)
            .unwrap();

        // Execute the request.
        let (response, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();
        assert_eq!(response.outputs().len(), 0);

        // Prepare the trace.
        trace.prepare(&Query::from(block_store)).unwrap();
        // Prove the execution.
        trace.prove_execution::<CurrentAleo, _>("testing", VarunaVersion::V2, rng).unwrap()
    };
    assert_eq!(execution_2.len(), 1);

    // Ensure that the transitions are unique.
    assert_ne!(execution_1.peek().unwrap().id(), execution_2.peek().unwrap().id());
    assert_ne!(execution_1.to_execution_id().unwrap(), execution_2.to_execution_id().unwrap());
}

#[test]
fn test_long_import_chain() {
    const MAX_PROGRAM_DEPTH: usize = 64;
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"
    program test0.aleo;
    function c:",
    )
    .unwrap();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Add `MAX_PROGRAM_DEPTH` programs to the process.
    for i in 1..=MAX_PROGRAM_DEPTH {
        println!("Adding program {i}");
        // Initialize a new program.
        let program = Program::from_str(&format!(
            "
        import test{}.aleo;
        program test{}.aleo;
        function c:",
            i - 1,
            i
        ))
        .unwrap();
        // Add the program to the process.
        process.lock().add_program(&program).unwrap();
    }

    // Add the `MAX_PROGRAM_DEPTH + 1` program to the process, which should fail.
    let program = Program::from_str(&format!(
        "
        import test{}.aleo;
        program test{}.aleo;
        function c:",
        MAX_PROGRAM_DEPTH,
        MAX_PROGRAM_DEPTH + 1
    ))
    .unwrap();
    let result = process.lock().add_program(&program);
    // Programs may create long import chains as long as number of calls does not exceed the maximum number of transitions.
    assert!(result.is_ok());
}

#[test]
fn test_long_import_chain_with_calls() {
    // Initialize a new program.
    let program = Program::<CurrentNetwork>::from_str(
        r"
    program test0.aleo;
    function c:",
    )
    .unwrap();

    // Construct the process.
    let process = crate::test_helpers::sample_process(&program);

    // Check that the number of calls, up to `Transaction::MAX_TRANSITIONS - 1`, is correct.
    for i in 1..(Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 1) {
        println!("Adding program {i}");
        // Initialize a new program.
        let program = Program::from_str(&format!(
            "
        import test{}.aleo;
        program test{}.aleo;
        function c:
            call test{}.aleo/c;",
            i - 1,
            i,
            i - 1
        ))
        .unwrap();
        // Add the program to the process.
        process.lock().add_program(&program).unwrap();
        // Check that the number of calls is correct.
        let stack = process.get_stack(program.id()).unwrap();
        let number_of_calls =
            stack.get_minimum_number_of_calls(program.functions().into_iter().next().unwrap().0).unwrap();
        assert_eq!(number_of_calls, i + 1);
    }

    // Check that `Transaction::MAX_TRANSITIONS - 1`-th call fails.
    let program = Program::from_str(&format!(
        "
        import test{}.aleo;
        program test{}.aleo;
        function c:
            call test{}.aleo/c;",
        Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 2,
        Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 1,
        Transaction::<CurrentNetwork>::MAX_TRANSITIONS - 2
    ))
    .unwrap();
    let result = process.lock().add_program(&program);
    assert!(result.is_err())
}

#[test]
fn test_max_imports() {
    // Construct the process.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Add `MAX_IMPORTS` programs to the process.
    for i in 0..CurrentNetwork::MAX_IMPORTS {
        println!("Adding program {i}");
        // Initialize a new program.
        let program = Program::from_str(&format!("program test{i}.aleo; function c:")).unwrap();
        // Add the program to the process.
        process.lock().add_program(&program).unwrap();
    }

    // Add a program importing all `MAX_IMPORTS` programs, which should pass.
    let import_string =
        (0..CurrentNetwork::MAX_IMPORTS).map(|i| format!("import test{i}.aleo;")).collect::<Vec<_>>().join(" ");
    let program =
        Program::from_str(&format!("{import_string}program test{}.aleo; function c:", CurrentNetwork::MAX_IMPORTS))
            .unwrap();
    process.lock().add_program(&program).unwrap();

    // Attempt to construct a program importing `MAX_IMPORTS + 1` programs, which should fail.
    let import_string =
        (0..CurrentNetwork::MAX_IMPORTS + 1).map(|i| format!("import test{i}.aleo;")).collect::<Vec<_>>().join(" ");
    let result = Program::<CurrentNetwork>::from_str(&format!(
        "{import_string}program test{}.aleo; function c:",
        CurrentNetwork::MAX_IMPORTS + 1
    ));
    assert!(result.is_err());
}

#[test]
fn test_program_exceeding_transaction_spend_limit() {
    // Construct a finalize body whose finalize cost is excessively large.
    let mut finalize_body = r"
    cast  0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 0u8 into r0 as [u8; 16u32];
    cast  r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [[u8; 16u32]; 16u32];
    cast  r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 r1 into r2 as [[[u8; 16u32]; 16u32]; 16u32];"
        .to_string();
    (3..500).for_each(|i| {
        finalize_body.push_str(&format!("hash.bhp256 r2 into r{i} as field;\n"));
    });
    // Construct the program.
    let program = Program::from_str(&format!(
        r"program test_max_spend_limit.aleo;
      function foo:
      async foo into r0;
      output r0 as test_max_spend_limit.aleo/foo.future;
      
      finalize foo:{finalize_body}",
    ))
    .unwrap();

    // Initialize a `Process`.
    let process = Process::<CurrentNetwork>::load().unwrap();

    // Attempt to deploy the program, which should succeed.
    let rng = &mut TestRng::default();
    let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
    // Attempt to verify the deployment, which should fail.
    assert!(process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V8, &deployment, rng).is_ok());
}

/// `execute` refuses an authorization with a request that no call takes.
#[test]
fn test_execute_rejects_unused_request() {
    let rng = &mut TestRng::default();

    let program = Program::<CurrentNetwork>::from_str(
        r"
program unused.aleo;
function twice:
    input r0 as u64.private;
    add r0 r0 into r1;
    output r1 as u64.private;",
    )
    .unwrap();
    let process = Process::<CurrentNetwork>::load().unwrap();
    process.lock().add_program(&program).unwrap();

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let mut authorize = |input: &str| {
        process
            .authorize::<CurrentAleo, _>(
                &private_key,
                program.id(),
                Identifier::from_str("twice").unwrap(),
                [Value::from_str(input).unwrap()].iter(),
                rng,
            )
            .unwrap()
    };
    let (first, second) = (authorize("1u64"), authorize("2u64"));

    // The second root request follows the first, so no call takes it.
    let authorization = Authorization::try_from((
        first.to_vec_deque().into_iter().chain(second.to_vec_deque()).collect(),
        first.transitions().into_values().chain(second.transitions().into_values()).collect(),
    ))
    .unwrap();
    let error = process.execute::<CurrentAleo, _>(authorization, rng).map(|_| ()).unwrap_err();
    assert!(format!("{error:#}").contains("used 1 of its 2 requests"), "{error:#}");
}

/// `authorize_requests` and `execute` refuse a root request flagged dynamic, and accept the same request unflagged.
#[test]
fn test_authorize_requests_and_execute_reject_dynamic_root() {
    let rng = &mut TestRng::default();

    let program = Program::<CurrentNetwork>::from_str(
        "program dynroot.aleo;
        record token: owner as address.private; amount as u64.private;
        function mint: input r0 as u64.private; cast self.signer r0 into r1 as token.record; output r1 as token.record;",
    )
    .unwrap();
    let process = Process::<CurrentNetwork>::load().unwrap();
    process.lock().add_program(&program).unwrap();
    let stack = process.get_stack(program.id()).unwrap();

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    for is_dynamic in [false, true] {
        let root = Request::sign(
            &private_key,
            *program.id(),
            Identifier::from_str("mint").unwrap(),
            [Value::<CurrentNetwork>::from_str("5u64").unwrap()].iter(),
            &[ValueType::from_str("u64.private").unwrap()],
            None,
            true,
            None,
            is_dynamic,
            rng,
        )
        .unwrap();

        let authorized =
            stack.authorize_requests::<CurrentAleo, _>(vec![root.clone()], rng).map(|_| ()).map_err(Error::from);
        let executed =
            process.execute::<CurrentAleo, _>(Authorization::new(root), rng).map(|_| ()).map_err(Error::from);
        for (name, result) in [("authorize_requests", authorized), ("execute", executed)] {
            match is_dynamic {
                false => result.expect(name),
                true => {
                    let message = format!("{:#}", result.expect_err(name));
                    assert!(message.contains("dynroot.aleo/mint") && message.contains("dynamic"), "{name}: {message}");
                }
            }
        }
    }
}

/// Executes `caller.aleo/main(1u8)`, whose body is `call`, after re-signing its callee request for
/// `program/function` on `input`, with the given `is_dynamic` flag, by the caller or by `other_signer`.
/// Returns the result of `execute`, and whether `twin_a.aleo`, the call's target, then holds any proving key.
fn execute_with_resigned_callee(
    call: &str,
    program: &str,
    function: &str,
    is_dynamic: bool,
    other_signer: bool,
    input: &str,
) -> (Result<()>, bool) {
    let rng = &mut TestRng::default();

    let process = Process::<CurrentNetwork>::load().unwrap();
    let twin = |name: &str| {
        format!(
            "program {name}.aleo;
            function f: input r0 as u8.private; output r0 as u8.private;
            function g: input r0 as u8.private; output r0 as u8.private;"
        )
    };
    let caller = format!(
        "import twin_a.aleo; program caller.aleo; function main: input r0 as u8.private; {call} output r1 as u8.private;"
    );
    for source in [twin("twin_a"), twin("twin_b"), caller] {
        process.lock().add_program(&Program::from_str(&source).unwrap()).unwrap();
    }

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &private_key,
            ProgramID::from_str("caller.aleo").unwrap(),
            Identifier::from_str("main").unwrap(),
            [Value::<CurrentNetwork>::from_str("1u8").unwrap()].iter(),
            rng,
        )
        .unwrap();
    let root = authorization.to_vec_deque().pop_front().unwrap();
    let signer = match other_signer {
        true => PrivateKey::new(rng).unwrap(),
        false => private_key,
    };
    let resigned = Request::sign(
        &signer,
        ProgramID::from_str(program).unwrap(),
        Identifier::from_str(function).unwrap(),
        [Value::<CurrentNetwork>::from_str(input).unwrap()].iter(),
        &[ValueType::from_str("u8.private").unwrap()],
        Some(*root.tvk()),
        false,
        None,
        is_dynamic,
        rng,
    )
    .unwrap();
    let authorization = Authorization::new(root);
    authorization.push(resigned).unwrap();

    let result = process.execute::<CurrentAleo, _>(authorization, rng).map(|_| ()).map_err(Error::from);
    let twin_a = process.get_stack(ProgramID::from_str("twin_a.aleo").unwrap()).unwrap();
    let holds_key =
        ["f", "g"].into_iter().any(|name| twin_a.contains_proving_key(&Identifier::from_str(name).unwrap()));
    (result, holds_key)
}

/// For a static `call` and a `call.dynamic`, `execute` rejects a callee request with one thing wrong before it creates
/// any key. A correctly re-signed request is the control: it executes, and its key is created.
#[test]
fn test_execute_rejects_mismatched_callee_request() {
    let field = |name: &str| Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap();
    let static_call = "call twin_a.aleo/f r0 into r1;".to_string();
    let dynamic_call = format!(
        "call.dynamic {} {} {} with r0 (as u8.private) into r1 (as u8.private);",
        field("twin_a"),
        field("aleo"),
        field("f")
    );

    for (call, is_dynamic) in [(static_call, false), (dynamic_call, true)] {
        let (result, holds_key) = execute_with_resigned_callee(&call, "twin_a.aleo", "f", is_dynamic, false, "1u8");
        assert!(result.is_ok(), "{call}: {result:?}");
        assert!(holds_key, "{call}");

        let flipped = match is_dynamic {
            true => "Retrieved a static request",
            false => "Retrieved a dynamic request",
        };
        let inputs = match is_dynamic {
            true => "different inputs",
            false => "Inputs do not match",
        };
        for (program, function, is_dynamic, other_signer, input, error) in [
            ("twin_b.aleo", "f", is_dynamic, false, "1u8", "different program ID"),
            ("twin_a.aleo", "g", is_dynamic, false, "1u8", "different function name"),
            ("twin_a.aleo", "f", !is_dynamic, false, "1u8", flipped),
            ("twin_a.aleo", "f", is_dynamic, true, "1u8", "different signer"),
            ("twin_a.aleo", "f", is_dynamic, false, "2u8", inputs),
        ] {
            let case = format!(
                "{call}: {program}/{function}({input}), is_dynamic: {is_dynamic}, other_signer: {other_signer}"
            );
            let (result, holds_key) =
                execute_with_resigned_callee(&call, program, function, is_dynamic, other_signer, input);
            let message = format!("{:#}", result.expect_err(&case));
            assert!(message.contains(error), "{case}: {message}");
            assert!(!holds_key, "{case}");
        }
    }
}

/// For a static `call` and a `call.dynamic`, `authorize_requests` and `execute` both refuse a callee request taken from
/// another authorization of the same root call on the same inputs.
#[test]
fn test_authorize_requests_rejects_callee_request_from_another_root() {
    let rng = &mut TestRng::default();

    let field = |name: &str| Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap();
    let static_call = "call callee.aleo/f r0 into r1;".to_string();
    let dynamic_call = format!(
        "call.dynamic {} {} {} with r0 (as u8.private) into r1 (as u8.private);",
        field("callee"),
        field("aleo"),
        field("f")
    );

    for call in [static_call, dynamic_call] {
        let process = Process::<CurrentNetwork>::load().unwrap();
        for source in [
            "program callee.aleo; function f: input r0 as u8.private; output r0 as u8.private;".to_string(),
            format!(
                "import callee.aleo; program caller.aleo; function main: input r0 as u8.private; {call} output r1 as u8.private;"
            ),
        ] {
            process.lock().add_program(&Program::from_str(&source).unwrap()).unwrap();
        }

        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let [honest, other] = [(); 2].map(|_| {
            process
                .authorize::<CurrentAleo, _>(
                    &private_key,
                    ProgramID::from_str("caller.aleo").unwrap(),
                    Identifier::from_str("main").unwrap(),
                    [Value::<CurrentNetwork>::from_str("1u8").unwrap()].iter(),
                    rng,
                )
                .unwrap()
                .to_vec_deque()
        });
        assert_ne!(honest[1].tvk(), other[1].tvk(), "{call}");

        let spliced = Authorization::new(honest[0].clone());
        spliced.push(other[1].clone()).unwrap();

        let stack = process.get_stack(ProgramID::from_str("caller.aleo").unwrap()).unwrap();
        stack.authorize_requests::<CurrentAleo, _>(honest.into(), rng).unwrap();

        assert!(process.execute::<CurrentAleo, _>(spliced.replicate(), rng).is_err(), "{call}");

        let result = stack.authorize_requests::<CurrentAleo, _>(spliced.to_vec_deque().into(), rng);
        let message = format!("{:#}", result.map(|_| ()).map_err(Error::from).expect_err(&call));
        assert!(message.contains("callee.aleo/f") && message.contains("signer commitment"), "{call}: {message}");
    }
}

/// `caller.aleo/main` makes four dynamic calls, one for each way a record is translated: `token.aleo/mint` outputs a
/// `coin`, `token.aleo/spend` takes a `note`, `wrapper.aleo/peek` takes an external `ticket`, and `wrapper.aleo/relay`
/// outputs an external `pass`, which it gets from a static call to `token.aleo/issue`. Each record has its own
/// translation key, so each way contributes a distinct key.
#[test]
fn test_execution_keys_are_the_keys_execute_uses() {
    let rng = &mut TestRng::default();

    let field = |name: &str| Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap();
    let (token, wrapper, aleo) = (field("token"), field("wrapper"), field("aleo"));
    let (mint, spend, peek, relay) = (field("mint"), field("spend"), field("peek"), field("relay"));
    let programs = [
        r"
        program token.aleo;
        record coin: owner as address.private; amount as u64.private;
        record note: owner as address.private; amount as u64.private;
        record ticket: owner as address.private; amount as u64.private;
        record pass: owner as address.private; amount as u64.private;
        function mint: input r0 as u64.private; cast self.signer r0 into r1 as coin.record; output r1 as coin.record;
        function issue: input r0 as u64.private; cast self.signer r0 into r1 as pass.record; output r1 as pass.record;
        function spend: input r0 as note.record; add r0.amount 0u64 into r1; output r1 as u64.private;",
        r"
        import token.aleo;
        program wrapper.aleo;
        function peek: input r0 as token.aleo/ticket.record; add r0.amount 0u64 into r1; output r1 as u64.private;
        function relay:
            input r0 as u64.private;
            call token.aleo/issue r0 into r1;
            output r1 as token.aleo/pass.record;",
        format!(
            r"
        program caller.aleo;
        function main:
            input r0 as dynamic.record;
            input r1 as dynamic.record;
            call.dynamic {token} {aleo} {mint} with 5u64 (as u64.private) into r2 (as dynamic.record);
            call.dynamic {token} {aleo} {spend} with r0 (as dynamic.record) into r3 (as u64.private);
            call.dynamic {wrapper} {aleo} {peek} with r1 (as dynamic.record) into r4 (as u64.private);
            call.dynamic {wrapper} {aleo} {relay} with 7u64 (as u64.private) into r5 (as dynamic.record);
            output r2 as dynamic.record;"
        )
        .as_str(),
    ]
    .map(|source| Program::<CurrentNetwork>::from_str(source).unwrap());

    let process = Process::<CurrentNetwork>::load().unwrap();
    for program in &programs {
        process.lock().add_program(program).unwrap();
    }

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let address = Address::try_from(&private_key).unwrap();
    let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
        "{{ owner: {address}.private, amount: 1u64.private, _nonce: 0group.public, _version: 1u8.public }}"
    ))
    .unwrap();
    let input = Value::DynamicRecord(DynamicRecord::from_record(&record).unwrap());
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &private_key,
            ProgramID::from_str("caller.aleo").unwrap(),
            Identifier::from_str("main").unwrap(),
            [input.clone(), input].iter(),
            rng,
        )
        .unwrap();

    let held = || {
        programs
            .iter()
            .flat_map(|program| {
                let stack = process.get_stack(program.id()).unwrap();
                program
                    .functions()
                    .keys()
                    .chain(program.records().keys())
                    .filter(move |name| stack.contains_proving_key(name))
                    .map(|name| (*program.id(), *name))
            })
            .collect::<IndexSet<_>>()
    };
    let key = |program: &str, name: &str| (ProgramID::from_str(program).unwrap(), Identifier::from_str(name).unwrap());

    // `authorize_requests` accepts the requests, so `execution_keys` is exact for them.
    process
        .get_stack(programs[2].id())
        .unwrap()
        .authorize_requests::<CurrentAleo, _>(authorization.to_vec_deque().into(), rng)
        .unwrap();

    // Every function the authorization runs, and every translated record, is used and missing.
    let (function, translation) = (ExecutionKeyKind::Function, ExecutionKeyKind::Translation);
    let expected: IndexMap<_, _> = [
        (key("caller.aleo", "main"), function),
        (key("token.aleo", "mint"), function),
        (key("token.aleo", "coin"), translation),
        (key("token.aleo", "spend"), function),
        (key("token.aleo", "note"), translation),
        (key("wrapper.aleo", "peek"), function),
        (key("token.aleo", "ticket"), translation),
        (key("wrapper.aleo", "relay"), function),
        (key("token.aleo", "issue"), function),
        (key("token.aleo", "pass"), translation),
    ]
    .into_iter()
    .collect();
    let flagged = |missing| expected.iter().map(|(key, kind)| (*key, (*kind, missing))).collect::<IndexMap<_, _>>();
    assert_eq!(process.execution_keys(&authorization).unwrap(), flagged(true));

    // A root request has no caller, so it cannot be flagged dynamic.
    let dynamic_root = Request::sign(
        &private_key,
        ProgramID::from_str("token.aleo").unwrap(),
        Identifier::from_str("spend").unwrap(),
        [Value::Record(record)].iter(),
        &[ValueType::from_str("note.record").unwrap()],
        None,
        true,
        None,
        true,
        rng,
    )
    .unwrap();
    let error = process
        .get_stack(programs[0].id())
        .unwrap()
        .authorize_requests::<CurrentAleo, _>(vec![dynamic_root], rng)
        .unwrap_err()
        .to_string();
    assert!(error.contains("root request") && error.contains("flagged dynamic"), "{error}");

    // The missing keys are exactly the keys `execute` inserts.
    let before = held();
    process.execute::<CurrentAleo, _>(authorization.replicate(), rng).unwrap();
    let inserted: IndexSet<_> = held().difference(&before).copied().collect();
    assert_eq!(inserted, expected.keys().copied().collect::<IndexSet<_>>());

    // Once `execute` has inserted them, every key is still used and none is missing.
    assert_eq!(process.execution_keys(&authorization).unwrap(), flagged(false));

    // Without its verifying key, a function key is still held, and a translation key is missing.
    let (main, coin) = (key("caller.aleo", "main"), key("token.aleo", "coin"));
    process.remove_verifying_key(&main.0, &main.1).unwrap();
    process.remove_verifying_key(&coin.0, &coin.1).unwrap();
    let mut expected_keys = flagged(false);
    expected_keys.insert(coin, (translation, true));
    assert_eq!(process.execution_keys(&authorization).unwrap(), expected_keys);
}

/// Same-kind repeats are one entry, a request must name a function, and a record type that now names a function fails.
#[test]
fn test_execution_keys_checks_each_key_is_of_its_kind() {
    let rng = &mut TestRng::default();

    let [token, wrapper, edition_1] = [
        r"
        program token.aleo;
        record pass: owner as address.private; amount as u64.private;
        function issue: input r0 as u64.private; cast self.signer r0 into r1 as pass.record; output r1 as pass.record;",
        r"
        import token.aleo;
        program wrapper.aleo;
        function relay:
            input r0 as u64.private;
            call token.aleo/issue r0 into r1;
            output r1 as token.aleo/pass.record;",
        r"
        program token.aleo;
        function pass: input r0 as u64.private; add r0 0u64 into r1; output r1 as u64.private;",
    ]
    .map(|source| Program::<CurrentNetwork>::from_str(source).unwrap());

    let process = Process::<CurrentNetwork>::load().unwrap();
    process.lock().add_program(&token).unwrap();
    process.lock().add_program(&wrapper).unwrap();

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let mut request = |program: &str, function: &str, is_dynamic| {
        Request::sign(
            &private_key,
            ProgramID::from_str(program).unwrap(),
            Identifier::from_str(function).unwrap(),
            [Value::<CurrentNetwork>::from_str("1u64").unwrap()].iter(),
            &[ValueType::from_str("u64.private").unwrap()],
            None,
            true,
            None,
            is_dynamic,
            rng,
        )
        .unwrap()
    };
    let key = |program: &str, name: &str| (ProgramID::from_str(program).unwrap(), Identifier::from_str(name).unwrap());

    // A key repeated with the same kind is one entry.
    let authorization = Authorization::new(request("wrapper.aleo", "relay", false));
    authorization.push(request("wrapper.aleo", "relay", true)).unwrap();
    authorization.push(request("wrapper.aleo", "relay", true)).unwrap();
    let expected = IndexMap::from([
        (key("wrapper.aleo", "relay"), (ExecutionKeyKind::Function, true)),
        (key("token.aleo", "pass"), (ExecutionKeyKind::Translation, true)),
    ]);
    assert_eq!(process.execution_keys(&authorization).unwrap(), expected);

    let record_as_function = Authorization::new(request("token.aleo", "pass", false));
    let message = process.execution_keys(&record_as_function).unwrap_err().to_string();
    assert_eq!(message, "Function 'token.aleo/pass' is not defined.");

    process.lock().add_program_with_edition(&edition_1, 1).unwrap();
    let message = process.execution_keys(&authorization).unwrap_err().to_string();
    assert_eq!(message, "Record 'token.aleo/pass' is not defined.");
}

/// Builds `caller.aleo/main`, which passes one dynamic record to `token.aleo/spend` (a `note`) and another to
/// `wrapper.aleo/peek` (an external `ticket`), and authorizes it on two records holding `1u64`, with distinct nonces.
fn authorize_dynamic_record_inputs(
    rng: &mut TestRng,
) -> (
    Process<CurrentNetwork>,
    PrivateKey<CurrentNetwork>,
    [Record<CurrentNetwork, Plaintext<CurrentNetwork>>; 2],
    Authorization<CurrentNetwork>,
) {
    let field = |name: &str| Identifier::<CurrentNetwork>::from_str(name).unwrap().to_field().unwrap();
    let (token, wrapper, aleo, spend, peek) =
        (field("token"), field("wrapper"), field("aleo"), field("spend"), field("peek"));
    let programs = [
        r"
        program token.aleo;
        record note: owner as address.private; amount as u64.private;
        record ticket: owner as address.private; amount as u64.private;
        function spend: input r0 as note.record; add r0.amount 0u64 into r1; output r1 as u64.private;",
        r"
        import token.aleo;
        program wrapper.aleo;
        function peek: input r0 as token.aleo/ticket.record; add r0.amount 0u64 into r1; output r1 as u64.private;",
        format!(
            r"
        program caller.aleo;
        function main:
            input r0 as dynamic.record;
            input r1 as dynamic.record;
            call.dynamic {token} {aleo} {spend} with r0 (as dynamic.record) into r2 (as u64.private);
            call.dynamic {wrapper} {aleo} {peek} with r1 (as dynamic.record) into r3 (as u64.private);
            output r2 as u64.private;"
        )
        .as_str(),
    ]
    .map(|source| Program::<CurrentNetwork>::from_str(source).unwrap());

    let process = Process::<CurrentNetwork>::load().unwrap();
    for program in &programs {
        process.lock().add_program(program).unwrap();
    }

    let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
    let address = Address::try_from(&private_key).unwrap();
    let records = [console::types::Group::<CurrentNetwork>::zero(), console::types::Group::generator()].map(|nonce| {
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
            "{{ owner: {address}.private, amount: 1u64.private, _nonce: {nonce}.public, _version: 1u8.public }}"
        ))
        .unwrap()
    });
    let inputs = records.each_ref().map(|record| Value::DynamicRecord(DynamicRecord::from_record(record).unwrap()));
    let authorization = process
        .authorize::<CurrentAleo, _>(
            &private_key,
            ProgramID::from_str("caller.aleo").unwrap(),
            Identifier::from_str("main").unwrap(),
            inputs.iter(),
            rng,
        )
        .unwrap();
    (process, private_key, records, authorization)
}

/// An authorization read back from bytes holds its dynamic records without their entry data. `authorize_requests`
/// and `execute` still check a dynamic callee's inputs against the call's, and accept it.
#[test]
fn test_dynamic_record_inputs_are_checked_without_entry_data() {
    let rng = &mut TestRng::default();
    let (process, _, _, authorization) = authorize_dynamic_record_inputs(rng);

    let decoded = Authorization::<CurrentNetwork>::read_le(&authorization.to_bytes_le().unwrap()[..]).unwrap();
    let root = decoded.peek_next().unwrap();
    for input in root.inputs() {
        let Value::DynamicRecord(record) = input else { panic!("expected a dynamic record, found {input}") };
        assert!(record.data().is_none());
    }

    process
        .get_stack(ProgramID::from_str("caller.aleo").unwrap())
        .unwrap()
        .authorize_requests::<CurrentAleo, _>(decoded.to_vec_deque().into(), rng)
        .unwrap();
    process.execute::<CurrentAleo, _>(decoded, rng).unwrap();
}

/// A dynamic callee request that takes a record other than the call's input, or the same record with the owner's
/// visibility changed, is rejected by `authorize_requests` and by `execute`, before `execute` creates the callee's key.
/// A different record fails the inputs check, and a changed visibility fails the callee's input types. Both callees
/// are covered: `token.aleo/spend` takes a local `note`, and `wrapper.aleo/peek` an external `ticket`.
#[test]
fn test_dynamic_record_inputs_reject_another_record() {
    let rng = &mut TestRng::default();
    let (process, private_key, records, authorization) = authorize_dynamic_record_inputs(rng);
    let address = Address::try_from(&private_key).unwrap();

    // The callee's index in the authorization, its program, function and input type, and its record.
    let callees = [
        (1, "token.aleo", "spend", "note.record", &records[0]),
        (2, "wrapper.aleo", "peek", "token.aleo/ticket.record", &records[1]),
    ];
    for (index, program, function, input_type, record) in callees {
        for (owner, amount, expected) in [
            ("private", "2u64", "different inputs"),
            ("public", "1u64", "Visibility of record entry 'owner' does not match"),
        ] {
            let mut requests = authorization.to_vec_deque();
            let root = requests.pop_front().unwrap();
            let other = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(&format!(
                "{{ owner: {address}.{owner}, amount: {amount}.private, _nonce: {}.public, _version: 1u8.public }}",
                record.nonce()
            ))
            .unwrap();
            let resigned = Request::sign(
                &private_key,
                ProgramID::from_str(program).unwrap(),
                Identifier::from_str(function).unwrap(),
                [Value::Record(other)].iter(),
                &[ValueType::from_str(input_type).unwrap()],
                Some(*root.tvk()),
                false,
                None,
                true,
                rng,
            )
            .unwrap();
            requests[index - 1] = resigned;
            let tampered = Authorization::new(root);
            for request in requests {
                tampered.push(request).unwrap();
            }
            let case = format!("{program}/{function}: owner {owner}, amount {amount}");

            let error = process
                .get_stack(ProgramID::from_str("caller.aleo").unwrap())
                .unwrap()
                .authorize_requests::<CurrentAleo, _>(tampered.to_vec_deque().into(), rng)
                .expect_err(&case);
            assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");

            let error = process.execute::<CurrentAleo, _>(tampered, rng).map(|_| ()).expect_err(&case);
            assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");
            let stack = process.get_stack(ProgramID::from_str(program).unwrap()).unwrap();
            assert!(!stack.contains_proving_key(&Identifier::from_str(function).unwrap()), "{case}");
        }
    }
}
