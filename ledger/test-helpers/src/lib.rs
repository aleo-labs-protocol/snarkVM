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

extern crate snarkvm_circuit as circuit;
extern crate snarkvm_console as console;

use console::{
    account::{Address, PrivateKey},
    prelude::*,
    program::{Ciphertext, Literal, Plaintext, ProgramOwner, Record, Value},
    types::Field,
};
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_ledger_block::{
    Block,
    ConfirmedTransaction,
    Deployment,
    Execution,
    Fee,
    Header,
    Input,
    Output,
    Ratifications,
    Rejected,
    Transaction,
    Transactions,
    Transition,
};
use snarkvm_ledger_query::Query;
use snarkvm_ledger_store::{BlockStore, helpers::memory::BlockMemory};
use snarkvm_synthesizer_process::Process;
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::PrettyUnwrap;

use aleo_std::StorageMode;
use anyhow::Context;
use std::sync::OnceLock;

type CurrentNetwork = console::network::MainnetV0;
type CurrentAleo = circuit::network::AleoV0;

/****************************************** Transition ********************************************/

/// Samples a random transition.
pub fn sample_transition(rng: &mut TestRng) -> Transition<CurrentNetwork> {
    crate::sample_execution(rng, 0).into_transitions().next().unwrap()
}

/// Sample the transition inputs.
pub fn sample_inputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Input<CurrentNetwork>)> {
    let rng = &mut TestRng::default();

    // Sample a transition.
    let transaction = crate::sample_execution_transaction_with_fee(true, rng, 0);
    let transition = transaction.transitions().next().unwrap();

    // Retrieve the transition ID and input.
    let transition_id = *transition.id();
    let input = transition.inputs().iter().next().unwrap().clone();

    // Sample a random plaintext.
    let plaintext = Plaintext::Literal(Literal::Field(Uniform::rand(rng)), Default::default());
    let plaintext_hash = CurrentNetwork::hash_bhp1024(&plaintext.to_bits_le()).unwrap();
    // Sample a random ciphertext.
    let fields: Vec<_> = (0..10).map(|_| Uniform::rand(rng)).collect();
    let ciphertext = Ciphertext::from_fields(&fields).unwrap();
    let ciphertext_hash = CurrentNetwork::hash_bhp1024(&ciphertext.to_bits_le()).unwrap();

    vec![
        (transition_id, input),
        (Uniform::rand(rng), Input::Constant(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Input::Constant(plaintext_hash, Some(plaintext.clone()))),
        (Uniform::rand(rng), Input::Public(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Input::Public(plaintext_hash, Some(plaintext))),
        (Uniform::rand(rng), Input::Private(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Input::Private(ciphertext_hash, Some(ciphertext))),
        (Uniform::rand(rng), Input::Record(Uniform::rand(rng), Uniform::rand(rng))),
        (Uniform::rand(rng), Input::ExternalRecord(Uniform::rand(rng))),
    ]
}

/// Sample the transition outputs.
pub fn sample_outputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Output<CurrentNetwork>)> {
    let rng = &mut TestRng::default();

    // Sample a transition.
    let transaction = crate::sample_execution_transaction_with_fee(true, rng, 0);
    let transition = transaction.transitions().next().unwrap();

    // Retrieve the transition ID and input.
    let transition_id = *transition.id();
    let input = transition.outputs().iter().next().unwrap().clone();

    // Sample a random plaintext.
    let plaintext = Plaintext::Literal(Literal::Field(Uniform::rand(rng)), Default::default());
    let plaintext_hash = CurrentNetwork::hash_bhp1024(&plaintext.to_bits_le()).unwrap();
    // Sample a random ciphertext.
    let fields: Vec<_> = (0..10).map(|_| Uniform::rand(rng)).collect();
    let ciphertext = Ciphertext::from_fields(&fields).unwrap();
    let ciphertext_hash = CurrentNetwork::hash_bhp1024(&ciphertext.to_bits_le()).unwrap();
    // Sample a random record.
    let randomizer = Uniform::rand(rng);
    let nonce = CurrentNetwork::g_scalar_multiply(&randomizer);
    let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_str(
        &format!("{{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, token_amount: 100u64.private, _nonce: {nonce}.public }}"),
    ).unwrap();
    let record_ciphertext = record.encrypt(randomizer).unwrap();
    let record_checksum = CurrentNetwork::hash_bhp1024(&record_ciphertext.to_bits_le()).unwrap();
    // Sample a sender ciphertext.
    let sender_ciphertext = match record_ciphertext.version().is_zero() {
        true => None,
        false => Some(Uniform::rand(rng)),
    };

    vec![
        (transition_id, input),
        (Uniform::rand(rng), Output::Constant(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Output::Constant(plaintext_hash, Some(plaintext.clone()))),
        (Uniform::rand(rng), Output::Public(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Output::Public(plaintext_hash, Some(plaintext))),
        (Uniform::rand(rng), Output::Private(Uniform::rand(rng), None)),
        (Uniform::rand(rng), Output::Private(ciphertext_hash, Some(ciphertext.clone()))),
        (Uniform::rand(rng), Output::Record(Uniform::rand(rng), Uniform::rand(rng), None, sender_ciphertext)),
        (
            Uniform::rand(rng),
            Output::Record(Uniform::rand(rng), record_checksum, Some(record_ciphertext.clone()), sender_ciphertext),
        ),
        (Uniform::rand(rng), Output::ExternalRecord(Uniform::rand(rng))),
        // RecordWithDynamicID with record ciphertext.
        (
            Uniform::rand(rng),
            Output::RecordWithDynamicID(
                Uniform::rand(rng),
                record_checksum,
                Some(record_ciphertext),
                sender_ciphertext,
                Uniform::rand(rng),
            ),
        ),
        // RecordWithDynamicID without record ciphertext.
        (
            Uniform::rand(rng),
            Output::RecordWithDynamicID(
                Uniform::rand(rng),
                Uniform::rand(rng),
                None,
                sender_ciphertext,
                Uniform::rand(rng),
            ),
        ),
        // ExternalRecordWithDynamicID.
        (Uniform::rand(rng), Output::ExternalRecordWithDynamicID(Uniform::rand(rng), Uniform::rand(rng))),
    ]
}

/******************************************* Deployment *******************************************/

pub fn sample_deployment_v1(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    static INSTANCE: OnceLock<Deployment<CurrentNetwork>> = OnceLock::new();
    let deployment = INSTANCE
        .get_or_init(|| {
            // Initialize a new program.
            let (string, program) = Program::<CurrentNetwork>::parse(
                r"
program testing_one.aleo;

mapping store:
    key as u32.public;
    value as u32.public;

function compute:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
            )
            .unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            // Construct the process.
            let process = Process::load().unwrap();
            // Compute the deployment.
            let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
            // Return the deployment.
            // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
            Deployment::from_str(&deployment.to_string()).unwrap()
        })
        .clone();
    // Create a new deployment with the desired edition.
    Deployment::<CurrentNetwork>::new(
        edition % 2,
        deployment.program().clone(),
        deployment.verifying_keys().clone(),
        None,
        None,
    )
    .unwrap()
}

pub fn sample_deployment_v2_without_translation_keys(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    static INSTANCE: OnceLock<Deployment<CurrentNetwork>> = OnceLock::new();
    let deployment = INSTANCE
        .get_or_init(|| {
            // Initialize a new program.
            let (string, program) = Program::<CurrentNetwork>::parse(
                r"
program testing_two.aleo;

mapping store:
    key as u32.public;
    value as u32.public;

function compute:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
            )
            .unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            // Construct the process.
            let process = Process::load().unwrap();
            // Compute the deployment.
            let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
            // Return the deployment.
            // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
            Deployment::from_str(&deployment.to_string()).unwrap()
        })
        .clone();
    // Create a new deployment with the desired edition.
    Deployment::<CurrentNetwork>::new(
        edition,
        deployment.program().clone(),
        deployment.verifying_keys().clone(),
        deployment.program_checksum(),
        Some(Address::rand(rng)),
    )
    .unwrap()
}

pub fn sample_deployment_v2_with_translation_keys(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    static INSTANCE: OnceLock<Deployment<CurrentNetwork>> = OnceLock::new();
    let deployment = INSTANCE
        .get_or_init(|| {
            // Initialize a new program.
            let (string, program) = Program::<CurrentNetwork>::parse(
                r"
program testing_three.aleo;

record data:
    owner as address.private;
    one as field.private;
    two as group.public;

mapping store:
    key as u32.public;
    value as u32.public;

function compute:
    input r0 as u32.private;
    add r0 r0 into r1;
    output r1 as u32.public;",
            )
            .unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            // Construct the process.
            let process = Process::load().unwrap();
            // Compute the deployment.
            let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
            // Return the deployment.
            // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
            Deployment::from_str(&deployment.to_string()).unwrap()
        })
        .clone();
    // Create a new deployment with the desired edition.
    Deployment::<CurrentNetwork>::new(
        edition,
        deployment.program().clone(),
        deployment.verifying_keys().clone(),
        deployment.program_checksum(),
        Some(Address::rand(rng)),
    )
    .unwrap()
}

/// Samples a V3 deployment (amendment) for the same program as V2 without translation keys.
/// The edition must match an existing deployment's edition.
/// V3 = checksum + no owner.
pub fn sample_deployment_v3(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    // Sample a V2 deployment without translation keys, then remove the owner to make it V3.
    let mut deployment = sample_deployment_v2_without_translation_keys(edition, rng);
    deployment.set_program_owner_raw(None);
    deployment
}

/// Samples a rejected deployment.
pub fn sample_rejected_deployment(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    is_fee_private: bool,
    rng: &mut TestRng,
) -> Rejected<CurrentNetwork> {
    // Sample a deploy transaction.
    let deployment =
        match crate::sample_deployment_transaction(version, edition, has_translation_keys, is_fee_private, rng) {
            Transaction::Deploy(_, _, _, deployment, _) => (*deployment).clone(),
            _ => unreachable!(),
        };

    // Sample a new program owner.
    let private_key = PrivateKey::new(rng).unwrap();
    let deployment_id = deployment.to_deployment_id().unwrap();
    let program_owner = ProgramOwner::new(&private_key, deployment_id, rng).unwrap();

    // Return the rejected deployment.
    Rejected::new_deployment(program_owner, deployment)
}

/******************************************* Execution ********************************************/

/// Samples a random execution.
pub fn sample_execution(rng: &mut TestRng, index: usize) -> Execution<CurrentNetwork> {
    // Sample the genesis block.
    let block = crate::sample_genesis_block(rng);
    // Retrieve a transaction.
    let transaction = block.transactions().iter().nth(index).unwrap().deref().clone();
    // Retrieve the execution.
    if let Transaction::Execute(_, _, execution, _) = transaction {
        *execution
    } else {
        panic!("Index {index} exceeded the number of executions in the genesis block")
    }
}

/// Samples a rejected execution.
pub fn sample_rejected_execution(is_fee_private: bool, rng: &mut TestRng) -> Rejected<CurrentNetwork> {
    // Sample an execute transaction.
    let execution = match crate::sample_execution_transaction_with_fee(is_fee_private, rng, 0) {
        Transaction::Execute(_, _, execution, _) => execution,
        _ => unreachable!(),
    };

    // Return the rejected execution.
    Rejected::new_execution(*execution)
}

/********************************************** Fee ***********************************************/

/// Samples a random hardcoded private fee.
pub fn sample_fee_private_hardcoded(rng: &mut TestRng) -> Fee<CurrentNetwork> {
    static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            // Sample a deployment or execution ID.
            let deployment_or_execution_id = Field::rand(rng);
            // Sample a fee.
            sample_fee_private(deployment_or_execution_id, rng)
        })
        .clone()
}

/// Samples a random private fee.
pub fn sample_fee_private(deployment_or_execution_id: Field<CurrentNetwork>, rng: &mut TestRng) -> Fee<CurrentNetwork> {
    // Sample the genesis block, transaction, and private key.
    let (block, transactions, private_key) = crate::sample_genesis_block_and_components(rng);
    // Retrieve a credits record.
    let credits = transactions.iter().next().unwrap().records().next().unwrap().1.clone();
    // Decrypt the record.
    let credits = credits.decrypt(&private_key.try_into().unwrap()).unwrap();
    // Sample a base fee in microcredits.
    let base_fee_in_microcredits = 10_000_000;
    // Sample a priority fee in microcredits.
    let priority_fee_in_microcredits = 1_000;

    // Initialize the process.
    let process = Process::load().unwrap();
    // Authorize the fee.
    let authorization = process
        .authorize_fee_private::<CurrentAleo, _>(
            &private_key,
            credits,
            base_fee_in_microcredits,
            priority_fee_in_microcredits,
            deployment_or_execution_id,
            rng,
        )
        .unwrap();
    // Construct the fee trace.
    let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Insert the block into the block store.
    // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
    block_store.insert(&FromStr::from_str(&block.to_string()).unwrap()).unwrap();

    // Prepare the assignments.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Compute the proof and construct the fee.
    let fee = trace.prove_fee::<CurrentAleo, _>(VarunaVersion::V1, rng).unwrap();

    // Convert the fee.
    // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
    Fee::from_str(&fee.to_string()).unwrap()
}

/// Samples a random hardcoded public fee.
pub fn sample_fee_public_hardcoded(rng: &mut TestRng) -> Fee<CurrentNetwork> {
    static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            // Sample a deployment or execution ID.
            let deployment_or_execution_id = Field::rand(rng);
            // Sample a fee.
            sample_fee_public(deployment_or_execution_id, rng)
        })
        .clone()
}

/// Samples a random public fee.
pub fn sample_fee_public(deployment_or_execution_id: Field<CurrentNetwork>, rng: &mut TestRng) -> Fee<CurrentNetwork> {
    // Sample the genesis block, transaction, and private key.
    let (block, _, private_key) = crate::sample_genesis_block_and_components(rng);
    // Sample a base fee in microcredits.
    let base_fee_in_microcredits = 10_000_000;
    // Sample a priority fee in microcredits.
    let priority_fee_in_microcredits = 1_000;

    // Initialize the process.
    let process = Process::load().unwrap();
    // Authorize the fee.
    let authorization = process
        .authorize_fee_public::<CurrentAleo, _>(
            &private_key,
            base_fee_in_microcredits,
            priority_fee_in_microcredits,
            deployment_or_execution_id,
            rng,
        )
        .unwrap();
    // Construct the fee trace.
    let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

    // Initialize a new block store.
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();
    // Insert the block into the block store.
    // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
    block_store.insert(&FromStr::from_str(&block.to_string()).unwrap()).unwrap();

    // Prepare the assignments.
    trace.prepare(&Query::from(block_store)).unwrap();
    // Compute the proof and construct the fee.
    let fee = trace.prove_fee::<CurrentAleo, _>(VarunaVersion::V1, rng).unwrap();

    // Convert the fee.
    // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
    Fee::from_str(&fee.to_string()).unwrap()
}

/******************************************** Program *********************************************/

/// Deploy a program that produces large transactions under the maximum transaction size.
pub fn small_transaction_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program testing_small.aleo;
function small_transaction:
    cast 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field into r0 as [field; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [[field; 32u32]; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r2 as [[field; 32u32]; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r3 as [[field; 32u32]; 32u32];
    output r1 as [[field; 32u32]; 32u32].public;
    output r2 as [[field; 32u32]; 32u32].public;
    output r3 as [[field; 32u32]; 32u32].public;").unwrap()
}

/// Deploy a program that produces large transactions above the maximum transaction size.
pub fn large_transaction_program() -> Program<CurrentNetwork> {
    Program::from_str(
        r"
program testing_large.aleo;
function large_transaction:
    cast 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field 0field into r0 as [field; 32u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r1 as [[field; 32u32]; 27u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r2 as [[field; 32u32]; 27u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r3 as [[field; 32u32]; 27u32];
    cast r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 r0 into r4 as [[field; 32u32]; 27u32];
    output r1 as [[field; 32u32]; 27u32].public;
    output r2 as [[field; 32u32]; 27u32].public;
    output r3 as [[field; 32u32]; 27u32].public;
    output r4 as [[field; 32u32]; 27u32].public;").unwrap()
}

/****************************************** Transaction *******************************************/

/// Samples a random deployment transaction with a private or public fee.
pub fn sample_deployment_transaction(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    is_fee_private: bool,
    rng: &mut TestRng,
) -> Transaction<CurrentNetwork> {
    // Sample a private key.
    let private_key = PrivateKey::new(rng).unwrap();
    // Sample a deployment.
    let deployment = match (version, has_translation_keys) {
        (1, false) => sample_deployment_v1(edition, rng),
        (2, false) => {
            let mut deployment = sample_deployment_v2_without_translation_keys(edition, rng);
            // Set the program owner to the address of the private key.
            deployment.set_program_owner_raw(Some(Address::try_from(&private_key).unwrap()));
            deployment
        }
        (2, true) => {
            let mut deployment = sample_deployment_v2_with_translation_keys(edition, rng);
            // Set the program owner to the address of the private key.
            deployment.set_program_owner_raw(Some(Address::try_from(&private_key).unwrap()));
            deployment
        }
        (3, _) => {
            // V3 is an amendment - uses the same program as V2 but with additional translation VKs and no program_owner.
            sample_deployment_v3(edition, rng)
        }
        _ => panic!("Invalid deployment version ({version}) or translation keys combination."),
    };

    // Compute the deployment ID.
    let deployment_id = deployment.to_deployment_id().unwrap();
    // Construct a program owner.
    let owner = ProgramOwner::new(&private_key, deployment_id, rng).unwrap();

    // Sample the fee.
    let fee = match is_fee_private {
        true => crate::sample_fee_private(deployment_id, rng),
        false => crate::sample_fee_public(deployment_id, rng),
    };

    // Construct a deployment transaction.
    Transaction::from_deployment(owner, deployment, fee).unwrap()
}

/// Samples a random execution transaction with a private or public fee.
pub fn sample_execution_transaction_with_fee(
    is_fee_private: bool,
    rng: &mut TestRng,
    index: usize,
) -> Transaction<CurrentNetwork> {
    // Sample an execution.
    let execution = crate::sample_execution(rng, index);
    // Compute the execution ID.
    let execution_id = execution.to_execution_id().unwrap();

    // Sample the fee.
    let fee = match is_fee_private {
        true => crate::sample_fee_private(execution_id, rng),
        false => crate::sample_fee_public(execution_id, rng),
    };

    // Construct an execution transaction.
    Transaction::from_execution(execution, Some(fee)).unwrap()
}

/// Samples a large transaction.
pub fn sample_large_execution_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
    static INSTANCE: std::sync::OnceLock<Execution<CurrentNetwork>> = std::sync::OnceLock::new();

    let execution = INSTANCE
        .get_or_init(|| {
            // Initialize a program that produces large transactions.
            let program = large_transaction_program();

            // Construct the process.
            let process = snarkvm_synthesizer_process::Process::load().unwrap();
            // Add the program.
            process.lock().add_program(&program).unwrap();

            // Initialize a private key.
            let private_key = PrivateKey::new(rng).unwrap();

            // Authorize the function.
            let authorization = process
                .authorize::<CurrentAleo, _>(
                    &private_key,
                    "testing_large.aleo",
                    "large_transaction",
                    Vec::<Value<CurrentNetwork>>::new().iter(),
                    rng,
                )
                .unwrap();
            // Execute the function.
            let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

            // Initialize a new block store.
            let block_store = snarkvm_ledger_store::BlockStore::<
                CurrentNetwork,
                snarkvm_ledger_store::helpers::memory::BlockMemory<_>,
            >::open(StorageMode::new_test(None))
            .unwrap();

            // Prepare the assignments.
            trace.prepare(&snarkvm_ledger_query::Query::from(block_store)).unwrap();
            // Compute the proof and construct the execution.
            let execution = trace.prove_execution::<CurrentAleo, _>("testing.aleo", VarunaVersion::V1, rng).unwrap();
            // Reconstruct the execution from bytes.
            // This is a hack to get around Rust dependency resolution.
            Execution::from_bytes_le(&execution.to_bytes_le().unwrap()).unwrap()
        })
        .clone();

    // Compute the execution ID.
    let execution_id = execution.to_execution_id().unwrap();

    // Sample the fee.
    let fee = crate::sample_fee_public(execution_id, rng);

    // Construct an execution transaction.
    Transaction::from_execution(execution, Some(fee)).unwrap()
}

/// Samples a random private fee transaction.
pub fn sample_fee_private_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
    // Sample a private fee.
    let fee = crate::sample_fee_private_hardcoded(rng);
    // Construct a fee transaction.
    Transaction::from_fee(fee).unwrap()
}

/// Samples a random public fee transaction.
pub fn sample_fee_public_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
    // Sample a public fee.
    let fee = crate::sample_fee_public_hardcoded(rng);
    // Construct a fee transaction.
    Transaction::from_fee(fee).unwrap()
}

/****************************************** Transactions ******************************************/

/// Samples a block transactions.
pub fn sample_block_transactions(rng: &mut TestRng) -> Transactions<CurrentNetwork> {
    crate::sample_genesis_block(rng).transactions().clone()
}

/********************************************* Block **********************************************/

/// Samples a random genesis block.
pub fn sample_genesis_block(rng: &mut TestRng) -> Block<CurrentNetwork> {
    // Sample the genesis block and components.
    let (block, _, _) = crate::sample_genesis_block_and_components(rng);
    // Return the block.
    block
}

/// Samples a random genesis block and the transactions from the genesis block.
pub fn sample_genesis_block_and_transactions(
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>) {
    // Sample the genesis block and components.
    let (block, transactions, _) = crate::sample_genesis_block_and_components(rng);
    // Return the block and transactions.
    (block, transactions)
}

/// Samples a random genesis block, the transactions from the genesis block, and the genesis private key.
/// If this function was called before, this returns a cached version.
pub fn sample_genesis_block_and_components(
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
    static INSTANCE: OnceLock<(Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>)> =
        OnceLock::new();
    INSTANCE.get_or_init(|| crate::sample_genesis_block_and_components_uncached(rng)).clone()
}

pub fn sample_genesis_private_key(rng: &mut TestRng) -> PrivateKey<CurrentNetwork> {
    static INSTANCE: OnceLock<PrivateKey<CurrentNetwork>> = OnceLock::new();
    *INSTANCE.get_or_init(|| {
        // Initialize a new caller.
        PrivateKey::<CurrentNetwork>::new(rng).unwrap()
    })
}

/// Samples a random genesis block, the transactions from the genesis block, and the genesis private key.
pub fn sample_genesis_block_and_components_uncached(
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
    // Sample the genesis private key.
    let private_key = sample_genesis_private_key(rng);
    let address = Address::<CurrentNetwork>::try_from(private_key).unwrap();

    // Prepare the locator.
    let locator = ("credits.aleo", "transfer_public_to_private");
    // Prepare the amount for each call to the function.
    let amount = 100_000_000u64;
    // Prepare the function inputs.
    let inputs = [address.to_string(), format!("{amount}_u64")];

    // Initialize the process.
    let process = Process::load().unwrap();
    // Create the transactions.
    let transactions = {
        Transactions::from_iter((0..2).map(|_| {
            // Authorize the function.
            let authorization =
                process.authorize::<CurrentAleo, _>(&private_key, locator.0, locator.1, inputs.iter(), rng).unwrap();
            // Execute the function.
            let (_, mut trace) = process.execute::<CurrentAleo, _>(authorization, rng).unwrap();

            // Initialize a new block store.
            let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(StorageMode::new_test(None)).unwrap();

            // Prepare the assignments.
            trace.prepare(&Query::from(block_store)).unwrap();
            // Compute the proof and construct the execution.
            let execution = trace.prove_execution::<CurrentAleo, _>(locator.0, VarunaVersion::V1, rng).unwrap();
            // Convert the execution.
            // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
            let execution = Execution::from_str(&execution.to_string()).unwrap();

            // Construct the transaction.
            let transaction = Transaction::from_execution(execution, None).unwrap();
            // Prepare the confirmed transaction.
            ConfirmedTransaction::accepted_execute(0, transaction.clone(), vec![]).unwrap()
        }))
    };

    // Construct the ratifications.
    let ratifications = Ratifications::try_from(vec![]).unwrap();

    // Prepare the block header.
    let header = Header::genesis(&ratifications, &transactions, vec![])
        .with_context(|| "Failed to generate genesis sample header")
        .pretty_unwrap();
    // Prepare the previous block hash.
    let previous_hash = <CurrentNetwork as Network>::BlockHash::default();

    // Construct the block.
    let block = Block::new_beacon(
        &private_key,
        previous_hash,
        header,
        ratifications,
        None.into(),
        vec![],
        transactions.clone(),
        vec![],
        rng,
    )
    .unwrap();
    assert!(block.header().is_genesis().unwrap(), "Failed to initialize a genesis block");
    // Return the block, transaction, and private key.
    (block, transactions, private_key)
}
