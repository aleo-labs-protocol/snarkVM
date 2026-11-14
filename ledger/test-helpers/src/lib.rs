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
use std::{
    fs,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::UNIX_EPOCH,
};

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

/// Returns the genesis block, the transactions of the genesis block, and the genesis private key.
///
/// Every call returns the same genesis block and genesis private key.
/// They do not depend on `_rng`, and `_rng` is not advanced.
pub fn sample_genesis_block_and_components(
    _rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
    let (private_key, block) = genesis_fixture();
    (block.clone(), block.transactions().clone(), *private_key)
}

/// Returns the genesis private key, which signs the block of `sample_genesis_block`.
///
/// The key does not depend on `_rng`, and `_rng` is not advanced.
pub fn sample_genesis_private_key(_rng: &mut TestRng) -> PrivateKey<CurrentNetwork> {
    genesis_fixture().0
}

/// The seed of the RNG that builds the genesis fixture.
const GENESIS_FIXTURE_SEED: u64 = 1_779_135_982;

/// Returns the genesis private key and the genesis block that it signs.
///
/// The test processes of one binary share the fixture through a file beside the binary.
fn genesis_fixture() -> &'static (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    static INSTANCE: OnceLock<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> = OnceLock::new();
    INSTANCE.get_or_init(|| match genesis_fixture_path_and_stamp() {
        Ok((path, stamp)) => load_or_build_genesis_fixture(&path, &stamp),
        Err(_) => build_genesis_fixture(),
    })
}

/// Builds the genesis fixture from an RNG with a fixed seed.
fn build_genesis_fixture() -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(GENESIS_FIXTURE_SEED);
    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample the genesis private key");
    // Construct the genesis block.
    let (block, _) = build_genesis_block_and_transactions(&private_key, rng);
    (private_key, block)
}

/// Returns the path of the genesis fixture file of the running binary, and the stamp of that binary.
///
/// The stamp holds the size and the modification time of the binary.
fn genesis_fixture_path_and_stamp() -> io::Result<(PathBuf, Vec<u8>)> {
    let binary = std::env::current_exe()?;
    let metadata = fs::metadata(&binary)?;
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let mut stamp = Vec::with_capacity(24);
    stamp.extend_from_slice(&metadata.len().to_le_bytes());
    stamp.extend_from_slice(&modified.as_nanos().to_le_bytes());
    Ok((binary.with_added_extension("test-helpers-genesis"), stamp))
}

/// Reads the genesis fixture at `path`, or builds the fixture and writes it to `path`.
///
/// An exclusive lock on the sibling `.lock` file lets one process build the fixture while the others wait.
/// A file that cannot be read or parsed, or that holds a different stamp, is rebuilt and overwritten.
fn load_or_build_genesis_fixture(path: &Path, stamp: &[u8]) -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    if let Some(fixture) = read_genesis_fixture(path, stamp) {
        return fixture;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_added_extension("lock"))
        .and_then(|file| file.lock().map(|()| file));
    // Without the lock, the fixture is built but not written.
    let Ok(lock) = lock else {
        return build_genesis_fixture();
    };
    // Another process may have written the fixture while this process waited for the lock.
    if let Some(fixture) = read_genesis_fixture(path, stamp) {
        return fixture;
    }
    let fixture = build_genesis_fixture();
    // A failed write leaves the file for a later process to rebuild.
    let _ = write_genesis_fixture(path, stamp, &fixture);
    drop(lock);
    fixture
}

/// Reads the genesis fixture at `path`, if the file holds a valid fixture with the given stamp.
fn read_genesis_fixture(path: &Path, stamp: &[u8]) -> Option<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> {
    genesis_fixture_from_bytes(&fs::read(path).ok()?, stamp)
}

/// Writes the genesis fixture to `path` through a temporary file and a rename.
fn write_genesis_fixture(
    path: &Path,
    stamp: &[u8],
    fixture: &(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>),
) -> io::Result<()> {
    let temporary_path = path.with_added_extension("tmp");
    fs::write(&temporary_path, genesis_fixture_to_bytes(stamp, fixture)?)?;
    fs::rename(temporary_path, path)
}

/// Returns the stamp, followed by the bytes of the genesis private key and the genesis block.
fn genesis_fixture_to_bytes(
    stamp: &[u8],
    fixture: &(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>),
) -> io::Result<Vec<u8>> {
    let mut bytes = stamp.to_vec();
    fixture.write_le(&mut bytes)?;
    Ok(bytes)
}

/// Parses the output of `genesis_fixture_to_bytes`.
///
/// Returns `None` if the bytes hold a different stamp, fail to parse, have trailing bytes,
/// or hold a block that the private key did not sign.
fn genesis_fixture_from_bytes(
    bytes: &[u8],
    stamp: &[u8],
) -> Option<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> {
    let mut reader = bytes.strip_prefix(stamp)?;
    let (private_key, block) = <(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)>::read_le(&mut reader).ok()?;
    let authority = block.authority();
    let is_signer = authority.is_beacon() && Address::try_from(&private_key).ok()? == authority.to_address();
    (reader.is_empty() && is_signer).then_some((private_key, block))
}

/// Samples a random genesis block, the transactions from the genesis block, and the genesis private key.
///
/// The genesis private key is the key of `sample_genesis_private_key`.
pub fn sample_genesis_block_and_components_uncached(
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
    // Sample the genesis private key.
    let private_key = sample_genesis_private_key(rng);
    // Construct the genesis block.
    let (block, transactions) = build_genesis_block_and_transactions(&private_key, rng);
    // Return the block, transaction, and private key.
    (block, transactions, private_key)
}

/// Returns a new genesis block, which `private_key` signs, and the transactions of the block.
fn build_genesis_block_and_transactions(
    private_key: &PrivateKey<CurrentNetwork>,
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>) {
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
                process.authorize::<CurrentAleo, _>(private_key, locator.0, locator.1, inputs.iter(), rng).unwrap();
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
        private_key,
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
    // Return the block and transactions.
    (block, transactions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_fixture_cache_hit_matches_miss() {
        let path = std::env::temp_dir().join(format!("snarkvm-test-helpers-genesis-fixture-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let stamp = b"stamp";

        // The file does not exist yet, so this call builds the fixture and writes the file.
        let miss = load_or_build_genesis_fixture(&path, stamp);
        // This call reads the file that the previous call wrote.
        let hit = read_genesis_fixture(&path, stamp).expect("The fixture file is valid");
        let bytes = fs::read(&path).expect("Failed to read the fixture file");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_added_extension("lock"));

        assert_eq!(miss, hit);
        assert_eq!(bytes, genesis_fixture_to_bytes(stamp, &miss).expect("Failed to serialize the fixture"));
        // The fixture of this process comes from a separate build, in this process or in another one.
        assert_eq!(&miss, genesis_fixture());
    }

    #[test]
    fn test_genesis_fixture_rejects_invalid_bytes() {
        let stamp = b"stamp";
        let fixture = genesis_fixture();
        let (private_key, block) = fixture;
        let bytes = genesis_fixture_to_bytes(stamp, fixture).expect("Failed to serialize the fixture");
        assert!(genesis_fixture_from_bytes(&bytes, stamp).is_some());

        // A different stamp.
        assert!(genesis_fixture_from_bytes(&bytes, b"stamq").is_none());
        // Missing bytes.
        assert!(genesis_fixture_from_bytes(&[], stamp).is_none());
        assert!(genesis_fixture_from_bytes(stamp, stamp).is_none());
        assert!(genesis_fixture_from_bytes(&bytes[..bytes.len() - 1], stamp).is_none());
        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(genesis_fixture_from_bytes(&extended, stamp).is_none());
        // Bytes that do not encode a fixture.
        let mut garbage = stamp.to_vec();
        garbage.resize(bytes.len(), 0xff);
        assert!(genesis_fixture_from_bytes(&garbage, stamp).is_none());
        // A private key that did not sign the block.
        let other_private_key =
            PrivateKey::<CurrentNetwork>::new(&mut TestRng::default()).expect("Failed to sample a private key");
        assert_ne!(other_private_key, *private_key);
        let other_bytes = genesis_fixture_to_bytes(stamp, &(other_private_key, block.clone()))
            .expect("Failed to serialize the fixture");
        assert!(genesis_fixture_from_bytes(&other_bytes, stamp).is_none());
    }

    #[test]
    fn test_genesis_helpers_do_not_advance_rng() {
        let rng = &mut TestRng::fixed(1);
        let (block, transactions, private_key) = sample_genesis_block_and_components(rng);
        assert_eq!(sample_genesis_private_key(rng), private_key);
        assert_eq!(rng.random::<u64>(), TestRng::fixed(1).random::<u64>());
        // The helpers return the genesis fixture.
        assert_eq!((&private_key, &block), (&genesis_fixture().0, &genesis_fixture().1));
        assert_eq!(&transactions, block.transactions());
    }
}
