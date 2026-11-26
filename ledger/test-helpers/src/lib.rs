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

//! Test helpers that build ledger data structures.
//!
//! This crate is for tests of snarkVM and of the crates that depend on it. Its API is not covered by semantic
//! versioning: it may change in any release.

// Every helper in this crate is `#[inline]`, so the crate that calls it compiles it.
// A helper without `#[inline]` is compiled here, and every test binary that uses this crate waits for it.
// Clippy enforces this for public helpers only.
#![warn(clippy::missing_inline_in_public_items)]

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
    Deployment,
    Execution,
    Fee,
    Input,
    Output,
    Rejected,
    Transaction,
    Transactions,
    Transition,
};
use snarkvm_ledger_query::Query;
use snarkvm_ledger_store::{
    BlockStore,
    ConsensusStore,
    StorageMode,
    helpers::memory::{BlockMemory, ConsensusMemory},
};
use snarkvm_synthesizer::vm::VM;
use snarkvm_synthesizer_process::Process;
use snarkvm_synthesizer_program::Program;
use snarkvm_utilities::load_or_build_fixture;

use std::{cell::RefCell, collections::HashMap, sync::OnceLock};

mod genesis_fixture;
pub use genesis_fixture::load_or_build_genesis_fixture;

type CurrentNetwork = console::network::MainnetV0;
type CurrentAleo = circuit::network::AleoV0;

/****************************************** Transition ********************************************/

/// Samples a random transition.
#[inline]
pub fn sample_transition(rng: &mut TestRng) -> Transition<CurrentNetwork> {
    crate::sample_execution(rng, 0).into_transitions().next().unwrap()
}

/// Sample the transition inputs.
#[inline]
pub fn sample_inputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Input<CurrentNetwork>)> {
    let rng = &mut TestRng::default();

    // Sample a transition.
    let transition = crate::sample_transition(rng);

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
#[inline]
pub fn sample_outputs() -> Vec<(<CurrentNetwork as Network>::TransitionID, Output<CurrentNetwork>)> {
    let rng = &mut TestRng::default();

    // Sample a transition.
    let transition = crate::sample_transition(rng);

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

#[inline]
pub fn sample_deployment_v1(edition: u16, _rng: &mut TestRng) -> Deployment<CurrentNetwork> {
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
            sample_fixture("deployment-v1", &[], |rng| {
                // Construct the process.
                let process = Process::load().unwrap();
                // Compute the deployment.
                let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
                // Return the deployment.
                // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
                Deployment::from_str(&deployment.to_string()).unwrap()
            })
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

#[inline]
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
            sample_fixture("deployment-v2", &[], |rng| {
                // Construct the process.
                let process = Process::load().unwrap();
                // Compute the deployment.
                let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
                // Return the deployment.
                // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
                Deployment::from_str(&deployment.to_string()).unwrap()
            })
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

#[inline]
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
            sample_fixture("deployment-v2-translation-keys", &[], |rng| {
                // Construct the process.
                let process = Process::load().unwrap();
                // Compute the deployment.
                let deployment = process.deploy::<CurrentAleo, _>(&program, rng).unwrap();
                // Return the deployment.
                // Note: This is a testing-only hack to adhere to Rust's dependency cycle rules.
                Deployment::from_str(&deployment.to_string()).unwrap()
            })
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
#[inline]
pub fn sample_deployment_v3(edition: u16, rng: &mut TestRng) -> Deployment<CurrentNetwork> {
    // Sample a V2 deployment without translation keys, then remove the owner to make it V3.
    let mut deployment = sample_deployment_v2_without_translation_keys(edition, rng);
    deployment.set_program_owner_raw(None);
    deployment
}

/// Samples a rejected deployment.
#[inline]
pub fn sample_rejected_deployment(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    rng: &mut TestRng,
) -> Rejected<CurrentNetwork> {
    // Sample a deployment and the private key that signs its program owner.
    let (deployment, private_key) =
        crate::sample_deployment_and_private_key(version, edition, has_translation_keys, rng);

    // Construct the program owner.
    let deployment_id = deployment.to_deployment_id().unwrap();
    let program_owner = ProgramOwner::new(&private_key, deployment_id, rng).unwrap();

    // Return the rejected deployment.
    Rejected::new_deployment(program_owner, deployment)
}

/******************************************* Execution ********************************************/

/// Samples a random execution.
#[inline]
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
#[inline]
pub fn sample_rejected_execution(rng: &mut TestRng) -> Rejected<CurrentNetwork> {
    // Sample an execution.
    let execution = crate::sample_execution(rng, 0);

    // Return the rejected execution.
    Rejected::new_execution(execution)
}

/********************************************** Fee ***********************************************/

/// Returns a private fee for a fixed ID.
///
/// Every call returns the same fee. It does not depend on `_rng`, and `_rng` is not advanced.
#[inline]
pub fn sample_fee_private_hardcoded(_rng: &mut TestRng) -> Fee<CurrentNetwork> {
    static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            sample_fixture("fee-private", &genesis_fixture_key(), |rng| {
                // Sample a deployment or execution ID.
                let deployment_or_execution_id = Field::rand(rng);
                // Sample a fee.
                sample_fee_private(deployment_or_execution_id, rng)
            })
        })
        .clone()
}

/// Samples a random private fee.
#[inline]
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

/// Returns a public fee for a fixed ID.
///
/// Every call returns the same fee. It does not depend on `_rng`, and `_rng` is not advanced.
#[inline]
pub fn sample_fee_public_hardcoded(_rng: &mut TestRng) -> Fee<CurrentNetwork> {
    static INSTANCE: OnceLock<Fee<CurrentNetwork>> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            sample_fixture("fee-public", &genesis_fixture_key(), |rng| {
                // Sample a deployment or execution ID.
                let deployment_or_execution_id = Field::rand(rng);
                // Sample a fee.
                sample_fee_public(deployment_or_execution_id, rng)
            })
        })
        .clone()
}

/// Samples a random public fee.
#[inline]
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
#[inline]
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
#[inline]
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

/// Samples a random deployment and the private key that signs its program owner.
#[inline]
fn sample_deployment_and_private_key(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    rng: &mut TestRng,
) -> (Deployment<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
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

    (deployment, private_key)
}

/// The largest edition of a deployment transaction that the test processes share.
///
/// Each shared edition has its own fixture files. A transaction with a larger edition, such as a random one,
/// is built for each call and writes no file.
const MAX_SHARED_EDITION: u16 = 3;

/// Samples a deployment transaction with a private or public fee.
///
/// For an edition up to `MAX_SHARED_EDITION`, the n-th call on a thread for a version, an edition, a choice of
/// translation keys and a fee kind returns the n-th such transaction, which is the same in every test process of
/// the binary. It does not depend on `rng`, and `rng` is not advanced. A version 1 deployment has edition 0 or 1.
#[inline]
pub fn sample_deployment_transaction(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    is_fee_private: bool,
    rng: &mut TestRng,
) -> Transaction<CurrentNetwork> {
    let edition = match version {
        1 => edition % 2,
        _ => edition,
    };
    if edition > MAX_SHARED_EDITION {
        return build_deployment_transaction(version, edition, has_translation_keys, is_fee_private, rng);
    }
    let name = format!(
        "deploy-v{version}-edition-{edition}-translation-keys-{has_translation_keys}-private-fee-{is_fee_private}"
    );
    sample_nth_fixture(&name, &genesis_fixture_key(), |rng| {
        build_deployment_transaction(version, edition, has_translation_keys, is_fee_private, rng)
    })
}

/// Builds a deployment transaction with a private or public fee.
#[inline]
fn build_deployment_transaction(
    version: u8,
    edition: u16,
    has_translation_keys: bool,
    is_fee_private: bool,
    rng: &mut TestRng,
) -> Transaction<CurrentNetwork> {
    // Sample a deployment and the private key that signs its program owner.
    let (deployment, private_key) =
        crate::sample_deployment_and_private_key(version, edition, has_translation_keys, rng);

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

/// Returns an execution transaction with a private or public fee.
///
/// The n-th call on a thread for an index and a fee kind returns the n-th such transaction,
/// which is the same in every test process of the binary. It does not depend on `_rng`, and `_rng` is not advanced.
#[inline]
pub fn sample_execution_transaction_with_fee(
    is_fee_private: bool,
    _rng: &mut TestRng,
    index: usize,
) -> Transaction<CurrentNetwork> {
    let name = format!("execute-{index}-private-fee-{is_fee_private}");
    sample_nth_fixture(&name, &genesis_fixture_key(), |rng| {
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
    })
}

/// Samples a large transaction.
#[inline]
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

/// Returns the fee transaction of `sample_fee_private_hardcoded`.
#[inline]
pub fn sample_fee_private_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
    // Sample a private fee.
    let fee = crate::sample_fee_private_hardcoded(rng);
    // Construct a fee transaction.
    Transaction::from_fee(fee).unwrap()
}

/// Returns the fee transaction of `sample_fee_public_hardcoded`.
#[inline]
pub fn sample_fee_public_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
    // Sample a public fee.
    let fee = crate::sample_fee_public_hardcoded(rng);
    // Construct a fee transaction.
    Transaction::from_fee(fee).unwrap()
}

/****************************************** Transactions ******************************************/

/// Samples a block transactions.
#[inline]
pub fn sample_block_transactions(rng: &mut TestRng) -> Transactions<CurrentNetwork> {
    crate::sample_genesis_block(rng).transactions().clone()
}

/********************************************* Block **********************************************/

/// Samples a random genesis block.
#[inline]
pub fn sample_genesis_block(rng: &mut TestRng) -> Block<CurrentNetwork> {
    // Sample the genesis block and components.
    let (block, _, _) = crate::sample_genesis_block_and_components(rng);
    // Return the block.
    block
}

/// Samples a random genesis block and the transactions from the genesis block.
#[inline]
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
#[inline]
pub fn sample_genesis_block_and_components(
    _rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>, PrivateKey<CurrentNetwork>) {
    let (private_key, block) = genesis_fixture();
    (block.clone(), block.transactions().clone(), *private_key)
}

/// Returns the genesis private key, which signs the block of `sample_genesis_block`.
///
/// The key does not depend on `_rng`, and `_rng` is not advanced.
#[inline]
pub fn sample_genesis_private_key(_rng: &mut TestRng) -> PrivateKey<CurrentNetwork> {
    genesis_fixture().0
}

/// The seed of the RNG that builds the genesis fixture.
const GENESIS_FIXTURE_SEED: u64 = 1_779_135_982;

/// Returns the genesis private key and the genesis block that it signs.
///
/// The test processes of one binary share the fixture through a file beside the binary.
#[inline]
fn genesis_fixture() -> &'static (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    static INSTANCE: OnceLock<(PrivateKey<CurrentNetwork>, Block<CurrentNetwork>)> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        load_or_build_genesis_fixture("test-helpers-genesis", GENESIS_FIXTURE_SEED, build_genesis_fixture)
    })
}

/// Returns the key of the fixtures that hold a proof for the genesis block: the hash of that block.
#[inline]
fn genesis_fixture_key() -> Vec<u8> {
    genesis_fixture().1.hash().to_string().into_bytes()
}

/// Returns the fixture `name` of the running test binary, which `build` builds from an RNG that `name` seeds.
///
/// The test processes of one binary share the fixture through a file beside the binary.
/// `key` holds the inputs of `build` that are not in `name`.
#[inline]
fn sample_fixture<T: FromBytes + ToBytes>(name: &str, key: &[u8], build: impl FnOnce(&mut TestRng) -> T) -> T {
    // Hash the name (FNV-1a), so that each fixture has its own random values.
    let seed = name
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3));
    load_or_build_fixture(&format!("test-helpers-{name}"), key, |_| true, || build(&mut TestRng::from_seed(seed)))
}

/// Returns the fixture `{name}-{n}` for the n-th call with `name` on this thread.
///
/// Two calls on one thread return different fixtures, and every thread gets the same fixtures in the same order.
#[inline]
fn sample_nth_fixture<T: FromBytes + ToBytes>(name: &str, key: &[u8], build: impl FnOnce(&mut TestRng) -> T) -> T {
    thread_local! {
        static CALLS: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    }
    let call = CALLS.with_borrow_mut(|calls| {
        let calls = calls.entry(name.to_string()).or_default();
        *calls += 1;
        *calls - 1
    });
    sample_fixture(&format!("{name}-{call}"), key, build)
}

/// Builds the genesis fixture from an RNG with the given seed.
#[inline]
fn build_genesis_fixture(seed: u64) -> (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>) {
    let rng = &mut TestRng::from_seed(seed);
    // Sample the genesis private key.
    let private_key = PrivateKey::<CurrentNetwork>::new(rng).expect("Failed to sample the genesis private key");
    // Construct the genesis block.
    let (block, _) = build_genesis_block_and_transactions(&private_key, rng);
    (private_key, block)
}

/// Samples a random genesis block, the transactions from the genesis block, and the genesis private key.
///
/// The genesis private key is the key of `sample_genesis_private_key`.
#[inline]
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
#[inline]
fn build_genesis_block_and_transactions(
    private_key: &PrivateKey<CurrentNetwork>,
    rng: &mut TestRng,
) -> (Block<CurrentNetwork>, Transactions<CurrentNetwork>) {
    // `VM::speculate` blocks on a channel, which panics on a thread that runs a tokio runtime.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let store = ConsensusStore::<CurrentNetwork, ConsensusMemory<CurrentNetwork>>::open(
                    StorageMode::new_test(None),
                )
                .expect("Failed to open the consensus store");
                let vm = VM::from(store).expect("Failed to initialize the VM");
                let block = vm.genesis_beacon(private_key, rng).expect("Failed to build the genesis block");
                let transactions = block.transactions().clone();
                (block, transactions)
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_shared_samples_do_not_advance_rng() {
        let rng = &mut TestRng::fixed(1);
        sample_fee_public_transaction(rng);
        sample_execution_transaction_with_fee(false, rng, 0);
        sample_deployment_transaction(1, 0, false, false, rng);
        sample_deployment_transaction(2, 0, false, false, rng);
        assert_eq!(rng.random::<u64>(), TestRng::fixed(1).random::<u64>());
    }

    #[test]
    fn test_shared_samples_follow_the_call_order_of_a_thread() {
        // Samples the first two public-fee transactions of a thread, for an execution and for a deployment.
        fn sample() -> [Transaction<CurrentNetwork>; 4] {
            let rng = &mut TestRng::default();
            [
                sample_execution_transaction_with_fee(false, rng, 0),
                sample_execution_transaction_with_fee(false, rng, 0),
                sample_deployment_transaction(2, 0, false, false, rng),
                sample_deployment_transaction(2, 0, false, false, rng),
            ]
        }

        // Two samples of one kind on one thread are different transactions.
        let samples = std::thread::spawn(sample).join().expect("The sampling thread panicked");
        assert_ne!(samples[0].id(), samples[1].id());
        assert_ne!(samples[2].id(), samples[3].id());
        // Another new thread gets the same transactions in the same order.
        let other_samples = std::thread::spawn(sample).join().expect("The sampling thread panicked");
        assert_eq!(samples, other_samples);
    }

    #[test]
    fn test_genesis_block_passes_production_checks() {
        assert!(sample_genesis_block(&mut TestRng::default()).is_genesis().expect("Malformed genesis block"));
    }

    #[tokio::test]
    async fn test_genesis_builds_inside_a_tokio_runtime() {
        let rng = &mut TestRng::default();
        let private_key = PrivateKey::new(rng).expect("Failed to sample a private key");
        let (block, _) = build_genesis_block_and_transactions(&private_key, rng);
        assert!(block.is_genesis().expect("Malformed genesis block"));
    }
}
