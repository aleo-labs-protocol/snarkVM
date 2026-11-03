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

use circuit::{Circuit, Environment};
use console::algorithms::U8;
use snarkvm_algorithms::snark::varuna::VarunaVersion;
use snarkvm_synthesizer_snark::{ProvingKey, UniversalSRS, VerifyingKey};

use std::sync::OnceLock;

#[test]
fn test_snark_verify() {
    // Define the verification program.
    let program = Program::from_str(
        r"
program test_snark_verify.aleo;

function verify_proof:
    input r0 as [u8; 673u32].private;
    input r1 as [field; 2u32].private;
    input r2 as [u8; 957u32].private;
    async verify_proof r0 r1 r2 into r3;
    output r3 as test_snark_verify.aleo/verify_proof.future;
finalize verify_proof:
    input r0 as [u8; 673u32].public;
    input r1 as [field; 2u32].public;
    input r2 as [u8; 957u32].public;
    snark.verify r0 2u8 r1 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Sample a Varuna assignment
    let assignment = snarkvm_synthesizer_snark::test_helpers::sample_assignment();

    // Varuna setup, prove, and verify.
    let srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    let (proving_key, verifying_key) = srs.to_circuit_key("test", &assignment).unwrap();
    let verifying_key_bytes = verifying_key.to_bytes_le().unwrap();

    // Construct the proof
    let varuna_version = VarunaVersion::V2;
    let proof = proving_key.prove("test", varuna_version, &assignment, &mut TestRng::default()).unwrap();
    let proof_bytes = proof.to_bytes_le().unwrap();

    println!("verifying_key_size: {}", verifying_key_bytes.len());
    println!("proof size: {}", proof_bytes.len());

    let one = <Circuit as circuit::Environment>::BaseField::one();
    let zero = <Circuit as circuit::Environment>::BaseField::zero();
    let public_inputs = vec![one, one];
    let invalid_public_inputs = vec![one, zero];
    assert!(verifying_key.verify("test", varuna_version, &public_inputs, &proof));
    assert!(!verifying_key.verify("test", varuna_version, &invalid_public_inputs, &proof));

    // Construct the inputs for the execution.
    let verifying_key_input = Value::Plaintext(Plaintext::Array(
        verifying_key_bytes
            .into_iter()
            .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
            .collect(),
        OnceLock::new(),
    ));
    let verification_inputs = Value::Plaintext(Plaintext::Array(
        public_inputs
            .into_iter()
            .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
            .collect(),
        OnceLock::new(),
    ));
    let invalid_verification_inputs = Value::Plaintext(Plaintext::Array(
        invalid_public_inputs
            .into_iter()
            .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
            .collect(),
        OnceLock::new(),
    ));
    let proof_input = Value::Plaintext(Plaintext::Array(
        proof_bytes.into_iter().map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte)))).collect(),
        OnceLock::new(),
    ));

    // Execute a transaction that verifies the proof correctly.
    let valid_execution = {
        let inputs = vec![verifying_key_input.clone(), verification_inputs, proof_input.clone()];

        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let valid_execution_id = valid_execution.id();

    // Execute a transaction that fails to verify the proof.
    let invalid_execution = {
        let inputs = vec![verifying_key_input, invalid_verification_inputs, proof_input];

        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let invalid_execution_id = invalid_execution.id();

    let block = sample_next_block(&vm, &caller_private_key, &[valid_execution, invalid_execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    assert!(vm.transaction_store().contains_transaction_id(&valid_execution_id).unwrap());
    assert!(vm.block_store().contains_rejected_or_aborted_transaction_id(&invalid_execution_id).unwrap());
}

#[test]
fn test_snark_verify_batch() {
    // Define the verification program.
    let program = Program::from_str(
        r"
program test_snark_verify_batch.aleo;

function verify_batch_proof:
    input r0 as [[u8; 673u32]; 1u32].private;
    input r1 as [[[field; 2u32]; 2u32]; 1u32].private;
    input r2 as [u8; 1101u32].private;
    async verify_batch_proof r0 r1 r2 into r3;
    output r3 as test_snark_verify_batch.aleo/verify_batch_proof.future;
finalize verify_batch_proof:
    input r0 as [[u8; 673u32]; 1u32].public;
    input r1 as [[[field; 2u32]; 2u32]; 1u32].public;
    input r2 as [u8; 1101u32].public;
    snark.verify.batch r0 2u8 r1 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Sample a Varuna assignment
    let assignment = snarkvm_synthesizer_snark::test_helpers::sample_assignment();

    // Varuna setup, prove, and verify.
    let srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    let (proving_key, verifying_key) = srs.to_circuit_key("test", &assignment).unwrap();
    let verifying_key_bytes = verifying_key.to_bytes_le().unwrap();

    // Construct the batch_proof
    let varuna_version = VarunaVersion::V2;
    let assignments = vec![(proving_key.clone(), vec![assignment.clone(); 2])];
    let batch_proof = ProvingKey::prove_batch("test", varuna_version, &assignments, &mut TestRng::default()).unwrap();
    let batch_proof_bytes = batch_proof.to_bytes_le().unwrap();

    println!("verifying_key_size: {}", verifying_key_bytes.len());
    println!("proof size: {}", batch_proof_bytes.len());

    let one = <Circuit as circuit::Environment>::BaseField::one();
    let zero = <Circuit as circuit::Environment>::BaseField::zero();
    let public_inputs = vec![one, one];
    let invalid_public_inputs = vec![one, zero];

    let valid_inputs = vec![(verifying_key.clone(), vec![public_inputs.clone(); 2])];
    let invalid_inputs = vec![(verifying_key.clone(), vec![invalid_public_inputs.clone(); 2])];
    assert!(VerifyingKey::verify_batch("test", varuna_version, valid_inputs, &batch_proof).is_ok());
    assert!(VerifyingKey::verify_batch("test", varuna_version, invalid_inputs, &batch_proof).is_err());

    // Construct the inputs for the execution.
    let verifying_key_input = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            verifying_key_bytes
                .into_iter()
                .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                .collect(),
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    public_inputs
                        .clone()
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let invalid_verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    invalid_public_inputs
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let proof_input = Value::Plaintext(Plaintext::Array(
        batch_proof_bytes
            .into_iter()
            .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
            .collect(),
        OnceLock::new(),
    ));

    // Execute a transaction that verifies the proof correctly.
    let valid_execution = {
        let inputs = vec![verifying_key_input.clone(), verification_inputs.clone(), proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let valid_execution_id = valid_execution.id();

    // Execute a transaction that fails to verify the proof.
    let invalid_execution = {
        let inputs = vec![verifying_key_input.clone(), invalid_verification_inputs, proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let invalid_execution_id = invalid_execution.id();

    let block = sample_next_block(&vm, &caller_private_key, &[valid_execution, invalid_execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    assert!(vm.transaction_store().contains_transaction_id(&valid_execution_id).unwrap());
    assert!(vm.block_store().contains_rejected_or_aborted_transaction_id(&invalid_execution_id).unwrap());
}

#[test]
fn test_snark_verify_batch_padded_inputs() {
    // Define the verification program.
    let program = Program::from_str(
        r"
program test_snark_verify_padded.aleo;

function verify_batch_proof:
    input r0 as [[u8; 673u32]; 1u32].private;
    input r1 as [[[field; 20u32]; 2u32]; 1u32].private;
    input r2 as [u8; 1101u32].private;
    async verify_batch_proof r0 r1 r2 into r3;
    output r3 as test_snark_verify_padded.aleo/verify_batch_proof.future;
finalize verify_batch_proof:
    input r0 as [[u8; 673u32]; 1u32].public;
    input r1 as [[[field; 20u32]; 2u32]; 1u32].public;
    input r2 as [u8; 1101u32].public;
    snark.verify.batch r0 2u8 r1 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Sample a Varuna assignment
    let assignment = snarkvm_synthesizer_snark::test_helpers::sample_assignment();

    // Varuna setup, prove, and verify.
    let srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    let (proving_key, verifying_key) = srs.to_circuit_key("test", &assignment).unwrap();
    let verifying_key_bytes = verifying_key.to_bytes_le().unwrap();

    // Construct the batch_proof
    let varuna_version = VarunaVersion::V2;
    let assignments = vec![(proving_key.clone(), vec![assignment.clone(); 2])];
    let batch_proof = ProvingKey::prove_batch("test", varuna_version, &assignments, &mut TestRng::default()).unwrap();
    let batch_proof_bytes = batch_proof.to_bytes_le().unwrap();

    println!("verifying_key_size: {}", verifying_key_bytes.len());
    println!("proof size: {}", batch_proof_bytes.len());

    let one = <Circuit as circuit::Environment>::BaseField::one();
    let zero = <Circuit as circuit::Environment>::BaseField::zero();
    let public_inputs = vec![one, one];
    let invalid_public_inputs = vec![one, zero];

    let valid_inputs = vec![(verifying_key.clone(), vec![public_inputs.clone(); 2])];
    let invalid_inputs = vec![(verifying_key.clone(), vec![invalid_public_inputs.clone(); 2])];
    assert!(VerifyingKey::verify_batch("test", varuna_version, valid_inputs, &batch_proof).is_ok());
    assert!(VerifyingKey::verify_batch("test", varuna_version, invalid_inputs, &batch_proof).is_err());

    // Pad the public inputs to match the expected size.
    let mut padded_public_inputs = public_inputs.clone();
    padded_public_inputs.resize(20, zero);

    // Pad the public inputs to match the expected size.
    let mut padded_invalid_public_inputs = public_inputs.clone();
    padded_invalid_public_inputs.resize(20, one);

    // Construct the inputs for the execution.
    let verifying_key_input = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            verifying_key_bytes
                .into_iter()
                .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                .collect(),
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    padded_public_inputs
                        .clone()
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let invalid_verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    padded_invalid_public_inputs
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let proof_input = Value::Plaintext(Plaintext::Array(
        batch_proof_bytes
            .into_iter()
            .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
            .collect(),
        OnceLock::new(),
    ));

    // Execute a transaction that verifies the proof correctly.
    let valid_execution = {
        let inputs = vec![verifying_key_input.clone(), verification_inputs.clone(), proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let valid_execution_id = valid_execution.id();

    // Execute a transaction that fails to verify the proof.
    let invalid_execution = {
        let inputs = vec![verifying_key_input.clone(), invalid_verification_inputs, proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let invalid_execution_id = invalid_execution.id();

    let block = sample_next_block(&vm, &caller_private_key, &[valid_execution, invalid_execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    assert!(vm.transaction_store().contains_transaction_id(&valid_execution_id).unwrap());
    assert!(vm.block_store().contains_rejected_or_aborted_transaction_id(&invalid_execution_id).unwrap());
}

#[test]
fn test_snark_verify_batch_multiple_circuits() {
    // Define the verification program.
    let program = Program::from_str(
        r"
program test_snark_verify_batch.aleo;

function verify_batch_proof:
    input r0 as [[u8; 673u32]; 2u32].private;
    input r1 as [[[field; 2u32]; 2u32]; 2u32].private;
    input r2 as [u8; 1733u32].private;
    async verify_batch_proof r0 r1 r2 into r3;
    output r3 as test_snark_verify_batch.aleo/verify_batch_proof.future;
finalize verify_batch_proof:
    input r0 as [[u8; 673u32]; 2u32].public;
    input r1 as [[[field; 2u32]; 2u32]; 2u32].public;
    input r2 as [u8; 1733u32].public;
    snark.verify.batch r0 2u8 r1 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Sample two Varuna assignments
    let assignment = snarkvm_synthesizer_snark::test_helpers::sample_assignment();
    let assignment_2 = {
        let _candidate_output = snarkvm_synthesizer_snark::test_helpers::create_example_circuit::<Circuit>();
        let _ = circuit::Field::<CurrentAleo>::new(Mode::Private, Field::from_u8(100));
        Circuit::eject_assignment_and_reset()
    };

    // Varuna setup, prove, and verify.
    let srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    let (proving_key, verifying_key) = srs.to_circuit_key("test", &assignment).unwrap();
    let (proving_key_2, verifying_key_2) = srs.to_circuit_key("test_2", &assignment_2).unwrap();
    let verifying_key_bytes = verifying_key.to_bytes_le().unwrap();
    let verifying_key_2_bytes = verifying_key_2.to_bytes_le().unwrap();

    // Construct the batch_proof
    let varuna_version = VarunaVersion::V2;
    let assignments = vec![
        (proving_key.clone(), vec![assignment.clone(); 2]),
        (proving_key_2.clone(), vec![assignment_2.clone(); 2]),
    ];
    let batch_proof = ProvingKey::prove_batch("test", varuna_version, &assignments, &mut TestRng::default()).unwrap();
    let batch_proof_bytes = batch_proof.to_bytes_le().unwrap();

    println!("verifying_key_size: {}", verifying_key_bytes.len());
    println!("proof size: {}", batch_proof_bytes.len());

    let one = <Circuit as circuit::Environment>::BaseField::one();
    let zero = <Circuit as circuit::Environment>::BaseField::zero();
    let public_inputs = vec![one, one];
    let invalid_public_inputs = vec![one, zero];

    let valid_inputs = vec![
        (verifying_key.clone(), vec![public_inputs.clone(); 2]),
        (verifying_key_2.clone(), vec![public_inputs.clone(); 2]),
    ];
    let invalid_inputs = vec![
        (verifying_key.clone(), vec![invalid_public_inputs.clone(); 2]),
        (verifying_key_2.clone(), vec![invalid_public_inputs.clone(); 2]),
    ];
    assert!(VerifyingKey::verify_batch("test", varuna_version, valid_inputs, &batch_proof).is_ok());
    assert!(VerifyingKey::verify_batch("test", varuna_version, invalid_inputs, &batch_proof).is_err());

    // Construct the inputs for the execution.
    let verifying_key_input = Value::Plaintext(Plaintext::Array(
        vec![
            Plaintext::Array(
                verifying_key_bytes
                    .into_iter()
                    .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                    .collect(),
                OnceLock::new(),
            ),
            Plaintext::Array(
                verifying_key_2_bytes
                    .into_iter()
                    .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                    .collect(),
                OnceLock::new(),
            ),
        ],
        OnceLock::new(),
    ));
    let verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![
            Plaintext::Array(
                vec![
                    Plaintext::Array(
                        public_inputs
                            .clone()
                            .into_iter()
                            .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                            .collect(),
                        OnceLock::new(),
                    )
                    .clone();
                    2
                ],
                OnceLock::new(),
            )
            .clone();
            2
        ],
        OnceLock::new(),
    ));
    let invalid_verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![
            Plaintext::Array(
                vec![
                    Plaintext::Array(
                        invalid_public_inputs
                            .into_iter()
                            .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                            .collect(),
                        OnceLock::new(),
                    )
                    .clone();
                    2
                ],
                OnceLock::new(),
            )
            .clone();
            2
        ],
        OnceLock::new(),
    ));
    let proof_input = Value::Plaintext(Plaintext::Array(
        batch_proof_bytes
            .into_iter()
            .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
            .collect(),
        OnceLock::new(),
    ));

    // Execute a transaction that verifies the proof correctly.
    let valid_execution = {
        let inputs = vec![verifying_key_input.clone(), verification_inputs.clone(), proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let valid_execution_id = valid_execution.id();

    // Execute a transaction that fails to verify the proof.
    let invalid_execution = {
        let inputs = vec![verifying_key_input.clone(), invalid_verification_inputs, proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let invalid_execution_id = invalid_execution.id();

    let block = sample_next_block(&vm, &caller_private_key, &[valid_execution, invalid_execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    assert!(vm.transaction_store().contains_transaction_id(&valid_execution_id).unwrap());
    assert!(vm.block_store().contains_rejected_or_aborted_transaction_id(&invalid_execution_id).unwrap());
}

#[test]
fn test_snark_verify_batch_via_mapping() {
    // Define the verification program.
    let program = Program::from_str(
        r"
program test_snark_verify_mapping.aleo;

mapping verifying_keys:
    key as u8.public;
    value as [[u8; 673u32]; 1u32].public;

mapping proofs:
    key as u8.public;
    value as [u8; 1101u32].public;

function store_verifying_key_and_proof:
    input r0 as [[u8; 673u32]; 1u32].private;
    input r1 as [u8; 1101u32].private;
    async store_verifying_key_and_proof r0 r1 into r2;
    output r2 as test_snark_verify_mapping.aleo/store_verifying_key_and_proof.future;

finalize store_verifying_key_and_proof:
    input r0 as [[u8; 673u32]; 1u32].public;
    input r1 as [u8; 1101u32].public;
    set r0 into verifying_keys[0u8];
    set r1 into proofs[0u8];

function verify_batch_proof:
    input r0 as [[[field; 2u32]; 2u32]; 1u32].private;
    async verify_batch_proof r0 into r1;
    output r1 as test_snark_verify_mapping.aleo/verify_batch_proof.future;
finalize verify_batch_proof:
    input r0 as [[[field; 2u32]; 2u32]; 1u32].public;
    get verifying_keys[0u8] into r1;
    get proofs[0u8] into r2;
    snark.verify.batch r1 2u8 r0 r2 into r3;
    assert.eq r3 true;

constructor:
    assert.eq true true;
    ",
    )
    .unwrap();

    // Initialize an RNG.
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);

    // Initialize the VM at the V14 height.
    let v14_height = CurrentNetwork::CONSENSUS_HEIGHT(ConsensusVersion::V14).unwrap();
    let vm = crate::vm::test_helpers::sample_vm_at_height(v14_height, rng);

    // Deploy the program.
    let deployment = vm.deploy(&caller_private_key, &program, None, 0, None, rng).unwrap();
    let block = sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 0);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    // Sample a Varuna assignment
    let assignment = snarkvm_synthesizer_snark::test_helpers::sample_assignment();

    // Varuna setup, prove, and verify.
    let srs = UniversalSRS::<CurrentNetwork>::load().unwrap();
    let (proving_key, verifying_key) = srs.to_circuit_key("test", &assignment).unwrap();
    let verifying_key_bytes = verifying_key.to_bytes_le().unwrap();

    // Construct the batch_proof
    let varuna_version = VarunaVersion::V2;
    let assignments = vec![(proving_key.clone(), vec![assignment.clone(); 2])];
    let batch_proof = ProvingKey::prove_batch("test", varuna_version, &assignments, &mut TestRng::default()).unwrap();
    let batch_proof_bytes = batch_proof.to_bytes_le().unwrap();

    let one = <Circuit as circuit::Environment>::BaseField::one();
    let zero = <Circuit as circuit::Environment>::BaseField::zero();
    let public_inputs = vec![one, one];
    let invalid_public_inputs = vec![one, zero];

    let valid_inputs = vec![(verifying_key.clone(), vec![public_inputs.clone(); 2])];
    let invalid_inputs = vec![(verifying_key.clone(), vec![invalid_public_inputs.clone(); 2])];
    assert!(VerifyingKey::verify_batch("test", varuna_version, valid_inputs, &batch_proof).is_ok());
    assert!(VerifyingKey::verify_batch("test", varuna_version, invalid_inputs, &batch_proof).is_err());

    // Construct the inputs for the execution.
    let verifying_key_input = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            verifying_key_bytes
                .into_iter()
                .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
                .collect(),
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    public_inputs
                        .clone()
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let invalid_verification_inputs = Value::Plaintext(Plaintext::Array(
        vec![Plaintext::Array(
            vec![
                Plaintext::Array(
                    invalid_public_inputs
                        .into_iter()
                        .map(|field| Plaintext::from(Literal::<CurrentNetwork>::Field(Field::new(field))))
                        .collect(),
                    OnceLock::new(),
                )
                .clone();
                2
            ],
            OnceLock::new(),
        )],
        OnceLock::new(),
    ));
    let proof_input = Value::Plaintext(Plaintext::Array(
        batch_proof_bytes
            .into_iter()
            .map(|byte| Plaintext::from(Literal::<CurrentNetwork>::U8(U8::new(byte))))
            .collect(),
        OnceLock::new(),
    ));

    // Store the verifying key and proof via the mapping.
    let store_vk_and_proof = {
        let inputs = vec![verifying_key_input.clone(), proof_input.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "store_verifying_key_and_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let block = sample_next_block(&vm, &caller_private_key, &[store_vk_and_proof], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    vm.add_next_block(&block).unwrap();

    // Execute a transaction that verifies the proof correctly.
    let valid_execution = {
        let inputs = vec![verification_inputs.clone()];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let valid_execution_id = valid_execution.id();

    // Execute a transaction that fails to verify the proof.
    let invalid_execution = {
        let inputs = vec![invalid_verification_inputs];
        vm.execute(
            &caller_private_key,
            (program.id().to_string(), "verify_batch_proof"),
            inputs.into_iter(),
            None,
            0,
            None,
            rng,
        )
        .unwrap()
    };
    let invalid_execution_id = invalid_execution.id();

    let block = sample_next_block(&vm, &caller_private_key, &[valid_execution, invalid_execution], rng).unwrap();
    assert_eq!(block.transactions().num_accepted(), 1);
    assert_eq!(block.transactions().num_rejected(), 1);
    assert_eq!(block.aborted_transaction_ids().len(), 0);
    vm.add_next_block(&block).unwrap();

    assert!(vm.transaction_store().contains_transaction_id(&valid_execution_id).unwrap());
    assert!(vm.block_store().contains_rejected_or_aborted_transaction_id(&invalid_execution_id).unwrap());
}
