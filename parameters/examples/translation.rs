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

#![allow(clippy::type_complexity)]

use snarkvm_algorithms::{crypto_hash::sha256::sha256, snark::varuna::VarunaVersion};
use snarkvm_circuit::{Aleo, Assignment};
use snarkvm_console::{
    account::PrivateKey,
    network::{CanaryV0, MainnetV0, Network, TestnetV0},
    prelude::ToBytes,
    program::{DynamicRecord, Identifier, One, ProgramID, ToFields, Zero, compute_function_id},
    types::{Address, Field, Group, U16},
};
use snarkvm_synthesizer::{
    Process,
    Stack,
    process::{TranslationAssignment, compute_console_dynamic_or_external_record_id},
    program::StackTrait,
};

use anyhow::Result;
use rand::CryptoRng;
use serde_json::{Value, json};
use snarkvm_utilities::Uniform;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    str::FromStr,
};

fn checksum(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

fn versioned_filename(filename: &str, checksum: &str) -> String {
    match checksum.get(0..7) {
        Some(sum) => format!("{filename}.{sum}"),
        _ => filename.to_string(),
    }
}

/// Writes the given bytes to the given versioned filename.
fn write_remote(filename: &str, version: &str, bytes: &[u8]) -> Result<()> {
    let mut file = BufWriter::new(File::create(PathBuf::from(&versioned_filename(filename, version)))?);
    file.write_all(bytes)?;
    Ok(())
}

/// Writes the given bytes to the given filename.
fn write_local(filename: &str, bytes: &[u8]) -> Result<()> {
    let mut file = BufWriter::new(File::create(PathBuf::from(filename))?);
    file.write_all(bytes)?;
    Ok(())
}

/// Writes the given metadata as JSON to the given filename.
fn write_metadata(filename: &str, metadata: &Value) -> Result<()> {
    let mut file = BufWriter::new(File::create(PathBuf::from(filename))?);
    file.write_all(&serde_json::to_vec_pretty(metadata)?)?;
    Ok(())
}

/// Returns a sample assignment for the translation circuit.
pub fn sample_assignment<N: Network, A: Aleo<Network = N>>(
    stack: &Stack<N>,
    credits_program_id: &ProgramID<N>,
    transfer_public_function_name: &Identifier<N>,
    credits_record_name: &Identifier<N>,
    rng: &mut impl CryptoRng,
) -> Result<(Assignment<N::Field>, Vec<N::Field>)> {
    // Auxiliary data for the `TranslationAssignment`.
    let private_key = PrivateKey::<N>::new(rng)?;
    let address = Address::try_from(&private_key)?;
    let nonce: Group<N> = Uniform::rand(rng);
    let function_id = compute_function_id(&U16::new(N::ID), credits_program_id, transfer_public_function_name)?;

    // Construct the random `TranslationAssignment`. We model the case
    // [Output static (at callee) -> dynamic (at caller)]
    let record_static = stack.sample_record(&address, credits_record_name, nonce, rng)?;
    let record_dynamic = DynamicRecord::<N>::from_record(&record_static)?;
    let translation_index: u16 = Uniform::rand(rng);
    let tvk = Uniform::rand(rng);
    let record_register_index = Uniform::rand(rng);
    let record_view_key: Field<N> = Uniform::rand(rng);
    let gamma = None;
    let id_dynamic = compute_console_dynamic_or_external_record_id(
        function_id,
        record_dynamic.to_fields().unwrap(),
        tvk,
        U16::new(record_register_index),
    )
    .unwrap();
    let is_to_static = false;
    let is_external_record = false;
    let id_static = record_static.to_commitment(credits_program_id, credits_record_name, &record_view_key).unwrap();

    let translation_assignment = TranslationAssignment::new(
        record_static,
        record_dynamic,
        *credits_program_id,
        function_id,
        *credits_record_name,
        is_to_static,
        is_external_record,
        tvk,
        Some(record_view_key),
        gamma,
        record_register_index,
        id_dynamic,
        id_static,
    );

    let verifier_inputs = vec![
        // constant 1
        *Field::<N>::one(),
        // is_to_static
        *Field::<N>::zero(),
        // is_external_record
        *Field::<N>::zero(),
        *function_id,
        *Field::<N>::from_u128(translation_index as u128),
        *Field::<N>::from_u128(record_register_index as u128),
        *id_static,
        *id_dynamic,
    ];

    Ok((translation_assignment.to_circuit_assignment::<A>(translation_index, None, None, None)?, verifier_inputs))
}

/// Synthesizes the circuit keys for the credits.aleo credits record translation circuit. (cargo run --release --features filesystem --example translation [network])
pub fn translation<N: Network, A: Aleo<Network = N>>() -> Result<()> {
    let rng = &mut rand::rng();
    let process = Process::<N>::setup::<A, _>(rng)?;
    let credits_stack = process.get_stack(ProgramID::<N>::from_str("credits.aleo").unwrap())?;
    let transfer_private_function_name = Identifier::<N>::from_str("transfer_private").unwrap();
    let credits_record_name = Identifier::<N>::from_str("credits").unwrap();
    let proving_key = credits_stack.get_proving_key(&credits_record_name)?;
    let verifying_key = credits_stack.get_verifying_key(&credits_record_name)?;

    // Sample a translation assignment for the credits record for the proving-
    // and verifying-key sanity check.
    let (assignment, verifier_inputs) = sample_assignment::<N, A>(
        &credits_stack,
        credits_stack.program_id(),
        &transfer_private_function_name,
        &credits_record_name,
        rng,
    )?;

    let debug_info_str = "credits_record_translation";

    for varuna_version in [VarunaVersion::V1, VarunaVersion::V2] {
        // Ensure the proving key and verifying keys are valid.
        let proof = proving_key.prove(debug_info_str, varuna_version, &assignment, rng)?;
        assert!(verifying_key.verify(debug_info_str, varuna_version, &verifier_inputs, &proof));
        // Ensure using the wrong varuna version is not valid.
        let wrong_varuna_version = if varuna_version == VarunaVersion::V1 { VarunaVersion::V2 } else { VarunaVersion::V1 };
        assert!(!verifying_key.verify(debug_info_str, wrong_varuna_version, &verifier_inputs, &proof));
    }

    // Initialize a vector for the commands.
    let mut commands = vec![];

    let proving_key_bytes = proving_key.to_bytes_le()?;
    let proving_key_checksum = checksum(&proving_key_bytes);

    let verifying_key_bytes = verifying_key.to_bytes_le()?;
    let verifying_key_checksum = checksum(&verifying_key_bytes);

    let metadata = json!({
        "prover_checksum": proving_key_checksum,
        "prover_size": proving_key_bytes.len(),
        "verifier_checksum": verifying_key_checksum,
        "verifier_size": verifying_key_bytes.len(),
    });

    println!("{}", serde_json::to_string_pretty(&metadata)?);
    write_metadata("translation_credits.metadata", &metadata)?;
    write_remote("translation_credits.prover", &proving_key_checksum, &proving_key_bytes)?;
    write_local("translation_credits.verifier", &verifying_key_bytes)?;

    commands.push(format!("upload \"{}\"", versioned_filename("translation_credits.prover", &proving_key_checksum)));

    // Print the commands.
    println!("\nNow, perform the following operations:\n");
    for command in commands {
        println!("{command}");
    }
    println!();

    Ok(())
}

/// Run the following command to generate the translation circuit keys.
/// `cargo run --features filesystem --example translation [network]`
pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Invalid number of arguments. Given: {} - Required: 1", args.len() - 1);
        return Ok(());
    }

    match args[1].as_str() {
        "mainnet" => {
            translation::<MainnetV0, snarkvm_circuit::AleoV0>()?;
        }
        "testnet" => {
            translation::<TestnetV0, snarkvm_circuit::AleoTestnetV0>()?;
        }
        "canary" => {
            translation::<CanaryV0, snarkvm_circuit::AleoCanaryV0>()?;
        }
        _ => panic!("Invalid network"),
    };

    Ok(())
}
