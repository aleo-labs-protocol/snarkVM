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

use aleo_std::StorageMode;
use snarkvm_algorithms::{crypto_hash::sha256::sha256, snark::varuna::VarunaVersion};
use snarkvm_circuit::{Aleo, Assignment};
use snarkvm_console::{
    account::PrivateKey,
    network::{CanaryV0, FromBits, MainnetV0, Network, TestnetV0},
    prelude::{One, ToBytes, Zero},
    program::{Plaintext, Record, StatePath},
    types::Field,
};
use snarkvm_ledger_store::ConsensusStore;

#[cfg(not(feature = "rocks"))]
type LedgerType<N> = snarkvm_ledger_store::helpers::memory::ConsensusMemory<N>;
#[cfg(feature = "rocks")]
type LedgerType<N> = snarkvm_ledger_store::helpers::rocksdb::ConsensusDB<N>;

use snarkvm_synthesizer::{
    VM,
    process::{InclusionAssignment, InclusionV0Assignment},
    snark::UniversalSRS,
};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
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

/// Returns the assignment for verifying the state path.
#[allow(clippy::type_complexity)]
pub fn sample_assignment_v0<N: Network, A: Aleo<Network = N>>() -> Result<(Assignment<N::Field>, StatePath<N>, Field<N>)> {
    // Initialize the consensus store.
    let store = ConsensusStore::<N, LedgerType<N>>::open(StorageMode::new_test(None))?;
    // Initialize a new VM.
    let vm = VM::from(store)?;

    // Initialize an RNG.
    let rng = &mut rand::rng();
    // Initialize a new caller.
    let caller_private_key = PrivateKey::<N>::new(rng).unwrap();
    // Return the block.
    let genesis_block = vm.genesis_beacon(&caller_private_key, rng)?;

    // Update the VM.
    vm.add_next_block(&genesis_block)?;

    // Fetch the first commitment.
    let commitment = genesis_block.commitments().next().ok_or_else(|| anyhow!("No commitments found"))?;
    // Compute the state path for the commitment.
    let state_path = vm.block_store().get_state_path_for_commitment(commitment)?;

    // Compute the generator `H` as `HashToGroup(commitment)`.
    let h = N::hash_to_group_psd2(&[N::serial_number_domain(), *commitment])?;
    // Compute `gamma` as `sk_sig * H`.
    let gamma = h * caller_private_key.sk_sig();
    // Compute the serial number.
    let serial_number = Record::<N, Plaintext<N>>::serial_number_from_gamma(&gamma, *commitment)?;

    // Construct the assignment for the inclusion circuit.
    let assignment = InclusionV0Assignment::new(state_path.clone(), *commitment, gamma, serial_number, Default::default(), true)
        .to_circuit_assignment::<A>()?;

    Ok((assignment, state_path, serial_number))
}

/// Returns the assignment for verifying the state path.
#[allow(clippy::type_complexity)]
pub fn sample_assignment<N: Network, A: Aleo<Network = N>>() -> Result<(Assignment<N::Field>, StatePath<N>, Field<N>, bool, u32)>
{
    // Initialize the consensus store.
    let store = ConsensusStore::<N, LedgerType<N>>::open(StorageMode::new_test(None))?;
    // Initialize a new VM.
    let vm = VM::from(store)?;

    // Initialize an RNG.
    let rng = &mut rand::rng();
    // Initialize a new caller.
    let caller_private_key = PrivateKey::<N>::new(rng).unwrap();
    // Return the block.
    let genesis_block = vm.genesis_beacon(&caller_private_key, rng)?;

    // Update the VM.
    vm.add_next_block(&genesis_block)?;

    // Fetch the first commitment.
    let commitment = genesis_block.commitments().next().ok_or_else(|| anyhow!("No commitments found"))?;
    // Compute the state path for the commitment.
    let state_path = vm.block_store().get_state_path_for_commitment(commitment)?;

    // Compute the generator `H` as `HashToGroup(commitment)`.
    let h = N::hash_to_group_psd2(&[N::serial_number_domain(), *commitment])?;
    // Compute `gamma` as `sk_sig * H`.
    let gamma = h * caller_private_key.sk_sig();
    // Compute the serial number.
    let serial_number = Record::<N, Plaintext<N>>::serial_number_from_gamma(&gamma, *commitment)?;

    // Set the `is_record_block_height_reached` flag.
    let is_record_block_height_reached = true;
    // Initialize the `upgrade_block_height`.
    let upgrade_block_height = 0;

    // Construct the assignment for the inclusion circuit.
    let assignment = InclusionAssignment::new(
        state_path.clone(),
        *commitment,
        gamma,
        serial_number,
        is_record_block_height_reached,
        upgrade_block_height,
        Default::default(),
        true,
    )
    .to_circuit_assignment::<A>()?;

    Ok((assignment, state_path, serial_number, is_record_block_height_reached, upgrade_block_height))
}

/// Synthesizes the circuit keys for the inclusion circuit. (cargo run --release --features filesystem --example inclusion [network])
pub fn inclusion<N: Network, A: Aleo<Network = N>>() -> Result<()> {
    // Load the universal SRS.
    let universal_srs = UniversalSRS::<N>::load()?;

    // Sample the assignment for the inclusion circuit.
    let (assignment, state_path, serial_number, is_record_block_height_reached, upgrade_block_height) =
        sample_assignment::<N, A>()?;

    // Synthesize the proving and verifying key.
    let inclusion_function_name = N::INCLUSION_FUNCTION_NAME;
    let (proving_key, verifying_key) = universal_srs.to_circuit_key(inclusion_function_name, &assignment)?;

    for varuna_version in [VarunaVersion::V1, VarunaVersion::V2] {
        // Ensure the proving key and verifying keys are valid.
        let proof = proving_key.prove(inclusion_function_name, varuna_version, &assignment, &mut rand::rng())?;
        assert!(verifying_key.verify(
            inclusion_function_name,
            varuna_version,
            &[
                N::Field::one(),
                **state_path.global_state_root(),
                *Field::<N>::zero(),
                *serial_number,
                *Field::<N>::from_bits_le(&[is_record_block_height_reached])?,
                *Field::<N>::from_u32(upgrade_block_height)
            ],
            &proof
        ));
        // Ensure using the wrong varuna version is not valid.
        let wrong_varuna_version = if varuna_version == VarunaVersion::V1 { VarunaVersion::V2 } else { VarunaVersion::V1 };
        assert!(!verifying_key.verify(
            inclusion_function_name,
            wrong_varuna_version,
            &[
                N::Field::one(),
                **state_path.global_state_root(),
                *Field::<N>::zero(),
                *serial_number,
                *Field::<N>::from_bits_le(&[is_record_block_height_reached])?,
                *Field::<N>::from_u32(upgrade_block_height)
            ],
            &proof
        ));
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
    write_metadata(&format!("{inclusion_function_name}.metadata"), &metadata)?;
    write_remote(&format!("{inclusion_function_name}.prover"), &proving_key_checksum, &proving_key_bytes)?;
    write_local(&format!("{inclusion_function_name}.verifier"), &verifying_key_bytes)?;

    commands
        .push(format!("upload \"{}\"", versioned_filename(&format!("{inclusion_function_name}.prover"), &proving_key_checksum)));

    // Print the commands.
    println!("\nNow, perform the following operations:\n");
    for command in commands {
        println!("{command}");
    }
    println!();

    Ok(())
}

/// Run the following command to generate the inclusion circuit keys.
/// `cargo run --features filesystem --example inclusion [network]`
pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Invalid number of arguments. Given: {} - Required: 1", args.len() - 1);
        return Ok(());
    }

    match args[1].as_str() {
        "mainnet" => {
            inclusion::<MainnetV0, snarkvm_circuit::AleoV0>()?;
        }
        "testnet" => {
            inclusion::<TestnetV0, snarkvm_circuit::AleoTestnetV0>()?;
        }
        "canary" => {
            inclusion::<CanaryV0, snarkvm_circuit::AleoCanaryV0>()?;
        }
        _ => panic!("Invalid network"),
    };

    Ok(())
}
