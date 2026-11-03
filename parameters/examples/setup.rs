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

use snarkvm_algorithms::crypto_hash::sha256::sha256;
use snarkvm_circuit::Aleo;
use snarkvm_console::{
    network::{CanaryV0, MainnetV0, Network, TestnetV0, prelude::ToBytes},
    program::{Identifier, ProgramID},
};
use snarkvm_synthesizer::{Process, Program};
use snarkvm_utilities::FixedRng;

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    fs::File,
    io::{BufWriter, Read, Write},
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

/// (Do not use) Writes the metadata files. (cargo run --release --features filesystem --example setup usrs)
pub fn usrs() -> Result<()> {
    let paths = fs::read_dir("../src/mainnet/resources/").unwrap();
    for path in paths {
        let path = path?.path();
        if let Some("usrs") = path.extension().and_then(|s| s.to_str()) {
            let metadata_path = path.with_extension("metadata");
            let mut file = File::open(&path)?;
            let file_size = file.metadata().unwrap().len() as usize;
            let mut file_bytes = Vec::with_capacity(file_size);
            file.read_to_end(&mut file_bytes)?;
            let checksum = checksum(&file_bytes);

            let metadata = json!({
                "checksum": checksum,
                "size": file_size,
            });

            write_metadata(metadata_path.to_str().unwrap(), &metadata)?;
            write_remote(path.to_str().unwrap(), &checksum, &file_bytes)?;
        }
    }
    Ok(())
}

/// Synthesizes the circuit keys for the credits program. (cargo run --release --features filesystem --example setup credits)
pub fn credits_program<N: Network, A: Aleo<Network = N>>() -> Result<()> {
    // Samples the burner key and inputs; the keys depend only on the circuit and the SRS, not on this seed.
    let rng = &mut FixedRng::new([0u8; 32]);
    // Initialize the process.
    let process = Process::setup::<A, _>(rng)?;
    // Initialize the program.
    let program = Program::<N>::credits()?;
    let program_id = program.id();

    // Initialize a vector for the commands.
    let mut commands = vec![];

    // Store the 'credits.aleo' circuit keys.
    for (function_name, _) in program.functions().iter() {
        // let timer = std::time::Instant::now();
        // process.synthesize_key::<A, _>(program_id, function_name, rng)?;
        // println!("Synthesized '{}': {} ms", function_name, timer.elapsed().as_millis());

        commands.push(write_keys(&process, program_id, function_name, &function_name.to_string())?);
    }

    // Print the commands.
    println!("\nNow, perform the following operations:\n");
    for command in commands {
        println!("{command}");
    }
    println!();

    Ok(())
}

/// Synthesizes the circuit keys for the last program given, after its imports in dependency order: for
/// every function, or for those `--functions` names.
/// (cargo run --release --example setup program mainnet [--functions a,b] [imports.aleo...] program.aleo)
pub fn program<N: Network, A: Aleo<Network = N>>(args: &[String]) -> Result<()> {
    let (functions, paths) = match args {
        [flag, names, paths @ ..] if flag == "--functions" => {
            (Some(names.split(',').map(Identifier::<N>::from_str).collect::<Result<Vec<_>>>()?), paths)
        }
        paths => (None, paths),
    };
    // Samples the burner key and inputs; the keys depend only on the circuit and the SRS, not on this seed.
    let rng = &mut FixedRng::new([0u8; 32]);
    let process = Process::<N>::load()?;
    let credits_id = ProgramID::<N>::from_str("credits.aleo")?;

    let mut program = None;
    for path in paths {
        let next = fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .and_then(|source| Program::<N>::from_str(&source))
            .with_context(|| format!("reading {path}"))?;
        // `add_program` silently skips credits.aleo, whose keys `setup credits` writes.
        ensure!(next.id() != &credits_id, "{path} is credits.aleo; use `setup credits`");
        process.lock().add_program(&next).with_context(|| format!("adding {path}"))?;
        program = Some(next);
    }
    let Some(program) = program else {
        bail!("Usage: setup program <network> [--functions a,b] [imports.aleo...] program.aleo, imports in dependency order")
    };
    let program_id = program.id();
    let functions = match functions {
        Some(functions) => {
            for function in &functions {
                ensure!(program.contains_function(function), "{program_id} has no function {function}");
            }
            functions
        }
        None => program.functions().keys().copied().collect(),
    };

    let mut commands = vec![];
    for function_name in &functions {
        process.synthesize_key::<A, _>(program_id, function_name, rng)?;
        commands.push(write_keys(&process, program_id, function_name, &format!("{}.{function_name}", program_id.name()))?);
        process.remove_proving_key(program_id, function_name)?;
    }

    // Print the commands.
    println!("\nNow, perform the following operations:\n");
    for command in commands {
        println!("{command}");
    }
    println!();

    Ok(())
}

/// Writes the metadata, prover and verifier files for a function's keys, and returns the upload command.
fn write_keys<N: Network>(
    process: &Process<N>,
    program_id: &ProgramID<N>,
    function_name: &Identifier<N>,
    stem: &str,
) -> Result<String> {
    let proving_key = process.get_proving_key(program_id, function_name)?;
    let proving_key_bytes = proving_key.to_bytes_le()?;
    let proving_key_checksum = checksum(&proving_key_bytes);

    let verifying_key = process.get_verifying_key(program_id, function_name)?;
    let verifying_key_bytes = verifying_key.to_bytes_le()?;
    let verifying_key_checksum = checksum(&verifying_key_bytes);

    let metadata = json!({
        "prover_checksum": proving_key_checksum,
        "prover_size": proving_key_bytes.len(),
        "verifier_checksum": verifying_key_checksum,
        "verifier_size": verifying_key_bytes.len(),
    });

    println!("{}", serde_json::to_string_pretty(&metadata)?);
    write_metadata(&format!("{stem}.metadata"), &metadata)?;
    write_remote(&format!("{stem}.prover"), &proving_key_checksum, &proving_key_bytes)?;
    write_local(&format!("{stem}.verifier"), &verifying_key_bytes)?;

    Ok(format!("upload \"{}\"", versioned_filename(&format!("{stem}.prover"), &proving_key_checksum)))
}

/// Run the following command to perform a setup.
/// `cargo run --features filesystem --example setup [variant]`
pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Invalid number of arguments. Given: {} - Required: 2", args.len() - 1);
        return Ok(());
    }

    match args[1].as_str() {
        "usrs" => usrs()?,
        "credits" => match args[2].as_str() {
            "mainnet" => credits_program::<MainnetV0, snarkvm_circuit::AleoV0>(),
            "testnet" => credits_program::<TestnetV0, snarkvm_circuit::AleoTestnetV0>(),
            "canary" => credits_program::<CanaryV0, snarkvm_circuit::AleoCanaryV0>(),
            _ => panic!("Invalid network"),
        }?,
        "program" => match args[2].as_str() {
            "mainnet" => program::<MainnetV0, snarkvm_circuit::AleoV0>(&args[3..]),
            "testnet" => program::<TestnetV0, snarkvm_circuit::AleoTestnetV0>(&args[3..]),
            "canary" => program::<CanaryV0, snarkvm_circuit::AleoCanaryV0>(&args[3..]),
            _ => panic!("Invalid network"),
        }?,
        _ => panic!("Invalid parameter"),
    };

    Ok(())
}
