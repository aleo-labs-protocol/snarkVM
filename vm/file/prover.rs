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
    prelude::{FromBytes, Identifier, IoResult, Network, Read, ToBytes},
    synthesizer::{Program, snark::ProvingKey},
};

use anyhow::{Result, anyhow, bail, ensure};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

static PROVER_FILE_EXTENSION: &str = "prover";

pub struct ProverFile<N: Network> {
    /// The function name.
    function_name: Identifier<N>,
    /// The proving key.
    proving_key: ProvingKey<N>,
}

impl<N: Network> ProverFile<N> {
    /// Creates a new proving key file, given the directory path, function name, and proving key.
    pub fn create(directory: &Path, function_name: &Identifier<N>, proving_key: ProvingKey<N>) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The build directory does not exist: '{}'", directory.display());
        // Ensure the function name is valid.
        ensure!(!Program::is_reserved_keyword(function_name), "Function name is invalid (reserved): {function_name}");

        // Create the candidate prover file.
        let prover_file = Self { function_name: *function_name, proving_key };

        // Create the file name.
        let file_name = format!("{function_name}.{PROVER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Write the file (overwriting if it already exists).
        File::create(&path)?.write_all(&prover_file.to_bytes_le()?)?;

        // Attempt to load the prover file.
        Self::from_filepath(&path)
    }

    /// Opens the prover file, given the directory path and function name.
    pub fn open(directory: &Path, function_name: &Identifier<N>) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The build directory does not exist: '{}'", directory.display());

        // Create the file name.
        let file_name = format!("{function_name}.{PROVER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Ensure the file path exists.
        ensure!(path.exists(), "The prover file is missing: '{}'", path.display());

        // Load the prover file.
        let prover = Self::from_filepath(&path)?;

        // Ensure the function name matches.
        if prover.function_name() != function_name {
            bail!(
                "The prover file for '{}' contains an incorrect function name of '{}'",
                function_name,
                prover.function_name()
            );
        }

        Ok(prover)
    }

    /// Returns `true` if the prover file for the given function name exists at the given directory.
    pub fn exists_at(directory: &Path, function_name: &Identifier<N>) -> bool {
        // Create the file name.
        let file_name = format!("{function_name}.{PROVER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Ensure the path is well-formed.
        Self::check_path(&path).is_ok() && path.exists()
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the proving key.
    pub const fn proving_key(&self) -> &ProvingKey<N> {
        &self.proving_key
    }

    /// Removes the file at the given path, if it exists.
    pub fn remove(&self, path: &Path) -> Result<()> {
        // If the path does not exist, do nothing.
        if !path.exists() {
            Ok(())
        } else {
            // Ensure the path is well-formed.
            Self::check_path(path)?;
            // Remove the file.
            Ok(fs::remove_file(path)?)
        }
    }
}

impl<N: Network> ProverFile<N> {
    /// Checks that the given path has the correct file extension.
    fn check_path(path: &Path) -> Result<()> {
        // Ensure the given path is a file.
        ensure!(path.is_file(), "The path is not a file.");

        // Ensure the given path has the correct file extension.
        let extension = path.extension().ok_or_else(|| anyhow!("File extension not found."))?;
        ensure!(extension == PROVER_FILE_EXTENSION, "File extension is incorrect.");

        // Ensure the given path exists.
        ensure!(path.exists(), "File does not exist: {}", path.display());

        Ok(())
    }

    /// Reads the prover from the given file path, if it exists.
    fn from_filepath(file: &Path) -> Result<Self> {
        // Ensure the path is well-formed.
        Self::check_path(file)?;
        // Parse the prover file bytes.
        let prover = Self::from_bytes_le(&fs::read(file)?)?;

        // Retrieve the file stem.
        let file_stem = file
            .file_stem()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_str()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_string();
        // Ensure the function name matches the file stem.
        ensure!(prover.function_name.to_string() == file_stem, "Function name does not match file stem.");

        // Return the prover file.
        Ok(prover)
    }

    /// Writes the prover to the file.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        // Ensure the path is well-formed.
        Self::check_path(path)?;

        // Retrieve the file stem.
        let file_stem = path
            .file_name()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_str()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_string();
        // Ensure the function name matches the file stem.
        ensure!(self.function_name.to_string() == file_stem, "Function name does not match file stem.");

        // Write to the file (overwriting if it already exists).
        Ok(File::create(path)?.write_all(&self.to_bytes_le()?)?)
    }
}

impl<N: Network> FromBytes for ProverFile<N> {
    /// Reads the prover file from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let function_name = Identifier::read_le(&mut reader)?;
        let proving_key = FromBytes::read_le(&mut reader)?;
        Ok(Self { function_name, proving_key })
    }
}

impl<N: Network> ToBytes for ProverFile<N> {
    /// Writes the prover file to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.function_name.write_le(&mut writer)?;
        self.proving_key.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prelude::{FromStr, Parser, TestRng},
        synthesizer::Process,
    };

    type CurrentNetwork = snarkvm_console::network::MainnetV0;
    type CurrentAleo = snarkvm_circuit::AleoV0;

    fn temp_dir() -> std::path::PathBuf {
        tempfile::tempdir().expect("Failed to open temporary directory").keep()
    }

    #[test]
    fn test_create_and_open() {
        // Initialize a temporary directory.
        let directory = temp_dir();

        let program_string = r"
program token.aleo;

record token:
    owner as address.private;
    token_amount as u64.private;

function compute:
    input r0 as token.record;
    add r0.token_amount r0.token_amount into r1;
    output r1 as u64.private;";

        // Initialize a new program.
        let (string, program) = Program::<CurrentNetwork>::parse(program_string).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        // Construct the process.
        let process = Process::load().unwrap();
        // Add the program to the process.
        process.lock().add_program(&program).unwrap();

        // Prepare the function name.
        let function_name = Identifier::from_str("compute").unwrap();

        // Sample the proving key.
        process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, &mut TestRng::default()).unwrap();

        // Retrieve the proving key.
        let proving_key = process.get_proving_key(program.id(), function_name).unwrap();

        // Create the prover file at the path.
        let expected = ProverFile::create(&directory, &function_name, proving_key).unwrap();
        // Open the prover file at the path.
        let candidate = ProverFile::open(&directory, &function_name).unwrap();
        // Ensure the prover files are equal.
        assert_eq!(expected.to_bytes_le().unwrap(), candidate.to_bytes_le().unwrap());
    }
}
