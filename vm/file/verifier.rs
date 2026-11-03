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
    synthesizer::{Program, snark::VerifyingKey},
};

use anyhow::{Result, anyhow, bail, ensure};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

static VERIFIER_FILE_EXTENSION: &str = "verifier";

pub struct VerifierFile<N: Network> {
    /// The function name.
    function_name: Identifier<N>,
    /// The verifying key.
    verifying_key: VerifyingKey<N>,
}

impl<N: Network> VerifierFile<N> {
    /// Creates a new verifying key file, given the directory path, function name, and verifying key.
    pub fn create(directory: &Path, function_name: &Identifier<N>, verifying_key: VerifyingKey<N>) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The build directory does not exist: '{}'", directory.display());
        // Ensure the function name is valid.
        ensure!(!Program::is_reserved_keyword(function_name), "Function name is invalid (reserved): {function_name}");

        // Create the candidate verifier file.
        let verifier_file = Self { function_name: *function_name, verifying_key };

        // Create the file name.
        let file_name = format!("{function_name}.{VERIFIER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Write the file (overwriting if it already exists).
        File::create(&path)?.write_all(&verifier_file.to_bytes_le()?)?;

        // Attempt to load the verifier file.
        Self::from_filepath(&path)
    }

    /// Opens the verifier file, given the directory path and function name.
    pub fn open(directory: &Path, function_name: &Identifier<N>) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The build directory does not exist: '{}'", directory.display());

        // Create the file name.
        let file_name = format!("{function_name}.{VERIFIER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Ensure the file path exists.
        ensure!(path.exists(), "The verifier file is missing: '{}'", path.display());

        // Load the verifier file.
        let verifier = Self::from_filepath(&path)?;

        // Ensure the function name matches.
        if verifier.function_name() != function_name {
            bail!(
                "The verifier file for '{}' contains an incorrect function name of '{}'",
                function_name,
                verifier.function_name()
            );
        }

        Ok(verifier)
    }

    /// Returns `true` if the verifier file for the given function name exists at the given directory.
    pub fn exists_at(directory: &Path, function_name: &Identifier<N>) -> bool {
        // Create the file name.
        let file_name = format!("{function_name}.{VERIFIER_FILE_EXTENSION}");
        // Construct the file path.
        let path = directory.join(file_name);
        // Ensure the path is well-formed.
        Self::check_path(&path).is_ok() && path.exists()
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the verifying key.
    pub const fn verifying_key(&self) -> &VerifyingKey<N> {
        &self.verifying_key
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

impl<N: Network> VerifierFile<N> {
    /// Checks that the given path has the correct file extension.
    fn check_path(path: &Path) -> Result<()> {
        // Ensure the given path is a file.
        ensure!(path.is_file(), "The path is not a file.");

        // Ensure the given path has the correct file extension.
        let extension = path.extension().ok_or_else(|| anyhow!("File extension not found."))?;
        ensure!(extension == VERIFIER_FILE_EXTENSION, "File extension is incorrect.");

        // Ensure the given path exists.
        ensure!(path.exists(), "File does not exist: {}", path.display());

        Ok(())
    }

    /// Reads the verifier from the given file path, if it exists.
    fn from_filepath(file: &Path) -> Result<Self> {
        // Ensure the path is well-formed.
        Self::check_path(file)?;
        // Parse the verifier file bytes.
        let verifier = Self::from_bytes_le(&fs::read(file)?)?;

        // Retrieve the file stem.
        let file_stem = file
            .file_stem()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_str()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_string();
        // Ensure the function name matches the file stem.
        ensure!(verifier.function_name.to_string() == file_stem, "Function name does not match file stem.");

        // Return the verifier file.
        Ok(verifier)
    }

    /// Writes the verifier to the file.
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

impl<N: Network> FromBytes for VerifierFile<N> {
    /// Reads the verifier file from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let function_name = Identifier::read_le(&mut reader)?;
        let verifying_key = FromBytes::read_le(&mut reader)?;
        Ok(Self { function_name, verifying_key })
    }
}

impl<N: Network> ToBytes for VerifierFile<N> {
    /// Writes the verifier file to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.function_name.write_le(&mut writer)?;
        self.verifying_key.write_le(&mut writer)
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

        // Sample the verifying key.
        process.synthesize_key::<CurrentAleo, _>(program.id(), &function_name, &mut TestRng::default()).unwrap();

        // Retrieve the verifying key.
        let verifying_key = process.get_verifying_key(program.id(), function_name).unwrap();

        // Create the verifier file at the path.
        let expected = VerifierFile::create(&directory, &function_name, verifying_key).unwrap();
        // Open the verifier file at the path.
        let candidate = VerifierFile::open(&directory, &function_name).unwrap();
        // Ensure the verifier files are equal.
        assert_eq!(expected.to_bytes_le().unwrap(), candidate.to_bytes_le().unwrap());
    }
}
