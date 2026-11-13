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
    file::Manifest,
    prelude::{Network, ProgramID},
    synthesizer::Program,
};

use anyhow::{Result, anyhow, bail, ensure};
use core::str::FromStr;
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

static ALEO_FILE_EXTENSION: &str = "aleo";

pub struct AleoFile<N: Network> {
    /// The file name (without the extension).
    file_name: String,
    /// The program as a string.
    program_string: String,
    /// The program.
    program: Program<N>,
}

impl<N: Network> FromStr for AleoFile<N> {
    type Err = anyhow::Error;

    /// Reads the file from a string.
    #[inline]
    fn from_str(s: &str) -> Result<Self> {
        let program = Program::from_str(s)?;
        let program_string = s.to_string();

        // The file name is defined as the string up to the extension (excluding the extension).
        let file_name = match program.id().is_aleo() {
            true => program.id().name().to_string(),
            false => program.id().to_string(),
        };

        Ok(Self { file_name, program_string, program })
    }
}

impl<N: Network> AleoFile<N> {
    /// Opens the Aleo program file, given the directory path, program ID, and `is_main` indicator.
    pub fn open(directory: &Path, program_id: &ProgramID<N>, is_main: bool) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The program directory does not exist: '{}'", directory.display());

        // Create the file.
        let file_name = if is_main {
            Self::main_file_name()
        } else {
            match program_id.is_aleo() {
                true => program_id.to_string(),
                false => format!("{program_id}.{ALEO_FILE_EXTENSION}"),
            }
        };
        // Construct the file path.
        let path = directory.join(file_name);
        // Ensure the file path exists.
        ensure!(path.exists(), "The Aleo file is missing: '{}'", path.display());

        // Load the Aleo file.
        let aleo_file = Self::from_filepath(&path)?;

        // Ensure the program ID matches, if this is the main file.
        if is_main && aleo_file.program.id() != program_id {
            bail!("The program ID from `{}` does not match in '{}'", Manifest::<N>::file_name(), path.display())
        }

        Ok(aleo_file)
    }

    /// Returns `true` if the file exists at the given path.
    pub fn exists_at(&self, file_path: &Path) -> bool {
        // Ensure the path is well-formed.
        Self::check_path(file_path).is_ok() && file_path.exists()
    }

    /// Returns `true` if the main program file exists at the given path.
    pub fn main_exists_at(directory: &Path) -> bool {
        // Construct the file path.
        let path = directory.join(Self::main_file_name());
        // Return the result.
        path.is_file() && path.exists()
    }

    /// Returns the main Aleo program file name.
    pub fn main_file_name() -> String {
        format!("main.{ALEO_FILE_EXTENSION}")
    }

    /// Returns the file name.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the program string.
    pub fn program_string(&self) -> &str {
        &self.program_string
    }

    /// Returns the program.
    pub const fn program(&self) -> &Program<N> {
        &self.program
    }

    /// Writes the program string to the file.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        // Ensure the path is well-formed.
        Self::check_path(path)?;

        // Retrieve the file name.
        let file_name = path
            .file_stem()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_str()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_string();
        // Ensure the file name matches the expected file name.
        ensure!(file_name == self.file_name, "File name does not match.");

        Ok(File::create(path)?.write_all(self.program_string.as_bytes())?)
    }

    /// Removes the file at the given path, if it exists.
    pub fn remove(&self, path: &Path) -> Result<()> {
        // If the path does not exist, do nothing.
        if !path.exists() {
            Ok(())
        } else {
            // Ensure the path is well-formed.
            Self::check_path(path)?;
            // If the path exists, remove it.
            if path.exists() {
                // Remove the file.
                fs::remove_file(path)?;
            }
            Ok(())
        }
    }
}

impl<N: Network> AleoFile<N> {
    /// Checks that the given path has the correct file extension.
    fn check_path(path: &Path) -> Result<()> {
        // Ensure the given path is a file.
        ensure!(path.is_file(), "The path is not a file.");

        // Ensure the given path has the correct file extension.
        let extension = path.extension().ok_or_else(|| anyhow!("File extension not found."))?;
        ensure!(extension == ALEO_FILE_EXTENSION, "File extension is incorrect.");

        Ok(())
    }

    /// Reads the program from the given file path, if it exists.
    fn from_filepath(file: &Path) -> Result<Self> {
        // Ensure the path is well-formed.
        Self::check_path(file)?;

        // Ensure the given path exists.
        ensure!(file.exists(), "File does not exist: {}", file.display());

        // Retrieve the file name.
        let file_name = file
            .file_stem()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_str()
            .ok_or_else(|| anyhow!("File name not found."))?
            .to_string();

        // Read the program string.
        let program_string = fs::read_to_string(file)?;
        // Parse the program string.
        let program = Program::from_str(&program_string)?;

        Ok(Self { file_name, program_string, program })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::Parser;

    type CurrentNetwork = snarkvm_console::network::MainnetV0;

    fn temp_dir() -> std::path::PathBuf {
        tempfile::tempdir().expect("Failed to open temporary directory").keep()
    }

    #[test]
    fn test_from_str() {
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

        // Read the program from the string.
        let file = AleoFile::from_str(program_string).unwrap();
        assert_eq!("token", file.file_name());
        assert_eq!(program_string, file.program_string());
        assert_eq!(&program, file.program());
    }

    #[test]
    fn test_from_path() {
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

        // Write the program string to a file in the temporary directory.
        let path = directory.join("token.aleo");
        let mut file = File::create(&path).unwrap();
        file.write_all(program_string.as_bytes()).unwrap();

        // Read the program from the path.
        let file = AleoFile::from_filepath(&path).unwrap();

        // Initialize a new program.
        let (string, program) = Program::<CurrentNetwork>::parse(program_string).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        assert_eq!("token", file.file_name());
        assert_eq!(program_string, file.program_string());
        assert_eq!(&program, file.program());
    }
}
