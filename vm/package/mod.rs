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

mod deploy;

pub use deploy::{DeployRequest, DeployResponse};

use crate::{
    console::{network::Network, program::ProgramID},
    file::{AleoFile, Manifest},
    prelude::{Deserialize, Deserializer, Serialize, SerializeStruct, Serializer},
    synthesizer::{process::Process, program::Program},
    utilities::dev_println,
};

use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};

pub struct Package<N: Network> {
    /// The program ID.
    program_id: ProgramID<N>,
    /// The directory path.
    directory: PathBuf,
    /// The manifest file.
    manifest_file: Manifest<N>,
    /// The program file.
    program_file: AleoFile<N>,
}

impl<N: Network> Package<N> {
    /// Opens the package at the given directory with the given program name.
    pub fn open(directory: &Path) -> Result<Self> {
        // Ensure the directory path exists.
        ensure!(directory.exists(), "The program directory does not exist: {}", directory.display());
        // Ensure the manifest file exists.
        ensure!(
            Manifest::<N>::exists_at(directory),
            "Missing '{}' at '{}'",
            Manifest::<N>::file_name(),
            directory.display()
        );
        // Ensure the main program file exists.
        ensure!(
            AleoFile::<N>::main_exists_at(directory),
            "Missing '{}' at '{}'",
            AleoFile::<N>::main_file_name(),
            directory.display()
        );

        // Open the manifest file.
        let manifest_file = Manifest::open(directory)?;
        // Retrieve the program ID.
        let program_id = *manifest_file.program_id();
        // Ensure the program name is valid.
        ensure!(!Program::is_reserved_keyword(program_id.name()), "Program name is invalid (reserved): {program_id}");

        // Open the program file.
        let program_file = AleoFile::open(directory, &program_id, true)?;

        Ok(Self { program_id, directory: directory.to_path_buf(), manifest_file, program_file })
    }

    /// Returns the program ID.
    pub const fn program_id(&self) -> &ProgramID<N> {
        &self.program_id
    }

    /// Returns the directory path.
    pub const fn directory(&self) -> &PathBuf {
        &self.directory
    }

    /// Returns the manifest file.
    pub const fn manifest_file(&self) -> &Manifest<N> {
        &self.manifest_file
    }

    /// Returns the program file.
    pub const fn program_file(&self) -> &AleoFile<N> {
        &self.program_file
    }

    /// Returns the program.
    pub const fn program(&self) -> &Program<N> {
        self.program_file.program()
    }

    /// Returns the imports directory.
    pub fn imports_directory(&self) -> PathBuf {
        self.directory.join("imports")
    }

    /// Returns a new process for the package.
    pub fn get_process(&self) -> Result<Process<N>> {
        // Load the default process.
        let process = Process::load()?;
        // Get the imported programs.
        let imports_directory = self.imports_directory();
        let mut programs = self
            .program()
            .imports()
            .keys()
            .map(|program_id| {
                // TODO (howardwu): Add the following checks:
                //  1) the imported program ID exists *on-chain* (for the given network)
                //  2) the AVM bytecode of the imported program matches the AVM bytecode of the program *on-chain*
                //  3) consensus performs the exact same checks (in `verify_deployment`)
                // Open the Aleo program file.
                let is_main = false;
                let import_program_file = AleoFile::open(&imports_directory, program_id, is_main)?;
                // Get the program.
                Ok(import_program_file.program().clone())
            })
            .collect::<Result<Vec<_>>>()?;
        // Add the main program.
        programs.push(self.program().clone());

        // Get the editions for the programs, if specified in the manifest.
        let programs_and_editions = programs
            .into_iter()
            .map(|program| {
                // Get the program ID.
                let program_id = program.id();
                // Get the edition, if specified.
                if let Some(edition) = self.manifest_file.editions().get(program_id) {
                    (program, *edition)
                } else {
                    dev_println!(
                        " Could not find an edition for '{}' in the manifest, using edition 0...",
                        program_id.to_string()
                    );
                    (program, 0)
                }
            })
            .collect::<Vec<_>>();

        // Load the programs.
        process.lock().add_programs_with_editions(&programs_and_editions)?;

        Ok(process)
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use snarkvm_console::network::MainnetV0;

    use core::str::FromStr;
    use std::{fs::File, io::Write};

    type CurrentNetwork = MainnetV0;

    fn temp_dir() -> PathBuf {
        tempfile::tempdir().expect("Failed to open temporary directory").keep()
    }

    /// Samples a (temporary) package containing a `token.aleo` program.
    pub(crate) fn sample_token_package() -> (PathBuf, Package<CurrentNetwork>) {
        // Initialize the program.
        let program = Program::<CurrentNetwork>::from_str(
            "
program token.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function initialize:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function transfer:
    input r0 as token.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.amount r2 into r3;
    cast r1 r2 into r4 as token.record;
    cast r0.owner r3 into r5 as token.record;
    output r4 as token.record;
    output r5 as token.record;",
        )
        .unwrap();

        // Sample the package using the program.
        sample_package_with_program_and_imports(&program, &[])
    }

    /// Samples a (temporary) package containing a `wallet.aleo` program which imports `token.aleo`.
    pub(crate) fn sample_wallet_package() -> (PathBuf, Package<CurrentNetwork>) {
        // Initialize the imported program.
        let imported_program = Program::<CurrentNetwork>::from_str(
            "
program token.aleo;

record token:
    owner as address.private;
    amount as u64.private;

function initialize:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function transfer:
    input r0 as token.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.amount r2 into r3;
    cast r1 r2 into r4 as token.record;
    cast r0.owner r3 into r5 as token.record;
    output r4 as token.record;
    output r5 as token.record;",
        )
        .unwrap();

        // Initialize the main program.
        let main_program = Program::<CurrentNetwork>::from_str(
            "
import token.aleo;

program wallet.aleo;

function transfer:
    input r0 as token.aleo/token.record;
    input r1 as address.private;
    input r2 as u64.private;
    call token.aleo/transfer r0 r1 r2 into r3 r4;
    output r3 as token.aleo/token.record;
    output r4 as token.aleo/token.record;",
        )
        .unwrap();

        // Sample the package using the main program and imported program.
        sample_package_with_program_and_imports(&main_program, &[imported_program])
    }

    /// Samples a (temporary) package containing a `grandparent.aleo` program which imports `parent.aleo` which imports `child.aleo`.
    pub(crate) fn sample_nested_package() -> (PathBuf, Package<CurrentNetwork>) {
        // Initialize the child program.
        let child_program = Program::<CurrentNetwork>::from_str(
            "
program child.aleo;

record A:
    owner as address.private;
    val as u32.private;

function mint:
    input r0 as address.private;
    input r1 as u32.private;
    cast r0 r1 into r2 as A.record;
    output r2 as A.record;",
        )
        .unwrap();

        // Initialize the parent program.
        let parent_program = Program::<CurrentNetwork>::from_str(
            "
import child.aleo;

program parent.aleo;

function wrapper_mint:
    input r0 as address.private;
    input r1 as u32.private;
    call child.aleo/mint r0 r1 into r2;
    output r2 as child.aleo/A.record;",
        )
        .unwrap();

        // Initialize the grandparent program.
        let grandparent_program = Program::<CurrentNetwork>::from_str(
            "
import child.aleo;
import parent.aleo;

program grandparent.aleo;

function double_wrapper_mint:
    input r0 as address.private;
    input r1 as u32.private;
    call parent.aleo/wrapper_mint r0 r1 into r2;
    output r2 as child.aleo/A.record;",
        )
        .unwrap();

        // Sample the package using the main program and imported program.
        sample_package_with_program_and_imports(&grandparent_program, &[child_program, parent_program])
    }

    /// Samples a (temporary) package containing a `transfer.aleo` program which imports `credits.aleo`.
    pub(crate) fn sample_transfer_package() -> (PathBuf, Package<CurrentNetwork>) {
        // Initialize the imported program.
        let imported_program = Program::credits().unwrap();

        // Initialize the main program.
        let main_program = Program::<CurrentNetwork>::from_str(
            "
import credits.aleo;

program transfer.aleo;

function main:
    input r0 as credits.aleo/credits.record;
    input r1 as address.private;
    input r2 as u64.private;
    call credits.aleo/transfer_private r0 r1 r2 into r3 r4;
    output r3 as credits.aleo/credits.record;
    output r4 as credits.aleo/credits.record;",
        )
        .unwrap();

        // Sample the package using the main program and imported program.
        sample_package_with_program_and_imports(&main_program, &[imported_program])
    }

    /// Samples a (temporary) package using a main program and imported programs.
    pub(crate) fn sample_package_with_program_and_imports(
        main_program: &Program<CurrentNetwork>,
        imported_programs: &[Program<CurrentNetwork>],
    ) -> (PathBuf, Package<CurrentNetwork>) {
        // Initialize a temporary directory.
        let directory = temp_dir();

        // If there are imports, create the imports directory.
        if !imported_programs.is_empty() {
            let imports_directory = directory.join("imports");
            std::fs::create_dir_all(&imports_directory).unwrap();

            // Add the imported programs.
            for imported_program in imported_programs {
                let imported_program_id = imported_program.id();

                // Write the imported program string to an imports file in the temporary directory.
                let import_filepath = imports_directory.join(imported_program_id.to_string());
                let mut file = File::create(import_filepath).unwrap();
                file.write_all(imported_program.to_string().as_bytes()).unwrap();
            }
        }

        // Initialize the main program ID.
        let main_program_id = main_program.id();

        // Write the program string to a file in the temporary directory.
        let main_filepath = directory.join("main.aleo");
        let mut file = File::create(main_filepath).unwrap();
        file.write_all(main_program.to_string().as_bytes()).unwrap();

        // Create the manifest file.
        let _manifest_file = Manifest::create(&directory, main_program_id).unwrap();

        // Open the package at the temporary directory.
        let package = Package::<MainnetV0>::open(&directory).unwrap();
        assert_eq!(package.program_id(), main_program_id);

        // Return the temporary directory and the package.
        (directory, package)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_imports_directory() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Ensure the imports directory is correct.
        assert_eq!(package.imports_directory(), directory.join("imports"));
        // Ensure the imports directory does *not* exist, when the package does not contain imports.
        assert!(!package.imports_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_imports_directory_with_an_import() {
        // Samples a new package with an import at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_wallet_package();

        // Ensure the imports directory is correct.
        assert_eq!(package.imports_directory(), directory.join("imports"));
        // Ensure the imports directory exists, as the package contains an import.
        assert!(package.imports_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_get_process() {
        for (directory, package) in [
            crate::package::test_helpers::sample_token_package(),
            crate::package::test_helpers::sample_wallet_package(),
            crate::package::test_helpers::sample_nested_package(),
            crate::package::test_helpers::sample_transfer_package(),
        ] {
            // Get the process, and ensure it contains the main program.
            let process = package.get_process().unwrap();
            assert!(process.contains_program(package.program_id()));

            // Proactively remove the temporary directory (to conserve space).
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
}
