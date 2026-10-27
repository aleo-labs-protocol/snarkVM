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

mod build;
mod clean;
mod deploy;
mod execute;
mod is_build_required;
mod run;

pub use deploy::{DeployRequest, DeployResponse};

use crate::{
    console::{
        account::PrivateKey,
        network::{ConsensusVersion, Network},
        program::{Identifier, Locator, ProgramID, Response, Value},
    },
    file::{AVMFile, AleoFile, Manifest, ProverFile, README, VerifierFile},
    ledger::{
        block::Execution,
        query::{Query, QueryTrait},
        store::helpers::memory::BlockMemory,
    },
    prelude::{Deserialize, Deserializer, Serialize, SerializeStruct, Serializer},
    synthesizer::{
        process::{Assignments, CallMetrics, CallStack, Process},
        program::{CallOperator, Instruction, Program, StackTrait},
    },
    utilities::dev_println,
};

use anyhow::{Result, bail, ensure};
use core::str::FromStr;
use rand::{CryptoRng, Rng};
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
    /// Creates a new package, at the given directory with the given program name.
    pub fn create(directory: &Path, program_id: &ProgramID<N>) -> Result<Self> {
        // Ensure the directory path does not exist.
        ensure!(!directory.exists(), "The program directory already exists: {}", directory.display());
        // Ensure the program name is valid.
        ensure!(!Program::is_reserved_keyword(program_id.name()), "Program name is invalid (reserved): {program_id}");

        // Create the program directory.
        if !directory.exists() {
            std::fs::create_dir_all(directory)?;
        }

        // Create the manifest file.
        let manifest_file = Manifest::create(directory, program_id)?;
        // Create the program file.
        let program_file = AleoFile::create(directory, program_id, true)?;
        // Create the README file.
        let _readme_file = README::create::<N>(directory, program_id)?;

        Ok(Self { program_id: *program_id, directory: directory.to_path_buf(), manifest_file, program_file })
    }

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

    /// Returns the build directory.
    pub fn build_directory(&self) -> PathBuf {
        self.directory.join("build")
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
    use snarkvm_console::{account::Address, network::MainnetV0, prelude::TestRng};

    use std::{fs::File, io::Write};

    use anyhow::anyhow;

    type CurrentNetwork = MainnetV0;

    fn temp_dir() -> PathBuf {
        tempfile::tempdir().expect("Failed to open temporary directory").keep()
    }

    fn env_template() -> String {
        r#"
    NETWORK=mainnet
    PRIVATE_KEY={{PASTE_YOUR_PRIVATE_KEY_HERE}}
    "#
        .to_string()
    }

    /// Loads the environment variables from the .env file.
    fn dotenv_load() -> Result<()> {
        // Load environment variables from .env file.
        // Fails if .env file not found, not readable or invalid.
        dotenvy::dotenv().map_err(|_| {
            anyhow!(
                "Missing a '.env' file. Create the '.env' file in your package's root directory with the following:\n\n{}\n",
                env_template()
            )
        })?;
        Ok(())
    }

    /// Returns the private key from the environment.
    fn dotenv_private_key() -> Result<PrivateKey<CurrentNetwork>> {
        if cfg!(test) {
            let rng = &mut crate::utilities::TestRng::fixed(123456789);
            PrivateKey::<CurrentNetwork>::new(rng)
        } else {
            use std::str::FromStr;
            dotenv_load()?;
            // Load the private key from the environment.
            let private_key = dotenvy::var("PRIVATE_KEY").map_err(|e| anyhow!("Missing PRIVATE_KEY - {e}"))?;
            // Parse the private key.
            PrivateKey::<CurrentNetwork>::from_str(&private_key)
        }
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

    /// Samples a candidate input to execute the sample package.
    pub(crate) fn sample_package_run(
        program_id: &ProgramID<CurrentNetwork>,
    ) -> (PrivateKey<CurrentNetwork>, Identifier<CurrentNetwork>, Vec<Value<CurrentNetwork>>) {
        // Initialize an RNG.
        let rng = &mut TestRng::default();

        match program_id.to_string().as_str() {
            "token.aleo" => {
                // Sample a random private key.
                let private_key = dotenv_private_key().unwrap();
                let caller = Address::try_from(&private_key).unwrap();

                // Initialize the function name.
                let function_name = Identifier::from_str("initialize").unwrap();

                // Initialize the function inputs.
                let r0 = Value::from_str(&caller.to_string()).unwrap();
                let r1 = Value::from_str("100u64").unwrap();

                (private_key, function_name, vec![r0, r1])
            }
            "wallet.aleo" => {
                // Initialize caller 0.
                let caller0_private_key = dotenv_private_key().unwrap();
                let caller0 = Address::try_from(&caller0_private_key).unwrap();

                // Initialize caller 1.
                let caller1_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
                let caller1 = Address::try_from(&caller1_private_key).unwrap();

                // Declare the function name.
                let function_name = Identifier::from_str("transfer").unwrap();

                // Initialize the function inputs.
                let r0 = Value::<CurrentNetwork>::from_str(&format!(
                    "{{ owner: {caller0}.private, amount: 100u64.private, _nonce: 0group.public }}"
                ))
                .unwrap();
                let r1 = Value::<CurrentNetwork>::from_str(&caller1.to_string()).unwrap();
                let r2 = Value::<CurrentNetwork>::from_str("99u64").unwrap();

                (caller0_private_key, function_name, vec![r0, r1, r2])
            }
            "grandparent.aleo" => {
                // Initialize caller 0.
                let caller0_private_key = dotenv_private_key().unwrap();

                // Initialize caller 1.
                let caller1_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
                let caller1 = Address::try_from(&caller1_private_key).unwrap();

                // Declare the function name.
                let function_name = Identifier::from_str("double_wrapper_mint").unwrap();

                // Initialize the function inputs.
                let r0 = Value::<CurrentNetwork>::from_str(&caller1.to_string()).unwrap();
                let r1 = Value::<CurrentNetwork>::from_str("1u32").unwrap();

                (caller0_private_key, function_name, vec![r0, r1])
            }
            _ => panic!("Invalid program ID for sample package (while testing)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::MainnetV0;
    use snarkvm_utilities::TestRng;

    type CurrentAleo = snarkvm_circuit::network::AleoV0;
    type CurrentNetwork = MainnetV0;

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
    fn test_build_directory() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Ensure the build directory is correct.
        assert_eq!(package.build_directory(), directory.join("build"));
        // Ensure the build directory does *not* exist, when the package has not been built.
        assert!(!package.build_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_get_process() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Get the program process and check all instructions.
        assert!(package.get_process().is_ok());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_package_run_and_execute_match() {
        // Initialize the program.
        let program = Program::<CurrentNetwork>::from_str(
            "
program foo.aleo;

function bar:
    input r0 as boolean.private;
    assert.eq r0 false;",
        )
        .unwrap();

        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_package_with_program_and_imports(&program, &[]);

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Sample the function inputs.
        let private_key = PrivateKey::new(rng).unwrap();
        let function_name = Identifier::from_str("bar").unwrap();
        let inputs = vec![Value::from_str("true").unwrap()];

        // Construct the endpoint.
        let endpoint = "https://api.explorer.aleo.org/v1".to_string();

        // Run the program function.
        let run_result = package.run::<CurrentAleo, _>(&private_key, function_name, &inputs, rng).ok();

        // Execute the program function.
        let execute_result =
            package.execute::<CurrentAleo, _>(endpoint, &private_key, function_name, &inputs, rng).ok();

        match (run_result, execute_result) {
            // If both results are `None`, then they both failed.
            (None, None) => {}
            // If both results are `Some`, then check that the responses match.
            (Some((run_response, _)), Some((execute_response, _, _))) => {
                assert_eq!(run_response, execute_response);
            }
            // Otherwise, the results do not match.
            _ => panic!("Run and execute results do not match"),
        }

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }
}
