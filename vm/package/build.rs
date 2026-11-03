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

impl<N: Network> Package<N> {
    /// Builds the package.
    pub fn build<A: crate::circuit::Aleo<Network = N, BaseField = N::Field>>(&self) -> Result<()> {
        // Skip the 'build' if the program is already built.
        if !self.is_build_required::<A>() {
            return Ok(());
        }

        // Retrieve the main program.
        let program = self.program();
        // Retrieve the program ID.
        let program_id = program.id();

        dev_println!("⏳ Compiling '{}'...\n", program_id.to_string());

        // Prepare the build directory.
        let build_directory = self.build_directory();
        // Create the build directory if it does not exist.
        if !build_directory.exists() {
            std::fs::create_dir_all(&build_directory)?;
        }

        // Construct the process.
        let process = self.get_process()?;

        // Synthesize each proving and verifying key.
        for function_name in program.functions().keys() {
            process.synthesize_key::<A, _>(program_id, function_name, &mut rand::rng())?;
        }

        // Load each function circuit.
        for function_name in program.functions().keys() {
            // Retrieve the program.
            let stack = process.get_stack(program_id)?;
            let program = stack.program();
            // Retrieve the function from the program.
            let function = program.get_function(function_name)?;
            // Save all the prover and verifier files for any function calls that are made.
            for instruction in function.instructions() {
                // Note: `CallDynamic` is not handled here because its targets are resolved at runtime,
                // so we cannot preload prover/verifier files for dynamic calls at build time.
                if let Instruction::Call(call) = instruction {
                    // Get the external stack and resource.
                    let (external_stack, resource) = match call.operator() {
                        CallOperator::Locator(locator) => {
                            (Some(process.get_stack(locator.program_id())?), locator.resource())
                        }
                        CallOperator::Resource(resource) => (None, resource),
                    };
                    // Retrieve the program.
                    let program = match &external_stack {
                        Some(external_stack) => external_stack.program(),
                        None => program,
                    };
                    // If this is a function call, save its corresponding prover and verifier files.
                    if program.contains_function(resource) {
                        // Set the function name to the resource, in this scope.
                        let function_name = resource;
                        // Retrieve the proving key.
                        let proving_key = process.get_proving_key(program.id(), resource)?;
                        // Retrieve the verifying key.
                        let verifying_key = process.get_verifying_key(program.id(), resource)?;

                        // Prepare the build directory for the imported program.
                        let import_build_directory =
                            self.build_directory().join(format!("{}-{}", program.id().name(), program.id().network()));
                        // Create the build directory if it does not exist.
                        if !import_build_directory.exists() {
                            std::fs::create_dir_all(&import_build_directory)?;
                        }

                        // Create the prover.
                        let _prover = ProverFile::create(&import_build_directory, function_name, proving_key)?;
                        // Create the verifier.
                        let _verifier = VerifierFile::create(&import_build_directory, function_name, verifying_key)?;
                    }
                }
            }

            // Retrieve the proving key.
            let proving_key = process.get_proving_key(program_id, function_name)?;
            // Retrieve the verifying key.
            let verifying_key = process.get_verifying_key(program_id, function_name)?;

            // Create the prover.
            let _prover = ProverFile::create(&build_directory, function_name, proving_key)?;
            // Create the verifier.
            let _verifier = VerifierFile::create(&build_directory, function_name, verifying_key)?;
        }

        // Lastly, write the AVM file.
        let _avm_file = AVMFile::create(&build_directory, program.clone(), true)?;

        // Ensure the build directory exists.
        if !self.build_directory().exists() {
            bail!("Build directory does not exist: {}", self.build_directory().display());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    type CurrentAleo = snarkvm_circuit::network::AleoV0;

    #[test]
    fn test_build() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_build_with_import() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_wallet_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore]
    fn test_build_with_import_credits() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_transfer_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }
}
