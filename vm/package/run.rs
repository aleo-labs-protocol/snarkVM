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
    /// Runs a program function with the given inputs.
    pub fn run<A: crate::circuit::Aleo<Network = N, BaseField = N::Field>, R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        function_name: Identifier<N>,
        inputs: &[Value<N>],
        rng: &mut R,
    ) -> Result<(Response<N>, Vec<CallMetrics<N>>)> {
        // Retrieve the main program.
        let program = self.program();
        // Retrieve the program ID.
        let program_id = program.id();
        // Ensure that the function exists.
        if !program.contains_function(&function_name) {
            bail!("Function '{function_name}' does not exist.")
        }

        // Prepare the locator (even if logging is disabled, to sanity check the locator is well-formed).
        let _locator = Locator::<N>::from_str(&format!("{program_id}/{function_name}"))?;

        dev_println!("🚀 Running '{}'...\n", _locator.to_string());

        // Construct the process.
        let process = self.get_process()?;
        // Authorize the function call.
        let authorization = process.authorize::<A, R>(private_key, program_id, function_name, inputs.iter(), rng)?;

        // TODO (howardwu): Retrieve the value directly from the authorize call.
        // Pop the first request.
        let request = authorization.next()?;
        // Retrieve the stack.
        let stack = process.get_stack(program_id)?;
        // Initialize the assignments.
        let assignments = Assignments::<N>::default();
        // Initialize the call stack.
        let call_stack = CallStack::PackageRun(vec![request], *private_key, assignments.clone());
        // Synthesize the circuit.
        let Some(response) = stack.execute_function::<A, R>(call_stack, None, None, rng)? else {
            bail!("Response should be present in `PackageRun` mode.");
        };
        // Retrieve the call metrics.
        let call_metrics = assignments.read().iter().map(|(_, metrics)| *metrics).collect::<Vec<_>>();
        // Return the response and call metrics.
        Ok((response, call_metrics))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_utilities::TestRng;

    type CurrentAleo = snarkvm_circuit::network::AleoV0;

    #[test]
    fn test_run() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Sample the function inputs.
        let (private_key, function_name, inputs) =
            crate::package::test_helpers::sample_package_run(package.program_id());
        // Run the program function.
        let (_response, _metrics) = package.run::<CurrentAleo, _>(&private_key, function_name, &inputs, rng).unwrap();

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_run_with_import() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_wallet_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Sample the function inputs.
        let (private_key, function_name, inputs) =
            crate::package::test_helpers::sample_package_run(package.program_id());
        // Run the program function.
        let (_response, _metrics) = package.run::<CurrentAleo, _>(&private_key, function_name, &inputs, rng).unwrap();

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn test_run_with_nested_imports() {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_nested_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Sample the function inputs.
        let (private_key, function_name, inputs) =
            crate::package::test_helpers::sample_package_run(package.program_id());
        // Run the program function.
        let (_response, _metrics) = package.run::<CurrentAleo, _>(&private_key, function_name, &inputs, rng).unwrap();

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Use `cargo test profiler --features timer` to run this test.
    #[ignore]
    #[test]
    fn test_profiler() -> Result<()> {
        // Samples a new package at a temporary directory.
        let (directory, package) = crate::package::test_helpers::sample_token_package();

        // Ensure the build directory does *not* exist.
        assert!(!package.build_directory().exists());
        // Build the package.
        package.build::<CurrentAleo>().unwrap();
        // Ensure the build directory exists.
        assert!(package.build_directory().exists());

        // Initialize an RNG.
        let rng = &mut TestRng::default();
        // Sample the function inputs.
        let (private_key, function_name, inputs) =
            crate::package::test_helpers::sample_package_run(package.program_id());
        // Run the program function.
        let (_response, _metrics) = package.run::<CurrentAleo, _>(&private_key, function_name, &inputs, rng).unwrap();

        // Proactively remove the temporary directory (to conserve space).
        std::fs::remove_dir_all(directory).unwrap();

        bail!("\n\nRemember to #[ignore] this test!\n\n")
    }
}
