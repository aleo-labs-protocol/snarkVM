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

impl<N: Network> Process<N> {
    /// Verifies the given deployment is ordered.
    #[inline]
    pub fn verify_deployment<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        consensus_version: ConsensusVersion,
        deployment: &Deployment<N>,
        rng: &mut R,
    ) -> Result<()> {
        let timer = timer!("Process::verify_deployment");

        // Retrieve the program ID.
        let program_id = deployment.program().id();
        // Retrieve the maximum number of mappings for the consensus version.
        let max_mappings = consensus_config_value_by_version!(N, MAX_MAPPINGS, consensus_version)
            .ok_or_else(|| anyhow!("Missing consensus config value: MAX_MAPPINGS"))?;
        // Ensure the program does not exceed the maximum number of mappings.
        ensure!(
            deployment.program().mappings().len() <= max_mappings,
            "Program '{program_id}' exceeds the maximum number of mappings ({max_mappings}) for {consensus_version}"
        );
        // Check if this deployment is an amendment.
        let version = deployment.version()?;
        let is_amendment = matches!(version, DeploymentVersion::V3);
        // If the deployment is an amendment, verify that the program exists.
        // If the edition is zero (and not an amendment), verify that the program does not exist.
        // Otherwise, verify that the program exists.
        if is_amendment {
            ensure!(
                self.contains_program(program_id),
                "Program '{program_id}' does not exist, but amendment requires an existing program"
            );
        } else {
            match deployment.edition().is_zero() {
                true => ensure!(
                    !self.contains_program(program_id),
                    "Program '{program_id}' already exists, but the deployment edition is zero"
                ),
                false => ensure!(
                    self.contains_program(program_id),
                    "Program '{program_id}' does not exist, but the deployment edition is non-zero"
                ),
            }
        }

        // Ensure the program is well-formed, by computing the stack.
        // Note: The program owner is intentionally not set, since `program_owner` is an operand
        //   that is only available in a finalize scope.
        let stack = if is_amendment {
            // For amendments, use the existing edition instead of incrementing.
            // Note: `Stack::new` cannot be used here because it would increment the edition.
            // Amendments must preserve the existing edition. Validity is verified by `initialize_and_check`.
            let existing_stack = self.get_stack(program_id)?;
            let stack = Stack::new_raw(self, deployment.program(), *existing_stack.program_edition())?;
            stack.initialize_and_check(self)?;
            stack
        } else {
            Stack::new(self, deployment.program())?
        };
        lap!(timer, "Compute the stack");

        // Ensure the verifying keys are well-formed and the certificates are valid.
        let verification = stack.verify_deployment::<A, R>(consensus_version, deployment, rng);
        lap!(timer, "Verify the deployment");

        finish!(timer);
        verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;

    type CurrentAleo = circuit::network::AleoV0;
    type CurrentNetwork = console::network::MainnetV0;

    /// Use `cargo test profiler --features timer` to run this test.
    #[ignore]
    #[test]
    fn test_profiler() -> Result<()> {
        let rng = &mut TestRng::default();

        // Initialize the process.
        let process = Process::load()?;

        // Fetch the large program to deploy.
        let large_program = Program::from_str(include_str!("./resources/large_functions.aleo"))?;

        // Create a deployment for the program.
        let deployment = process.deploy::<CurrentAleo, _>(&large_program, rng)?;

        // Verify the deployment.
        assert!(process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V8, &deployment, rng).is_ok());

        bail!("\n\nRemember to #[ignore] this test!\n\n")
    }

    /// Inflates the claimed variable count on the first verifying key of `deployment`.
    fn with_inflated_variables<N: Network>(deployment: &Deployment<N>, num_variables: u64) -> Deployment<N> {
        let (function_id, (vk, certificate)) = &deployment.verifying_keys()[0];
        let tampered_vks =
            vec![(*function_id, (VerifyingKey::new(Arc::new(vk.deref().clone()), num_variables), certificate.clone()))];
        Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            tampered_vks,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap()
    }

    /// Inflates the claimed constraint count on the first verifying key of `deployment`.
    fn with_inflated_constraints<N: Network>(deployment: &Deployment<N>, num_constraints: usize) -> Deployment<N> {
        let (function_id, (vk, certificate)) = &deployment.verifying_keys()[0];
        let mut circuit_vk = vk.deref().clone();
        circuit_vk.circuit_info.num_constraints = num_constraints;
        let tampered_vks =
            vec![(*function_id, (VerifyingKey::new(Arc::new(circuit_vk), vk.num_variables()), certificate.clone()))];
        Deployment::new(
            deployment.edition(),
            deployment.program().clone(),
            tampered_vks,
            deployment.program_checksum(),
            deployment.program_owner(),
        )
        .unwrap()
    }

    fn program_with_mappings(num_mappings: usize) -> Result<Program<CurrentNetwork>> {
        let mut program = String::new();
        program.push_str("program mappings.aleo;\n\n");
        for i in 0..num_mappings {
            program
                .push_str(&format!("mapping mapping_{i}:\n    key as field.public;\n    value as field.public;\n\n"));
        }
        program.push_str("function foo:\n    add 0u8 1u8 into r0;\n");
        Program::from_str(&program)
    }

    #[test]
    fn test_mapping_limits_by_consensus_version() -> Result<()> {
        let rng = &mut TestRng::default();
        let process = Process::load()?;

        let program_with_31_mappings = program_with_mappings(31)?;
        let deployment_with_31_mappings = process.deploy::<CurrentAleo, _>(&program_with_31_mappings, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V21, &deployment_with_31_mappings, rng)?;

        let program_with_32_mappings = program_with_mappings(32)?;
        let deployment_with_32_mappings = process.deploy::<CurrentAleo, _>(&program_with_32_mappings, rng)?;
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V21, &deployment_with_32_mappings, rng)
                .unwrap_err()
                .to_string()
                .contains("exceeds the maximum number of mappings (31) for V21")
        );
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V22, &deployment_with_32_mappings, rng)?;

        let program_with_128_mappings = program_with_mappings(128)?;
        let deployment_with_128_mappings = process.deploy::<CurrentAleo, _>(&program_with_128_mappings, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V22, &deployment_with_128_mappings, rng)?;

        Ok(())
    }

    /// Per-transaction variable and constraint limits are enforced before V18 and from V19,
    /// using the v2 limits from V19. V18 skips these checks in favor of a block-wide synthesis limit.
    #[test]
    fn test_deployment_variable_and_constraint_limits_by_consensus_version() -> Result<()> {
        let rng = &mut TestRng::default();
        let process = Process::load()?;

        let program = Program::from_str(
            r"
program testing.aleo;
function foo:
    add 0u8 1u8 into r0;",
        )?;
        let deployment = process.deploy::<CurrentAleo, _>(&program, rng)?;

        let over_v1_variables = with_inflated_variables(&deployment, CurrentNetwork::MAX_DEPLOYMENT_VARIABLES + 1);
        let over_v2_variables = with_inflated_variables(&deployment, CurrentNetwork::MAX_DEPLOYMENT_VARIABLES_V2 + 1);
        let over_v1_constraints =
            with_inflated_constraints(&deployment, (CurrentNetwork::MAX_DEPLOYMENT_CONSTRAINTS + 1) as usize);
        let over_v2_constraints =
            with_inflated_constraints(&deployment, (CurrentNetwork::MAX_DEPLOYMENT_CONSTRAINTS_V2 + 1) as usize);

        // V16 enforces the original per-transaction limits.
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V16, &over_v1_variables, rng)
                .unwrap_err()
                .to_string()
                .contains("combined variables exceeds the deployment limit")
        );
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V16, &over_v1_constraints, rng)
                .unwrap_err()
                .to_string()
                .contains("combined constraints exceeds the deployment limit")
        );

        // V18 skips per-transaction variable/constraint limits.
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V18, &over_v1_variables, rng)?;
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V18, &over_v2_variables, rng)?;

        // V19 enforces the v2 per-transaction limits.
        process.verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v1_variables, rng)?;
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v2_variables, rng)
                .unwrap_err()
                .to_string()
                .contains("combined variables exceeds the deployment limit")
        );
        assert!(
            process
                .verify_deployment::<CurrentAleo, _>(ConsensusVersion::V19, &over_v2_constraints, rng)
                .unwrap_err()
                .to_string()
                .contains("combined constraints exceeds the deployment limit")
        );

        Ok(())
    }
}
