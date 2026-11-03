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
use snarkvm_synthesizer_error::*;

impl<N: Network> Process<N> {
    /// Deploys the given program ID, if it does not exist.
    #[inline]
    pub fn deploy<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        program: &Program<N>,
        rng: &mut R,
    ) -> Result<Deployment<N>, ProcessDeployError> {
        let timer = timer!("Process::deploy");

        // Compute the stack.
        let stack = Stack::new(self, program)?;
        lap!(timer, "Compute the stack");

        // Return the deployment.
        let deployment = stack.deploy::<A, R>(rng)?;
        lap!(timer, "Construct the deployment");

        finish!(timer);

        Ok(deployment)
    }

    /// Adds the newly-deployed program.
    /// This method assumes the given deployment **is valid**.
    #[inline]
    pub fn load_deployment(&self, deployment: &Deployment<N>) -> Result<()> {
        let timer = timer!("Process::load_deployment");

        // Get the deployment version.
        let version = deployment.version()?;

        // Load the deployment based on its version.
        let stack = match version {
            DeploymentVersion::V1 | DeploymentVersion::V2 => {
                // Compute the program stack.
                let mut stack = Stack::new(self, deployment.program())?;
                lap!(timer, "Compute the stack");

                // Set the program owner.
                stack.set_program_owner(deployment.program_owner());

                stack
            }
            DeploymentVersion::V3 => {
                // V3 is an amendment — get the existing stack.
                let existing_stack = self.get_stack(deployment.program_id())?;
                // Increment the amendment count while preserving the existing edition.
                let amendment_count = existing_stack
                    .program_amendment_count()
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("Overflow while incrementing the program amendment count"))?;

                // Compute a new stack with the same program and edition.
                // Note: `Stack::new` cannot be used here because it would increment the edition.
                // Amendments must preserve the existing edition. Validity is verified by `initialize_and_check`.
                let mut stack = Stack::new_raw(self, deployment.program(), *existing_stack.program_edition())?;
                stack.initialize_and_check(self)?;
                lap!(timer, "Compute the stack");

                // Set the amendment count for this edition.
                stack.set_program_amendment_count(amendment_count);
                // Set the program owner to the existing owner.
                stack.set_program_owner(*existing_stack.program_owner());

                stack
            }
        };

        // Insert all verifying keys (unified: functions + records).
        for (name, (verifying_key, _)) in deployment.verifying_keys() {
            stack.insert_verifying_key(name, verifying_key.clone())?;
        }
        lap!(timer, "Insert the verifying keys");

        // Add the stack to the process.
        self.lock().add_stack(stack);

        finish!(timer);

        Ok(())
    }
}
