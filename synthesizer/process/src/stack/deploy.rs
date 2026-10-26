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

impl<N: Network> Stack<N> {
    /// Deploys the given program ID, if it does not exist.
    #[inline]
    pub fn deploy<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Deployment<N>> {
        let timer = timer!("Stack::deploy");

        // Ensure the program contains functions.
        ensure!(!self.program.functions().is_empty(), "Program '{}' has no functions", self.program.id());

        // Initialize a vector for the verifying keys and certificates.
        let mut verifying_keys = Vec::with_capacity(self.program.functions().len() + self.program.records().len());

        // Synthesize function verifying keys.
        for function_name in self.program.functions().keys() {
            // Synthesize the proving and verifying key.
            self.synthesize_key::<A, R>(function_name, rng)?;
            lap!(timer, "Synthesize key for {function_name}");

            // Retrieve the proving key.
            let proving_key = self.get_proving_key(function_name)?;
            // Retrieve the verifying key.
            let verifying_key = self.get_verifying_key(function_name)?;
            lap!(timer, "Retrieve the keys for {function_name}");

            // Certify the circuit.
            let certificate = Certificate::certify(&function_name.to_string(), &proving_key, &verifying_key)?;
            lap!(timer, "Certify the circuit");

            // Add the verifying key and certificate to the bundle.
            verifying_keys.push((*function_name, (verifying_key, certificate)));
        }

        // Synthesize record (translation) verifying keys.
        for record_name in self.program.records().keys() {
            // Synthesize the proving and verifying key.
            self.synthesize_translation_key::<A, R>(record_name, rng)?;
            lap!(timer, "Synthesize key for translation circuit for {record_name}");

            // Retrieve the proving key.
            let proving_key = self.get_proving_key(record_name)?;

            // Retrieve the verifying key.
            let verifying_key = self.get_verifying_key(record_name)?;
            lap!(timer, "Retrieve the keys for translation circuit for {record_name}");

            // Certify the circuit.
            let certificate = Certificate::certify(&record_name.to_string(), &proving_key, &verifying_key)?;
            lap!(timer, "Certify the circuit");

            // Add the verifying key and certificate to the bundle.
            verifying_keys.push((*record_name, (verifying_key, certificate)));
        }

        finish!(timer);

        // Return the deployment.
        // Note: The owner placeholder `Address::zero()` is unconditionally overwritten by
        // `VM::deploy()` before the deployment reaches the ledger (the caller's address is set
        // for V9+, or the owner is cleared for pre-V9).
        Deployment::new(
            *self.program_edition,
            self.program.clone(),
            verifying_keys,
            Some(self.program.to_checksum()),
            Some(Address::zero()),
        )
    }

    /// Checks each function in the program on the given verifying key and certificate.
    #[inline]
    pub fn verify_deployment<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        consensus_version: ConsensusVersion,
        deployment: &Deployment<N>,
        // Retained for API compatibility. Deployment verification is intentionally deterministic:
        // all randomness is drawn from `seeded_rng` (seeded by the deployment ID) so that every
        // validator computes the same result.
        _rng: &mut R,
    ) -> Result<()> {
        let timer = timer!("Stack::verify_deployment");

        // NOTE: As developer, you will likely still want to confirm that your
        // deployment is within R1CS constraint and variable limits using
        // targeted and parallelized synthesis.
        if cfg!(all(feature = "dev_skip_checks", feature = "test_consensus_heights")) {
            return Ok(());
        }

        // Sanity Checks //

        // Ensure the deployment is ordered.
        deployment.check_is_ordered()?;

        // Ensure the program in the stack and deployment matches.
        ensure!(&self.program == deployment.program(), "The stack program does not match the deployment program");
        // If the deployment contains a checksum, ensure it matches the one computed by the stack.
        if let Some(program_checksum) = deployment.program_checksum() {
            ensure!(
                program_checksum == self.program_checksum,
                "The deployment checksum does not match the stack checksum"
            );
        }

        // Check Verifying Keys //

        // Get the program ID.
        let program_id = self.program.id();

        // Enforce per-transaction variable and constraint limits, except at V18 where a block-wide
        // synthesis limit is used instead.
        let (variable_limit, constraint_limit) = if consensus_version >= ConsensusVersion::V19 {
            (Some(N::MAX_DEPLOYMENT_VARIABLES_V2), Some(N::MAX_DEPLOYMENT_CONSTRAINTS_V2))
        } else if consensus_version >= ConsensusVersion::V18 {
            (None, None)
        } else {
            (Some(N::MAX_DEPLOYMENT_VARIABLES), Some(N::MAX_DEPLOYMENT_CONSTRAINTS))
        };
        if let Some(variable_limit) = variable_limit {
            ensure!(
                deployment.num_combined_variables()? <= variable_limit,
                "The number of combined variables exceeds the deployment limit"
            );
        }
        if let Some(constraint_limit) = constraint_limit {
            ensure!(
                deployment.num_combined_constraints()? <= constraint_limit,
                "The number of combined constraints exceeds the deployment limit"
            );
        }

        // Construct the call stacks and assignments used to verify the certificates.
        let mut call_stacks = Vec::with_capacity(deployment.function_verifying_keys().len());

        // Sample a dummy `root_tvk` for circuit synthesis.
        let root_tvk = None;
        // Sample a dummy `caller` for circuit synthesis.
        let caller = None;

        // Check that the number of functions matches the number of function verifying keys.
        ensure!(
            deployment.program().functions().len() == deployment.function_verifying_keys().len(),
            "The number of functions in the program does not match the number of function verifying keys"
        );

        #[cfg(not(any(test, feature = "test")))]
        // Skip the certificate verification if the consensus version is before ConsensusVersion::V8.
        // Circuit synthesis was changed in a backwards incompatible way in ConsensusVersion::V8.
        if (ConsensusVersion::V1..=ConsensusVersion::V7).contains(&consensus_version) {
            finish!(timer);
            return Ok(());
        }

        // Create a seeded rng to use for input value and sub-stack generation.
        // This is needed to ensure that the verification results of deployments are consistent across all parties,
        // because currently there is a possible flakiness due to overflows in Field to Scalar casting.
        let seed = u64::from_bytes_le(&deployment.to_deployment_id()?.to_bytes_le()?[0..8])?;
        let mut seeded_rng = rand_chacha::ChaChaRng::seed_from_u64(seed);

        // Seed a new RNG to sample some of the random values without altering `seeded_rng`.
        let mut sub_seeded_rng = rand_chacha::ChaChaRng::seed_from_u64(seeded_rng.random());

        // Iterate through the program functions and construct the callstacks and corresponding assignments.
        for (function, (_, (verifying_key, _))) in
            deployment.program().functions().values().zip_eq(deployment.function_verifying_keys())
        {
            // Initialize a burner private key.
            let burner_private_key = PrivateKey::new(&mut sub_seeded_rng)?;
            // Compute the burner address.
            let burner_address = Address::try_from(&burner_private_key)?;
            // Retrieve the input types.
            let input_types = function.input_types();
            // Retrieve the program checksum, if the program has a constructor.
            let program_checksum = match self.program().contains_constructor() {
                true => Some(self.program_checksum_as_field()?),
                false => None,
            };
            // Sample the inputs.
            let inputs = input_types
                .iter()
                .map(|input_type| match input_type {
                    ValueType::ExternalRecord(locator) => {
                        // Retrieve the external stack.
                        let stack = self.get_external_stack(locator.program_id())?;
                        // Sample the input.
                        stack.sample_value(
                            &burner_address,
                            &ValueType::Record(*locator.resource()).into(),
                            &mut seeded_rng,
                        )
                    }
                    _ => self.sample_value(&burner_address, &input_type.into(), &mut seeded_rng),
                })
                .collect::<Result<Vec<_>>>()?;
            lap!(timer, "Sample the inputs");
            // Set 'is_root' to true. In particular, this guarantees self.caller is set to self.signer.
            let is_root = true;

            // Compute the request, with a burner private key.
            let request = Request::sign(
                &burner_private_key,
                *program_id,
                *function.name(),
                inputs.into_iter(),
                &input_types,
                root_tvk,
                is_root,
                program_checksum,
                false,
                // Draw the request nonce from the secondary seeded RNG as well, so no part of the
                // `CheckDeployment` synthesis depends on the ambient RNG. See the burner note above.
                &mut sub_seeded_rng,
            )?;
            lap!(timer, "Compute the request for {}", function.name());
            // Initialize the assignments.
            let assignments = Assignments::<N>::default();
            // Initialize the constraint limit. Account for the constraint added after synthesis that makes the Varuna zerocheck hiding.
            let Some(constraint_limit) = verifying_key.circuit_info.num_constraints.checked_sub(1) else {
                // Since a deployment must always pay non-zero fee, it must always have at least one constraint.
                bail!("The constraint limit of 0 for function '{}' is invalid", function.name());
            };
            // Retrieve the variable limit.
            let variable_limit = verifying_key.num_variables();
            // If the consensus version is >= V18, set the density limit, accounting for one non-zero entry (with value 1) added to
            // each of A, B and C in order to make the Varuna zerocheck hiding.
            let non_zero_limit = if consensus_version >= ConsensusVersion::V18 {
                let info = verifying_key.circuit_info;
                if info.num_non_zero_a >= 1 && info.num_non_zero_b >= 1 && info.num_non_zero_c >= 1 {
                    Some((
                        info.num_non_zero_a as u64 - 1,
                        info.num_non_zero_b as u64 - 1,
                        info.num_non_zero_c as u64 - 1,
                    ))
                } else {
                    bail!(
                        "The claimed number of non-zero entries for function '{}' is less than the one added by the Varuna hiding constraint (A: {}, B: {}, C: {})",
                        function.name(),
                        info.num_non_zero_a,
                        info.num_non_zero_b,
                        info.num_non_zero_c,
                    );
                }
            } else {
                None
            };
            // Initialize the call stack.
            let call_stack = CallStack::CheckDeployment(
                vec![request],
                burner_private_key,
                assignments.clone(),
                Some(constraint_limit as u64),
                Some(variable_limit),
                non_zero_limit,
            );
            // Append the function name, callstack, and assignments.
            call_stacks.push((function.name(), call_stack, assignments));
        }

        // Verify the certificates.
        let rngs = (0..call_stacks.len()).map(|_| StdRng::from_seed(seeded_rng.random())).collect::<Vec<_>>();
        cfg_into_iter!(call_stacks).zip_eq(deployment.function_verifying_keys()).zip_eq(rngs).try_for_each(
            |(((function_name, call_stack, assignments), (_, (verifying_key, certificate))), mut rng)| {
                // Synthesize the circuit.
                if let Err(err) = self.execute_function::<A, _>(call_stack, caller, root_tvk, &mut rng) {
                    bail!("Failed to synthesize the circuit for '{function_name}': {err}")
                }
                // Check the certificate.
                match assignments.read().last() {
                    None => bail!("The assignment for function '{function_name}' is missing in '{program_id}'"),
                    Some((assignment, _metrics)) => {
                        // Ensure the certificate is valid.
                        if !certificate.verify(&function_name.to_string(), assignment, verifying_key) {
                            bail!("The certificate for function '{function_name}' is invalid in '{program_id}'")
                        }
                    }
                };
                Ok(())
            },
        )?;

        // If the deployment contains translation verifying keys, verify them.
        if let Some(translation_verifying_keys) = deployment.translation_verifying_keys() {
            // Iterate through the program records and produce translation assignments.
            ensure!(
                deployment.program().records().len() == translation_verifying_keys.len(),
                "The number of records in the program does not match the number of translation verifying keys"
            );
            let translation_names_assignments = deployment
                .program()
                .records()
                .iter()
                .map(|(record_name, _record_type)| {
                    // Construct a random `TranslationAssignment`.
                    // Note: All randomness here is drawn from `seeded_rng` (seeded by the deployment
                    // ID), not the ambient `_rng`, so that the translation assignment — and thus the
                    // certificate check below — is identical across all validators.
                    let program_id = *self.program_id();
                    let function_id = Field::<N>::from_u64(Uniform::rand(&mut sub_seeded_rng));
                    let record_name = *record_name;
                    let record_static = self.sample_record(
                        &Address::rand(&mut sub_seeded_rng),
                        &record_name,
                        Group::rand(&mut sub_seeded_rng),
                        &mut sub_seeded_rng,
                    )?;
                    let record_dynamic = DynamicRecord::<N>::from_record(&record_static)?;
                    let translation_index: u16 = Uniform::rand(&mut sub_seeded_rng);
                    let tvk = Uniform::rand(&mut sub_seeded_rng);
                    let record_register_index = Uniform::rand(&mut sub_seeded_rng);
                    let record_view_key: Option<Field<N>> = UniformExt::rand_option(&mut sub_seeded_rng);
                    let gamma: Option<Group<N>> = UniformExt::rand_option(&mut sub_seeded_rng);
                    let id_dynamic = compute_console_dynamic_or_external_record_id(
                        function_id,
                        record_dynamic.to_fields()?,
                        tvk,
                        U16::new(record_register_index),
                    )?;
                    let is_to_static = Uniform::rand(&mut sub_seeded_rng);
                    let is_external_record = Uniform::rand(&mut sub_seeded_rng);
                    let id_static = Uniform::rand(&mut sub_seeded_rng);

                    lap!(timer, "Sample the inputs to the translation circuit for record {record_name}");

                    Ok((
                        record_name,
                        translation_index,
                        TranslationAssignment::new(
                            record_static,
                            record_dynamic,
                            program_id,
                            function_id,
                            record_name,
                            is_to_static,
                            is_external_record,
                            tvk,
                            record_view_key,
                            gamma,
                            record_register_index,
                            id_dynamic,
                            id_static,
                        ),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;

            // Verify the translation certificates.
            // Note: `Deployment::check_is_ordered` (called above) ensures that the translation
            // verifying keys appear in the same order as the program's record definitions, so
            // `zip_eq` correctly pairs each record assignment with its corresponding key.
            cfg_into_iter!(translation_names_assignments).zip_eq(translation_verifying_keys).try_for_each(
            |((record_name, translation_index, translation_assignment), (_, (verifying_key, certificate)))| {
                // Construct the variable, constraint and non-zero element counts to pass to the translation-circuit
                // synthesizer as bounds. These are only enforced in ConsensusVersion::V18 and later.
                let (variable_limit, constraint_limit, non_zero_limit) = if consensus_version < ConsensusVersion::V18 {
                    (None, None, None)
                } else {
                    let variable_limit = Some(verifying_key.num_variables());

                    let constraint_limit = if verifying_key.circuit_info.num_constraints >= 1 {
                        // Since a deployment must always pay non-zero fee, it must always have at least one constraint.
                        Some(verifying_key.circuit_info.num_constraints as u64 - 1)
                    } else {
                        bail!("The constraint limit of 0 for translation circuit for record '{record_name}' is invalid");
                    };

                    // Set the density limit, accounting for one non-zero entry (with value 1) added to each of A, B and C
                    // in order to make the Varuna zerocheck hiding.
                    let info = verifying_key.circuit_info;
                    let non_zero_limit = if info.num_non_zero_a >= 1 && info.num_non_zero_b >= 1 && info.num_non_zero_c >= 1 {
                        Some((
                            info.num_non_zero_a as u64 - 1,
                            info.num_non_zero_b as u64 - 1,
                            info.num_non_zero_c as u64 - 1,
                        ))
                    } else {
                        bail!(
                            "The claimed number of non-zero entries for translation circuit for record '{}' is less than the one added by the Varuna hiding constraint (A: {}, B: {}, C: {})",
                            record_name,
                            info.num_non_zero_a,
                            info.num_non_zero_b,
                            info.num_non_zero_c,
                        );
                    };

                    (variable_limit, constraint_limit, non_zero_limit)
                };

                // Synthesize the circuit.
                match translation_assignment.to_circuit_assignment::<A>(translation_index, variable_limit, constraint_limit, non_zero_limit) {
                    Err(err) => Err(anyhow!("Failed to synthesize the circuit for '{record_name}': {err}")),
                    Ok(circuit_assignment) => {
                        // Ensure the certificate is valid.
                        ensure!(
                            certificate.verify(&record_name.to_string(), &circuit_assignment, verifying_key),
                            "The translation-circuit certificate for record '{record_name}' is invalid in '{program_id}'"
                        );
                        Ok(())
                    },
                }
            })?;
        }

        finish!(timer);

        Ok(())
    }
}
