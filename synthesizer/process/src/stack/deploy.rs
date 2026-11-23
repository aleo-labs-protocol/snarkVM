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
        let timer = timing_span!("Stack::deploy").entered();

        // Ensure the program contains functions.
        ensure!(!self.program.functions().is_empty(), "Program '{}' has no functions", self.program.id());

        // Initialize a vector for the verifying keys and certificates.
        let mut verifying_keys = Vec::with_capacity(self.program.functions().len() + self.program.records().len());

        // Synthesize function verifying keys.
        for function_name in self.program.functions().keys() {
            // Synthesize the proving and verifying key.
            self.synthesize_key::<A, R>(function_name, rng)?;
            timing_event!("Synthesize key for {function_name}");

            // Retrieve the proving key.
            let proving_key = self.get_proving_key(function_name)?;
            // Retrieve the verifying key.
            let verifying_key = self.get_verifying_key(function_name)?;
            timing_event!("Retrieve the keys for {function_name}");

            // Certify the circuit.
            let certificate = Certificate::certify(&function_name.to_string(), &proving_key, &verifying_key)?;
            timing_event!("Certify the circuit");

            // Add the verifying key and certificate to the bundle.
            verifying_keys.push((*function_name, (verifying_key, certificate)));
        }

        // Synthesize record (translation) verifying keys.
        for record_name in self.program.records().keys() {
            // Synthesize the proving and verifying key.
            self.synthesize_translation_key::<A, R>(record_name, rng)?;
            timing_event!("Synthesize key for translation circuit for {record_name}");

            // Retrieve the proving key.
            let proving_key = self.get_proving_key(record_name)?;

            // Retrieve the verifying key.
            let verifying_key = self.get_verifying_key(record_name)?;
            timing_event!("Retrieve the keys for translation circuit for {record_name}");

            // Certify the circuit.
            let certificate = Certificate::certify(&record_name.to_string(), &proving_key, &verifying_key)?;
            timing_event!("Certify the circuit");

            // Add the verifying key and certificate to the bundle.
            verifying_keys.push((*record_name, (verifying_key, certificate)));
        }

        drop(timer);

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

    /// Checks a plaintext type against the raw bit limit. Cached struct sizes belong to their declaring program.
    #[doc(hidden)]
    pub fn check_plaintext_type_size(
        &self,
        pt: &PlaintextType<N>,
        max_bits: usize,
        memoized: &mut HashMap<(ProgramID<N>, Identifier<N>), (usize, usize)>,
    ) -> Result<()> {
        let bits = plaintext_size_in_bits_raw(self, pt, 0, memoized)?.0;
        ensure!(
            bits <= max_bits,
            "Plaintext type '{pt}' exceeds the maximum allowed size in bits ({bits} > {max_bits})"
        );
        Ok(())
    }

    /// Checks the plaintext destinations of each synthesized function and the closures it executes.
    pub(crate) fn check_deployment_register_sizes(&self, max_bits: usize) -> Result<()> {
        let mut memoized = HashMap::new();
        let mut checked_calls = std::collections::HashSet::new();
        let check_scope =
            |stack: &Self, name: &Identifier<N>, instructions: &[Instruction<N>], memoized: &mut _| -> Result<()> {
                let registers = stack.register_types.read();
                let types = registers.get(name).ok_or_else(|| anyhow!("Register types for '{name}' do not exist"))?;
                for instruction in instructions {
                    // Static calls use their callee's declarations.
                    if matches!(instruction, Instruction::Call(_)) {
                        continue;
                    }
                    for destination in instruction.destinations() {
                        let destination_type = types
                            .destinations
                            .get(&destination.locator())
                            .ok_or_else(|| anyhow!("Register '{destination}' does not exist"))?;
                        if let RegisterType::Plaintext(pt) = destination_type {
                            stack.check_plaintext_type_size(pt, max_bits, memoized)?;
                        }
                    }
                }
                Ok(())
            };
        for function in self.program.functions().values() {
            check_scope(self, function.name(), function.instructions(), &mut memoized)?;
            for instruction in function.instructions() {
                let Instruction::Call(call) = instruction else { continue };
                let (program_id, name) = match call.operator() {
                    CallOperator::Resource(name) => (self.program_id(), name),
                    CallOperator::Locator(locator) => (locator.program_id(), locator.resource()),
                };
                if !checked_calls.insert((*program_id, *name)) {
                    continue;
                }
                let external;
                let callee = if program_id == self.program_id() {
                    self
                } else {
                    external = self.get_external_stack(program_id)?;
                    external.as_ref()
                };
                // Static call destinations use the callee's types, including structs from its own imports.
                if let Some(closure) = callee.program.closures().get(name) {
                    for output in closure.outputs() {
                        if let RegisterType::Plaintext(pt) = output.register_type() {
                            callee.check_plaintext_type_size(pt, max_bits, &mut memoized)?;
                        }
                    }
                    // Synthesis executes closures inline. Closures cannot contain call instructions.
                    check_scope(callee, name, closure.instructions(), &mut memoized)?;
                } else {
                    for output in callee.get_function_ref(name)?.outputs() {
                        if let ValueType::Constant(pt) | ValueType::Public(pt) | ValueType::Private(pt) =
                            output.value_type()
                        {
                            callee.check_plaintext_type_size(pt, max_bits, &mut memoized)?;
                        }
                    }
                }
            }
        }
        Ok(())
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
        let timer = timing_span!("Stack::verify_deployment").entered();

        // NOTE: As developer, you will likely still want to confirm that your
        // deployment is within R1CS constraint and variable limits using
        // targeted and parallelized synthesis.
        if cfg!(all(feature = "dev_skip_checks", feature = "dev-network")) {
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

        if consensus_version >= ConsensusVersion::V23 {
            let max_bits = consensus_config_value_by_version!(N, MAX_PLAINTEXT_TYPE_SIZE_IN_BITS, consensus_version)
                .ok_or_else(|| anyhow!("Missing consensus config value: MAX_PLAINTEXT_TYPE_SIZE_IN_BITS"))?;
            self.check_deployment_register_sizes(max_bits)?;
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

        // Skip the certificate verification if the consensus version is before ConsensusVersion::V8.
        // Circuit synthesis was changed in a backwards incompatible way in ConsensusVersion::V8.
        if (ConsensusVersion::V1..=ConsensusVersion::V7).contains(&consensus_version) {
            drop(timer);
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
            timing_event!("Sample the inputs");
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
            timing_event!("Compute the request for {}", function.name());
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
        // Each job synthesizes in the VM scope of this thread. `certificate.verify` may wait on rayon, so it runs
        // outside, and its panics reach the host panic hook.
        VmScope::parallel(|vm_scope| {
            cfg_into_iter!(call_stacks).zip_eq(deployment.function_verifying_keys()).zip_eq(rngs).try_for_each(
                |(((function_name, call_stack, assignments), (_, (verifying_key, certificate))), mut rng)| {
                    // Synthesize the circuit.
                    if let Err(err) =
                        vm_scope.run(|| self.execute_function::<A, _>(call_stack, caller, root_tvk, &mut rng))
                    {
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
            )
        })?;

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

                    timing_event!("Sample the inputs to the translation circuit for record {record_name}");

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
            // As above, each job synthesizes in the VM scope of this thread.
            VmScope::parallel(|vm_scope| {
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
                    match vm_scope.run(|| translation_assignment.to_circuit_assignment::<A>(translation_index, variable_limit, constraint_limit, non_zero_limit)) {
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
                })
            })?;
        }

        drop(timer);

        Ok(())
    }
}

/// Returns the `(size, height)` in bits of the given plaintext type, excluding any type metadata.
///
/// Each struct reference is resolved against the program that declares it, since a struct declared
/// in an external program may refer to structs local to that program, or to structs in programs
/// that the current program does not import.
///
/// `memoized` records the result for each `(program, struct)` pair already sized, so that a struct shared by many
/// members is expanded at most once. Without this, a program in which every member of each struct refers to the
/// same earlier struct forms an acyclic graph with exponentially many paths, and this walk would make up to
/// `MAX_STRUCT_ENTRIES ^ MAX_STRUCTS` recursive calls.
///
/// `height` is the number of levels below a type at which its deepest node sits (a literal is `0`). It lets a
/// memoized hit at a deeper position re-apply the depth check the skipped recursion would have performed on that
/// node, so the memoization changes only the running time and never the result.
fn plaintext_size_in_bits_raw<N: Network>(
    stack: &Stack<N>,
    plaintext_type: &PlaintextType<N>,
    depth: usize,
    memoized: &mut HashMap<(ProgramID<N>, Identifier<N>), (usize, usize)>,
) -> Result<(usize, usize)> {
    // Ensure that the depth is within the maximum limit.
    ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext depth exceeds maximum limit: {}", N::MAX_DATA_DEPTH);

    match plaintext_type {
        PlaintextType::Literal(literal_type) => Ok((literal_type.size_in_bits::<N>() as usize, 0)),
        PlaintextType::Struct(struct_name) => {
            // If this struct has already been sized in the current traversal, reuse that result.
            let key = (*stack.program_id(), *struct_name);
            if let Some(&(size, height)) = memoized.get(&key) {
                ensure!(
                    depth.saturating_add(height) <= N::MAX_DATA_DEPTH,
                    "Plaintext depth exceeds maximum limit: {}",
                    N::MAX_DATA_DEPTH
                );
                return Ok((size, height));
            }

            // Add up the sizes of the members, which are declared in the same program.
            let members = stack.program().get_struct(struct_name)?.members();
            let mut total = 0usize;
            // Track the maximum height of any member's subtree.
            let mut member_height = 0usize;
            for member_type in members.values() {
                let (member_size, subtree_height) =
                    plaintext_size_in_bits_raw(stack, member_type, depth + 1, memoized)?;
                total =
                    total.checked_add(member_size).ok_or_else(|| anyhow!("`plaintext_size_in_bits_raw` overflowed"))?;
                member_height = member_height.max(subtree_height);
            }

            // The struct sits one level above its deepest member; a memberless struct recurses nowhere.
            let height = match members.is_empty() {
                true => 0,
                false => member_height + 1,
            };
            memoized.insert(key, (total, height));
            Ok((total, height))
        }
        PlaintextType::ExternalStruct(locator) => {
            // Resolve the struct, and therefore its members, against the external program.
            let external_stack = stack.get_external_stack(locator.program_id())?;
            plaintext_size_in_bits_raw(&external_stack, &PlaintextType::Struct(*locator.resource()), depth, memoized)
        }
        PlaintextType::Array(array_type) => {
            // Multiply the size of an element by the length of the array.
            let (element_size, element_height) =
                plaintext_size_in_bits_raw(stack, array_type.next_element_type(), depth + 1, memoized)?;
            let total = element_size
                .checked_mul(**array_type.length() as usize)
                .ok_or_else(|| anyhow!("`plaintext_size_in_bits_raw` overflowed"))?;
            // The array sits one level above its element.
            Ok((total, element_height + 1))
        }
    }
}
