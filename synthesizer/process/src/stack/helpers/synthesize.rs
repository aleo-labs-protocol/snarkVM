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

use console::program::{DynamicRecord, ToFields};

use crate::{TranslationAssignment, compute_console_dynamic_or_external_record_id};

use super::*;

impl<N: Network> Stack<N> {
    /// Synthesizes the proving key and verifying key for the given function name.
    #[inline]
    pub fn synthesize_key<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        function_name: &Identifier<N>,
        rng: &mut R,
    ) -> Result<()> {
        // If the proving and verifying key already exist, skip the synthesis for this function.
        if self.contains_proving_key(function_name) && self.contains_verifying_key(function_name) {
            return Ok(());
        }

        // Retrieve the program ID.
        let program_id = self.program_id();
        // Retrieve the function input types.
        let input_types = self.get_function(function_name)?.input_types();
        // Retrieve the program checksum, if the program has a constructor.
        let program_checksum = match self.program().contains_constructor() {
            true => Some(self.program_checksum_as_field()?),
            false => None,
        };

        // Initialize a burner private key.
        let burner_private_key = PrivateKey::new(rng)?;
        // Compute the burner address.
        let burner_address = Address::try_from(&burner_private_key)?;
        // Sample the inputs.
        let inputs = input_types
            .iter()
            .map(|input_type| match input_type {
                ValueType::ExternalRecord(locator) => {
                    // Retrieve the external stack.
                    let stack = self.get_external_stack(locator.program_id())?;
                    // Sample the input.
                    stack.sample_value(&burner_address, &ValueType::Record(*locator.resource()).into(), rng)
                }
                _ => self.sample_value(&burner_address, &input_type.into(), rng),
            })
            .collect::<Result<Vec<_>>>()?;
        // Set 'is_root' to true. In particular, this guarantees self.caller is set to self.signer.
        let is_root = true;
        // Sample a dummy `root_tvk` for circuit synthesis.
        let root_tvk = None;
        // Sample a dummy `caller` for circuit synthesis.
        let caller = None;

        // Compute the request, with a burner private key.
        let request = Request::sign(
            &burner_private_key,
            *program_id,
            *function_name,
            inputs.into_iter(),
            &input_types,
            root_tvk,
            is_root,
            program_checksum,
            false,
            rng,
        )?;

        // Initialize the authorization.
        let authorization = Authorization::new(request.clone());
        // Initialize the call stack.
        let call_stack = CallStack::Synthesize(vec![request], burner_private_key, authorization);
        // Synthesize the circuit.
        let _response = self.execute_function::<A, R>(call_stack, caller, root_tvk, rng)?;

        // Ensure the proving key exists.
        ensure!(self.contains_proving_key(function_name), "Function '{function_name}' is missing a proving key.");
        // Ensure the verifying key exists.
        ensure!(self.contains_verifying_key(function_name), "Function '{function_name}' is missing a verifying key.");
        Ok(())
    }

    /// Synthesizes and stores the `(proving_key, verifying_key)` for the given function name and assignment.
    #[inline]
    pub fn synthesize_from_assignment(
        &self,
        function_name: &Identifier<N>,
        assignment: &circuit::Assignment<N::Field>,
    ) -> Result<()> {
        // If the proving and verifying key already exist, skip the synthesis for this function.
        if self.contains_proving_key(function_name) && self.contains_verifying_key(function_name) {
            return Ok(());
        }

        // Synthesize the proving and verifying key.
        let (proving_key, verifying_key) = self.universal_srs.to_circuit_key(&function_name.to_string(), assignment)?;
        // Insert the proving key.
        self.insert_proving_key(function_name, proving_key)?;
        // Insert the verifying key.
        self.insert_verifying_key(function_name, verifying_key)
    }

    /// Synthesizes the proving key and verifying key for the translation circuit of the record with the given name.
    #[inline]
    pub fn synthesize_translation_key<A: circuit::Aleo<Network = N>, R: Rng + CryptoRng>(
        &self,
        record_name: &Identifier<N>,
        rng: &mut R,
    ) -> Result<()> {
        // If the translation proving and verifying key already exist, skip the synthesis for this record.
        if self.contains_proving_key(record_name) && self.contains_verifying_key(record_name) {
            return Ok(());
        }

        // Construct a TranslationAssignment:
        let private_key = PrivateKey::new(rng)?;
        let address = Address::try_from(&private_key)?;
        let program_id = *self.program_id();
        let function_id = Field::<N>::from_u64(Uniform::rand(rng));
        let record_name = *record_name;
        let record_static = self.sample_record(&address, &record_name, Group::rand(rng), rng)?;
        let record_dynamic = DynamicRecord::<N>::from_record(&record_static)?;
        let translation_index: u16 = Uniform::rand(rng);
        let tvk = Uniform::rand(rng);
        let record_register_index = Uniform::rand(rng);
        let record_view_key = UniformExt::rand_option(rng);
        let gamma = UniformExt::rand_option(rng);
        // Compute the dynamic ID for external or dynamic record inputs/outputs.
        let id_dynamic = compute_console_dynamic_or_external_record_id(
            function_id,
            record_dynamic.to_fields()?,
            tvk,
            U16::new(record_register_index),
        )?;
        let is_to_static = Uniform::rand(rng);
        let is_external_record = Uniform::rand(rng);
        let id_static = Uniform::rand(rng);

        let translation_assignment = TranslationAssignment::new(
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
        );

        // Construct the translation circuit.
        let circuit_assignment =
            translation_assignment.to_circuit_assignment::<A>(translation_index, None, None, None)?;

        // Synthesize the proving and verifying key.
        let (proving_key, verifying_key) =
            self.universal_srs.to_circuit_key(&record_name.to_string(), &circuit_assignment)?;
        // Insert the proving key.
        self.insert_proving_key(&record_name, proving_key)?;
        // Insert the verifying key.
        self.insert_verifying_key(&record_name, verifying_key)
    }
}
