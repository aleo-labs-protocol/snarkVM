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

impl<N: Network> Request<N> {
    /// Returns `true` if the request is valid, and `false` otherwise.
    ///
    /// Verifies (challenge == challenge') && (address == address') && (serial_numbers == serial_numbers') where:
    ///     challenge' := HashToScalar(r * G, pk_sig, pr_sig, signer, \[tvk, tcm, function ID, is_root, program checksum?, input IDs\])
    /// The program checksum must be provided if the program has a constructor and should not be provided otherwise.
    pub fn verify(&self, input_types: &[ValueType<N>], is_root: bool, program_checksum: Option<Field<N>>) -> bool {
        // Verify the transition public key, transition view key, and transition commitment are well-formed.
        {
            // Compute the transition commitment `tcm` as `Hash(tvk)`.
            match N::hash_psd2(&[self.tvk]) {
                Ok(tcm) => {
                    // Ensure the computed transition commitment matches.
                    if tcm != self.tcm {
                        eprintln!("Invalid transition commitment in request.");
                        return false;
                    }
                }
                Err(error) => {
                    eprintln!("Failed to compute transition commitment in request verification: {error}");
                    return false;
                }
            }
        }

        // Retrieve the challenge from the signature.
        let challenge = self.signature.challenge();
        // Retrieve the response from the signature.
        let response = self.signature.response();

        // Compute the function ID.
        let function_id = match compute_function_id(&self.network_id, &self.program_id, &self.function_name) {
            Ok(function_id) => function_id,
            Err(error) => {
                eprintln!("Failed to construct the function ID: {error}");
                return false;
            }
        };

        // Compute the 'is_root' field.
        let is_root = if is_root { Field::<N>::one() } else { Field::<N>::zero() };

        // Construct the signature message as `[tvk, tcm, function ID, is_root, program checksum?, input IDs]`.
        // Capacity: 5 fixed fields + up to 4 elements per input (record inputs contribute H_x, (rH)_x, gamma_x, tag).
        let mut message = Vec::with_capacity(5 + 4 * self.input_ids.len());
        message.push(self.tvk);
        message.push(self.tcm);
        message.push(function_id);
        message.push(is_root);

        // Add the program checksum to the signature message if it was provided.
        if let Some(program_checksum) = program_checksum {
            message.push(program_checksum);
        }

        if let Err(error) = self.input_ids.iter().zip_eq(&self.inputs).zip_eq(input_types).enumerate().try_for_each(
            |(index, ((input_id, input), input_type))| {
                // Convert index to u16.
                let index = u16::try_from(index).or_halt_with::<N>("Input index exceeds u16");

                match input_id {
                    // A constant input is hashed (using `tcm`) to a field element.
                    InputID::Constant(input_hash) => {
                        let candidate = InputID::constant(function_id, input, self.tcm, index)?;
                        ensure!(*input_hash == *candidate.id(), "Expected a constant input with the same hash");
                        message.push(*candidate.id());
                    }
                    // A public input is hashed (using `tcm`) to a field element.
                    InputID::Public(input_hash) => {
                        let candidate = InputID::public(function_id, input, self.tcm, index)?;
                        ensure!(*input_hash == *candidate.id(), "Expected a public input with the same hash");
                        message.push(*candidate.id());
                    }
                    // A private input is encrypted (using `tvk`) and hashed to a field element.
                    InputID::Private(input_hash) => {
                        let candidate = InputID::private(function_id, input, self.tvk, index)?;
                        ensure!(*input_hash == *candidate.id(), "Expected a private input with the same hash");
                        message.push(*candidate.id());
                    }
                    // A record input is computed to its serial number.
                    InputID::Record(commitment, gamma, record_view_key, serial_number, tag) => {
                        // Retrieve the record.
                        let record = match &input {
                            Value::Record(record) => record,
                            Value::Plaintext(..) => bail!("Expected a record input, found a plaintext input"),
                            Value::Future(..) => bail!("Expected a record input, found a future input"),
                            Value::DynamicRecord(..) => bail!("Expected a record input, found a dynamic record input"),
                            Value::DynamicFuture(..) => bail!("Expected a record input, found a dynamic future input"),
                        };
                        // Retrieve the record name.
                        let record_name = match input_type {
                            ValueType::Record(record_name) => record_name,
                            _ => bail!("Expected a record type at input {index}"),
                        };
                        // Ensure the record belongs to the signer.
                        ensure!(**record.owner() == self.signer, "Input record does not belong to the signer");

                        // Compute the record commitment.
                        let candidate_commitment =
                            record.to_commitment(&self.program_id, record_name, record_view_key)?;
                        ensure!(
                            *commitment == candidate_commitment,
                            "Expected a record input with the same commitment"
                        );

                        // Compute the candidate serial number from `gamma`.
                        let candidate_sn = Record::<N, Plaintext<N>>::serial_number_from_gamma(gamma, *commitment)?;
                        ensure!(*serial_number == candidate_sn, "Expected a record input with the same serial number");

                        // Compute the generator `H` as `HashToGroup(commitment)`.
                        let h = N::hash_to_group_psd2(&[N::serial_number_domain(), *commitment])?;
                        // Compute `h_r` as `(challenge * gamma) + (response * H)`, equivalent to `r * H`.
                        let h_r = (*gamma * challenge) + (h * response);

                        // Compute the tag as `Hash(sk_tag || commitment)`.
                        let candidate_tag = N::hash_psd2(&[self.sk_tag, *commitment])?;
                        ensure!(*tag == candidate_tag, "Expected a record input with the same tag");

                        // Add (`H`, `r * H`, `gamma`, `tag`) to the message.
                        message.extend([h, h_r, *gamma].iter().map(|point| point.to_x_coordinate()));
                        message.push(*tag);
                    }
                    // An external record input is hashed (using `tvk`) to a field element.
                    InputID::ExternalRecord(input_hash) => {
                        let candidate = InputID::external_record(function_id, input, self.tvk, index)?;
                        ensure!(*input_hash == *candidate.id(), "Expected an external record input with the same hash");
                        message.push(*candidate.id());
                    }
                    // A dynamic record input is hashed (using `tvk`) to a field element.
                    InputID::DynamicRecord(input_hash) => {
                        let candidate = InputID::dynamic_record(function_id, input, self.tvk, index)?;
                        ensure!(*input_hash == *candidate.id(), "Expected a dynamic record input with the same hash");
                        message.push(*candidate.id());
                    }
                }
                Ok(())
            },
        ) {
            eprintln!("Request verification failed on input checks: {error}");
            return false;
        }

        // Verify the signature.
        self.signature.verify(&self.signer, &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_account::PrivateKey;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    pub(crate) const ITERATIONS: usize = 1000;

    #[test]
    fn test_sign_and_verify() {
        let rng = &mut TestRng::default();

        for _i in 0..ITERATIONS {
            // Sample a random private key and address.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let address = Address::try_from(&private_key).unwrap();

            // Construct a program ID and function name.
            let program_id = ProgramID::from_str("token.aleo").unwrap();
            let function_name = Identifier::from_str("transfer").unwrap();

            // Prepare a record belonging to the address.
            let record_string = format!(
                "{{ owner: {address}.private, token_amount: 100u64.private, _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public }}"
            );

            // Construct four inputs.
            let input_constant = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_public = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_private = Value::from_str("{ token_amount: 9876543210u128 }").unwrap();
            let input_record = Value::from_str(&record_string).unwrap();
            let input_external_record = Value::from_str(&record_string).unwrap();
            let inputs = [input_constant, input_public, input_private, input_record, input_external_record];

            // Construct the input types.
            let input_types = vec![
                ValueType::from_str("amount.constant").unwrap(),
                ValueType::from_str("amount.public").unwrap(),
                ValueType::from_str("amount.private").unwrap(),
                ValueType::from_str("token.record").unwrap(),
                ValueType::from_str("token.aleo/token.record").unwrap(),
            ];

            // Sample 'root_tvk'.
            let root_tvk = None;
            // Sample 'is_root'.
            let is_root = Uniform::rand(rng);
            // Sample 'program_checksum'.
            let program_checksum = match bool::rand(rng) {
                true => Some(Field::rand(rng)),
                false => None,
            };

            // Randomly choose whether to sign as static or dynamic.
            let is_dynamic = bool::rand(rng);
            // Compute the signed request.
            let request = Request::sign(
                &private_key,
                program_id,
                function_name,
                inputs.into_iter(),
                &input_types,
                root_tvk,
                is_root,
                program_checksum,
                is_dynamic,
                rng,
            )
            .unwrap();
            assert!(request.verify(&input_types, is_root, program_checksum));
        }
    }

    #[test]
    fn test_sign_record_as_dynamic_record() {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random private key and address.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
            let address = Address::try_from(&private_key).unwrap();

            // Construct a program ID and function name.
            let program_id = ProgramID::from_str("token.aleo").unwrap();
            let function_name = Identifier::from_str("transfer").unwrap();

            // Prepare a record belonging to the address.
            let record_string = format!(
                "{{ owner: {address}.private, token_amount: 100u64.private, _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public }}"
            );

            // Construct a Value::Record input.
            let input_record = Value::from_str(&record_string).unwrap();
            assert!(matches!(input_record, Value::Record(..)));
            let inputs = [input_record];

            // Declare the input type as DynamicRecord.
            let input_types = vec![ValueType::DynamicRecord];

            // Sample 'is_root'.
            let is_root = Uniform::rand(rng);
            // Sample 'program_checksum'.
            let program_checksum = match bool::rand(rng) {
                true => Some(Field::rand(rng)),
                false => None,
            };

            // Sign the request — should succeed because Record is implicitly converted to DynamicRecord.
            let request = Request::sign(
                &private_key,
                program_id,
                function_name,
                inputs.into_iter(),
                &input_types,
                None,
                is_root,
                program_checksum,
                true,
                rng,
            )
            .unwrap();

            // Assert the stored input is Value::DynamicRecord (not Value::Record).
            assert!(matches!(request.inputs()[0], Value::DynamicRecord(..)));

            // Assert verification passes.
            assert!(request.verify(&input_types, is_root, program_checksum));
        }
    }
}
