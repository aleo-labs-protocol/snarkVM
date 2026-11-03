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
    /// Returns the request for a given private key, program ID, function name, inputs, input types, is_dynamic, and RNG, where:
    ///     challenge := HashToScalar(r * G, pk_sig, pr_sig, signer, \[tvk, tcm, function ID, is_root, program checksum?, input IDs\])
    ///     response := r - challenge * sk_sig
    /// The program checksum must be provided if the program has a constructor and should not be provided otherwise.
    pub fn sign<R: Rng + CryptoRng>(
        private_key: &PrivateKey<N>,
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        input_types: &[ValueType<N>],
        root_tvk: Option<Field<N>>,
        is_root: bool,
        program_checksum: Option<Field<N>>,
        is_dynamic: bool,
        rng: &mut R,
    ) -> Result<Self> {
        // Ensure the number of inputs matches the number of input types.
        if input_types.len() != inputs.len() {
            bail!(
                "'{program_id}/{function_name}' expects {} inputs, but {} were provided.",
                input_types.len(),
                inputs.len()
            )
        }

        // Retrieve `sk_sig`.
        let sk_sig = private_key.sk_sig();

        // Derive the compute key.
        let compute_key = ComputeKey::try_from(private_key)?;
        // Retrieve `pk_sig`.
        let pk_sig = compute_key.pk_sig();
        // Retrieve `pr_sig`.
        let pr_sig = compute_key.pr_sig();

        // Derive the view key.
        let view_key = ViewKey::try_from((private_key, &compute_key))?;
        // Derive `sk_tag` from the graph key.
        let sk_tag = GraphKey::try_from(view_key)?.sk_tag();

        // Sample a random nonce.
        let nonce = Field::<N>::rand(rng);
        // Compute a `r` as `HashToScalar(sk_sig || nonce)`. Note: This is the transition secret key `tsk`.
        let r = N::hash_to_scalar_psd4(&[N::serial_number_domain(), sk_sig.to_field()?, nonce])?;
        // Compute `g_r` as `r * G`. Note: This is the transition public key `tpk`.
        let g_r = N::g_scalar_multiply(&r);

        // Derive the signer from the compute key.
        let signer = Address::try_from(compute_key)?;
        // Compute the transition view key `tvk` as `r * signer`.
        let tvk = (*signer * r).to_x_coordinate();
        // Compute the transition commitment `tcm` as `Hash(tvk)`.
        let tcm = N::hash_psd2(&[tvk])?;
        // Compute the signer commitment `scm` as `Hash(signer || root_tvk)`.
        let root_tvk = root_tvk.unwrap_or(tvk);
        let scm = N::hash_psd2(&[signer.deref().to_x_coordinate(), root_tvk])?;
        // Compute 'is_root' as a field element.
        let is_root = if is_root { Field::<N>::one() } else { Field::<N>::zero() };

        // Retrieve the network ID.
        let network_id = U16::new(N::ID);
        // Compute the function ID.
        let function_id = compute_function_id(&network_id, &program_id, &function_name)?;

        // Construct the hash input as `(r * G, pk_sig, pr_sig, signer, [tvk, tcm, function ID, is_root, program checksum?, input IDs])`.
        let mut message = Vec::with_capacity(9 + 2 * inputs.len());
        message.extend([g_r, pk_sig, pr_sig, *signer].map(|point| point.to_x_coordinate()));
        message.extend([tvk, tcm, function_id, is_root]);
        // Add the program checksum to the hash input if it was provided.
        if let Some(program_checksum) = program_checksum {
            message.push(program_checksum);
        }

        // Initialize a vector to store the prepared inputs.
        let mut prepared_inputs = Vec::with_capacity(inputs.len());
        // Initialize a vector to store the input IDs.
        let mut input_ids = Vec::with_capacity(inputs.len());

        // Prepare the inputs.
        for (index, (input, input_type)) in inputs.zip_eq(input_types).enumerate() {
            // Prepare the input.
            let input = input.try_into().map_err(|_| {
                anyhow!("Failed to parse input #{index} ('{input_type}') for '{program_id}/{function_name}'")
            })?;
            // If the function expects a dynamic record but a record was provided, convert it.
            let input = match (&input, input_type) {
                (Value::Record(record), ValueType::DynamicRecord) => {
                    Value::DynamicRecord(DynamicRecord::from_record(record)?)
                }
                _ => input,
            };
            // Store the prepared input.
            prepared_inputs.push(input.clone());

            // Convert index to u16.
            let index = u16::try_from(index).map_err(|_| anyhow!("Input index exceeds u16"))?;

            match input_type {
                // A constant input is hashed (using `tcm`) to a field element.
                ValueType::Constant(..) => {
                    let input_id = InputID::constant(function_id, &input, tcm, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A public input is hashed (using `tcm`) to a field element.
                ValueType::Public(..) => {
                    let input_id = InputID::public(function_id, &input, tcm, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A private input is encrypted (using `tvk`) and hashed to a field element.
                ValueType::Private(..) => {
                    let input_id = InputID::private(function_id, &input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A record input is computed to its serial number.
                ValueType::Record(record_name) => {
                    // Compute the input ID (commitment, gamma, record view key, serial number, tag).
                    let input_id =
                        InputID::record(&program_id, record_name, &input, &signer, &view_key, &sk_sig, sk_tag)?;
                    // Extract the commitment, gamma, and tag for the message.
                    let (commitment, gamma, tag) = match &input_id {
                        InputID::Record(c, g, _, _, t) => (*c, *g, *t),
                        // InputID::record always returns the Record variant.
                        _ => unreachable!(),
                    };
                    // Compute the generator `H` as `HashToGroup(commitment)`.
                    let h = N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])?;
                    // Compute `h_r` as `r * H`.
                    let h_r = h * r;
                    // Add (`H`, `r * H`, `gamma`, `tag`) to the preimage.
                    message.extend([h, h_r, gamma].iter().map(|point| point.to_x_coordinate()));
                    message.push(tag);
                    input_ids.push(input_id);
                }
                // An external record input is hashed (using `tvk`) to a field element.
                ValueType::ExternalRecord(..) => {
                    let input_id = InputID::external_record(function_id, &input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A future is not a valid input.
                ValueType::Future(..) => bail!("A future is not a valid input"),
                // A dynamic record input is hashed (using `tvk`) to a field element.
                ValueType::DynamicRecord => {
                    let input_id = InputID::dynamic_record(function_id, &input, tvk, index)?;
                    message.push(*input_id.id());
                    input_ids.push(input_id);
                }
                // A dynamic future is not a valid input.
                ValueType::DynamicFuture => bail!("A dynamic future is not a valid input"),
            }
        }

        // Compute `challenge` as `HashToScalar(r * G, pk_sig, pr_sig, signer, [tvk, tcm, function ID, is_root, program checksum?, input IDs])`.
        let challenge = N::hash_to_scalar_psd8(&message)?;
        // Compute `response` as `r - challenge * sk_sig`.
        let response = r - challenge * sk_sig;

        Ok(Self {
            signer,
            network_id,
            program_id,
            function_name,
            input_ids,
            inputs: prepared_inputs,
            signature: Signature::from((challenge, response, compute_key)),
            sk_tag,
            tvk,
            tcm,
            scm,
            is_dynamic,
        })
    }

    /// Samples a `Request` with the given `signer`, `program_id`,
    /// `function_name` and `inputs`. The fields `sk_tag`, `tvk`, `tcm`, `scm`,
    /// `signature` and `input_ids` are random, but the size of the sampled
    /// `Request` is the same as if it were correctly produced from the given
    /// inputs and signed.
    pub fn sample<R: Rng + CryptoRng>(
        signer: Address<N>,
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: impl ExactSizeIterator<Item = impl TryInto<Value<N>>>,
        input_types: &[ValueType<N>],
        is_dynamic: bool,
        rng: &mut R,
    ) -> Result<Self> {
        // Ensure the number of inputs matches the number of input types.
        if input_types.len() != inputs.len() {
            bail!(
                "'{program_id}/{function_name}' expects {} inputs, but {} were provided.",
                input_types.len(),
                inputs.len()
            )
        }

        // Initialize a vector to store the prepared inputs.
        let mut prepared_inputs = Vec::with_capacity(inputs.len());
        // Initialize a vector to store the input IDs.
        let mut input_ids = Vec::with_capacity(inputs.len());

        // Prepare the inputs.
        for (index, (input, input_type)) in inputs.zip_eq(input_types).enumerate() {
            // Prepare the input.
            let input = input.try_into().map_err(|_| {
                anyhow!("Failed to parse input #{index} ('{input_type}') for '{program_id}/{function_name}'")
            })?;
            // If the function expects a dynamic record but a record was provided, convert it.
            let input = match (&input, input_type) {
                (Value::Record(record), ValueType::DynamicRecord) => {
                    Value::DynamicRecord(DynamicRecord::from_record(record)?)
                }
                _ => input,
            };
            // Store the prepared input.
            prepared_inputs.push(input.clone());

            match input_type {
                ValueType::Constant(..) => {
                    input_ids.push(InputID::Constant(Field::rand(rng)));
                }
                ValueType::Public(..) => {
                    input_ids.push(InputID::Public(Field::rand(rng)));
                }
                ValueType::Private(..) => {
                    input_ids.push(InputID::Private(Field::rand(rng)));
                }
                ValueType::Record(..) => {
                    input_ids.push(InputID::Record(
                        Field::rand(rng),
                        Group::rand(rng),
                        Field::rand(rng),
                        Field::rand(rng),
                        Field::rand(rng),
                    ));
                }
                ValueType::ExternalRecord(..) => {
                    input_ids.push(InputID::ExternalRecord(Field::rand(rng)));
                }
                ValueType::Future(..) => bail!("A future is not a valid input"),
                ValueType::DynamicRecord => {
                    input_ids.push(InputID::DynamicRecord(Field::rand(rng)));
                }
                ValueType::DynamicFuture => bail!("A dynamic future is not a valid input"),
            }
        }

        let challenge = Scalar::rand(rng);
        let response = Scalar::rand(rng);

        let compute_key = {
            let private_key = PrivateKey::<N>::new(rng)?;
            ComputeKey::<N>::try_from(private_key)?
        };

        Ok(Self {
            signer,
            network_id: U16::new(N::ID),
            program_id,
            function_name,
            input_ids,
            inputs: prepared_inputs,
            signature: Signature::from((challenge, response, compute_key)),
            sk_tag: Field::zero(),
            tvk: Field::rand(rng),
            tcm: Field::rand(rng),
            scm: Field::rand(rng),
            is_dynamic,
        })
    }
}
