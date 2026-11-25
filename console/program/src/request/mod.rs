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

mod input_id;
pub use input_id::InputID;

mod bytes;
mod serialize;
mod sign;
mod string;
mod verify;

use crate::{DynamicRecord, Identifier, Plaintext, ProgramID, Record, Value, ValueType, compute_function_id};
use snarkvm_console_account::{Address, ComputeKey, GraphKey, PrivateKey, Signature, ViewKey};
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

#[derive(Clone, PartialEq, Eq)]
pub struct Request<N: Network> {
    /// The request signer.
    signer: Address<N>,
    /// The network ID.
    network_id: U16<N>,
    /// The program ID.
    program_id: ProgramID<N>,
    /// The function name.
    function_name: Identifier<N>,
    /// The input ID for the transition.
    input_ids: Vec<InputID<N>>,
    /// The function inputs.
    inputs: Vec<Value<N>>,
    /// The signature for the transition.
    signature: Signature<N>,
    /// The tag secret key.
    sk_tag: Field<N>,
    /// The transition view key.
    tvk: Field<N>,
    /// The transition commitment.
    tcm: Field<N>,
    /// The signer commitment.
    scm: Field<N>,
    /// A flag indicating whether or not the request is dynamic.
    is_dynamic: bool,
}

impl<N: Network>
    From<(
        Address<N>,
        U16<N>,
        ProgramID<N>,
        Identifier<N>,
        Vec<InputID<N>>,
        Vec<Value<N>>,
        Signature<N>,
        Field<N>,
        Field<N>,
        Field<N>,
        Field<N>,
        bool,
    )> for Request<N>
{
    /// Note: See `Request::sign` to create the request. This method is used to eject from a circuit.
    fn from(
        (
            signer,
            network_id,
            program_id,
            function_name,
            input_ids,
            inputs,
            signature,
            sk_tag,
            tvk,
            tcm,
            scm,
            is_dynamic,
        ): (
            Address<N>,
            U16<N>,
            ProgramID<N>,
            Identifier<N>,
            Vec<InputID<N>>,
            Vec<Value<N>>,
            Signature<N>,
            Field<N>,
            Field<N>,
            Field<N>,
            Field<N>,
            bool,
        ),
    ) -> Self {
        // Ensure that the number of inputs matches the number of input IDs.
        if inputs.len() != input_ids.len() {
            N::halt(format!(
                "Invalid request: mismatching number of input IDs ({}) and inputs ({})",
                input_ids.len(),
                inputs.len()
            ))
        }

        // Ensure the network ID is correct.
        if *network_id != N::ID {
            N::halt(format!("Invalid network ID. Expected {}, found {}", N::ID, *network_id))
        } else {
            Self {
                signer,
                network_id,
                program_id,
                function_name,
                input_ids,
                inputs,
                signature,
                sk_tag,
                tvk,
                tcm,
                scm,
                is_dynamic,
            }
        }
    }
}

impl<N: Network> Request<N> {
    /// Returns the request signer.
    pub const fn signer(&self) -> &Address<N> {
        &self.signer
    }

    /// Returns the network ID.
    pub const fn network_id(&self) -> &U16<N> {
        &self.network_id
    }

    /// Returns the program ID.
    pub const fn program_id(&self) -> &ProgramID<N> {
        &self.program_id
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the input ID for the transition.
    pub fn input_ids(&self) -> &[InputID<N>] {
        &self.input_ids
    }

    /// Returns the function inputs.
    pub fn inputs(&self) -> &[Value<N>] {
        &self.inputs
    }

    /// Returns the signature for the transition.
    pub const fn signature(&self) -> &Signature<N> {
        &self.signature
    }

    /// Returns the tag secret key `sk_tag`.
    pub const fn sk_tag(&self) -> &Field<N> {
        &self.sk_tag
    }

    /// Returns the transition view key `tvk`.
    pub const fn tvk(&self) -> &Field<N> {
        &self.tvk
    }

    /// Returns the transition public key `tpk`.
    pub fn to_tpk(&self) -> Group<N> {
        // Retrieve the challenge from the signature.
        let challenge = self.signature.challenge();
        // Retrieve the response from the signature.
        let response = self.signature.response();
        // Retrieve `pk_sig` from the signature.
        let pk_sig = self.signature.compute_key().pk_sig();
        // Compute `tpk` as `(challenge * pk_sig) + (response * G)`, equivalent to `r * G`.
        (pk_sig * challenge) + N::g_scalar_multiply(&response)
    }

    /// Returns the transition commitment `tcm`.
    pub const fn tcm(&self) -> &Field<N> {
        &self.tcm
    }

    /// Returns the signer commitment `scm`.
    pub const fn scm(&self) -> &Field<N> {
        &self.scm
    }

    /// Returns whether or not the request is dynamic.
    pub const fn is_dynamic(&self) -> bool {
        self.is_dynamic
    }

    /// Returns the expected caller input IDs for a dynamic call by:
    ///
    /// - converting all record inputs to dynamic record inputs
    /// - leaving all other inputs unchanged.
    ///
    /// and then computing their corresponding input IDs.
    pub fn to_dynamic_input_ids(&self) -> Result<Vec<InputID<N>>> {
        // Compute the function ID.
        let function_id = compute_function_id(&self.network_id, &self.program_id, &self.function_name)?;

        ensure!(
            self.input_ids().len() == self.inputs.len(),
            "Mismatched number of input IDs and inputs: {} vs. {}",
            self.input_ids().len(),
            self.inputs.len(),
        );

        // Compute and return the caller input IDs.
        self.input_ids()
            .iter()
            .zip(self.inputs.iter())
            .enumerate()
            .map(|(index, (input_id, input))| match (input_id, input) {
                (InputID::Constant(..), Value::Plaintext(..))
                | (InputID::Public(..), Value::Plaintext(..))
                | (InputID::Private(..), Value::Plaintext(..))
                | (InputID::DynamicRecord(..), Value::DynamicRecord(..)) => Ok(*input_id),
                (InputID::Record(..), Value::Record(record)) | (InputID::ExternalRecord(..), Value::Record(record)) => {
                    // Convert index to u16.
                    let index = u16::try_from(index).map_err(|_| anyhow!("Input index exceeds u16"))?;
                    // Convert the record to a dynamic record.
                    let caller_input = Value::DynamicRecord(DynamicRecord::from_record(record)?);
                    // Compute the input ID for the dynamic record.
                    InputID::dynamic_record(function_id, &caller_input, self.tvk, index)
                }
                _ => bail!("Mismatching input ID and input value at index {index}"),
            })
            .collect()
    }

    /// Returns the expected caller inputs for a dynamic call by:
    /// - converting all record inputs to dynamic record inputs
    /// - leaving all other inputs unchanged.
    pub fn to_dynamic_inputs(&self) -> Result<Vec<Value<N>>> {
        self.inputs
            .iter()
            .map(|input| match input {
                Value::Record(record) => {
                    // This covers both the non-external and external record cases.
                    Ok(Value::DynamicRecord(DynamicRecord::from_record(record)?))
                }
                Value::Future(_) => bail!("A future cannot be an input to a request."),
                Value::DynamicFuture(_) => bail!("A dynamic future cannot be an input to a request."),
                _ => Ok(input.clone()),
            })
            .collect::<Result<Vec<_>>>()
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 1000;

    pub(super) fn sample_requests(rng: &mut TestRng) -> Vec<Request<CurrentNetwork>> {
        (0..ITERATIONS)
            .map(|i| {
                // Sample a random private key and address.
                let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
                let address = Address::try_from(&private_key).unwrap();

                // Construct a program ID and function name.
                let program_id = ProgramID::from_str("token.aleo").unwrap();
                let function_name = Identifier::from_str("transfer").unwrap();

                // Prepare a record belonging to the address.
                let record_string =
                    format!("{{ owner: {address}.private, token_amount: {i}u64.private, _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public }}");

                // Construct four inputs.
                let input_constant = Value::from_str(&format!("{{ token_amount: {i}u128 }}")).unwrap();
                let input_public = Value::from_str(&format!("{{ token_amount: {i}u128 }}")).unwrap();
                let input_private = Value::from_str(&format!("{{ token_amount: {i}u128 }}")).unwrap();
                let input_record = Value::from_str(&record_string).unwrap();
                let input_external_record = Value::from_str(&record_string).unwrap();
                let inputs = vec![input_constant, input_public, input_private, input_record, input_external_record];

                // Construct the input types.
                let input_types = [
                    ValueType::from_str("amount.constant").unwrap(),
                    ValueType::from_str("amount.public").unwrap(),
                    ValueType::from_str("amount.private").unwrap(),
                    ValueType::from_str("token.record").unwrap(),
                    ValueType::from_str("token.aleo/token.record").unwrap(),
                ];

                // Sample root_tvk.
                let root_tvk = None;
                // Construct 'is_root'.
                let is_root = Uniform::rand(rng);
                // Sample the program checksum.
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
                request
            })
            .collect()
    }
}
