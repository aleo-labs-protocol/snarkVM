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

use crate::{DynamicFuture, DynamicRecord, Identifier, ProgramID, Register, Value, ValueType, compute_function_id};
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputID<N: Network> {
    /// The hash of the constant output.
    Constant(Field<N>),
    /// The hash of the public output.
    Public(Field<N>),
    /// The ciphertext hash of the private output.
    Private(Field<N>),
    /// The `(commitment, checksum, sender_ciphertext)` tuple of the record output.
    Record(Field<N>, Field<N>, Field<N>),
    /// The hash of the external record's (function_id, record, tvk, output index).
    ExternalRecord(Field<N>),
    /// The hash of the future output.
    Future(Field<N>),
    /// The hash of the dynamic record's (function_id, dynamic record, tvk, output index).
    DynamicRecord(Field<N>),
    /// The hash of the dynamic future's (function_id, dynamic future, tcm, output index).
    DynamicFuture(Field<N>),
}

impl<N: Network> OutputID<N> {
    /// Returns the (primary) output ID.
    pub const fn id(&self) -> &Field<N> {
        match self {
            OutputID::Constant(id) => id,
            OutputID::Public(id) => id,
            OutputID::Private(id) => id,
            OutputID::Record(id, ..) => id,
            OutputID::ExternalRecord(id) => id,
            OutputID::Future(id) => id,
            OutputID::DynamicRecord(id) => id,
            OutputID::DynamicFuture(id) => id,
        }
    }

    /// Computes the output ID for a constant output.
    /// Constructs the preimage as `(function_id || output || tcm || index)` and hashes it.
    pub fn constant(function_id: Field<N>, output: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a plaintext.
        ensure!(matches!(output, Value::Plaintext(..)), "Expected a plaintext output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::Constant(hash))
    }

    /// Computes the output ID for a public output.
    /// Constructs the preimage as `(function_id || output || tcm || index)` and hashes it.
    pub fn public(function_id: Field<N>, output: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a plaintext.
        ensure!(matches!(output, Value::Plaintext(..)), "Expected a plaintext output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::Public(hash))
    }

    /// Computes the output ID for a private output.
    /// Encrypts the output using the output view key derived from `tvk` and hashes the ciphertext.
    pub fn private(function_id: Field<N>, output: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a plaintext.
        ensure!(matches!(output, Value::Plaintext(..)), "Expected a plaintext output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Compute the output view key as `Hash(function ID || tvk || index)`.
        let output_view_key = N::hash_psd4(&[function_id, tvk, index])?;
        // Compute the ciphertext.
        let ciphertext = match output {
            Value::Plaintext(plaintext) => plaintext.encrypt_symmetric(output_view_key)?,
            Value::Record(..) => bail!("Expected a plaintext output, found a record output"),
            Value::Future(..) => bail!("Expected a plaintext output, found a future output"),
            Value::DynamicRecord(..) => bail!("Expected a plaintext output, found a dynamic record output"),
            Value::DynamicFuture(..) => bail!("Expected a plaintext output, found a dynamic future output"),
        };
        // Hash the ciphertext to a field element.
        let hash = N::hash_psd8(&ciphertext.to_fields()?)?;
        Ok(Self::Private(hash))
    }

    /// Computes the output ID for a record output.
    /// Encrypts the record using `tvk` and returns the `(commitment, checksum, sender_ciphertext)` tuple.
    pub fn record(
        signer: &Address<N>,
        program_id: &ProgramID<N>,
        record_name: &Identifier<N>,
        output: &Value<N>,
        tvk: Field<N>,
        output_register: &Register<N>,
    ) -> Result<Self> {
        // Retrieve the record.
        let record = match output {
            Value::Record(record) => record,
            Value::Plaintext(..) => bail!("Expected a record output, found a plaintext output"),
            Value::Future(..) => bail!("Expected a record output, found a future output"),
            Value::DynamicRecord(..) => bail!("Expected a record output, found a dynamic record output"),
            Value::DynamicFuture(..) => bail!("Expected a record output, found a dynamic future output"),
        };
        // Construct the (console) output index as a field element.
        let index = Field::from_u64(output_register.locator());
        // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
        let randomizer = N::hash_to_scalar_psd2(&[tvk, index])?;
        // Encrypt the record, using the randomizer.
        let (encrypted_record, record_view_key) = record.encrypt_symmetric(randomizer)?;
        // Compute the record commitment.
        let commitment = record.to_commitment(program_id, record_name, &record_view_key)?;
        // Compute the record checksum, as the hash of the encrypted record.
        let checksum = N::hash_bhp1024(&encrypted_record.to_bits_le())?;
        // Prepare a randomizer for the sender ciphertext.
        let randomizer = N::hash_psd4(&[N::encryption_domain(), record_view_key, Field::one()])?;
        // Encrypt the signer address using the randomizer.
        let sender_ciphertext = (**signer).to_x_coordinate() + randomizer;
        Ok(Self::Record(commitment, checksum, sender_ciphertext))
    }

    /// Computes the output ID for an external record output.
    /// Constructs the preimage as `(function_id || output || tvk || index)` and hashes it.
    pub fn external_record(function_id: Field<N>, output: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a record.
        ensure!(matches!(output, Value::Record(..)), "Expected a record output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tvk || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tvk);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::ExternalRecord(hash))
    }

    /// Computes the output ID for a future output.
    /// Constructs the preimage as `(function_id || output || tcm || index)` and hashes it.
    pub fn future(function_id: Field<N>, output: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a future.
        ensure!(matches!(output, Value::Future(..)), "Expected a future output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::Future(hash))
    }

    /// Computes the output ID for a dynamic record output.
    /// Constructs the preimage as `(function_id || output || tvk || index)` and hashes it.
    pub fn dynamic_record(function_id: Field<N>, output: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a dynamic record.
        ensure!(matches!(output, Value::DynamicRecord(..)), "Expected a dynamic record output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tvk || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tvk);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::DynamicRecord(hash))
    }

    /// Computes the output ID for a dynamic future output.
    /// Constructs the preimage as `(function_id || output || tcm || index)` and hashes it.
    pub fn dynamic_future(function_id: Field<N>, output: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the output is a dynamic future.
        ensure!(matches!(output, Value::DynamicFuture(..)), "Expected a dynamic future output");
        // Construct the (console) output index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || output || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(output.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the output to a field element.
        let hash = N::hash_psd8(&preimage)?;
        Ok(Self::DynamicFuture(hash))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response<N: Network> {
    /// The output ID for the transition.
    output_ids: Vec<OutputID<N>>,
    /// The function outputs.
    outputs: Vec<Value<N>>,
}

impl<N: Network> From<(Vec<OutputID<N>>, Vec<Value<N>>)> for Response<N> {
    /// Note: This method is used to eject from a circuit.
    fn from((output_ids, outputs): (Vec<OutputID<N>>, Vec<Value<N>>)) -> Self {
        Self { output_ids, outputs }
    }
}

impl<N: Network> Response<N> {
    /// Initializes a new response.
    pub fn new(
        signer: &Address<N>,
        network_id: &U16<N>,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        num_inputs: usize,
        tvk: &Field<N>,
        tcm: &Field<N>,
        outputs: Vec<Value<N>>,
        output_types: &[ValueType<N>],
        output_operands: &[Option<Register<N>>],
    ) -> Result<Self> {
        // Compute the function ID.
        let function_id = compute_function_id(network_id, program_id, function_name)?;

        // Compute the output IDs.
        let output_ids = outputs
            .iter()
            .zip_eq(output_types)
            .zip_eq(output_operands)
            .enumerate()
            .map(|(index, ((output, output_type), output_register))| {
                match output_type {
                    // For a constant output, compute the hash (using `tcm`) of the output.
                    ValueType::Constant(..) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::constant(function_id, output, *tcm, output_index)
                    }
                    // For a public output, compute the hash (using `tcm`) of the output.
                    ValueType::Public(..) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::public(function_id, output, *tcm, output_index)
                    }
                    // For a private output, encrypt (using `tvk`) and hash the ciphertext.
                    ValueType::Private(..) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::private(function_id, output, *tvk, output_index)
                    }
                    // For a record output, compute the commitment and encrypt the record (using `tvk`).
                    ValueType::Record(record_name) => {
                        let Some(output_register) = output_register else {
                            bail!("Expected a register to be paired with a record output");
                        };
                        OutputID::record(signer, program_id, record_name, output, *tvk, output_register)
                    }
                    // For an external record, compute the hash (using `tvk`) of the output.
                    ValueType::ExternalRecord(..) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::external_record(function_id, output, *tvk, output_index)
                    }
                    // For a future output, compute the hash (using `tcm`) of the output.
                    ValueType::Future(..) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::future(function_id, output, *tcm, output_index)
                    }
                    // For a dynamic record, compute the hash (using `tvk`) of the output.
                    ValueType::DynamicRecord => {
                        // Safe: num_inputs ≤ N::MAX_INPUTS and index < N::MAX_OUTPUTS,
                        // so num_inputs + index fits well within u16::MAX.
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::dynamic_record(function_id, output, *tvk, output_index)
                    }
                    // For a dynamic future output, compute the hash (using `tcm`) of the output.
                    ValueType::DynamicFuture => {
                        // Safe: num_inputs ≤ N::MAX_INPUTS and index < N::MAX_OUTPUTS,
                        // so num_inputs + index fits well within u16::MAX.
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::dynamic_future(function_id, output, *tcm, output_index)
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { output_ids, outputs })
    }

    /// Returns the output ID for the transition.
    pub fn output_ids(&self) -> &[OutputID<N>] {
        &self.output_ids
    }

    /// Returns the function outputs.
    pub fn outputs(&self) -> &[Value<N>] {
        &self.outputs
    }

    /// Returns the expected caller outputs for a dynamic call by:
    /// - converting all record outputs to dynamic record outputs
    /// - converting all future outputs to dynamic future outputs.
    /// - leaving all other outputs unchanged.
    pub fn to_dynamic_outputs(&self) -> Result<Vec<Value<N>>> {
        self.outputs
            .iter()
            .map(|output| match output {
                Value::Record(record) => {
                    // This covers both the non-external and external record cases.
                    Ok(Value::DynamicRecord(DynamicRecord::from_record(record)?))
                }
                Value::Future(future) => Ok(Value::DynamicFuture(DynamicFuture::from_future(future)?)),
                Value::DynamicFuture(_) => bail!("A dynamic future cannot be a response output"),
                Value::Plaintext(_) => Ok(output.clone()),
                Value::DynamicRecord(_) => Ok(output.clone()),
            })
            .collect::<Result<Vec<_>>>()
    }

    /// Returns the expected caller output IDs for a dynamic call by:
    /// - converting all record output IDs to dynamic record output IDs
    /// - converting all future output IDs to dynamic future output IDs.
    /// - leaving all other output IDs unchanged.
    pub fn to_dynamic_output_ids(
        &self,
        network_id: &U16<N>,
        program_id: &ProgramID<N>,
        function_name: &Identifier<N>,
        num_inputs: usize,
        tvk: &Field<N>,
        tcm: &Field<N>,
    ) -> Result<Vec<OutputID<N>>> {
        // Compute the function ID.
        let function_id = compute_function_id(network_id, program_id, function_name)?;
        // Get the caller outputs.
        let caller_outputs = self.to_dynamic_outputs()?;
        // Ensure the number of caller outputs matches the number of output IDs.
        ensure!(
            caller_outputs.len() == self.output_ids.len(),
            "The number of caller outputs ({}) does not match the number of output IDs ({})",
            caller_outputs.len(),
            self.output_ids.len()
        );
        // Compute the caller output IDs for the caller outputs.
        caller_outputs
            .iter()
            .zip_eq(self.output_ids.iter())
            .enumerate()
            .map(|(index, (output, callee_output_id))| {
                match callee_output_id {
                    OutputID::Record(_, _, _) | OutputID::ExternalRecord(_) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::dynamic_record(function_id, output, *tvk, output_index)
                    }
                    OutputID::Future(_) => {
                        let output_index =
                            u16::try_from(num_inputs + index).or_halt_with::<N>("Output index exceeds u16");
                        OutputID::dynamic_future(function_id, output, *tcm, output_index)
                    }
                    // Otherwise, return the output ID unchanged.
                    OutputID::Constant(_) => Ok(callee_output_id.clone()),
                    OutputID::Public(_) => Ok(callee_output_id.clone()),
                    OutputID::Private(_) => Ok(callee_output_id.clone()),
                    OutputID::DynamicRecord(_) => Ok(callee_output_id.clone()),
                    OutputID::DynamicFuture(_) => Ok(callee_output_id.clone()),
                }
            })
            .collect::<Result<Vec<_>>>()
    }
}
