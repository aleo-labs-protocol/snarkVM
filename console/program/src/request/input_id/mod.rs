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

mod bytes;
mod serialize;
mod string;

use crate::{Identifier, Plaintext, ProgramID, Record, Value};
use snarkvm_console_account::ViewKey;
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum InputID<N: Network> {
    /// The hash of the constant input.
    Constant(Field<N>),
    /// The hash of the public input.
    Public(Field<N>),
    /// The ciphertext hash of the private input.
    Private(Field<N>),
    /// The commitment, gamma, record view key, serial number, and tag of the record input.
    Record(Field<N>, Group<N>, Field<N>, Field<N>, Field<N>),
    /// The hash of the external record's (function_id, record, tvk, input index).
    ExternalRecord(Field<N>),
    /// The hash of the dynamic record's (function_id, record, tvk, input index).
    DynamicRecord(Field<N>),
}

impl<N: Network> InputID<N> {
    /// Returns the (primary) input ID.
    pub const fn id(&self) -> &Field<N> {
        match self {
            InputID::Constant(id) => id,
            InputID::Public(id) => id,
            InputID::Private(id) => id,
            InputID::Record(id, ..) => id,
            InputID::ExternalRecord(id) => id,
            InputID::DynamicRecord(id) => id,
        }
    }

    /// Computes the input ID for a constant input.
    /// Constructs the preimage as `(function_id || input || tcm || index)` and hashes it.
    pub fn constant(function_id: Field<N>, input: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the input is a plaintext.
        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");

        // Construct the (console) input index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || input || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(input.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the input to a field element.
        let hash = N::hash_psd8(&preimage)?;

        Ok(Self::Constant(hash))
    }

    /// Computes the input ID for a public input.
    /// Constructs the preimage as `(function_id || input || tcm || index)` and hashes it.
    pub fn public(function_id: Field<N>, input: &Value<N>, tcm: Field<N>, index: u16) -> Result<Self> {
        // Ensure the input is a plaintext.
        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");

        // Construct the (console) input index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || input || tcm || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(input.to_fields()?);
        preimage.push(tcm);
        preimage.push(index);
        // Hash the input to a field element.
        let hash = N::hash_psd8(&preimage)?;

        Ok(Self::Public(hash))
    }

    /// Computes the input ID for a private input.
    /// Encrypts the input using the input view key and hashes the ciphertext.
    pub fn private(function_id: Field<N>, input: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the input is a plaintext.
        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");

        // Construct the (console) input index as a field element.
        let index = Field::from_u16(index);
        // Compute the input view key as `Hash(function ID || tvk || index)`.
        let input_view_key = N::hash_psd4(&[function_id, tvk, index])?;
        // Compute the ciphertext.
        let ciphertext = match &input {
            Value::Plaintext(plaintext) => plaintext.encrypt_symmetric(input_view_key)?,
            // Ensure the input is a plaintext.
            Value::Record(..) => bail!("Expected a plaintext input, found a record input"),
            Value::Future(..) => bail!("Expected a plaintext input, found a future input"),
            Value::DynamicRecord(..) => bail!("Expected a plaintext input, found a dynamic record input"),
            Value::DynamicFuture(..) => bail!("Expected a plaintext input, found a dynamic future input"),
        };
        // Hash the ciphertext to a field element.
        let hash = N::hash_psd8(&ciphertext.to_fields()?)?;

        Ok(Self::Private(hash))
    }

    /// Computes the input ID for a record input.
    /// Returns the full InputID::Record variant with commitment, gamma, record view key, serial number, and tag.
    pub fn record(
        program_id: &ProgramID<N>,
        record_name: &Identifier<N>,
        input: &Value<N>,
        signer: &Address<N>,
        view_key: &ViewKey<N>,
        sk_sig: &Scalar<N>,
        sk_tag: Field<N>,
    ) -> Result<Self> {
        // Retrieve the record.
        let record = match &input {
            Value::Record(record) => record,
            // Ensure the input is a record.
            Value::Plaintext(..) => bail!("Expected a record input, found a plaintext input"),
            Value::Future(..) => bail!("Expected a record input, found a future input"),
            Value::DynamicRecord(..) => bail!("Expected a record input, found a dynamic record input"),
            Value::DynamicFuture(..) => bail!("Expected a record input, found a dynamic future input"),
        };
        // Ensure the record belongs to the signer.
        ensure!(**record.owner() == *signer, "Input record '{program_id}/{record_name}' must belong to the signer");
        // Compute the record view key.
        let record_view_key = (*record.nonce() * **view_key).to_x_coordinate();
        // Compute the record commitment.
        let commitment = record.to_commitment(program_id, record_name, &record_view_key)?;

        // Compute the generator `H` as `HashToGroup(commitment)`.
        let h = N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])?;
        // Compute `gamma` as `sk_sig * H`.
        let gamma = h * sk_sig;

        // Compute the `serial_number` from `gamma`.
        let serial_number = Record::<N, Plaintext<N>>::serial_number_from_gamma(&gamma, commitment)?;
        // Compute the tag.
        let tag = Record::<N, Plaintext<N>>::tag(sk_tag, commitment)?;

        Ok(InputID::Record(commitment, gamma, record_view_key, serial_number, tag))
    }

    /// Computes the input ID for an external record input.
    /// Constructs the preimage as `(function_id || input || tvk || index)` and hashes it.
    pub fn external_record(function_id: Field<N>, input: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the input is a record.
        ensure!(matches!(input, Value::Record(..)), "Expected a record input");

        // Construct the (console) input index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || input || tvk || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(input.to_fields()?);
        preimage.push(tvk);
        preimage.push(index);
        // Hash the input to a field element.
        let hash = N::hash_psd8(&preimage)?;

        Ok(Self::ExternalRecord(hash))
    }

    /// Computes the input ID for a dynamic record input.
    /// Constructs the preimage as `(function_id || input || tvk || index)` and hashes it.
    pub fn dynamic_record(function_id: Field<N>, input: &Value<N>, tvk: Field<N>, index: u16) -> Result<Self> {
        // Ensure the input is a dynamic record.
        ensure!(matches!(input, Value::DynamicRecord(..)), "Expected a dynamic record input");

        // Construct the (console) input index as a field element.
        let index = Field::from_u16(index);
        // Construct the preimage as `(function ID || input || tvk || index)`.
        let mut preimage = Vec::new();
        preimage.push(function_id);
        preimage.extend(input.to_fields()?);
        preimage.push(tvk);
        preimage.push(index);
        // Hash the input to a field element.
        let hash = N::hash_psd8(&preimage)?;

        Ok(Self::DynamicRecord(hash))
    }
}
