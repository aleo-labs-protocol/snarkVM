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

mod from_outputs;
mod process_outputs_from_callback;

use crate::{Identifier, ProgramID, Value, compute_function_id};
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Field, U16, environment::prelude::*};

pub enum OutputID<A: Aleo> {
    /// The hash of the constant output.
    Constant(Field<A>),
    /// The hash of the public output.
    Public(Field<A>),
    /// The ciphertext hash of the private output.
    Private(Field<A>),
    /// The `(commitment, checksum, sender_ciphertext)` tuple of the record output.
    Record(Field<A>, Field<A>, Field<A>),
    /// The hash of the external record's (function_id, record, tvk, output index).
    ExternalRecord(Field<A>),
    /// The hash of the future output.
    Future(Field<A>),
    /// The hash of the dynamic record's (function_id, dynamic record, tvk, output index).
    DynamicRecord(Field<A>),
    /// The hash of the dynamic future's (function_id, dynamic future, tvk, output index).
    DynamicFuture(Field<A>),
}

impl<A: Aleo> Inject for OutputID<A> {
    type Primitive = console::OutputID<A::Network>;

    /// Initializes the output ID from the given mode and console output ID.
    fn new(_: Mode, output: Self::Primitive) -> Self {
        match output {
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::Constant(field) => Self::Constant(Field::new(Mode::Public, field)),
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::Public(field) => Self::Public(Field::new(Mode::Public, field)),
            // Inject the ciphertext hash as `Mode::Public`.
            console::OutputID::Private(field) => Self::Private(Field::new(Mode::Public, field)),
            // Inject the expected commitment and checksum as `Mode::Public`.
            console::OutputID::Record(commitment, checksum, sender_ciphertext) => Self::Record(
                Field::new(Mode::Public, commitment),
                Field::new(Mode::Public, checksum),
                Field::new(Mode::Public, sender_ciphertext),
            ),
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::ExternalRecord(hash) => Self::ExternalRecord(Field::new(Mode::Public, hash)),
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::Future(hash) => Self::Future(Field::new(Mode::Public, hash)),
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::DynamicRecord(hash) => Self::DynamicRecord(Field::new(Mode::Public, hash)),
            // Inject the expected hash as `Mode::Public`.
            console::OutputID::DynamicFuture(hash) => Self::DynamicFuture(Field::new(Mode::Public, hash)),
        }
    }
}

impl<A: Aleo> OutputID<A> {
    /// Initializes a constant output ID.
    fn constant(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("Constant output hash mismatch");
        // Return the output ID.
        Self::Constant(output_hash)
    }

    /// Initializes a public output ID.
    fn public(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("Public output hash mismatch");
        // Return the output ID.
        Self::Public(output_hash)
    }

    /// Initializes a private output ID.
    fn private(expected_hash: Field<A>) -> Self {
        // Inject the ciphertext hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("Private output hash mismatch");
        // Return the output ID.
        Self::Private(output_hash)
    }

    /// Initializes a record output ID.
    fn record(
        expected_commitment: Field<A>,
        expected_checksum: Field<A>,
        expected_sender_ciphertext: Field<A>,
    ) -> Self {
        // Inject the expected commitment, checksum, and sender ciphertext as `Mode::Public`.
        let output_commitment = Field::new(Mode::Public, expected_commitment.eject_value());
        let output_checksum = Field::new(Mode::Public, expected_checksum.eject_value());
        let output_sender_ciphertext = Field::new(Mode::Public, expected_sender_ciphertext.eject_value()); // Note: Set to `0field` here and in consensus to make optional or deactivated.
        // Ensure the injected commitment and checksum matches the given commitment and checksum.
        A::assert_eq(&output_commitment, expected_commitment).expect("Record output commitment mismatch");
        A::assert_eq(&output_checksum, expected_checksum).expect("Record output checksum mismatch");
        // Ensure the sender ciphertext matches, or the sender ciphertext is zero.
        // Note: The option to allow a zero-value in the sender ciphertext allows
        // this feature to become optional or deactivated in the future.
        let is_sender_ciphertext_equal = output_sender_ciphertext.is_equal(&expected_sender_ciphertext);
        let is_sender_ciphertext_zero = output_sender_ciphertext.is_zero();
        A::assert(is_sender_ciphertext_equal | is_sender_ciphertext_zero).expect("Record sender ciphertext mismatch");
        // Return the output ID.
        Self::Record(output_commitment, output_checksum, output_sender_ciphertext)
    }

    /// Initializes an external record output ID.
    fn external_record(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given commitment.
        A::assert_eq(&output_hash, expected_hash).expect("ExternalRecord output hash mismatch");
        // Return the output ID.
        Self::ExternalRecord(output_hash)
    }

    /// Initializes a future output ID.
    fn future(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("Future output hash mismatch");
        // Return the output ID.
        Self::Future(output_hash)
    }

    /// Initializes a dynamic record output ID.
    fn dynamic_record(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("DynamicRecord output hash mismatch");
        // Return the output ID.
        Self::DynamicRecord(output_hash)
    }

    /// Initializes a dynamic future output ID.
    fn dynamic_future(expected_hash: Field<A>) -> Self {
        // Inject the expected hash as `Mode::Public`.
        let output_hash = Field::new(Mode::Public, expected_hash.eject_value());
        // Ensure the injected hash matches the given hash.
        A::assert_eq(&output_hash, expected_hash).expect("DynamicFuture output hash mismatch");
        // Return the output ID.
        Self::DynamicFuture(output_hash)
    }
}

impl<A: Aleo> Eject for OutputID<A> {
    type Primitive = console::OutputID<A::Network>;

    /// Ejects the mode of the output ID.
    fn eject_mode(&self) -> Mode {
        match self {
            Self::Constant(field) => field.eject_mode(),
            Self::Public(field) => field.eject_mode(),
            Self::Private(field) => field.eject_mode(),
            Self::Record(commitment, checksum, sender_ciphertext) => {
                Mode::combine(commitment.eject_mode(), [checksum.eject_mode(), sender_ciphertext.eject_mode()])
            }
            Self::ExternalRecord(hash) => hash.eject_mode(),
            Self::Future(hash) => hash.eject_mode(),
            Self::DynamicRecord(hash) => hash.eject_mode(),
            Self::DynamicFuture(hash) => hash.eject_mode(),
        }
    }

    /// Ejects the output ID as a primitive.
    fn eject_value(&self) -> Self::Primitive {
        match self {
            Self::Constant(field) => console::OutputID::Constant(field.eject_value()),
            Self::Public(field) => console::OutputID::Public(field.eject_value()),
            Self::Private(field) => console::OutputID::Private(field.eject_value()),
            Self::Record(commitment, checksum, sender_ciphertext) => console::OutputID::Record(
                commitment.eject_value(),
                checksum.eject_value(),
                sender_ciphertext.eject_value(),
            ),
            Self::ExternalRecord(hash) => console::OutputID::ExternalRecord(hash.eject_value()),
            Self::Future(hash) => console::OutputID::Future(hash.eject_value()),
            Self::DynamicRecord(hash) => console::OutputID::DynamicRecord(hash.eject_value()),
            Self::DynamicFuture(hash) => console::OutputID::DynamicFuture(hash.eject_value()),
        }
    }
}

pub struct Response<A: Aleo> {
    /// The function output IDs.
    output_ids: Vec<OutputID<A>>,
    /// The function outputs.
    outputs: Vec<Value<A>>,
}

impl<A: Aleo> Response<A> {
    /// Returns the output IDs for the transition.
    pub fn output_ids(&self) -> &[OutputID<A>] {
        &self.output_ids
    }

    /// Returns the function outputs.
    pub fn outputs(&self) -> &[Value<A>] {
        &self.outputs
    }
}

impl<A: Aleo> Eject for Response<A> {
    type Primitive = console::Response<A::Network>;

    /// Ejects the mode of the response.
    fn eject_mode(&self) -> Mode {
        Mode::combine(self.output_ids.eject_mode(), [self.outputs.eject_mode()])
    }

    /// Ejects the response as a primitive.
    fn eject_value(&self) -> Self::Primitive {
        Self::Primitive::from((
            self.output_ids.iter().map(|output_id| output_id.eject_value()).collect(),
            self.outputs.eject_value(),
        ))
    }
}
