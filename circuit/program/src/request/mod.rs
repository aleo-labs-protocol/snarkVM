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

mod to_tpk;
mod verify;

use crate::{Identifier, Plaintext, ProgramID, Record, Value, compute_function_id};
use snarkvm_circuit_account::Signature;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Boolean, Field, Group, U16, environment::prelude::*};

pub enum InputID<A: Aleo> {
    /// The hash of the constant input.
    Constant(Field<A>),
    /// The hash of the public input.
    Public(Field<A>),
    /// The ciphertext hash of the private input.
    Private(Field<A>),
    /// The `(commitment, gamma, record_view_key, serial_number, tag)` tuple of the record input.
    Record(Field<A>, Box<Group<A>>, Field<A>, Field<A>, Field<A>),
    /// The hash of the external record's (function_id, record, tvk, input index).
    ExternalRecord(Field<A>),
    /// The hash of a dynamic record's (function_id, record, tvk, input index).
    DynamicRecord(Field<A>),
}

impl<A: Aleo> Inject for InputID<A> {
    type Primitive = console::InputID<A::Network>;

    /// Initializes the input ID from the given mode and console input ID.
    fn new(_: Mode, input: Self::Primitive) -> Self {
        match input {
            // Inject the expected hash as `Mode::Public`.
            console::InputID::Constant(field) => Self::Constant(Field::new(Mode::Public, field)),
            // Inject the expected hash as `Mode::Public`.
            console::InputID::Public(field) => Self::Public(Field::new(Mode::Public, field)),
            // Inject the ciphertext hash as `Mode::Public`.
            console::InputID::Private(field) => Self::Private(Field::new(Mode::Public, field)),
            // Inject commitment, gamma, and record view key as `Mode::Private`, and the expected serial number and tag as `Mode::Public`.
            console::InputID::Record(commitment, gamma, record_view_key, serial_number, tag) => Self::Record(
                Field::new(Mode::Private, commitment),
                Box::new(Group::new(Mode::Private, gamma)),
                Field::new(Mode::Private, record_view_key),
                Field::new(Mode::Public, serial_number),
                Field::new(Mode::Public, tag),
            ),
            // Inject the commitment of the external record as `Mode::Public`.
            console::InputID::ExternalRecord(field) => Self::ExternalRecord(Field::new(Mode::Public, field)),
            // Inject the commitment of the dynamic record as `Mode::Public`.
            console::InputID::DynamicRecord(field) => Self::DynamicRecord(Field::new(Mode::Public, field)),
        }
    }
}

impl<A: Aleo> Eject for InputID<A> {
    type Primitive = console::InputID<A::Network>;

    /// Ejects the mode of the input ID.
    fn eject_mode(&self) -> Mode {
        match self {
            Self::Constant(field) => field.eject_mode(),
            Self::Public(field) => field.eject_mode(),
            Self::Private(field) => field.eject_mode(),
            Self::Record(commitment, gamma, record_view_key, serial_number, tag) => {
                Mode::combine(commitment.eject_mode(), [
                    gamma.eject_mode(),
                    record_view_key.eject_mode(),
                    serial_number.eject_mode(),
                    tag.eject_mode(),
                ])
            }
            Self::ExternalRecord(field) => field.eject_mode(),
            Self::DynamicRecord(field) => field.eject_mode(),
        }
    }

    /// Ejects the input ID as a primitive.
    fn eject_value(&self) -> Self::Primitive {
        match self {
            Self::Constant(field) => console::InputID::Constant(field.eject_value()),
            Self::Public(field) => console::InputID::Public(field.eject_value()),
            Self::Private(field) => console::InputID::Private(field.eject_value()),
            Self::Record(commitment, gamma, record_view_key, serial_number, tag) => console::InputID::Record(
                commitment.eject_value(),
                gamma.eject_value(),
                record_view_key.eject_value(),
                serial_number.eject_value(),
                tag.eject_value(),
            ),
            Self::ExternalRecord(field) => console::InputID::ExternalRecord(field.eject_value()),
            Self::DynamicRecord(field) => console::InputID::DynamicRecord(field.eject_value()),
        }
    }
}

impl<A: Aleo> ToFields for InputID<A> {
    type Field = Field<A>;

    /// Returns the input as a list of field elements.
    fn to_fields(&self) -> Vec<Self::Field> {
        match self {
            InputID::Constant(field) => vec![field.clone()],
            InputID::Public(field) => vec![field.clone()],
            InputID::Private(field) => vec![field.clone()],
            InputID::Record(commitment, gamma, record_view_key, serial_number, tag) => {
                vec![
                    commitment.clone(),
                    gamma.to_x_coordinate(),
                    record_view_key.clone(),
                    serial_number.clone(),
                    tag.clone(),
                ]
            }
            InputID::ExternalRecord(field) => vec![field.clone()],
            InputID::DynamicRecord(field) => vec![field.clone()],
        }
    }
}

pub struct Request<A: Aleo> {
    /// The request signer.
    signer: Address<A>,
    /// The network ID.
    network_id: U16<A>,
    /// The program ID.
    program_id: ProgramID<A>,
    /// The function name.
    function_name: Identifier<A>,
    /// The function input IDs.
    input_ids: Vec<InputID<A>>,
    /// The function inputs.
    inputs: Vec<Value<A>>,
    /// The signature for the transition.
    signature: Signature<A>,
    /// The tag secret key.
    sk_tag: Field<A>,
    /// The transition view key.
    tvk: Field<A>,
    /// The transition commitment.
    tcm: Field<A>,
    /// The signer commitment.
    scm: Field<A>,
    /// A flag indicating whether or not the request is dynamic.
    is_dynamic: bool,
}

impl<A: Aleo> Inject for Request<A> {
    type Primitive = console::Request<A::Network>;

    /// Initializes the request from the given mode and console request.
    fn new(mode: Mode, request: Self::Primitive) -> Self {
        // Inject the transition commitment `tcm` as `Mode::Public`.
        let tcm = Field::new(Mode::Public, *request.tcm());

        // Inject the signer commitment `scm` as `Mode::Public`.
        let scm = Field::new(Mode::Public, *request.scm());

        // Inject the inputs.
        let inputs = match request
            .input_ids()
            .iter()
            .zip_eq(request.inputs())
            .map(|(input_id, input)| {
                match input_id {
                    // A constant input is injected as `Mode::Constant`.
                    console::InputID::Constant(..) => {
                        // Inject the input as `Mode::Constant`.
                        let input = Value::new(Mode::Constant, input.clone());
                        // Ensure the input is a plaintext.
                        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");
                        // Return the input.
                        Ok(input)
                    }
                    // A public input is injected as `Mode::Private`.
                    console::InputID::Public(..) => {
                        // Inject the input as `Mode::Private`.
                        let input = Value::new(Mode::Private, input.clone());
                        // Ensure the input is a plaintext.
                        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");
                        // Return the input.
                        Ok(input)
                    }
                    // A private input is injected as `Mode::Private`.
                    console::InputID::Private(..) => {
                        // Inject the input as `Mode::Private`.
                        let input = Value::new(Mode::Private, input.clone());
                        // Ensure the input is a plaintext.
                        ensure!(matches!(input, Value::Plaintext(..)), "Expected a plaintext input");
                        // Return the input.
                        Ok(input)
                    }
                    // A record input is injected as `Mode::Private`.
                    console::InputID::Record(..) => {
                        // Inject the input as `Mode::Private`.
                        let input = Value::new(Mode::Private, input.clone());
                        // Ensure the input is a record.
                        ensure!(matches!(input, Value::Record(..)), "Expected a record input");
                        // Return the input.
                        Ok(input)
                    }
                    // An external record input is injected as `Mode::Private`.
                    console::InputID::ExternalRecord(..) => {
                        // Inject the input as `Mode::Private`.
                        let input = Value::new(Mode::Private, input.clone());
                        // Ensure the input is a record.
                        ensure!(matches!(input, Value::Record(..)), "Expected an external record input");
                        // Return the input.
                        Ok(input)
                    }
                    // A dynamic record input is injected as `Mode::Private`.
                    console::InputID::DynamicRecord(..) => {
                        // Inject the input as `Mode::Private`.
                        let input = Value::new(Mode::Private, input.clone());
                        // Ensure the input is a dynamic record.
                        ensure!(matches!(input, Value::DynamicRecord(..)), "Expected a dynamic record input");
                        // Return the input.
                        Ok(input)
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(inputs) => inputs,
            Err(error) => A::halt(format!("{error}")),
        };

        Self {
            signer: Address::new(mode, *request.signer()),
            network_id: U16::new(Mode::Constant, *request.network_id()),
            program_id: ProgramID::constant(*request.program_id()),
            function_name: Identifier::constant(*request.function_name()),
            input_ids: request.input_ids().iter().map(|input_id| InputID::new(Mode::Public, *input_id)).collect(),
            inputs,
            signature: Signature::new(mode, *request.signature()),
            sk_tag: Field::new(mode, *request.sk_tag()),
            tvk: Field::new(mode, *request.tvk()),
            tcm,
            scm,
            is_dynamic: request.is_dynamic(),
        }
    }
}

impl<A: Aleo> Request<A> {
    /// Returns the request signer.
    pub const fn signer(&self) -> &Address<A> {
        &self.signer
    }

    /// Returns the network ID.
    pub const fn network_id(&self) -> &U16<A> {
        &self.network_id
    }

    /// Returns the program ID.
    pub const fn program_id(&self) -> &ProgramID<A> {
        &self.program_id
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Identifier<A> {
        &self.function_name
    }

    /// Returns the input IDs for the transition.
    pub fn input_ids(&self) -> &[InputID<A>] {
        &self.input_ids
    }

    /// Returns the function inputs.
    pub fn inputs(&self) -> &[Value<A>] {
        &self.inputs
    }

    /// Returns the signature for the transition.
    pub const fn signature(&self) -> &Signature<A> {
        &self.signature
    }

    /// Returns the tag secret key.
    pub const fn sk_tag(&self) -> &Field<A> {
        &self.sk_tag
    }

    /// Returns the transition view key.
    pub const fn tvk(&self) -> &Field<A> {
        &self.tvk
    }

    /// Returns the transition commitment.
    pub const fn tcm(&self) -> &Field<A> {
        &self.tcm
    }

    /// Returns the signer commitment.
    pub const fn scm(&self) -> &Field<A> {
        &self.scm
    }

    /// Returns whether or not the request is dynamic.
    pub fn is_dynamic(&self) -> bool {
        self.is_dynamic
    }
}

impl<A: Aleo> Eject for Request<A> {
    type Primitive = console::Request<A::Network>;

    /// Ejects the mode of the request.
    fn eject_mode(&self) -> Mode {
        Mode::combine(self.signer.eject_mode(), [
            self.network_id.eject_mode(),
            self.program_id.eject_mode(),
            self.function_name.eject_mode(),
            self.input_ids.eject_mode(),
            self.inputs.eject_mode(),
            self.signature.eject_mode(),
            self.sk_tag.eject_mode(),
            self.tvk.eject_mode(),
            self.tcm.eject_mode(),
            self.scm.eject_mode(),
        ])
    }

    /// Ejects the request as a primitive.
    fn eject_value(&self) -> Self::Primitive {
        Self::Primitive::from((
            self.signer.eject_value(),
            self.network_id.eject_value(),
            self.program_id.eject_value(),
            self.function_name.eject_value(),
            self.input_ids.iter().map(|input_id| input_id.eject_value()).collect(),
            self.inputs.eject_value(),
            self.signature.eject_value(),
            self.sk_tag.eject_value(),
            self.tvk.eject_value(),
            self.tcm.eject_value(),
            self.scm.eject_value(),
            self.is_dynamic,
        ))
    }
}
