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
mod parse;
mod serialize;
mod size_in_bits;

use crate::{FinalizeType, Identifier, Locator, PlaintextType, ProgramID, ValueType};
use snarkvm_console_network::prelude::*;

use enum_index::EnumIndex;

#[derive(Clone, PartialEq, Eq, Hash, EnumIndex)]
pub enum RegisterType<N: Network> {
    /// A plaintext type.
    Plaintext(PlaintextType<N>),
    /// A record name.
    Record(Identifier<N>),
    /// A record locator.
    ExternalRecord(Locator<N>),
    /// A future.
    Future(Locator<N>),
    /// A dynamic record.
    DynamicRecord,
    /// A dynamic future.
    DynamicFuture,
}

impl<N: Network> RegisterType<N> {
    // Make unqualified structs or records into external ones with the given `id`.
    pub fn qualify(self, id: ProgramID<N>) -> Self {
        match self {
            RegisterType::Plaintext(plaintext_type) => RegisterType::Plaintext(plaintext_type.qualify(id)),
            RegisterType::Record(name) => RegisterType::ExternalRecord(Locator::new(id, name)),
            RegisterType::ExternalRecord(..)
            | RegisterType::Future(..)
            | RegisterType::DynamicRecord
            | RegisterType::DynamicFuture => self,
        }
    }

    /// Returns whether this type refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        matches!(self, RegisterType::Plaintext(t) if t.contains_external_struct())
    }
}

impl<N: Network> From<ValueType<N>> for RegisterType<N> {
    /// Converts a value type to a register type.
    fn from(value: ValueType<N>) -> Self {
        match value {
            ValueType::Constant(plaintext_type)
            | ValueType::Public(plaintext_type)
            | ValueType::Private(plaintext_type) => Self::Plaintext(plaintext_type),
            ValueType::Record(record_name) => Self::Record(record_name),
            ValueType::ExternalRecord(locator) => Self::ExternalRecord(locator),
            ValueType::Future(locator) => Self::Future(locator),
            ValueType::DynamicRecord => Self::DynamicRecord,
            ValueType::DynamicFuture => Self::DynamicFuture,
        }
    }
}

impl<N: Network> From<&ValueType<N>> for RegisterType<N> {
    /// Converts a value type to a register type.
    fn from(value: &ValueType<N>) -> Self {
        value.clone().into()
    }
}

impl<N: Network> From<FinalizeType<N>> for RegisterType<N> {
    /// Converts a finalize type to a register type.
    fn from(finalize: FinalizeType<N>) -> Self {
        match finalize {
            FinalizeType::Plaintext(plaintext_type) => Self::Plaintext(plaintext_type),
            FinalizeType::Future(locator) => Self::Future(locator),
            FinalizeType::DynamicFuture => Self::DynamicFuture,
        }
    }
}

impl<N: Network> RegisterType<N> {
    /// Returns `true` if the register type contains a string type.
    pub fn contains_string_type(&self) -> bool {
        match self {
            Self::Plaintext(plaintext_type) => plaintext_type.contains_string_type(),
            _ => false, // Record, external record, and future types are checked elsewhere.
        }
    }

    /// Returns `true` if the register type contains an identifier type.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Self::Plaintext(plaintext_type) => plaintext_type.contains_identifier_type(),
            // Record, external record, future, and dynamic types cannot contain identifier types.
            Self::Record(_) | Self::ExternalRecord(_) | Self::Future(_) | Self::DynamicRecord | Self::DynamicFuture => {
                Ok(false)
            }
        }
    }

    /// Returns `true` if the register type is an array and the size exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        match self {
            Self::Plaintext(PlaintextType::Array(array_type)) => array_type.exceeds_max_array_size(max_array_size),
            _ => false,
        }
    }
}
