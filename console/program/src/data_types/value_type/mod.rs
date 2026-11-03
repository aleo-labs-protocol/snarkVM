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

use crate::{EntryType, Identifier, Locator, PlaintextType};
use snarkvm_console_network::prelude::*;

use enum_index::EnumIndex;

pub type Variant = u8;

#[derive(Clone, PartialEq, Eq, Hash, EnumIndex)]
pub enum ValueType<N: Network> {
    /// A constant type.
    Constant(PlaintextType<N>),
    /// A publicly-visible type.
    Public(PlaintextType<N>),
    /// A private type decrypted with the account owner's address.
    Private(PlaintextType<N>),
    /// A record type inherits its visibility from the record definition.
    Record(Identifier<N>),
    /// An external record type inherits its visibility from its record definition.
    ExternalRecord(Locator<N>),
    /// A publicly-visible future.
    Future(Locator<N>),
    /// A dynamic record.
    DynamicRecord,
    /// A dynamic future.
    DynamicFuture,
}

impl<N: Network> ValueType<N> {
    /// Returns the variant of the value type.
    pub const fn variant(&self) -> Variant {
        match self {
            ValueType::Constant(..) => 0,
            ValueType::Public(..) => 1,
            ValueType::Private(..) => 2,
            ValueType::Record(..) => 3,
            ValueType::ExternalRecord(..) => 4,
            ValueType::Future(..) => 5,
            ValueType::DynamicRecord => 6,
            ValueType::DynamicFuture => 7,
        }
    }

    /// Returns whether this type references an external struct.
    pub fn contains_external_struct(&self) -> bool {
        use ValueType::*;
        matches!(
            self,
            Constant(plaintext) | Public(plaintext) | Private(plaintext) if plaintext.contains_external_struct()
        )
    }
}

impl<N: Network> From<EntryType<N>> for ValueType<N> {
    fn from(entry: EntryType<N>) -> Self {
        match entry {
            EntryType::Constant(plaintext) => ValueType::Constant(plaintext),
            EntryType::Public(plaintext) => ValueType::Public(plaintext),
            EntryType::Private(private) => ValueType::Private(private),
        }
    }
}

impl<N: Network> ValueType<N> {
    /// Returns `true` if the value type contains a string type.
    /// Record, external record, and future types are checked elsewhere.
    pub fn contains_string_type(&self) -> bool {
        use ValueType::*;
        matches!(
            self,
            Constant(plaintext) | Public(plaintext) | Private(plaintext) if plaintext.contains_string_type()
        )
    }

    /// Returns `true` if the value type contains an identifier type.
    /// Record, external record, future, and dynamic types cannot contain identifier types.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Self::Constant(plaintext) | Self::Public(plaintext) | Self::Private(plaintext) => {
                plaintext.contains_identifier_type()
            }
            // Record, external record, future, and dynamic types cannot contain identifier types.
            Self::Record(_) | Self::ExternalRecord(_) | Self::Future(_) | Self::DynamicRecord | Self::DynamicFuture => {
                Ok(false)
            }
        }
    }

    /// Returns `true` if the value type is an array and the size exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        use ValueType::*;
        matches!(
            self,
            Constant(plaintext) | Public(plaintext) | Private(plaintext) if plaintext.exceeds_max_array_size(max_array_size)
        )
    }
}
