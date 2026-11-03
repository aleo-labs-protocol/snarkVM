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
mod equal;
mod find;
mod parse;
mod serialize;
mod to_bits;
mod to_bits_raw;
mod to_fields;
mod to_fields_raw;

use crate::{Access, Argument, DynamicFuture, DynamicRecord, Entry, Future, Literal, Plaintext, Record};
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

#[derive(Clone)]
pub enum Value<N: Network> {
    /// A plaintext value.
    Plaintext(Plaintext<N>),
    /// A record value.
    Record(Record<N, Plaintext<N>>),
    /// A future.
    Future(Future<N>),
    /// A dynamic record.
    DynamicRecord(DynamicRecord<N>),
    /// A dynamic future.
    DynamicFuture(DynamicFuture<N>),
}

impl<N: Network> From<Literal<N>> for Value<N> {
    /// Initializes the value from a literal.
    fn from(literal: Literal<N>) -> Self {
        Self::Plaintext(Plaintext::from(literal))
    }
}

impl<N: Network> From<&Literal<N>> for Value<N> {
    /// Initializes the value from a literal.
    fn from(literal: &Literal<N>) -> Self {
        Self::from(Plaintext::from(literal))
    }
}

impl<N: Network> From<Plaintext<N>> for Value<N> {
    /// Initializes the value from a plaintext.
    fn from(plaintext: Plaintext<N>) -> Self {
        Self::Plaintext(plaintext)
    }
}

impl<N: Network> From<&Plaintext<N>> for Value<N> {
    /// Initializes the value from a plaintext.
    fn from(plaintext: &Plaintext<N>) -> Self {
        Self::from(plaintext.clone())
    }
}

impl<N: Network> From<Record<N, Plaintext<N>>> for Value<N> {
    /// Initializes the value from a record.
    fn from(record: Record<N, Plaintext<N>>) -> Self {
        Self::Record(record)
    }
}

impl<N: Network> From<&Record<N, Plaintext<N>>> for Value<N> {
    /// Initializes the value from a record.
    fn from(record: &Record<N, Plaintext<N>>) -> Self {
        Self::from(record.clone())
    }
}

impl<N: Network> From<Future<N>> for Value<N> {
    /// Initializes the value from a future.
    fn from(future: Future<N>) -> Self {
        Self::Future(future)
    }
}

impl<N: Network> From<&Future<N>> for Value<N> {
    /// Initializes the value from a future.
    fn from(future: &Future<N>) -> Self {
        Self::from(future.clone())
    }
}

impl<N: Network> From<DynamicRecord<N>> for Value<N> {
    /// Initializes the value from a dynamic record.
    fn from(dynamic_record: DynamicRecord<N>) -> Self {
        Self::DynamicRecord(dynamic_record)
    }
}

impl<N: Network> From<&DynamicRecord<N>> for Value<N> {
    /// Initializes the value from a dynamic record.
    fn from(dynamic_record: &DynamicRecord<N>) -> Self {
        Self::from(dynamic_record.clone())
    }
}

impl<N: Network> From<DynamicFuture<N>> for Value<N> {
    /// Initializes the value from a dynamic future.
    fn from(dynamic_future: DynamicFuture<N>) -> Self {
        Self::DynamicFuture(dynamic_future)
    }
}

impl<N: Network> From<&DynamicFuture<N>> for Value<N> {
    /// Initializes the value from a dynamic future.
    fn from(dynamic_future: &DynamicFuture<N>) -> Self {
        Self::from(dynamic_future.clone())
    }
}

impl<N: Network> From<Argument<N>> for Value<N> {
    /// Initializes the value from an argument.
    fn from(argument: Argument<N>) -> Self {
        match argument {
            Argument::Plaintext(plaintext) => Self::Plaintext(plaintext),
            Argument::Future(future) => Self::Future(future),
            Argument::DynamicFuture(future) => Self::DynamicFuture(future),
        }
    }
}

impl<N: Network> From<&Argument<N>> for Value<N> {
    /// Initializes the value from an argument.
    fn from(argument: &Argument<N>) -> Self {
        Self::from(argument.clone())
    }
}

impl<N: Network> From<&Value<N>> for Value<N> {
    /// Returns a clone of the value.
    fn from(value: &Value<N>) -> Self {
        value.clone()
    }
}

impl<N: Network> TryFrom<Result<Value<N>>> for Value<N> {
    type Error = Error;

    /// Initializes a value from a result.
    fn try_from(value: Result<Value<N>>) -> Result<Self> {
        value
    }
}

impl<N: Network> TryFrom<String> for Value<N> {
    type Error = Error;

    /// Initializes a value from a string.
    fn try_from(value: String) -> Result<Self> {
        Self::from_str(&value)
    }
}

impl<N: Network> TryFrom<&String> for Value<N> {
    type Error = Error;

    /// Initializes a value from a string.
    fn try_from(value: &String) -> Result<Self> {
        Self::from_str(value)
    }
}

impl<N: Network> TryFrom<&str> for Value<N> {
    type Error = Error;

    /// Initializes a value from a string.
    fn try_from(value: &str) -> Result<Self> {
        Self::from_str(value)
    }
}
