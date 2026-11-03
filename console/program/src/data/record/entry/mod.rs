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
mod num_randomizers;
mod parse;
mod to_bits;
mod to_fields;

use crate::{Access, Ciphertext, Identifier, Literal, Plaintext};
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

use indexmap::IndexMap;

/// An entry stored in program data.
#[derive(Clone)]
pub enum Entry<N: Network, Private: Visibility> {
    /// A constant entry.
    Constant(Plaintext<N>),
    /// A publicly-visible entry.
    Public(Plaintext<N>),
    /// A private entry encrypted under the address of the record owner.
    Private(Private),
}

impl<N: Network, Private: Visibility> Entry<N, Private> {
    /// Returns the variant of the entry.
    pub fn variant(&self) -> u8 {
        match self {
            Self::Constant(_) => 0,
            Self::Public(_) => 1,
            Self::Private(_) => 2,
        }
    }
}
