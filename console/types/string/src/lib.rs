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

#![cfg_attr(test, allow(clippy::assertions_on_result_states))]
#![warn(clippy::cast_possible_truncation)]

pub mod identifier_literal;
pub use identifier_literal::{IdentifierLiteral, SIZE_IN_BITS, SIZE_IN_BYTES};

mod bitwise;
mod bytes;
mod parse;
mod random;
mod serialize;

pub use snarkvm_console_network_environment::prelude::*;
pub use snarkvm_console_types_boolean::Boolean;
pub use snarkvm_console_types_field::Field;
pub use snarkvm_console_types_integers::Integer;

use core::marker::PhantomData;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StringType<E: Environment> {
    /// The underlying string.
    string: String,
    /// PhantomData
    _phantom: PhantomData<E>,
}

impl<E: Environment> StringTrait for StringType<E> {}

impl<E: Environment> StringType<E> {
    /// Initializes a new string.
    pub fn new(string: &str) -> Self {
        // Ensure the string is within the allowed capacity.
        let num_bytes = string.len();
        match num_bytes <= E::MAX_STRING_BYTES as usize {
            true => Self { string: string.to_string(), _phantom: PhantomData },
            false => E::halt(format!("Attempted to allocate a string of size {num_bytes}")),
        }
    }
}

impl<E: Environment> TypeName for StringType<E> {
    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "string"
    }
}

impl<E: Environment> Deref for StringType<E> {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.string.as_str()
    }
}
