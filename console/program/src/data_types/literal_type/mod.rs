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
mod size_in_bytes;

use snarkvm_console_account::Signature;
use snarkvm_console_network::prelude::*;
use snarkvm_console_types::{Boolean, prelude::*};

use core::fmt::{self, Debug, Display};
use enum_iterator::Sequence;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(Copy, Clone, PartialEq, Eq, Hash, FromPrimitive, Sequence)]
pub enum LiteralType {
    /// The Aleo address type.
    Address,
    /// The boolean type.
    Boolean,
    /// The field type (base field).
    Field,
    /// The group type (affine).
    Group,
    /// The 8-bit signed integer type.
    I8,
    /// The 16-bit signed integer type.
    I16,
    /// The 32-bit signed integer type.
    I32,
    /// The 64-bit signed integer type.
    I64,
    /// The 128-bit signed integer type.
    I128,
    /// The 8-bit unsigned integer type.
    U8,
    /// The 16-bit unsigned integer type.
    U16,
    /// The 32-bit unsigned integer type.
    U32,
    /// The 64-bit unsigned integer type.
    U64,
    /// The 128-bit unsigned integer type.
    U128,
    /// The scalar type (scalar field).
    Scalar,
    /// The signature type.
    Signature,
    /// The string type.
    String,
    /// The identifier literal type.
    Identifier,
}

impl LiteralType {
    /// Returns the literal type name.
    pub const fn type_name(&self) -> &str {
        match self {
            Self::Address => "address",
            Self::Boolean => "boolean",
            Self::Field => "field",
            Self::Group => "group",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::I128 => "i128",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Scalar => "scalar",
            Self::Signature => "signature",
            Self::String => "string",
            Self::Identifier => "identifier",
        }
    }

    /// Returns the unique numeric identifier for the literal type.
    pub fn type_id(&self) -> u8 {
        *self as u8
    }
}
