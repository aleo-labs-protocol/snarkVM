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

mod boolean;
mod field;
mod integer;
mod scalar;

use crate::{Literal, LiteralType};
use snarkvm_console_algorithms::Elligator2;
use snarkvm_console_network::Network;
use snarkvm_console_types::{Boolean, integers::Integer, prelude::*};

/// Unary operator for casting values of one type to another, with lossy truncation.
pub trait CastLossy<T: Sized = Self> {
    /// Casts the value of `self` into a value of type `T`, with lossy truncation.
    ///
    /// This method makes a *best-effort* attempt to preserve all bits of information,
    /// but it is not guaranteed to do so.
    fn cast_lossy(&self) -> T;
}

impl<N: Network> Literal<N> {
    /// Casts the literal to the given literal type, with lossy truncation.
    ///
    /// This method makes a *best-effort* attempt to preserve all bits of information,
    /// but it is not guaranteed to do so.
    ///
    /// The hierarchy of casting is as follows:
    ///  - (`Address`, `Group`) <-> `Field` <-> `Scalar` <-> `Integer` <-> `Boolean`
    ///  - `Signature` (not supported)
    ///  - `String` (not supported)
    ///
    /// Note that casting to left along the hierarchy always preserves information.
    pub fn cast_lossy(&self, to_type: LiteralType) -> Result<Self> {
        match self {
            Self::Address(address) => cast_lossy_group_to_type(address.to_group(), to_type),
            Self::Boolean(boolean) => cast_lossy_boolean_to_type(boolean, to_type),
            Self::Field(field) => cast_lossy_field_to_type(field, to_type),
            Self::Group(group) => cast_lossy_group_to_type(group, to_type),
            Self::I8(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::I16(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::I32(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::I64(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::I128(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::U8(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::U16(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::U32(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::U64(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::U128(integer) => cast_lossy_integer_to_type(integer, to_type),
            Self::Scalar(scalar) => cast_lossy_scalar_to_type(scalar, to_type),
            Self::Signature(..) => bail!("Cannot cast a signature literal to another type."),
            Self::String(..) => bail!("Cannot cast a string literal to another type."),
            Self::Identifier(..) => bail!("Cannot cast an identifier literal to another type."),
        }
    }
}

/// A helper macro to implement the body of the `cast_lossy` methods.
macro_rules! impl_cast_lossy_body {
    ($type_name:ident, $cast_lossy:ident, $input:expr, $to_type:expr) => {
        match $to_type {
            LiteralType::Address => Ok(Literal::Address($input.$cast_lossy())),
            LiteralType::Boolean => Ok(Literal::Boolean($input.$cast_lossy())),
            LiteralType::Field => Ok(Literal::Field($input.$cast_lossy())),
            LiteralType::Group => Ok(Literal::Group($input.$cast_lossy())),
            LiteralType::I8 => Ok(Literal::I8($input.$cast_lossy())),
            LiteralType::I16 => Ok(Literal::I16($input.$cast_lossy())),
            LiteralType::I32 => Ok(Literal::I32($input.$cast_lossy())),
            LiteralType::I64 => Ok(Literal::I64($input.$cast_lossy())),
            LiteralType::I128 => Ok(Literal::I128($input.$cast_lossy())),
            LiteralType::U8 => Ok(Literal::U8($input.$cast_lossy())),
            LiteralType::U16 => Ok(Literal::U16($input.$cast_lossy())),
            LiteralType::U32 => Ok(Literal::U32($input.$cast_lossy())),
            LiteralType::U64 => Ok(Literal::U64($input.$cast_lossy())),
            LiteralType::U128 => Ok(Literal::U128($input.$cast_lossy())),
            LiteralType::Scalar => Ok(Literal::Scalar($input.$cast_lossy())),
            LiteralType::Signature => {
                bail!(concat!("Cannot cast (lossy) a ", stringify!($type_name), " literal to a signature type."))
            }
            LiteralType::String => {
                bail!(concat!("Cannot cast (lossy) a ", stringify!($type_name), " literal to a string type."))
            }
            LiteralType::Identifier => {
                bail!(concat!("Cannot cast (lossy) a ", stringify!($type_name), " literal to an identifier type."))
            }
        }
    };
}

/// Casts a boolean literal to the given literal type, with lossy truncation.
fn cast_lossy_boolean_to_type<N: Network>(input: &Boolean<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_lossy_body!(boolean, cast_lossy, input, to_type)
}

/// Casts a field literal to the given literal type, with lossy truncation.
fn cast_lossy_field_to_type<N: Network>(input: &Field<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_lossy_body!(field, cast_lossy, input, to_type)
}

/// Casts a group literal to the given literal type, with lossy truncation.
fn cast_lossy_group_to_type<N: Network>(input: &Group<N>, to_type: LiteralType) -> Result<Literal<N>> {
    match to_type {
        LiteralType::Address => Ok(Literal::Address(Address::new(*input))),
        LiteralType::Group => Ok(Literal::Group(*input)),
        _ => cast_lossy_field_to_type(&input.to_x_coordinate(), to_type),
    }
}

/// Casts an integer literal to the given literal type, with lossy truncation.
fn cast_lossy_integer_to_type<N: Network, I>(input: &Integer<N, I>, to_type: LiteralType) -> Result<Literal<N>>
where
    I: AsPrimitive<u8>
        + AsPrimitive<u16>
        + AsPrimitive<u32>
        + AsPrimitive<u64>
        + AsPrimitive<u128>
        + AsPrimitive<i8>
        + AsPrimitive<i16>
        + AsPrimitive<i32>
        + AsPrimitive<i64>
        + AsPrimitive<i128>
        + IntegerType,
{
    impl_cast_lossy_body!(integer, cast_lossy, input, to_type)
}

/// Casts a scalar literal to the given literal type, with lossy truncation.
fn cast_lossy_scalar_to_type<N: Network>(input: &Scalar<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_lossy_body!(scalar, cast_lossy, input, to_type)
}
