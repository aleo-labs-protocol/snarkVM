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
mod identifier;
mod integer;
mod scalar;

use crate::{Literal, LiteralType};
use snarkvm_console_network::Network;
use snarkvm_console_types::{Boolean, integers::Integer, prelude::*};

/// Unary operator for casting values of one type to another.
pub trait Cast<T: Sized = Self> {
    /// Casts the value of `self` into a value of type `T`.
    ///
    /// This method checks that the cast does not lose any bits of information,
    /// and returns an error if it does.
    fn cast(&self) -> Result<T>;
}

impl<N: Network> Literal<N> {
    /// Casts the literal to the given literal type.
    ///
    /// This method checks that the cast does not lose any bits of information,
    /// and returns an error if it does.
    ///
    /// The hierarchy of casting is as follows:
    ///  - (`Address`, `Group`) <-> `Field` <-> `Scalar` <-> `Integer` <-> `Boolean`
    ///  - `Identifier` <-> `Field`
    ///  - `Signature` (not supported)
    ///  - `String` (not supported)
    ///
    /// Note that casting to left along the hierarchy always preserves information.
    pub fn cast(&self, to_type: LiteralType) -> Result<Self> {
        match self {
            Self::Address(address) => cast_group_to_type(address.to_group(), to_type),
            Self::Boolean(boolean) => cast_boolean_to_type(boolean, to_type),
            Self::Field(field) => cast_field_to_type(field, to_type),
            Self::Group(group) => cast_group_to_type(group, to_type),
            Self::I8(integer) => cast_integer_to_type(integer, to_type),
            Self::I16(integer) => cast_integer_to_type(integer, to_type),
            Self::I32(integer) => cast_integer_to_type(integer, to_type),
            Self::I64(integer) => cast_integer_to_type(integer, to_type),
            Self::I128(integer) => cast_integer_to_type(integer, to_type),
            Self::U8(integer) => cast_integer_to_type(integer, to_type),
            Self::U16(integer) => cast_integer_to_type(integer, to_type),
            Self::U32(integer) => cast_integer_to_type(integer, to_type),
            Self::U64(integer) => cast_integer_to_type(integer, to_type),
            Self::U128(integer) => cast_integer_to_type(integer, to_type),
            Self::Scalar(scalar) => cast_scalar_to_type(scalar, to_type),
            Self::Signature(..) => bail!("Cannot cast a signature literal to another type."),
            Self::String(..) => bail!("Cannot cast a string literal to another type."),
            Self::Identifier(identifier) => cast_identifier_literal_to_type(identifier, to_type),
        }
    }
}

/// A helper macro to implement the body of the `cast` methods.
macro_rules! impl_cast_body {
    ($type_name:ident, $cast:ident, $input:expr, $to_type:expr) => {
        match $to_type {
            LiteralType::Address => Ok(Literal::Address($input.$cast()?)),
            LiteralType::Boolean => Ok(Literal::Boolean($input.$cast()?)),
            LiteralType::Field => Ok(Literal::Field($input.$cast()?)),
            LiteralType::Group => Ok(Literal::Group($input.$cast()?)),
            LiteralType::I8 => Ok(Literal::I8($input.$cast()?)),
            LiteralType::I16 => Ok(Literal::I16($input.$cast()?)),
            LiteralType::I32 => Ok(Literal::I32($input.$cast()?)),
            LiteralType::I64 => Ok(Literal::I64($input.$cast()?)),
            LiteralType::I128 => Ok(Literal::I128($input.$cast()?)),
            LiteralType::U8 => Ok(Literal::U8($input.$cast()?)),
            LiteralType::U16 => Ok(Literal::U16($input.$cast()?)),
            LiteralType::U32 => Ok(Literal::U32($input.$cast()?)),
            LiteralType::U64 => Ok(Literal::U64($input.$cast()?)),
            LiteralType::U128 => Ok(Literal::U128($input.$cast()?)),
            LiteralType::Scalar => Ok(Literal::Scalar($input.$cast()?)),
            LiteralType::Signature => {
                bail!(concat!("Cannot cast a ", stringify!($type_name), " literal to a signature type."))
            }
            LiteralType::String => {
                bail!(concat!("Cannot cast a ", stringify!($type_name), " literal to a string type."))
            }
            LiteralType::Identifier => Ok(Literal::Identifier(Box::new($input.$cast()?))),
        }
    };
}

/// Casts a boolean literal to the given literal type.
fn cast_boolean_to_type<N: Network>(input: &Boolean<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_body!(boolean, cast, input, to_type)
}

/// Casts a field literal to the given literal type.
fn cast_field_to_type<N: Network>(input: &Field<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_body!(field, cast, input, to_type)
}

/// Casts a group literal to the given literal type.
fn cast_group_to_type<N: Network>(input: &Group<N>, to_type: LiteralType) -> Result<Literal<N>> {
    match to_type {
        LiteralType::Address => Ok(Literal::Address(Address::new(*input))),
        LiteralType::Group => Ok(Literal::Group(*input)),
        _ => cast_field_to_type(&input.to_x_coordinate(), to_type),
    }
}

/// Casts an integer literal to the given literal type.
fn cast_integer_to_type<N: Network, I: IntegerType>(
    input: &integers::Integer<N, I>,
    to_type: LiteralType,
) -> Result<Literal<N>>
where
    i8: TryFrom<I>,
    i16: TryFrom<I>,
    i32: TryFrom<I>,
    i64: TryFrom<I>,
    i128: TryFrom<I>,
    u8: TryFrom<I>,
    u16: TryFrom<I>,
    u32: TryFrom<I>,
    u64: TryFrom<I>,
    u128: TryFrom<I>,
{
    impl_cast_body!(integer, cast, input, to_type)
}

/// Casts a scalar literal to the given literal type.
fn cast_scalar_to_type<N: Network>(input: &Scalar<N>, to_type: LiteralType) -> Result<Literal<N>> {
    impl_cast_body!(scalar, cast, input, to_type)
}

/// Casts an identifier literal to the given literal type.
fn cast_identifier_literal_to_type<N: Network>(
    input: &IdentifierLiteral<N>,
    to_type: LiteralType,
) -> Result<Literal<N>> {
    impl_cast_body!(identifier, cast, input, to_type)
}
