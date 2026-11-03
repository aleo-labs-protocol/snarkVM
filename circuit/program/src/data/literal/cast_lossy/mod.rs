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

use crate::data::Literal;
use console::LiteralType;
use snarkvm_circuit_algorithms::Elligator2;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::prelude::{
    Address,
    Boolean,
    Environment,
    Field,
    FromBits,
    FromBoolean,
    FromGroup,
    Group,
    Inject,
    IntegerType,
    MSB,
    One,
    Result,
    Scalar,
    Ternary,
    ToBits,
    ToField,
    ToGroup,
    Zero,
    bail,
    integers::Integer,
};

#[cfg(test)]
use snarkvm_circuit_types::prelude::{I8, I16, I32, I64, I128, U8, U16, U32, U64, U128};

/// Unary operator for casting values of one type to another, with lossy truncation.
pub trait CastLossy<T: Sized = Self> {
    /// Casts the value of `self` into a value of type `T`, with lossy truncation.
    ///
    /// This method makes a *best-effort* attempt to preserve all bits of information,
    /// but it is not guaranteed to do so.
    fn cast_lossy(&self) -> T;
}

impl<A: Aleo> Literal<A> {
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
            Self::Address(address) => cast_lossy_group_to_type(&address.to_group(), to_type),
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
            Self::Signature(..) => bail!("Cannot cast (lossy) a signature literal to another type."),
            Self::String(..) => bail!("Cannot cast (lossy) a string literal to another type."),
            Self::Identifier(..) => bail!("Cannot cast (lossy) an identifier literal to another type."),
        }
    }
}

/// A helper macro to implement the body of the `cast_lossy` methods.
macro_rules! impl_cast_body {
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
fn cast_lossy_boolean_to_type<A: Aleo>(input: &Boolean<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(boolean, cast_lossy, input, to_type)
}

/// Casts a field literal to the given literal type, with lossy truncation.
fn cast_lossy_field_to_type<A: Aleo>(input: &Field<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(field, cast_lossy, input, to_type)
}

/// Casts a group literal to the given literal type, with lossy truncation.
fn cast_lossy_group_to_type<A: Aleo>(input: &Group<A>, to_type: LiteralType) -> Result<Literal<A>> {
    match to_type {
        LiteralType::Address => Ok(Literal::Address(Address::from_group(input.clone()))),
        LiteralType::Group => Ok(Literal::Group(input.clone())),
        _ => cast_lossy_field_to_type(&input.to_x_coordinate(), to_type),
    }
}

/// Casts an integer literal to the given literal type, with lossy truncation.
fn cast_lossy_integer_to_type<A: Aleo, I: IntegerType>(
    input: &Integer<A, I>,
    to_type: LiteralType,
) -> Result<Literal<A>> {
    impl_cast_body!(integer, cast_lossy, input, to_type)
}

/// Casts a scalar literal to the given literal type, with lossy truncation.
fn cast_lossy_scalar_to_type<A: Aleo>(input: &Scalar<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(scalar, cast_lossy, input, to_type)
}

#[cfg(test)]
macro_rules! check_cast_lossy {
    ($fun:ident, $circuit_type:ty, $console_type:ty) => {
        fn check_cast_lossy<CircuitType, ConsoleType>(mode: Mode, count: UpdatableCount)
        where
            CircuitType: Eject,
            <CircuitType as Eject>::Primitive: Debug + PartialEq<ConsoleType>,
            ConsoleType: Debug,
            $console_type: console::CastLossy<ConsoleType>,
            $circuit_type: crate::CastLossy<CircuitType>,
        {
            let rng = &mut TestRng::default();
            for i in 0..ITERATIONS {
                // Sample a random value.
                let (console_value, circuit_value) = sample_values(i, mode, rng);

                // Compute the expected result.
                let expected = console_value.$fun();

                // Run the test.
                Circuit::scope("test", || {
                    let result = circuit_value.$fun();
                    assert_eq!(result.eject_value(), expected);
                    assert!(Circuit::is_satisfied());
                    count.assert_matches(
                        Circuit::num_constants_in_scope(),
                        Circuit::num_public_in_scope(),
                        Circuit::num_private_in_scope(),
                        Circuit::num_constraints_in_scope(),
                    );
                });
                Circuit::reset();
            }
        }
    };
}
#[cfg(test)]
pub(super) use check_cast_lossy;
