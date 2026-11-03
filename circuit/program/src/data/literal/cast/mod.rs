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

use crate::data::{CastLossy, Literal};
use console::LiteralType;
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{
    IdentifierLiteral,
    prelude::{
        Address,
        BitOr,
        Boolean,
        Environment,
        Field,
        FromBits,
        FromField,
        FromGroup,
        Group,
        IntegerType,
        MSB,
        One,
        Result,
        Scalar,
        ToBits,
        ToField,
        ToGroup,
        Zero,
        bail,
        integers::Integer,
    },
};

#[cfg(test)]
use snarkvm_circuit_types::prelude::{I8, I16, I32, I64, I128, U8, U16, U32, U64, U128};

/// Unary operator for casting values of one type to another.
pub trait Cast<T: Sized = Self> {
    /// Casts the value of `self` into a value of type `T`.
    ///
    /// This method checks that the cast does not lose any bits of information.
    fn cast(&self) -> T;
}

impl<A: Aleo> Literal<A> {
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
            Self::Address(address) => cast_group_to_type(&address.to_group(), to_type),
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
            Self::Identifier(identifier) => cast_identifier_to_type(identifier, to_type),
        }
    }
}

/// A helper macro to implement the body of the `cast` methods.
macro_rules! impl_cast_body {
    ($type_name:ident, $cast:ident, $input:expr, $to_type:expr) => {
        match $to_type {
            LiteralType::Address => Ok(Literal::Address($input.$cast())),
            LiteralType::Boolean => Ok(Literal::Boolean($input.$cast())),
            LiteralType::Field => Ok(Literal::Field($input.$cast())),
            LiteralType::Group => Ok(Literal::Group($input.$cast())),
            LiteralType::I8 => Ok(Literal::I8($input.$cast())),
            LiteralType::I16 => Ok(Literal::I16($input.$cast())),
            LiteralType::I32 => Ok(Literal::I32($input.$cast())),
            LiteralType::I64 => Ok(Literal::I64($input.$cast())),
            LiteralType::I128 => Ok(Literal::I128($input.$cast())),
            LiteralType::U8 => Ok(Literal::U8($input.$cast())),
            LiteralType::U16 => Ok(Literal::U16($input.$cast())),
            LiteralType::U32 => Ok(Literal::U32($input.$cast())),
            LiteralType::U64 => Ok(Literal::U64($input.$cast())),
            LiteralType::U128 => Ok(Literal::U128($input.$cast())),
            LiteralType::Scalar => Ok(Literal::Scalar($input.$cast())),
            LiteralType::Signature => {
                bail!(concat!("Cannot cast a ", stringify!($type_name), " literal to a signature type."))
            }
            LiteralType::String => {
                bail!(concat!("Cannot cast a ", stringify!($type_name), " literal to a string type."))
            }
            LiteralType::Identifier => Ok(Literal::Identifier(Box::new($input.$cast()))),
        }
    };
}

/// Casts a boolean literal to the given literal type.
fn cast_boolean_to_type<A: Aleo>(input: &Boolean<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(boolean, cast, input, to_type)
}

/// Casts a field literal to the given literal type.
fn cast_field_to_type<A: Aleo>(input: &Field<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(field, cast, input, to_type)
}

/// Casts a group literal to the given literal type.
fn cast_group_to_type<A: Aleo>(input: &Group<A>, to_type: LiteralType) -> Result<Literal<A>> {
    match to_type {
        LiteralType::Address => Ok(Literal::Address(Address::from_group(input.clone()))),
        LiteralType::Group => Ok(Literal::Group(input.clone())),
        _ => cast_field_to_type(&input.to_x_coordinate(), to_type),
    }
}

/// Casts an integer literal to the given literal type.
fn cast_integer_to_type<A: Aleo, I: IntegerType>(input: &Integer<A, I>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(integer, cast, input, to_type)
}

/// Casts a scalar literal to the given literal type.
fn cast_scalar_to_type<A: Aleo>(input: &Scalar<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(scalar, cast, input, to_type)
}

/// Casts an identifier literal to the given literal type.
fn cast_identifier_to_type<A: Aleo>(input: &IdentifierLiteral<A>, to_type: LiteralType) -> Result<Literal<A>> {
    impl_cast_body!(identifier, cast, input, to_type)
}

#[cfg(test)]
macro_rules! impl_check_cast {
    ($fun:ident, $circuit_type:ty, $console_type:ty) => {
        fn check_cast<CircuitType, ConsoleType>(mode: Mode, count: UpdatableCount)
        where
            CircuitType: Eject,
            <CircuitType as Eject>::Primitive: Debug + PartialEq<ConsoleType>,
            ConsoleType: Debug,
            $console_type: console::Cast<ConsoleType>,
            $circuit_type: crate::Cast<CircuitType>,
        {
            let rng = &mut TestRng::default();
            for i in 0..ITERATIONS {
                let (console_value, circuit_value) = sample_values(i, mode, rng);
                match console_value.$fun() {
                    // If the console cast fails and the mode is constant, then the circuit cast should fail.
                    Err(_) if mode == Mode::Constant => {
                        assert!(
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| circuit_value.$fun())).is_err()
                        )
                    }
                    // If the console cast fails, the circuit cast can either fail by panicking or fail by being unsatisfied.
                    Err(_) => {
                        Circuit::scope("test", || {
                            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| circuit_value.$fun())).is_ok() {
                                assert!(!Circuit::is_satisfied());
                                count.assert_matches(
                                    Circuit::num_constants_in_scope(),
                                    Circuit::num_public_in_scope(),
                                    Circuit::num_private_in_scope(),
                                    Circuit::num_constraints_in_scope(),
                                );
                            }
                        });
                    }
                    // If the console cast succeeds, the circuit cast should succeed and the values should match.
                    Ok(expected) => Circuit::scope("test", || {
                        let result = circuit_value.$fun();
                        assert_eq!(result.eject_value(), expected);
                        assert!(Circuit::is_satisfied());
                        count.assert_matches(
                            Circuit::num_constants_in_scope(),
                            Circuit::num_public_in_scope(),
                            Circuit::num_private_in_scope(),
                            Circuit::num_constraints_in_scope(),
                        );
                    }),
                };
                Circuit::reset();
            }
        }
    };
}
#[cfg(test)]
pub(super) use impl_check_cast;
