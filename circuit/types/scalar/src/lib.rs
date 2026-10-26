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

#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

extern crate snarkvm_console_types_scalar as console;

mod helpers;

pub mod add;
pub mod compare;
pub mod equal;
pub mod ternary;

#[cfg(test)]
use console::{TestRng, Uniform};
#[cfg(test)]
use snarkvm_circuit_environment::{assert_count, assert_output_mode, assert_scope, count, output_mode};

use snarkvm_circuit_environment::prelude::*;
use snarkvm_circuit_types_boolean::Boolean;
use snarkvm_circuit_types_field::Field;

use std::cell::OnceCell;

#[derive(Clone)]
pub struct Scalar<E: Environment> {
    /// The primary representation of the scalar element.
    field: Field<E>,
    /// An optional secondary representation in little-endian bits is provided,
    /// so that calls to `ToBits` only incur constraint costs once.
    bits_le: OnceCell<Vec<Boolean<E>>>,
}

impl<E: Environment> ScalarTrait for Scalar<E> {}

impl<E: Environment> Inject for Scalar<E> {
    type Primitive = console::Scalar<E::Network>;

    /// Initializes a scalar circuit from a console scalar.
    ///
    /// Note: The scalar is stored as a base field element, and is not range-checked on injection.
    /// Callers must convert the scalar to bits during synthesis, which enforces that it is less than
    /// the scalar field modulus. Otherwise, a prover can assign any base field element to it.
    fn new(mode: Mode, scalar: Self::Primitive) -> Self {
        debug_assert!(console::Scalar::<E::Network>::size_in_bits() < console::Field::<E::Network>::size_in_bits());

        // Initialize the scalar as a field element.
        match console::ToField::to_field(&scalar) {
            Ok(field) => Self { field: Field::new(mode, field), bits_le: OnceCell::new() },
            Err(error) => E::halt(format!("Unable to initialize a scalar circuit as a field element: {error}")),
        }
    }
}

impl<E: Environment> Eject for Scalar<E> {
    type Primitive = console::Scalar<E::Network>;

    /// Ejects the mode of the scalar.
    fn eject_mode(&self) -> Mode {
        self.field.eject_mode()
    }

    /// Ejects the scalar circuit as a console scalar.
    fn eject_value(&self) -> Self::Primitive {
        match console::Scalar::<E::Network>::from_bits_le(&self.field.eject_value().to_bits_le()) {
            Ok(scalar) => scalar,
            Err(error) => E::halt(format!("Failed to eject scalar value: {error}")),
        }
    }
}

impl<E: Environment> Parser for Scalar<E> {
    /// Parses a string into a scalar circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the scalar from the string.
        let (string, scalar) = console::Scalar::parse(string)?;
        // Parse the mode from the string.
        let (string, mode) = opt(pair(tag("."), Mode::parse))(string)?;

        match mode {
            Some((_, mode)) => Ok((string, Scalar::new(mode, scalar))),
            None => Ok((string, Scalar::new(Mode::Constant, scalar))),
        }
    }
}

impl<E: Environment> FromStr for Scalar<E> {
    type Err = Error;

    /// Parses a string into a scalar circuit.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<E: Environment> TypeName for Scalar<E> {
    /// Returns the type name of the circuit as a string.
    #[inline]
    fn type_name() -> &'static str {
        console::Scalar::<E::Network>::type_name()
    }
}

impl<E: Environment> Debug for Scalar<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for Scalar<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.eject_value(), self.eject_mode())
    }
}

impl<E: Environment> From<Scalar<E>> for LinearCombination<E::BaseField> {
    fn from(scalar: Scalar<E>) -> Self {
        From::from(&scalar)
    }
}

impl<E: Environment> From<&Scalar<E>> for LinearCombination<E::BaseField> {
    fn from(scalar: &Scalar<E>) -> Self {
        scalar.to_field().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    use core::str::FromStr;

    const ITERATIONS: u64 = 10;

    fn check_new(
        name: &str,
        expected: console::Scalar<<Circuit as Environment>::Network>,
        mode: Mode,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        Circuit::scope(name, || {
            let candidate = Scalar::<Circuit>::new(mode, expected);
            assert_eq!(expected, candidate.eject_value());
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });
    }

    /// Attempts to construct a field from the given element and mode,
    /// format it in display mode, and recover a field from it.
    fn check_display(mode: Mode, element: console::Scalar<<Circuit as Environment>::Network>) -> Result<()> {
        let candidate = Scalar::<Circuit>::new(mode, element);
        assert_eq!(format!("{element}.{mode}"), format!("{candidate}"));

        let candidate_recovered = Scalar::<Circuit>::from_str(&format!("{candidate}"))?;
        assert_eq!(candidate.eject_value(), candidate_recovered.eject_value());
        Ok(())
    }

    #[test]
    fn test_new_constant() {
        let expected = Uniform::rand(&mut TestRng::default());
        check_new("Constant", expected, Mode::Constant, 1, 0, 0, 0);
    }

    #[test]
    fn test_new_public() {
        let expected = Uniform::rand(&mut TestRng::default());
        check_new("Public", expected, Mode::Public, 0, 1, 0, 0);
    }

    #[test]
    fn test_new_private() {
        let expected = Uniform::rand(&mut TestRng::default());
        check_new("Private", expected, Mode::Private, 0, 0, 1, 0);
    }

    #[test]
    fn test_display() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let element = Uniform::rand(&mut rng);

            // Constant
            check_display(Mode::Constant, element)?;
            // Public
            check_display(Mode::Public, element)?;
            // Private
            check_display(Mode::Private, element)?;
        }
        Ok(())
    }

    #[test]
    fn test_display_zero() {
        let zero = console::Scalar::<<Circuit as Environment>::Network>::zero();

        // Constant
        let candidate = Scalar::<Circuit>::new(Mode::Constant, zero);
        assert_eq!("0scalar.constant", &format!("{candidate}"));

        // Public
        let candidate = Scalar::<Circuit>::new(Mode::Public, zero);
        assert_eq!("0scalar.public", &format!("{candidate}"));

        // Private
        let candidate = Scalar::<Circuit>::new(Mode::Private, zero);
        assert_eq!("0scalar.private", &format!("{candidate}"));
    }

    #[test]
    fn test_display_one() {
        let one = console::Scalar::<<Circuit as Environment>::Network>::one();

        // Constant
        let candidate = Scalar::<Circuit>::new(Mode::Constant, one);
        assert_eq!("1scalar.constant", &format!("{candidate}"));

        // Public
        let candidate = Scalar::<Circuit>::new(Mode::Public, one);
        assert_eq!("1scalar.public", &format!("{candidate}"));

        // Private
        let candidate = Scalar::<Circuit>::new(Mode::Private, one);
        assert_eq!("1scalar.private", &format!("{candidate}"));
    }

    #[test]
    fn test_display_two() {
        let one = console::Scalar::<<Circuit as Environment>::Network>::one();
        let two = one + one;

        // Constant
        let candidate = Scalar::<Circuit>::new(Mode::Constant, two);
        assert_eq!("2scalar.constant", &format!("{candidate}"));

        // Public
        let candidate = Scalar::<Circuit>::new(Mode::Public, two);
        assert_eq!("2scalar.public", &format!("{candidate}"));

        // Private
        let candidate = Scalar::<Circuit>::new(Mode::Private, two);
        assert_eq!("2scalar.private", &format!("{candidate}"));
    }

    #[test]
    fn test_parser() {
        type Primitive = console::Scalar<<Circuit as Environment>::Network>;

        // Constant

        let (_, candidate) = Scalar::<Circuit>::parse("5scalar").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Scalar::<Circuit>::parse("5_scalar").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Scalar::<Circuit>::parse("1_5_scalar").unwrap();
        assert_eq!(Primitive::from_str("15scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Scalar::<Circuit>::parse("5scalar.constant").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Scalar::<Circuit>::parse("5_scalar.constant").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Scalar::<Circuit>::parse("1_5_scalar.constant").unwrap();
        assert_eq!(Primitive::from_str("15scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        // Public

        let (_, candidate) = Scalar::<Circuit>::parse("5scalar.public").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        let (_, candidate) = Scalar::<Circuit>::parse("5_scalar.public").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        let (_, candidate) = Scalar::<Circuit>::parse("1_5_scalar.public").unwrap();
        assert_eq!(Primitive::from_str("15scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        // Private

        let (_, candidate) = Scalar::<Circuit>::parse("5scalar.private").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        let (_, candidate) = Scalar::<Circuit>::parse("5_scalar.private").unwrap();
        assert_eq!(Primitive::from_str("5scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        let (_, candidate) = Scalar::<Circuit>::parse("1_5_scalar.private").unwrap();
        assert_eq!(Primitive::from_str("15scalar").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        // Random

        let mut rng = TestRng::default();

        for mode in [Mode::Constant, Mode::Public, Mode::Private] {
            for _ in 0..ITERATIONS {
                let value = Uniform::rand(&mut rng);
                let expected = Scalar::<Circuit>::new(mode, value);

                let (_, candidate) = Scalar::<Circuit>::parse(&format!("{expected}")).unwrap();
                assert_eq!(expected.eject_value(), candidate.eject_value());
                assert_eq!(mode, candidate.eject_mode());
            }
        }
    }
}
