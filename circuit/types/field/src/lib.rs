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

extern crate snarkvm_console_types_field as console;

mod helpers;

pub mod add;
pub mod compare;
pub mod div;
pub mod div_unchecked;
pub mod double;
pub mod equal;
pub mod inverse;
pub mod mul;
pub mod neg;
pub mod pow;
pub mod square;
pub mod square_root;
pub mod sub;
pub mod ternary;

#[cfg(test)]
use console::{TestRng, Uniform};
#[cfg(test)]
use snarkvm_circuit_environment::{assert_count, assert_output_mode, assert_scope, count, output_mode};

use snarkvm_circuit_environment::prelude::*;
use snarkvm_circuit_types_boolean::Boolean;

use std::cell::OnceCell;

#[derive(Clone)]
pub struct Field<E: Environment> {
    /// The linear combination contains the primary representation of the field.
    linear_combination: LinearCombination<E::BaseField>,
    /// An optional secondary representation in little-endian bits is provided,
    /// so that calls to `ToBits` only incur constraint costs once.
    bits_le: OnceCell<Vec<Boolean<E>>>,
}

impl<E: Environment> FieldTrait for Field<E> {}

impl<E: Environment> Default for Field<E> {
    /// Returns the default field element.
    fn default() -> Self {
        Self::zero()
    }
}

impl<E: Environment> Inject for Field<E> {
    type Primitive = console::Field<E::Network>;

    /// Initializes a field circuit from a console field.
    fn new(mode: Mode, field: Self::Primitive) -> Self {
        Self { linear_combination: E::new_variable(mode, *field).into(), bits_le: Default::default() }
    }
}

impl<E: Environment> Eject for Field<E> {
    type Primitive = console::Field<E::Network>;

    /// Ejects the mode of the field circuit.
    fn eject_mode(&self) -> Mode {
        self.linear_combination.mode()
    }

    /// Ejects the field circuit as a console field.
    fn eject_value(&self) -> Self::Primitive {
        console::Field::new(self.linear_combination.value())
    }
}

impl<E: Environment> Parser for Field<E> {
    /// Parses a string into a field circuit.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the field from the string.
        let (string, field) = console::Field::parse(string)?;
        // Parse the mode from the string.
        let (string, mode) = opt(pair(tag("."), Mode::parse))(string)?;

        match mode {
            Some((_, mode)) => Ok((string, Field::new(mode, field))),
            None => Ok((string, Field::new(Mode::Constant, field))),
        }
    }
}

impl<E: Environment> FromStr for Field<E> {
    type Err = Error;

    /// Parses a string into a field circuit.
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

impl<E: Environment> TypeName for Field<E> {
    /// Returns the type name of the circuit as a string.
    #[inline]
    fn type_name() -> &'static str {
        console::Field::<E::Network>::type_name()
    }
}

impl<E: Environment> Debug for Field<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for Field<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.eject_value(), self.eject_mode())
    }
}

impl<E: Environment> From<LinearCombination<E::BaseField>> for Field<E> {
    fn from(linear_combination: LinearCombination<E::BaseField>) -> Self {
        Self { linear_combination, bits_le: Default::default() }
    }
}

impl<E: Environment> From<&LinearCombination<E::BaseField>> for Field<E> {
    fn from(linear_combination: &LinearCombination<E::BaseField>) -> Self {
        From::from(linear_combination.clone())
    }
}

impl<E: Environment> From<Field<E>> for LinearCombination<E::BaseField> {
    fn from(field: Field<E>) -> Self {
        From::from(&field)
    }
}

impl<E: Environment> From<&Field<E>> for LinearCombination<E::BaseField> {
    fn from(field: &Field<E>) -> Self {
        field.linear_combination.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuit_environment::Circuit;

    const ITERATIONS: u64 = 10;

    /// Attempts to construct a field from the given element and mode,
    /// format it in display mode, and recover a field from it.
    fn check_display(mode: Mode, element: console::Field<<Circuit as Environment>::Network>) -> Result<()> {
        let candidate = Field::<Circuit>::new(mode, element);
        assert_eq!(format!("{element}.{mode}"), format!("{candidate}"));

        let candidate_recovered = Field::<Circuit>::from_str(&format!("{candidate}"))?;
        assert_eq!(candidate.eject_value(), candidate_recovered.eject_value());
        Ok(())
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
        let zero = console::Field::<<Circuit as Environment>::Network>::zero();

        // Constant
        let candidate = Field::<Circuit>::new(Mode::Constant, zero);
        assert_eq!("0field.constant", &format!("{candidate}"));

        // Public
        let candidate = Field::<Circuit>::new(Mode::Public, zero);
        assert_eq!("0field.public", &format!("{candidate}"));

        // Private
        let candidate = Field::<Circuit>::new(Mode::Private, zero);
        assert_eq!("0field.private", &format!("{candidate}"));
    }

    #[test]
    fn test_display_one() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();

        // Constant
        let candidate = Field::<Circuit>::new(Mode::Constant, one);
        assert_eq!("1field.constant", &format!("{candidate}"));

        // Public
        let candidate = Field::<Circuit>::new(Mode::Public, one);
        assert_eq!("1field.public", &format!("{candidate}"));

        // Private
        let candidate = Field::<Circuit>::new(Mode::Private, one);
        assert_eq!("1field.private", &format!("{candidate}"));
    }

    #[test]
    fn test_display_two() {
        let one = console::Field::<<Circuit as Environment>::Network>::one();
        let two = one + one;

        // Constant
        let candidate = Field::<Circuit>::new(Mode::Constant, two);
        assert_eq!("2field.constant", &format!("{candidate}"));

        // Public
        let candidate = Field::<Circuit>::new(Mode::Public, two);
        assert_eq!("2field.public", &format!("{candidate}"));

        // Private
        let candidate = Field::<Circuit>::new(Mode::Private, two);
        assert_eq!("2field.private", &format!("{candidate}"));
    }

    #[test]
    fn test_parser() {
        type Primitive = console::Field<<Circuit as Environment>::Network>;

        // Constant

        let (_, candidate) = Field::<Circuit>::parse("5field").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Field::<Circuit>::parse("5_field").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Field::<Circuit>::parse("1_5_field").unwrap();
        assert_eq!(Primitive::from_str("15field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Field::<Circuit>::parse("5field.constant").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Field::<Circuit>::parse("5_field.constant").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        let (_, candidate) = Field::<Circuit>::parse("1_5_field.constant").unwrap();
        assert_eq!(Primitive::from_str("15field").unwrap(), candidate.eject_value());
        assert!(candidate.is_constant());

        // Public

        let (_, candidate) = Field::<Circuit>::parse("5field.public").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        let (_, candidate) = Field::<Circuit>::parse("5_field.public").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        let (_, candidate) = Field::<Circuit>::parse("1_5_field.public").unwrap();
        assert_eq!(Primitive::from_str("15field").unwrap(), candidate.eject_value());
        assert!(candidate.is_public());

        // Private

        let (_, candidate) = Field::<Circuit>::parse("5field.private").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        let (_, candidate) = Field::<Circuit>::parse("5_field.private").unwrap();
        assert_eq!(Primitive::from_str("5field").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        let (_, candidate) = Field::<Circuit>::parse("1_5_field.private").unwrap();
        assert_eq!(Primitive::from_str("15field").unwrap(), candidate.eject_value());
        assert!(candidate.is_private());

        // Random

        let mut rng = TestRng::default();

        for mode in [Mode::Constant, Mode::Public, Mode::Private] {
            for _ in 0..ITERATIONS {
                let value = Uniform::rand(&mut rng);
                let expected = Field::<Circuit>::new(mode, value);

                let (_, candidate) = Field::<Circuit>::parse(&format!("{expected}")).unwrap();
                assert_eq!(expected.eject_value(), candidate.eject_value());
                assert_eq!(mode, candidate.eject_mode());
            }
        }
    }
}
