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

use std::cell::OnceCell;

#[cfg(test)]
use snarkvm_circuit_types::environment::assert_scope;

mod encrypt;
mod equal;
mod find;
mod num_randomizers;
mod size_in_fields;
mod ternary;
mod to_bits;
mod to_bits_raw;
mod to_fields;
mod to_fields_raw;

use crate::{Access, Ciphertext, Identifier, Literal, Visibility};
use snarkvm_circuit_network::Aleo;
use snarkvm_circuit_types::{Address, Boolean, Field, Scalar, U8, U16, U32, environment::prelude::*};

#[derive(Clone)]
pub enum Plaintext<A: Aleo> {
    /// A plaintext literal.
    Literal(Literal<A>, OnceCell<Vec<Boolean<A>>>),
    /// A plaintext struct.
    Struct(IndexMap<Identifier<A>, Plaintext<A>>, OnceCell<Vec<Boolean<A>>>),
    /// A plaintext array.
    Array(Vec<Plaintext<A>>, OnceCell<Vec<Boolean<A>>>),
}

impl<A: Aleo> Plaintext<A> {
    /// Returns a new `Plaintext::Array` from `Vec<Boolean<A>>`, checking that the length is correct.
    pub fn from_bit_array(bits: Vec<Boolean<A>>, length: u32) -> Result<Self> {
        ensure!(bits.len() == length as usize, "Expected '{length}' bits, got '{}' bits", bits.len());
        Ok(Self::Array(bits.into_iter().map(|bit| Plaintext::from(Literal::Boolean(bit))).collect(), OnceCell::new()))
    }

    /// Returns the `Plaintext` as a `Vec<Boolean<A>>`, if it is a bit array.
    pub fn as_bit_array(&self) -> Result<Vec<Boolean<A>>> {
        match self {
            Self::Array(elements, _) => {
                let mut bits = Vec::with_capacity(elements.len());
                for element in elements {
                    match element {
                        Self::Literal(Literal::Boolean(bit), _) => bits.push(bit.clone()),
                        _ => bail!("Expected a bit array, found a non-boolean element."),
                    }
                }
                Ok(bits)
            }
            _ => bail!("Expected a bit array, found a non-array plaintext."),
        }
    }
}

impl<A: Aleo> Inject for Plaintext<A> {
    type Primitive = console::Plaintext<A::Network>;

    /// Initializes a new plaintext circuit from a primitive.
    fn new(mode: Mode, plaintext: Self::Primitive) -> Self {
        match plaintext {
            Self::Primitive::Literal(literal, _) => Self::Literal(Literal::new(mode, literal), Default::default()),
            Self::Primitive::Struct(struct_, _) => Self::Struct(
                struct_
                    .into_iter()
                    .map(|(identifier, member)| (Identifier::constant(identifier), Inject::new(mode, member)))
                    .collect(),
                Default::default(),
            ),
            Self::Primitive::Array(array, _) => Self::Array(Inject::new(mode, array), Default::default()),
        }
    }
}

impl<A: Aleo> Eject for Plaintext<A> {
    type Primitive = console::Plaintext<A::Network>;

    /// Ejects the mode of the plaintext value.
    fn eject_mode(&self) -> Mode {
        match self {
            Self::Literal(literal, _) => literal.eject_mode(),
            Self::Struct(struct_, _) => struct_
                .iter()
                .map(|(identifier, value)| (identifier, value).eject_mode())
                .collect::<Vec<_>>()
                .eject_mode(),
            Self::Array(array, _) => array.iter().map(Eject::eject_mode).collect::<Vec<_>>().eject_mode(),
        }
    }

    /// Ejects the plaintext value.
    fn eject_value(&self) -> Self::Primitive {
        match self {
            Self::Literal(literal, _) => console::Plaintext::Literal(literal.eject_value(), Default::default()),
            Self::Struct(struct_, _) => {
                console::Plaintext::Struct(struct_.iter().map(|pair| pair.eject_value()).collect(), Default::default())
            }
            Self::Array(array, _) => {
                console::Plaintext::Array(array.iter().map(Eject::eject_value).collect(), Default::default())
            }
        }
    }
}

impl<A: Aleo> From<Literal<A>> for Plaintext<A> {
    /// Returns a new `Plaintext` from a `Literal`.
    fn from(literal: Literal<A>) -> Self {
        Self::Literal(literal, OnceCell::new())
    }
}

impl<A: Aleo> From<&Literal<A>> for Plaintext<A> {
    /// Returns a new `Plaintext` from a `Literal`.
    fn from(literal: &Literal<A>) -> Self {
        Self::Literal((*literal).clone(), OnceCell::new())
    }
}

// A macro that derives implementations of `From` for arrays of a plaintext literals of various sizes.
macro_rules! impl_plaintext_from_array {
    ($element:ident, $($size:literal),+) => {
        $(
            impl<A: Aleo> From<[$element<A>; $size]> for Plaintext<A> {
                fn from(value: [$element<A>; $size]) -> Self {
                    Self::Array(
                        value
                            .into_iter()
                            .map(|element| Plaintext::from(Literal::$element(element)))
                            .collect(),
                        OnceCell::new(),
                    )
                }
            }
        )+
    };
}

// Implement for `[U8<N>, SIZE]` for sizes 1 through 32.
impl_plaintext_from_array!(
    U8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use console::ToFields as _;
    use snarkvm_utilities::{TestRng, Uniform};

    use anyhow::Result;

    #[test]
    fn test_plaintext() -> Result<()> {
        let run_test = |value: Plaintext<Circuit>| {
            assert_eq!(value.to_bits_le().eject_value(), value.eject_value().to_bits_le());
            // Safe: each sampled test plaintext is within the maximum data size in fields.
            assert_eq!(value.to_fields().eject_value(), value.eject_value().to_fields().unwrap());
            assert!(value.is_equal(&value).eject_value());
            assert!(!value.is_not_equal(&value).eject_value());
        };

        let mut rng = TestRng::default();

        // Test booleans.
        run_test(Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, true)), OnceCell::new()));
        run_test(Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, false)), OnceCell::new()));

        // Test a random field element.
        run_test(Plaintext::<Circuit>::Literal(
            Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
            OnceCell::new(),
        ));

        // Test a random struct with literal members.
        run_test(Plaintext::<Circuit>::Struct(
            IndexMap::from_iter(vec![
                (
                    Identifier::constant("a".try_into()?),
                    Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, true)), OnceCell::new()),
                ),
                (
                    Identifier::constant("b".try_into()?),
                    Plaintext::<Circuit>::Literal(
                        Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                        OnceCell::new(),
                    ),
                ),
            ]),
            OnceCell::new(),
        ));

        // Test a random struct with array members.
        run_test(Plaintext::<Circuit>::Struct(
            IndexMap::from_iter(vec![
                (
                    Identifier::constant("a".try_into()?),
                    Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, true)), OnceCell::new()),
                ),
                (
                    Identifier::constant("b".try_into()?),
                    Plaintext::<Circuit>::Array(
                        vec![
                            Plaintext::<Circuit>::Literal(
                                Literal::Boolean(Boolean::new(Mode::Private, true)),
                                OnceCell::new(),
                            ),
                            Plaintext::<Circuit>::Literal(
                                Literal::Boolean(Boolean::new(Mode::Private, false)),
                                OnceCell::new(),
                            ),
                        ],
                        OnceCell::new(),
                    ),
                ),
            ]),
            OnceCell::new(),
        ));

        // Test random deeply-nested struct.
        run_test(Plaintext::<Circuit>::Struct(
            IndexMap::from_iter(vec![
                (
                    Identifier::constant("a".try_into()?),
                    Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, true)), OnceCell::new()),
                ),
                (
                    Identifier::constant("b".try_into()?),
                    Plaintext::<Circuit>::Struct(
                        IndexMap::from_iter(vec![
                            (
                                Identifier::constant("c".try_into()?),
                                Plaintext::<Circuit>::Literal(
                                    Literal::Boolean(Boolean::new(Mode::Private, true)),
                                    OnceCell::new(),
                                ),
                            ),
                            (
                                Identifier::constant("d".try_into()?),
                                Plaintext::<Circuit>::Struct(
                                    IndexMap::from_iter(vec![
                                        (
                                            Identifier::constant("e".try_into()?),
                                            Plaintext::<Circuit>::Literal(
                                                Literal::Boolean(Boolean::new(Mode::Private, true)),
                                                OnceCell::new(),
                                            ),
                                        ),
                                        (
                                            Identifier::constant("f".try_into()?),
                                            Plaintext::<Circuit>::Literal(
                                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                                OnceCell::new(),
                                            ),
                                        ),
                                    ]),
                                    OnceCell::new(),
                                ),
                            ),
                            (
                                Identifier::constant("g".try_into()?),
                                Plaintext::<Circuit>::Array(
                                    vec![
                                        Plaintext::<Circuit>::Literal(
                                            Literal::Boolean(Boolean::new(Mode::Private, true)),
                                            OnceCell::new(),
                                        ),
                                        Plaintext::<Circuit>::Literal(
                                            Literal::Boolean(Boolean::new(Mode::Private, false)),
                                            OnceCell::new(),
                                        ),
                                    ],
                                    OnceCell::new(),
                                ),
                            ),
                        ]),
                        OnceCell::new(),
                    ),
                ),
                (
                    Identifier::constant("h".try_into()?),
                    Plaintext::<Circuit>::Literal(
                        Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                        OnceCell::new(),
                    ),
                ),
            ]),
            OnceCell::new(),
        ));

        // Test an array of literals.
        run_test(Plaintext::<Circuit>::Array(
            vec![
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
            ],
            OnceCell::new(),
        ));

        // Test an array of structs.
        run_test(Plaintext::<Circuit>::Array(
            vec![
                Plaintext::<Circuit>::Struct(
                    IndexMap::from_iter(vec![
                        (
                            Identifier::constant("x".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                        (
                            Identifier::constant("y".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                    ]),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Struct(
                    IndexMap::from_iter(vec![
                        (
                            Identifier::constant("x".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                        (
                            Identifier::constant("y".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                    ]),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Struct(
                    IndexMap::from_iter(vec![
                        (
                            Identifier::constant("x".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                        (
                            Identifier::constant("y".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                    ]),
                    OnceCell::new(),
                ),
            ],
            OnceCell::new(),
        ));

        // Test a non-uniform array.
        run_test(Plaintext::<Circuit>::Array(
            vec![
                Plaintext::<Circuit>::Literal(Literal::Boolean(Boolean::new(Mode::Private, true)), OnceCell::new()),
                Plaintext::<Circuit>::Literal(
                    Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                    OnceCell::new(),
                ),
                Plaintext::<Circuit>::Struct(
                    IndexMap::from_iter(vec![
                        (
                            Identifier::constant("x".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                        (
                            Identifier::constant("y".try_into()?),
                            Plaintext::<Circuit>::Literal(
                                Literal::Field(Field::new(Mode::Private, Uniform::rand(&mut rng))),
                                OnceCell::new(),
                            ),
                        ),
                    ]),
                    OnceCell::new(),
                ),
            ],
            OnceCell::new(),
        ));

        Ok(())
    }
}
