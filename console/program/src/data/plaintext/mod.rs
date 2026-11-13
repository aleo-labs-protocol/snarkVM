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
mod encrypt;
mod equal;
mod find;
mod from_bits;
mod from_fields;
mod num_randomizers;
mod parse;
mod serialize;
mod size_in_fields;
mod ternary;
mod to_bits;
mod to_bits_raw;
mod to_fields;
mod to_fields_raw;

use crate::{Access, Ciphertext, Identifier, Literal, PlaintextType};
use snarkvm_console_network::Network;
use snarkvm_console_types::prelude::*;

use indexmap::IndexMap;
use std::{
    hash::{Hash, Hasher},
    sync::OnceLock,
};

#[derive(Clone)]
pub enum Plaintext<N: Network> {
    /// A literal.
    Literal(Literal<N>, OnceLock<Vec<bool>>),
    /// A struct.
    Struct(IndexMap<Identifier<N>, Plaintext<N>>, OnceLock<Vec<bool>>),
    /// An array.
    Array(Vec<Plaintext<N>>, OnceLock<Vec<bool>>),
}

impl<N: Network> Plaintext<N> {
    /// Returns a new `Plaintext::Array` from `Vec<bool>`, checking that the length is correct.
    pub fn from_bit_array(bits: Vec<bool>, length: u32) -> Result<Self> {
        ensure!(bits.len() == length as usize, "Expected '{length}' bits, got '{}' bits", bits.len());
        Ok(Self::Array(
            bits.into_iter().map(|bit| Plaintext::from(Literal::Boolean(Boolean::new(bit)))).collect(),
            OnceLock::new(),
        ))
    }

    /// Returns the `Plaintext` as a `Vec<bool>`, if it is a bit array.
    pub fn as_bit_array(&self) -> Result<Vec<bool>> {
        match self {
            Self::Array(elements, _) => {
                let mut bits = Vec::with_capacity(elements.len());
                for element in elements {
                    match element {
                        Self::Literal(Literal::Boolean(bit), _) => bits.push(**bit),
                        _ => bail!("Expected a bit array, found a non-boolean element."),
                    }
                }
                Ok(bits)
            }
            _ => bail!("Expected a bit array, found a non-array plaintext."),
        }
    }

    /// Returns the `Plaintext` as a `Vec<u8>`, if it is a u8 array.
    pub fn as_byte_array(&self) -> Result<Vec<u8>> {
        match self {
            Self::Array(elements, _) => {
                let mut bytes = Vec::with_capacity(elements.len());
                for element in elements {
                    match element {
                        Self::Literal(Literal::U8(byte), _) => bytes.push(**byte),
                        _ => bail!("Expected a u8 array, found a non-u8 element."),
                    }
                }
                Ok(bytes)
            }
            _ => bail!("Expected a u8 array, found a non-array plaintext."),
        }
    }

    /// Returns the `Plaintext` as a `Vec<N::Field>`, if it is a field array.
    pub fn as_field_array(&self) -> Result<Vec<Field<N>>> {
        match self {
            Self::Array(elements, _) => {
                let mut fields = Vec::with_capacity(elements.len());
                for element in elements {
                    match element {
                        Self::Literal(Literal::Field(field), _) => fields.push(*field),
                        _ => bail!("Expected an array of fields, found a non-field element."),
                    }
                }
                Ok(fields)
            }
            _ => bail!("Expected an array of fields, found a non-array plaintext."),
        }
    }
}

impl<N: Network> From<Literal<N>> for Plaintext<N> {
    /// Returns a new `Plaintext` from a `Literal`.
    fn from(literal: Literal<N>) -> Self {
        Self::Literal(literal, OnceLock::new())
    }
}

impl<N: Network> From<&Literal<N>> for Plaintext<N> {
    /// Returns a new `Plaintext` from a `&Literal`.
    fn from(literal: &Literal<N>) -> Self {
        Self::Literal(literal.clone(), OnceLock::new())
    }
}

impl<N: Network> Hash for Plaintext<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Literal(literal, _bits) => {
                literal.hash(state);
            }
            Self::Struct(fields, _bits) => {
                for (name, value) in fields {
                    name.hash(state);
                    value.hash(state);
                }
            }
            Self::Array(array, _bits) => {
                array.hash(state);
            }
        }
    }
}

// A macro that derives implementations of `From` for arrays of a plaintext literals of various sizes.
macro_rules! impl_plaintext_from_array {
    ($element:ident, $($size:literal),+) => {
        $(
            impl<N: Network> From<[$element<N>; $size]> for Plaintext<N> {
                fn from(value: [$element<N>; $size]) -> Self {
                    Self::Array(
                        value
                            .into_iter()
                            .map(|element| Plaintext::from(Literal::$element(element)))
                            .collect(),
                        OnceLock::new(),
                    )
                }
            }
        )+
    };
}

// Implement for `[U8<N>, SIZE]` for sizes 1 through 256.
seq_macro::seq!(S in 1..=256 {
    impl_plaintext_from_array!(U8, S);
});

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;
    use snarkvm_console_types::Field;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_plaintext() -> Result<()> {
        let run_test = |value: Plaintext<CurrentNetwork>| {
            assert_eq!(
                value.to_bits_le(),
                Plaintext::<CurrentNetwork>::from_bits_le(&value.to_bits_le()).unwrap().to_bits_le()
            );
            assert_eq!(value, Plaintext::<CurrentNetwork>::from_fields(&value.to_fields().unwrap()).unwrap());
            assert_eq!(value, Plaintext::<CurrentNetwork>::from_str(&value.to_string()).unwrap());
            assert!(*value.is_equal(&value));
            assert!(*!value.is_not_equal(&value));
        };

        let mut rng = TestRng::default();

        // Test booleans.
        run_test(Plaintext::<CurrentNetwork>::from_str("true")?);
        run_test(Plaintext::<CurrentNetwork>::from_str("false")?);

        // Test a random field element.
        run_test(Plaintext::<CurrentNetwork>::Literal(
            Literal::Field(Field::new(Uniform::rand(&mut rng))),
            OnceLock::new(),
        ));

        // Test a random struct with literal members.
        run_test(Plaintext::<CurrentNetwork>::Struct(
            IndexMap::from_iter(vec![
                (Identifier::from_str("a")?, Plaintext::<CurrentNetwork>::from_str("true")?),
                (
                    Identifier::from_str("b")?,
                    Plaintext::<CurrentNetwork>::Literal(
                        Literal::Field(Field::new(Uniform::rand(&mut rng))),
                        OnceLock::new(),
                    ),
                ),
            ]),
            OnceLock::new(),
        ));

        // Test a random struct with array members.
        run_test(Plaintext::<CurrentNetwork>::Struct(
            IndexMap::from_iter(vec![
                (Identifier::from_str("a")?, Plaintext::<CurrentNetwork>::from_str("true")?),
                (
                    Identifier::from_str("b")?,
                    Plaintext::<CurrentNetwork>::Array(
                        vec![
                            Plaintext::<CurrentNetwork>::from_str("true")?,
                            Plaintext::<CurrentNetwork>::from_str("false")?,
                        ],
                        OnceLock::new(),
                    ),
                ),
            ]),
            OnceLock::new(),
        ));

        // Test random deeply-nested struct.
        run_test(Plaintext::<CurrentNetwork>::Struct(
            IndexMap::from_iter(vec![
                (Identifier::from_str("a")?, Plaintext::<CurrentNetwork>::from_str("true")?),
                (
                    Identifier::from_str("b")?,
                    Plaintext::<CurrentNetwork>::Struct(
                        IndexMap::from_iter(vec![
                            (Identifier::from_str("c")?, Plaintext::<CurrentNetwork>::from_str("true")?),
                            (
                                Identifier::from_str("d")?,
                                Plaintext::<CurrentNetwork>::Struct(
                                    IndexMap::from_iter(vec![
                                        (Identifier::from_str("e")?, Plaintext::<CurrentNetwork>::from_str("true")?),
                                        (
                                            Identifier::from_str("f")?,
                                            Plaintext::<CurrentNetwork>::Literal(
                                                Literal::Field(Field::new(Uniform::rand(&mut rng))),
                                                OnceLock::new(),
                                            ),
                                        ),
                                    ]),
                                    OnceLock::new(),
                                ),
                            ),
                            (
                                Identifier::from_str("g")?,
                                Plaintext::Array(
                                    vec![
                                        Plaintext::<CurrentNetwork>::from_str("true")?,
                                        Plaintext::<CurrentNetwork>::from_str("false")?,
                                    ],
                                    OnceLock::new(),
                                ),
                            ),
                        ]),
                        OnceLock::new(),
                    ),
                ),
                (
                    Identifier::from_str("h")?,
                    Plaintext::<CurrentNetwork>::Literal(
                        Literal::Field(Field::new(Uniform::rand(&mut rng))),
                        OnceLock::new(),
                    ),
                ),
            ]),
            OnceLock::new(),
        ));

        // Test an array of literals.
        run_test(Plaintext::<CurrentNetwork>::Array(
            vec![
                Plaintext::<CurrentNetwork>::from_str("0field")?,
                Plaintext::<CurrentNetwork>::from_str("1field")?,
                Plaintext::<CurrentNetwork>::from_str("2field")?,
                Plaintext::<CurrentNetwork>::from_str("3field")?,
                Plaintext::<CurrentNetwork>::from_str("4field")?,
            ],
            OnceLock::new(),
        ));

        // Test an array of structs.
        run_test(Plaintext::<CurrentNetwork>::Array(
            vec![
                Plaintext::<CurrentNetwork>::from_str("{ x: 0field, y: 1field }")?,
                Plaintext::<CurrentNetwork>::from_str("{ x: 2field, y: 3field }")?,
                Plaintext::<CurrentNetwork>::from_str("{ x: 4field, y: 5field }")?,
                Plaintext::<CurrentNetwork>::from_str("{ x: 6field, y: 7field }")?,
                Plaintext::<CurrentNetwork>::from_str("{ x: 8field, y: 9field }")?,
            ],
            OnceLock::new(),
        ));

        // Test a non-uniform array.
        run_test(Plaintext::<CurrentNetwork>::Array(
            vec![
                Plaintext::<CurrentNetwork>::from_str("true")?,
                Plaintext::<CurrentNetwork>::from_str("1field")?,
                Plaintext::<CurrentNetwork>::from_str("{ x: 4field, y: 1u8 }")?,
            ],
            OnceLock::new(),
        ));

        Ok(())
    }
}
