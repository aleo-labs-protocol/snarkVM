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

use super::*;

impl<N: Network> ToBits for Plaintext<N> {
    /// Returns this plaintext as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Literal(literal, bits_le) => {
                // Compute the bits.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = PlaintextType::<N>::LITERAL_PREFIX_BITS.to_vec(); // Variant bits.
                    literal.variant().write_bits_le(&mut bits_le);
                    literal.size_in_bits().write_bits_le(&mut bits_le);
                    literal.write_bits_le(&mut bits_le);
                    bits_le
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
            Self::Struct(struct_, bits_le) => {
                // Compute the bits.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = PlaintextType::<N>::STRUCT_PREFIX_BITS.to_vec(); // Variant bits.

                    // Write the length of the struct.
                    u8::try_from(struct_.len())
                        .or_halt_with::<N>("Plaintext struct length exceeds u8::MAX")
                        .write_bits_le(&mut bits_le);

                    // Write each member of the struct.
                    for (identifier, value) in struct_ {
                        // Write the identifier of the member.
                        identifier.size_in_bits().write_bits_le(&mut bits_le);
                        identifier.write_bits_le(&mut bits_le);

                        // Write the value of the member.
                        let value_bits = value.to_bits_le();
                        u16::try_from(value_bits.len())
                            .or_halt_with::<N>("Plaintext member exceeds u16::MAX bits")
                            .write_bits_le(&mut bits_le);
                        bits_le.extend_from_slice(&value_bits);
                    }
                    bits_le
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
            Self::Array(array, bits_le) => {
                // Compute the bits.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = PlaintextType::<N>::ARRAY_PREFIX_BITS.to_vec(); // Variant bits.

                    // Write the length of the array.
                    u32::try_from(array.len())
                        .or_halt_with::<N>("Plaintext array length exceeds u32::MAX")
                        .write_bits_le(&mut bits_le);

                    // Write each element of the array.
                    for element in array {
                        let element_bits = element.to_bits_le();

                        // Write the size of the element.
                        u16::try_from(element_bits.len())
                            .or_halt_with::<N>("Plaintext element exceeds u16::MAX bits")
                            .write_bits_le(&mut bits_le);

                        // Write the element.
                        bits_le.extend(element_bits);
                    }
                    bits_le
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
        }
    }

    /// Returns this plaintext as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Literal(literal, bits_be) => {
                // Compute the bits.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = PlaintextType::<N>::LITERAL_PREFIX_BITS.to_vec(); // Variant bits.
                    literal.variant().write_bits_be(&mut bits_be);
                    literal.size_in_bits().write_bits_be(&mut bits_be);
                    literal.write_bits_be(&mut bits_be);
                    bits_be
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
            Self::Struct(struct_, bits_be) => {
                // Compute the bits.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = PlaintextType::<N>::STRUCT_PREFIX_BITS.to_vec(); // Variant bits.

                    // Write the length of the struct.
                    u8::try_from(struct_.len())
                        .or_halt_with::<N>("Plaintext struct length exceeds u8::MAX")
                        .write_bits_be(&mut bits_be);

                    // Write each member of the struct.
                    for (identifier, value) in struct_ {
                        // Write the identifier of the member.
                        identifier.size_in_bits().write_bits_be(&mut bits_be);
                        identifier.write_bits_be(&mut bits_be);

                        // Write the value of the member.
                        let value_bits = value.to_bits_be();
                        u16::try_from(value_bits.len())
                            .or_halt_with::<N>("Plaintext member exceeds u16::MAX bits")
                            .write_bits_be(&mut bits_be);
                        bits_be.extend_from_slice(&value_bits);
                    }

                    bits_be
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
            Self::Array(array, bits_be) => {
                // Compute the bits.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = PlaintextType::<N>::ARRAY_PREFIX_BITS.to_vec(); // Variant bits.

                    // Write the length of the array.
                    u32::try_from(array.len())
                        .or_halt_with::<N>("Plaintext array length exceeds u32::MAX")
                        .write_bits_be(&mut bits_be);

                    // Write each element of the array.
                    for element in array {
                        let element_bits = element.to_bits_be();

                        // Write the size of the element.
                        u16::try_from(element_bits.len())
                            .or_halt_with::<N>("Plaintext element exceeds u16::MAX bits")
                            .write_bits_be(&mut bits_be);

                        // Write the element.
                        bits_be.extend(element_bits);
                    }
                    bits_be
                });
                // Extend the vector with the bits.
                vec.extend_from_slice(bits)
            }
        }
    }
}

impl<N: Network> Plaintext<N> {
    /// Returns the number of bits [`ToBits::write_bits_le`] writes for this plaintext.
    ///
    /// A literal stores its bit length in a `u16`. A struct member and an array element do too.
    /// A value whose bit length does not fit in that prefix is rejected.
    pub(crate) fn encoded_size_in_bits(&self) -> Result<usize> {
        /// Adds `more` bits to `size`.
        fn checked_bits(size: usize, more: usize) -> Result<usize> {
            size.checked_add(more).ok_or_else(|| anyhow!("Plaintext bit length overflowed"))
        }

        match self {
            Self::Literal(literal, _) => Ok(Self::literal_encoded_size_in_bits(literal)),
            Self::Struct(members, _) => {
                // Variant bits, then the member count.
                let mut size = checked_bits(PlaintextType::<N>::STRUCT_PREFIX_BITS.len(), 8)?;
                u8::try_from(members.len())
                    .map_err(|error| anyhow!("Plaintext struct length exceeds u8::MAX: {error}"))?;
                for (identifier, value) in members {
                    let value_bits = value.encoded_size_in_bits()?;
                    // The member's bit length is written as a `u16`.
                    u16::try_from(value_bits)
                        .map_err(|error| anyhow!("Plaintext member exceeds u16::MAX bits: {error}"))?;
                    // Identifier length, identifier, member length, member.
                    size = checked_bits(size, 8)?;
                    size = checked_bits(size, identifier.size_in_bits() as usize)?;
                    size = checked_bits(size, 16)?;
                    size = checked_bits(size, value_bits)?;
                }
                Ok(size)
            }
            Self::Array(elements, _) => {
                // Variant bits, then the element count.
                let mut size = checked_bits(PlaintextType::<N>::ARRAY_PREFIX_BITS.len(), 32)?;
                u32::try_from(elements.len())
                    .map_err(|error| anyhow!("Plaintext array length exceeds u32::MAX: {error}"))?;
                for element in elements {
                    let element_bits = element.encoded_size_in_bits()?;
                    // The element's bit length is written as a `u16`.
                    u16::try_from(element_bits)
                        .map_err(|error| anyhow!("Plaintext element exceeds u16::MAX bits: {error}"))?;
                    // Element length, then the element.
                    size = checked_bits(size, 16)?;
                    size = checked_bits(size, element_bits)?;
                }
                Ok(size)
            }
        }
    }

    /// Returns the number of bits [`ToBits::write_bits_le`] writes for a literal plaintext.
    fn literal_encoded_size_in_bits(literal: &Literal<N>) -> usize {
        // Variant bits, literal variant, literal length, literal value.
        PlaintextType::<N>::LITERAL_PREFIX_BITS.len() + 8 + 16 + literal.size_in_bits() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    fn assert_encoded_size(plaintext: &Plaintext<CurrentNetwork>) {
        assert_eq!(plaintext.encoded_size_in_bits().unwrap(), plaintext.to_bits_le().len());
    }

    #[test]
    fn test_encoded_size_in_bits_matches_write_bits_le() {
        let literal = Plaintext::<CurrentNetwork>::from(Literal::U64(U64::new(1)));
        assert_encoded_size(&literal);

        let mut members = IndexMap::new();
        members.insert(Identifier::from_str("amount").unwrap(), literal);
        let struct_ = Plaintext::<CurrentNetwork>::Struct(members, Default::default());
        assert_encoded_size(&struct_);

        let array = Plaintext::<CurrentNetwork>::Array(
            vec![Plaintext::from(Literal::U64(U64::new(1))), Plaintext::from(Literal::U64(U64::new(2)))],
            Default::default(),
        );
        assert_encoded_size(&array);

        let nested = Plaintext::<CurrentNetwork>::Array(vec![array], Default::default());
        assert_encoded_size(&nested);
    }
}
