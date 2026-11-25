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

use console::PlaintextType;

impl<A: Aleo> ToBits for Plaintext<A> {
    type Boolean = Boolean<A>;

    /// Returns this plaintext as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<Boolean<A>>) {
        match self {
            Self::Literal(literal, bits_le) => {
                // Compute the bits of the literal.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = Vec::new();
                    bits_le.extend(PlaintextType::<A::Network>::LITERAL_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    literal.variant().write_bits_le(&mut bits_le);
                    literal.size_in_bits().write_bits_le(&mut bits_le);
                    literal.write_bits_le(&mut bits_le);
                    bits_le.shrink_to_fit();
                    bits_le
                });
                // Extend the vector with the bits of the literal.
                vec.extend_from_slice(bits);
            }
            Self::Struct(members, bits_le) => {
                // Compute the bits of the struct.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = Vec::new();
                    bits_le.extend(PlaintextType::<A::Network>::STRUCT_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    let num_members = u8::try_from(members.len())
                        .unwrap_or_else(|_| A::halt("Plaintext struct length exceeds u8::MAX"));
                    U8::constant(console::U8::new(num_members)).write_bits_le(&mut bits_le);
                    for (identifier, value) in members {
                        let value_bits = value.to_bits_le();
                        identifier.size_in_bits().write_bits_le(&mut bits_le);
                        identifier.write_bits_le(&mut bits_le);
                        // Hazard: this cast wraps when the value exceeds `u16::MAX` bits, where the console
                        // counterpart halts. See https://github.com/aleo-labs-protocol/snarkVM/issues/3730.
                        #[allow(clippy::cast_possible_truncation)]
                        U16::constant(console::U16::new(value_bits.len() as u16)).write_bits_le(&mut bits_le);
                        bits_le.extend(value_bits);
                    }
                    bits_le.shrink_to_fit();
                    bits_le
                });
                // Extend the vector with the bits of the struct.
                vec.extend_from_slice(bits);
            }
            Self::Array(elements, bits_le) => {
                // Compute the bits of the array.
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = Vec::new();
                    bits_le.extend(PlaintextType::<A::Network>::ARRAY_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    let num_elements = u32::try_from(elements.len())
                        .unwrap_or_else(|_| A::halt("Plaintext array length exceeds u32::MAX"));
                    U32::constant(console::U32::new(num_elements)).write_bits_le(&mut bits_le);
                    for value in elements {
                        let value_bits = value.to_bits_le();
                        // Hazard: this cast wraps when the value exceeds `u16::MAX` bits, where the console
                        // counterpart halts. See https://github.com/aleo-labs-protocol/snarkVM/issues/3730.
                        #[allow(clippy::cast_possible_truncation)]
                        U16::constant(console::U16::new(value_bits.len() as u16)).write_bits_le(&mut bits_le);
                        bits_le.extend(value_bits);
                    }
                    bits_le.shrink_to_fit();
                    bits_le
                });
                // Extend the vector with the bits of the array.
                vec.extend_from_slice(bits);
            }
        }
    }

    /// Returns this plaintext as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<Boolean<A>>) {
        match self {
            Self::Literal(literal, bits_be) => {
                // Compute the bits of the literal.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = Vec::new();
                    bits_be.extend(PlaintextType::<A::Network>::LITERAL_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    literal.variant().write_bits_be(&mut bits_be);
                    literal.size_in_bits().write_bits_be(&mut bits_be);
                    literal.write_bits_be(&mut bits_be);
                    bits_be.shrink_to_fit();
                    bits_be
                });
                // Extend the vector with the bits of the literal.
                vec.extend_from_slice(bits);
            }
            Self::Struct(members, bits_be) => {
                // Compute the bits of the struct.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = Vec::new();
                    bits_be.extend(PlaintextType::<A::Network>::STRUCT_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    let num_members = u8::try_from(members.len())
                        .unwrap_or_else(|_| A::halt("Plaintext struct length exceeds u8::MAX"));
                    U8::constant(console::U8::new(num_members)).write_bits_be(&mut bits_be);
                    for (identifier, value) in members {
                        let value_bits = value.to_bits_be();
                        identifier.size_in_bits().write_bits_be(&mut bits_be);
                        identifier.write_bits_be(&mut bits_be);
                        // Hazard: this cast wraps when the value exceeds `u16::MAX` bits, where the console
                        // counterpart halts. See https://github.com/aleo-labs-protocol/snarkVM/issues/3730.
                        #[allow(clippy::cast_possible_truncation)]
                        U16::constant(console::U16::new(value_bits.len() as u16)).write_bits_be(&mut bits_be);
                        bits_be.extend(value_bits);
                    }
                    bits_be.shrink_to_fit();
                    bits_be
                });
                // Extend the vector with the bits of the struct.
                vec.extend_from_slice(bits)
            }
            Self::Array(elements, bits_be) => {
                // Compute the bits of the array.
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = Vec::new();
                    bits_be.extend(PlaintextType::<A::Network>::ARRAY_PREFIX_BITS.map(Boolean::constant)); // Variant bit.
                    let num_elements = u32::try_from(elements.len())
                        .unwrap_or_else(|_| A::halt("Plaintext array length exceeds u32::MAX"));
                    U32::constant(console::U32::new(num_elements)).write_bits_be(&mut bits_be);
                    for value in elements {
                        let value_bits = value.to_bits_be();
                        // Hazard: this cast wraps when the value exceeds `u16::MAX` bits, where the console
                        // counterpart halts. See https://github.com/aleo-labs-protocol/snarkVM/issues/3730.
                        #[allow(clippy::cast_possible_truncation)]
                        U16::constant(console::U16::new(value_bits.len() as u16)).write_bits_be(&mut bits_be);
                        bits_be.extend(value_bits);
                    }
                    bits_be.shrink_to_fit();
                    bits_be
                });
                // Extend the vector with the bits of the array.
                vec.extend_from_slice(bits)
            }
        }
    }
}
