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

impl<N: Network> ToBits for Literal<N> {
    /// Returns the little-endian bits of the literal.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        (&self).write_bits_le(vec);
    }

    /// Returns the big-endian bits of the literal.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        (&self).write_bits_be(vec);
    }
}

impl<N: Network> ToBits for &Literal<N> {
    /// Returns the little-endian bits of the literal.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        match self {
            Literal::Address(literal) => literal.write_bits_le(vec),
            Literal::Boolean(literal) => literal.write_bits_le(vec),
            Literal::Field(literal) => literal.write_bits_le(vec),
            Literal::Group(literal) => literal.write_bits_le(vec),
            Literal::I8(literal) => literal.write_bits_le(vec),
            Literal::I16(literal) => literal.write_bits_le(vec),
            Literal::I32(literal) => literal.write_bits_le(vec),
            Literal::I64(literal) => literal.write_bits_le(vec),
            Literal::I128(literal) => literal.write_bits_le(vec),
            Literal::U8(literal) => literal.write_bits_le(vec),
            Literal::U16(literal) => literal.write_bits_le(vec),
            Literal::U32(literal) => literal.write_bits_le(vec),
            Literal::U64(literal) => literal.write_bits_le(vec),
            Literal::U128(literal) => literal.write_bits_le(vec),
            Literal::Scalar(literal) => literal.write_bits_le(vec),
            Literal::Signature(literal) => literal.write_bits_le(vec),
            Literal::String(literal) => literal.as_bytes().write_bits_le(vec),
            Literal::Identifier(literal) => literal.write_bits_le(vec),
        }
    }

    /// Returns the big-endian bits of the literal.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Literal::Address(literal) => literal.write_bits_be(vec),
            Literal::Boolean(literal) => literal.write_bits_be(vec),
            Literal::Field(literal) => literal.write_bits_be(vec),
            Literal::Group(literal) => literal.write_bits_be(vec),
            Literal::I8(literal) => literal.write_bits_be(vec),
            Literal::I16(literal) => literal.write_bits_be(vec),
            Literal::I32(literal) => literal.write_bits_be(vec),
            Literal::I64(literal) => literal.write_bits_be(vec),
            Literal::I128(literal) => literal.write_bits_be(vec),
            Literal::U8(literal) => literal.write_bits_be(vec),
            Literal::U16(literal) => literal.write_bits_be(vec),
            Literal::U32(literal) => literal.write_bits_be(vec),
            Literal::U64(literal) => literal.write_bits_be(vec),
            Literal::U128(literal) => literal.write_bits_be(vec),
            Literal::Scalar(literal) => literal.write_bits_be(vec),
            Literal::Signature(literal) => literal.write_bits_be(vec),
            Literal::String(literal) => literal.as_bytes().write_bits_be(vec),
            Literal::Identifier(literal) => literal.write_bits_be(vec),
        }
    }
}
