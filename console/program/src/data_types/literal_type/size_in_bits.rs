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

impl LiteralType {
    /// Returns the number of bits of this literal type.
    ///
    /// For string literals, this method returns the maximum number of bits that can be stored in the string.
    pub fn size_in_bits<N: Network>(&self) -> u16 {
        let size = match self {
            Self::Address => Address::<N>::size_in_bits(),
            Self::Boolean => Boolean::<N>::size_in_bits(),
            Self::Field => Field::<N>::size_in_bits(),
            Self::Group => Group::<N>::size_in_bits(),
            Self::I8 => I8::<N>::size_in_bits(),
            Self::I16 => I16::<N>::size_in_bits(),
            Self::I32 => I32::<N>::size_in_bits(),
            Self::I64 => I64::<N>::size_in_bits(),
            Self::I128 => I128::<N>::size_in_bits(),
            Self::U8 => U8::<N>::size_in_bits(),
            Self::U16 => U16::<N>::size_in_bits(),
            Self::U32 => U32::<N>::size_in_bits(),
            Self::U64 => U64::<N>::size_in_bits(),
            Self::U128 => U128::<N>::size_in_bits(),
            Self::Scalar => Scalar::<N>::size_in_bits(),
            Self::Signature => Signature::<N>::size_in_bits(),
            Self::String => N::MAX_STRING_BYTES.saturating_mul(8) as usize,
            Self::Identifier => IdentifierLiteral::<N>::size_in_bits(),
        };
        u16::try_from(size).or_halt_with::<N>("Literal exceeds u16::MAX bits.")
    }
}
