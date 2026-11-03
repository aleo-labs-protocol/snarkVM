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

impl<A: Aleo> Literal<A> {
    /// Returns the number of bits of this literal.
    pub fn size_in_bits(&self) -> U16<A> {
        U16::constant(console::U16::new(match self {
            Self::Address(..) => console::Address::<A::Network>::size_in_bits() as u16,
            Self::Boolean(..) => console::Boolean::<A::Network>::size_in_bits() as u16,
            Self::Field(..) => console::Field::<A::Network>::size_in_bits() as u16,
            Self::Group(..) => console::Group::<A::Network>::size_in_bits() as u16,
            Self::I8(..) => console::I8::<A::Network>::size_in_bits() as u16,
            Self::I16(..) => console::I16::<A::Network>::size_in_bits() as u16,
            Self::I32(..) => console::I32::<A::Network>::size_in_bits() as u16,
            Self::I64(..) => console::I64::<A::Network>::size_in_bits() as u16,
            Self::I128(..) => console::I128::<A::Network>::size_in_bits() as u16,
            Self::U8(..) => console::U8::<A::Network>::size_in_bits() as u16,
            Self::U16(..) => console::U16::<A::Network>::size_in_bits() as u16,
            Self::U32(..) => console::U32::<A::Network>::size_in_bits() as u16,
            Self::U64(..) => console::U64::<A::Network>::size_in_bits() as u16,
            Self::U128(..) => console::U128::<A::Network>::size_in_bits() as u16,
            Self::Scalar(..) => console::Scalar::<A::Network>::size_in_bits() as u16,
            Self::Signature(..) => console::Signature::<A::Network>::size_in_bits() as u16,
            Self::String(string) => string.to_bits_le().len() as u16,
            Self::Identifier(..) => console::IdentifierLiteral::<A::Network>::size_in_bits() as u16,
        }))
    }
}
