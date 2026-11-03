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

impl<N: Network> Literal<N> {
    /// Returns the variant of the literal.
    pub fn variant(&self) -> u8 {
        match self {
            Self::Address(..) => LiteralType::Address.type_id(),
            Self::Boolean(..) => LiteralType::Boolean.type_id(),
            Self::Field(..) => LiteralType::Field.type_id(),
            Self::Group(..) => LiteralType::Group.type_id(),
            Self::I8(..) => LiteralType::I8.type_id(),
            Self::I16(..) => LiteralType::I16.type_id(),
            Self::I32(..) => LiteralType::I32.type_id(),
            Self::I64(..) => LiteralType::I64.type_id(),
            Self::I128(..) => LiteralType::I128.type_id(),
            Self::U8(..) => LiteralType::U8.type_id(),
            Self::U16(..) => LiteralType::U16.type_id(),
            Self::U32(..) => LiteralType::U32.type_id(),
            Self::U64(..) => LiteralType::U64.type_id(),
            Self::U128(..) => LiteralType::U128.type_id(),
            Self::Scalar(..) => LiteralType::Scalar.type_id(),
            Self::Signature(..) => LiteralType::Signature.type_id(),
            Self::String(..) => LiteralType::String.type_id(),
            Self::Identifier(..) => LiteralType::Identifier.type_id(),
        }
    }
}
