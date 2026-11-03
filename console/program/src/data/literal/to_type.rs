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
    /// Returns the type name of the literal.
    pub fn to_type(&self) -> LiteralType {
        match self {
            Self::Address(..) => LiteralType::Address,
            Self::Boolean(..) => LiteralType::Boolean,
            Self::Field(..) => LiteralType::Field,
            Self::Group(..) => LiteralType::Group,
            Self::I8(..) => LiteralType::I8,
            Self::I16(..) => LiteralType::I16,
            Self::I32(..) => LiteralType::I32,
            Self::I64(..) => LiteralType::I64,
            Self::I128(..) => LiteralType::I128,
            Self::U8(..) => LiteralType::U8,
            Self::U16(..) => LiteralType::U16,
            Self::U32(..) => LiteralType::U32,
            Self::U64(..) => LiteralType::U64,
            Self::U128(..) => LiteralType::U128,
            Self::Scalar(..) => LiteralType::Scalar,
            Self::Signature(..) => LiteralType::Signature,
            Self::String(..) => LiteralType::String,
            Self::Identifier(..) => LiteralType::Identifier,
        }
    }
}
