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
    /// Returns the type name of the literal.
    pub fn to_type(&self) -> console::LiteralType {
        match self {
            Self::Address(..) => console::LiteralType::Address,
            Self::Boolean(..) => console::LiteralType::Boolean,
            Self::Field(..) => console::LiteralType::Field,
            Self::Group(..) => console::LiteralType::Group,
            Self::I8(..) => console::LiteralType::I8,
            Self::I16(..) => console::LiteralType::I16,
            Self::I32(..) => console::LiteralType::I32,
            Self::I64(..) => console::LiteralType::I64,
            Self::I128(..) => console::LiteralType::I128,
            Self::U8(..) => console::LiteralType::U8,
            Self::U16(..) => console::LiteralType::U16,
            Self::U32(..) => console::LiteralType::U32,
            Self::U64(..) => console::LiteralType::U64,
            Self::U128(..) => console::LiteralType::U128,
            Self::Scalar(..) => console::LiteralType::Scalar,
            Self::Signature(..) => console::LiteralType::Signature,
            Self::String(..) => console::LiteralType::String,
            Self::Identifier(..) => console::LiteralType::Identifier,
        }
    }
}
