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
    /// Returns the variant of the literal.
    pub fn variant(&self) -> U8<A> {
        U8::constant(match self {
            Self::Address(..) => console::U8::new(0),
            Self::Boolean(..) => console::U8::new(1),
            Self::Field(..) => console::U8::new(2),
            Self::Group(..) => console::U8::new(3),
            Self::I8(..) => console::U8::new(4),
            Self::I16(..) => console::U8::new(5),
            Self::I32(..) => console::U8::new(6),
            Self::I64(..) => console::U8::new(7),
            Self::I128(..) => console::U8::new(8),
            Self::U8(..) => console::U8::new(9),
            Self::U16(..) => console::U8::new(10),
            Self::U32(..) => console::U8::new(11),
            Self::U64(..) => console::U8::new(12),
            Self::U128(..) => console::U8::new(13),
            Self::Scalar(..) => console::U8::new(14),
            Self::Signature(..) => console::U8::new(15),
            Self::String(..) => console::U8::new(16),
            Self::Identifier(..) => console::U8::new(17),
        })
    }
}
