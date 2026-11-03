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

impl<A: Aleo> ToFields for Literal<A> {
    type Field = Field<A>;

    /// Returns the literal as a list of base field elements.
    fn to_fields(&self) -> Vec<Field<A>> {
        (&self).to_fields()
    }
}

impl<A: Aleo> ToFields for &Literal<A> {
    type Field = Field<A>;

    /// Returns the literal as a list of base field elements.
    fn to_fields(&self) -> Vec<Self::Field> {
        match self {
            Literal::Address(literal) => vec![literal.to_field()],
            Literal::Boolean(literal) => vec![Field::from_boolean(literal)],
            Literal::Field(literal) => vec![literal.clone()],
            Literal::Group(literal) => vec![literal.to_x_coordinate()],
            Literal::I8(literal) => vec![literal.to_field()],
            Literal::I16(literal) => vec![literal.to_field()],
            Literal::I32(literal) => vec![literal.to_field()],
            Literal::I64(literal) => vec![literal.to_field()],
            Literal::I128(literal) => vec![literal.to_field()],
            Literal::U8(literal) => vec![literal.to_field()],
            Literal::U16(literal) => vec![literal.to_field()],
            Literal::U32(literal) => vec![literal.to_field()],
            Literal::U64(literal) => vec![literal.to_field()],
            Literal::U128(literal) => vec![literal.to_field()],
            Literal::Scalar(literal) => vec![literal.to_field()],
            Literal::Signature(literal) => literal.to_fields(),
            Literal::String(literal) => literal.to_fields(),
            Literal::Identifier(literal) => vec![literal.to_field()],
        }
    }
}
