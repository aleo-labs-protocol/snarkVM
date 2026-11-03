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
    /// Returns a randomly-sampled literal of the given literal type.
    pub fn sample<R: Rng + CryptoRng>(literal_type: LiteralType, rng: &mut R) -> Self {
        match literal_type {
            LiteralType::Address => Literal::Address(Address::rand(rng)),
            LiteralType::Boolean => Literal::Boolean(Boolean::rand(rng)),
            LiteralType::Field => Literal::Field(Field::rand(rng)),
            LiteralType::Group => Literal::Group(Group::rand(rng)),
            LiteralType::I8 => Literal::I8(I8::rand(rng)),
            LiteralType::I16 => Literal::I16(I16::rand(rng)),
            LiteralType::I32 => Literal::I32(I32::rand(rng)),
            LiteralType::I64 => Literal::I64(I64::rand(rng)),
            LiteralType::I128 => Literal::I128(I128::rand(rng)),
            LiteralType::U8 => Literal::U8(U8::rand(rng)),
            LiteralType::U16 => Literal::U16(U16::rand(rng)),
            LiteralType::U32 => Literal::U32(U32::rand(rng)),
            LiteralType::U64 => Literal::U64(U64::rand(rng)),
            LiteralType::U128 => Literal::U128(U128::rand(rng)),
            LiteralType::Scalar => Literal::Scalar(Scalar::rand(rng)),
            LiteralType::Signature => Literal::Signature(Box::new(Signature::from((
                Scalar::rand(rng),
                Scalar::rand(rng),
                ComputeKey::try_from(PrivateKey::new(rng).expect("Failed to sample a PrivateKey."))
                    .expect("ComputeKey::try_from failed."),
            )))),
            LiteralType::String => Literal::String(StringType::rand(rng)),
            LiteralType::Identifier => Literal::Identifier(Box::new(Uniform::rand(rng))),
        }
    }
}
