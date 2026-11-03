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

impl<N: Network> EpochProgram<N> {
    /// Construct the inputs for the given epoch program.
    pub fn construct_inputs(&self, rng: &mut ChaChaRng) -> Result<Vec<Value<N>>> {
        // Prepare the inputs.
        let mut inputs = Vec::new();

        // Iterate over the input registers.
        for literal_type in self.register_table().input_register_types() {
            // Initialize the literal.
            let literal = match literal_type {
                // If the literal type is a `boolean`, then generate a random `boolean` element.
                LiteralType::Boolean => Literal::<N>::Boolean(rng.random()),
                // If the literal type is a `field`, then generate a random non-zero `field` element.
                LiteralType::Field => {
                    let field = Field::<N>::rand(rng);
                    match field.is_zero() {
                        true => return Err(anyhow!("Invalid input, zero field element found")),
                        false => Literal::<N>::Field(field),
                    }
                }
                // If the literal type is a `i8`, then generate a random `i8`.
                LiteralType::I8 => Literal::<N>::I8(rng.random()),
                // If the literal type is a `i16`, then generate a random `i16`.
                LiteralType::I16 => Literal::<N>::I16(rng.random()),
                // If the literal type is a `i32`, then generate a random `i32`.
                LiteralType::I32 => Literal::<N>::I32(rng.random()),
                // If the literal type is a `i64`, then generate a random `i64`.
                LiteralType::I64 => Literal::<N>::I64(rng.random()),
                // If the literal type is a `i128`, then generate a random `i128`.
                LiteralType::I128 => Literal::<N>::I128(rng.random()),
                // Unreachable.
                LiteralType::Address
                | LiteralType::Group
                | LiteralType::U8
                | LiteralType::U16
                | LiteralType::U32
                | LiteralType::U64
                | LiteralType::U128
                | LiteralType::Scalar
                | LiteralType::Signature
                | LiteralType::String
                | LiteralType::Identifier => {
                    unreachable!("Invalid input literal type, malformed program");
                }
            };

            // Store the input.
            inputs.push(Value::from(literal));
        }

        Ok(inputs)
    }
}
