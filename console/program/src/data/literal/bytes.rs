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

impl<N: Network> FromBytes for Literal<N> {
    /// Reads the literal from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let index = u16::read_le(&mut reader)?;
        let literal = match index {
            0 => Self::Address(Address::read_le(&mut reader)?),
            1 => Self::Boolean(Boolean::read_le(&mut reader)?),
            2 => Self::Field(Field::read_le(&mut reader)?),
            3 => Self::Group(Group::read_le(&mut reader)?),
            4 => Self::I8(I8::read_le(&mut reader)?),
            5 => Self::I16(I16::read_le(&mut reader)?),
            6 => Self::I32(I32::read_le(&mut reader)?),
            7 => Self::I64(I64::read_le(&mut reader)?),
            8 => Self::I128(I128::read_le(&mut reader)?),
            9 => Self::U8(U8::read_le(&mut reader)?),
            10 => Self::U16(U16::read_le(&mut reader)?),
            11 => Self::U32(U32::read_le(&mut reader)?),
            12 => Self::U64(U64::read_le(&mut reader)?),
            13 => Self::U128(U128::read_le(&mut reader)?),
            14 => Self::Scalar(Scalar::read_le(&mut reader)?),
            15 => Self::Signature(Box::new(Signature::read_le(&mut reader)?)),
            16 => Self::String(StringType::read_le(&mut reader)?),
            17 => Self::Identifier(Box::new(IdentifierLiteral::read_le(&mut reader)?)),
            18.. => return Err(error(format!("Failed to decode literal variant {index}"))),
        };
        Ok(literal)
    }
}

impl<N: Network> ToBytes for Literal<N> {
    /// Writes the literal to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        type Size = u16;
        match self {
            Self::Address(primitive) => {
                (0 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Boolean(primitive) => {
                (1 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Field(primitive) => {
                (2 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Group(primitive) => {
                (3 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::I8(primitive) => {
                (4 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::I16(primitive) => {
                (5 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::I32(primitive) => {
                (6 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::I64(primitive) => {
                (7 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::I128(primitive) => {
                (8 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::U8(primitive) => {
                (9 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::U16(primitive) => {
                (10 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::U32(primitive) => {
                (11 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::U64(primitive) => {
                (12 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::U128(primitive) => {
                (13 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Scalar(primitive) => {
                (14 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Signature(primitive) => {
                (15 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::String(primitive) => {
                (16 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
            Self::Identifier(primitive) => {
                (17 as Size).write_le(&mut writer)?;
                primitive.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u32 = 1000;

    fn check_bytes(expected: Literal<CurrentNetwork>) -> Result<()> {
        // Check the byte representation.
        let expected_bytes = expected.to_bytes_le()?;
        assert_eq!(expected, Literal::read_le(&expected_bytes[..])?);
        Ok(())
    }

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let private_key = snarkvm_console_account::PrivateKey::<CurrentNetwork>::new(rng)?;

            // Address
            check_bytes(Literal::<CurrentNetwork>::Address(Address::try_from(private_key)?))?;
            // Boolean
            check_bytes(Literal::<CurrentNetwork>::Boolean(Boolean::new(Uniform::rand(rng))))?;
            // Field
            check_bytes(Literal::<CurrentNetwork>::Field(Uniform::rand(rng)))?;
            // Group
            check_bytes(Literal::<CurrentNetwork>::Group(Uniform::rand(rng)))?;
            // I8
            check_bytes(Literal::<CurrentNetwork>::I8(I8::new(Uniform::rand(rng))))?;
            // I16
            check_bytes(Literal::<CurrentNetwork>::I16(I16::new(Uniform::rand(rng))))?;
            // I32
            check_bytes(Literal::<CurrentNetwork>::I32(I32::new(Uniform::rand(rng))))?;
            // I64
            check_bytes(Literal::<CurrentNetwork>::I64(I64::new(Uniform::rand(rng))))?;
            // I128
            check_bytes(Literal::<CurrentNetwork>::I128(I128::new(Uniform::rand(rng))))?;
            // U8
            check_bytes(Literal::<CurrentNetwork>::U8(U8::new(Uniform::rand(rng))))?;
            // U16
            check_bytes(Literal::<CurrentNetwork>::U16(U16::new(Uniform::rand(rng))))?;
            // U32
            check_bytes(Literal::<CurrentNetwork>::U32(U32::new(Uniform::rand(rng))))?;
            // U64
            check_bytes(Literal::<CurrentNetwork>::U64(U64::new(Uniform::rand(rng))))?;
            // U128
            check_bytes(Literal::<CurrentNetwork>::U128(U128::new(Uniform::rand(rng))))?;
            // Scalar
            check_bytes(Literal::<CurrentNetwork>::Scalar(Uniform::rand(rng)))?;
            // Signature
            check_bytes(Literal::sample(LiteralType::Signature, rng))?;
            // String
            check_bytes(Literal::<CurrentNetwork>::String(StringType::rand(rng)))?;
            // Identifier
            check_bytes(Literal::<CurrentNetwork>::Identifier(Box::new(Uniform::rand(rng))))?;
        }
        Ok(())
    }
}
