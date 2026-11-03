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
    /// Initializes a new literal from a list of little-endian bits *without* trailing zeros.
    pub fn from_bits_le(variant: u8, bits_le: &[bool]) -> Result<Self> {
        let literal = bits_le;
        let literal = match variant {
            0 => Literal::Address(Address::new(Group::from_x_coordinate(Field::<N>::from_bits_le(literal)?)?)),
            1 => match bits_le.len() {
                1 => Literal::Boolean(Boolean::new(literal[0])),
                _ => bail!("Expected a boolean literal, but found a list of {} bits.", bits_le.len()),
            },
            2 => Literal::Field(Field::from_bits_le(literal)?),
            3 => Literal::Group(Group::from_bits_le(literal)?),
            4 => Literal::I8(I8::from_bits_le(literal)?),
            5 => Literal::I16(I16::from_bits_le(literal)?),
            6 => Literal::I32(I32::from_bits_le(literal)?),
            7 => Literal::I64(I64::from_bits_le(literal)?),
            8 => Literal::I128(I128::from_bits_le(literal)?),
            9 => Literal::U8(U8::from_bits_le(literal)?),
            10 => Literal::U16(U16::from_bits_le(literal)?),
            11 => Literal::U32(U32::from_bits_le(literal)?),
            12 => Literal::U64(U64::from_bits_le(literal)?),
            13 => Literal::U128(U128::from_bits_le(literal)?),
            14 => Literal::Scalar(Scalar::from_bits_le(literal)?),
            15 => Literal::Signature(Box::new(Signature::from_bits_le(literal)?)),
            16 => {
                let buffer = Vec::<u8>::from_bits_le(literal)?;
                match buffer.len() <= N::MAX_STRING_BYTES as usize {
                    true => {
                        let string = String::from_utf8(buffer).map_err(|e| error(format!("{e}")))?;
                        Self::String(StringType::new(&string))
                    }
                    false => bail!("String literal exceeds maximum length of {} bytes.", N::MAX_STRING_BYTES),
                }
            }
            17 => Literal::Identifier(Box::new(IdentifierLiteral::from_bits_le(literal)?)),
            18.. => bail!("Failed to initialize literal variant {variant} from bits (LE)"),
        };
        Ok(literal)
    }

    /// Initializes a new literal from a list of big-endian bits *without* leading zeros.
    pub fn from_bits_be(variant: u8, bits_be: &[bool]) -> Result<Self> {
        let literal = bits_be;
        let literal = match variant {
            0 => Literal::Address(Address::new(Group::from_x_coordinate(Field::from_bits_be(literal)?)?)),
            1 => match bits_be.len() {
                1 => Literal::Boolean(Boolean::new(literal[0])),
                _ => bail!("Expected a boolean literal, but found a list of {} bits.", bits_be.len()),
            },
            2 => Literal::Field(Field::from_bits_be(literal)?),
            3 => Literal::Group(Group::from_bits_be(literal)?),
            4 => Literal::I8(I8::from_bits_be(literal)?),
            5 => Literal::I16(I16::from_bits_be(literal)?),
            6 => Literal::I32(I32::from_bits_be(literal)?),
            7 => Literal::I64(I64::from_bits_be(literal)?),
            8 => Literal::I128(I128::from_bits_be(literal)?),
            9 => Literal::U8(U8::from_bits_be(literal)?),
            10 => Literal::U16(U16::from_bits_be(literal)?),
            11 => Literal::U32(U32::from_bits_be(literal)?),
            12 => Literal::U64(U64::from_bits_be(literal)?),
            13 => Literal::U128(U128::from_bits_be(literal)?),
            14 => Literal::Scalar(Scalar::from_bits_be(literal)?),
            15 => Literal::Signature(Box::new(Signature::from_bits_be(literal)?)),
            16 => {
                let buffer = Vec::<u8>::from_bits_be(literal)?;
                match buffer.len() <= N::MAX_STRING_BYTES as usize {
                    true => {
                        let string = String::from_utf8(buffer).map_err(|e| error(format!("{e}")))?;
                        Self::String(StringType::new(&string))
                    }
                    false => bail!("String literal exceeds maximum length of {} bytes.", N::MAX_STRING_BYTES),
                }
            }
            17 => Literal::Identifier(Box::new(IdentifierLiteral::from_bits_be(literal)?)),
            18.. => bail!("Failed to initialize literal variant {variant} from bits (BE)"),
        };
        Ok(literal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u32 = 1000;

    fn check_serialization(expected: Literal<CurrentNetwork>) -> Result<()> {
        println!("{expected}");
        assert_eq!(expected, Literal::from_bits_le(expected.variant(), &expected.to_bits_le())?);
        assert_eq!(expected, Literal::from_bits_be(expected.variant(), &expected.to_bits_be())?);
        Ok(())
    }

    #[test]
    fn test_from_bits() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            let private_key = snarkvm_console_account::PrivateKey::<CurrentNetwork>::new(rng)?;

            // Address
            check_serialization(Literal::<CurrentNetwork>::Address(Address::try_from(private_key)?))?;
            // Boolean
            check_serialization(Literal::<CurrentNetwork>::Boolean(Boolean::new(Uniform::rand(rng))))?;
            // Field
            check_serialization(Literal::<CurrentNetwork>::Field(Uniform::rand(rng)))?;
            // Group
            check_serialization(Literal::<CurrentNetwork>::Group(Uniform::rand(rng)))?;
            // I8
            check_serialization(Literal::<CurrentNetwork>::I8(I8::new(Uniform::rand(rng))))?;
            // I16
            check_serialization(Literal::<CurrentNetwork>::I16(I16::new(Uniform::rand(rng))))?;
            // I32
            check_serialization(Literal::<CurrentNetwork>::I32(I32::new(Uniform::rand(rng))))?;
            // I64
            check_serialization(Literal::<CurrentNetwork>::I64(I64::new(Uniform::rand(rng))))?;
            // I128
            check_serialization(Literal::<CurrentNetwork>::I128(I128::new(Uniform::rand(rng))))?;
            // U8
            check_serialization(Literal::<CurrentNetwork>::U8(U8::new(Uniform::rand(rng))))?;
            // U16
            check_serialization(Literal::<CurrentNetwork>::U16(U16::new(Uniform::rand(rng))))?;
            // U32
            check_serialization(Literal::<CurrentNetwork>::U32(U32::new(Uniform::rand(rng))))?;
            // U64
            check_serialization(Literal::<CurrentNetwork>::U64(U64::new(Uniform::rand(rng))))?;
            // U128
            check_serialization(Literal::<CurrentNetwork>::U128(U128::new(Uniform::rand(rng))))?;
            // Scalar
            check_serialization(Literal::<CurrentNetwork>::Scalar(Uniform::rand(rng)))?;
            // Signature
            check_serialization(Literal::sample(LiteralType::Signature, rng))?;
            // String
            // Sample a random string. Take 1/4th to ensure we fit for all code points.
            let string = rng.next_string(CurrentNetwork::MAX_STRING_BYTES / 4, false);
            check_serialization(Literal::<CurrentNetwork>::String(StringType::new(&string)))?;
        }
        Ok(())
    }
}
