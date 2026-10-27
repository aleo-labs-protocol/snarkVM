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

use crate::{FinalizeRegistersState, Opcode, Operand, StackTrait};
use console::{
    network::prelude::*,
    program::{Literal, LiteralType, Plaintext, Register, Value},
    types::{Address, Boolean, Field, Group, I8, I16, I32, I64, I128, Scalar, U8, U16, U32, U64, U128},
};

use rand::SeedableRng;

/// The maximum number of additional seeds that can be provided.
pub const MAX_ADDITIONAL_SEEDS: usize = 2;

/// A random-number generator command, e.g. `rand.chacha into r1 as field;` or
/// `rand.chacha r0 into r1 as field;`, with the latter including an optional additional seed(s).
///
/// This command samples a deterministic and unique element, and stores the result in `destination`.
/// When the optional operand(s) are provided, it is used as additional seed(s) to the
/// random-number generator. Note that the maximum number of additional seeds is currently 2.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RandChaCha<N: Network> {
    /// The operand(s) as `seed(s)`.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
    /// The destination register type.
    destination_type: LiteralType,
}

impl<N: Network> RandChaCha<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Command("rand.chacha")
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub const fn destination(&self) -> &Register<N> {
        &self.destination
    }

    /// Returns the destination register type.
    #[inline]
    pub const fn destination_type(&self) -> LiteralType {
        self.destination_type
    }

    /// Returns whether this command refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network> RandChaCha<N> {
    /// Finalizes the command.
    #[inline]
    pub fn finalize(&self, stack: &impl StackTrait<N>, registers: &mut impl FinalizeRegistersState<N>) -> Result<()> {
        // Ensure the number of operands is within bounds.
        if self.operands.len() > MAX_ADDITIONAL_SEEDS {
            bail!("The number of operands must be <= {MAX_ADDITIONAL_SEEDS}")
        }

        // Load the operands values.
        let seeds: Vec<_> = self.operands.iter().map(|operand| registers.load(stack, operand)).try_collect()?;

        // Construct the random seed.
        // If the height is greater than or equal to consensus V3, then use the new preimage definition.
        // The difference is that a nonce is also included in the new definition.
        //
        // `transition_id` and `nonce` are `Option`s on the trait — the view path leaves both as
        // `None`. Views already reject `rand.chacha` at construction, so reaching this code on
        // a view is unreachable, but we surface a clear runtime error here as a defense in depth.
        let consensus_version = N::CONSENSUS_VERSION(registers.state().block_height())?;
        let transition_id = registers
            .transition_id()
            .ok_or_else(|| anyhow!("'rand.chacha' requires a transition ID, which is not available in this scope"))?;
        let preimage = if (ConsensusVersion::V1..=ConsensusVersion::V2).contains(&consensus_version) {
            to_bits_le![
                registers.state().random_seed(),
                **transition_id,
                stack.program_id(),
                registers.function_name(),
                self.destination.locator(),
                self.destination_type.type_id(),
                seeds
            ]
        } else {
            let nonce = registers
                .nonce()
                .ok_or_else(|| anyhow!("'rand.chacha' requires a nonce, which is not available in this scope"))?;
            to_bits_le![
                registers.state().random_seed(),
                **transition_id,
                stack.program_id(),
                registers.function_name(),
                nonce,
                self.destination.locator(),
                self.destination_type.type_id(),
                seeds
            ]
        };

        // Hash the preimage.
        let digest = N::hash_bhp1024(&preimage)?.to_bytes_le()?;
        // Ensure the digest is 32-bytes.
        ensure!(digest.len() == 32, "The digest for the ChaChaRng seed must be 32-bytes");

        // Construct the ChaChaRng seed.
        let mut chacha_seed = [0u8; 32];
        chacha_seed.copy_from_slice(&digest[..32]);

        // Construct the ChaChaRng.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(chacha_seed);

        // Sample a random element.
        let output = match self.destination_type {
            LiteralType::Address => Literal::Address(Address::new(Group::rand(&mut rng))),
            LiteralType::Boolean => Literal::Boolean(Boolean::rand(&mut rng)),
            LiteralType::Field => Literal::Field(Field::rand(&mut rng)),
            LiteralType::Group => Literal::Group(Group::rand(&mut rng)),
            LiteralType::I8 => Literal::I8(I8::rand(&mut rng)),
            LiteralType::I16 => Literal::I16(I16::rand(&mut rng)),
            LiteralType::I32 => Literal::I32(I32::rand(&mut rng)),
            LiteralType::I64 => Literal::I64(I64::rand(&mut rng)),
            LiteralType::I128 => Literal::I128(I128::rand(&mut rng)),
            LiteralType::U8 => Literal::U8(U8::rand(&mut rng)),
            LiteralType::U16 => Literal::U16(U16::rand(&mut rng)),
            LiteralType::U32 => Literal::U32(U32::rand(&mut rng)),
            LiteralType::U64 => Literal::U64(U64::rand(&mut rng)),
            LiteralType::U128 => Literal::U128(U128::rand(&mut rng)),
            LiteralType::Scalar => Literal::Scalar(Scalar::rand(&mut rng)),
            LiteralType::Signature => bail!("Cannot 'rand.chacha' into a 'signature'"),
            LiteralType::String => bail!("Cannot 'rand.chacha' into a 'string'"),
            LiteralType::Identifier => bail!("Cannot 'rand.chacha' into an 'identifier'"),
        };

        // Assign the value to the destination register.
        registers.store(stack, &self.destination, Value::Plaintext(Plaintext::from(output)))
    }
}

impl<N: Network> Parser for RandChaCha<N> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses an operand from the string.
        fn parse_operand<N: Network>(string: &str) -> ParserResult<'_, Operand<N>> {
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the operand from the string.
            Operand::parse(string)
        }

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the operands from the string.
        let (string, operands) = many0(parse_operand)(string)?;

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" keyword from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register type from the string.
        let (string, destination_type) = LiteralType::parse(string)?;

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        // Ensure the destination type is allowed.
        if matches!(destination_type, LiteralType::String | LiteralType::Identifier) {
            return map_res(fail, |_: ParserResult<Self>| {
                Err(error(format!("Failed to parse 'rand.chacha': '{destination_type}' is invalid")))
            })(string);
        }

        match operands.len() <= MAX_ADDITIONAL_SEEDS {
            true => Ok((string, Self { operands, destination, destination_type })),
            false => map_res(fail, |_: ParserResult<Self>| {
                Err(error("Failed to parse 'rand.chacha' opcode: too many operands"))
            })(string),
        }
    }
}

impl<N: Network> FromStr for RandChaCha<N> {
    type Err = Error;

    /// Parses a string into the command.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for RandChaCha<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for RandChaCha<N> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is within the bounds.
        if self.operands.len() > MAX_ADDITIONAL_SEEDS {
            return Err(fmt::Error);
        }

        // Print the command.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {} as {};", self.destination, self.destination_type)
    }
}

impl<N: Network> FromBytes for RandChaCha<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the number of operands.
        let num_operands = u8::read_le(&mut reader)? as usize;

        // Ensure that the number of operands does not exceed the upper bound.
        if num_operands > MAX_ADDITIONAL_SEEDS {
            return Err(error(format!("The number of operands must be <= {MAX_ADDITIONAL_SEEDS}")));
        }

        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(num_operands);
        // Read the operands.
        for _ in 0..num_operands {
            operands.push(Operand::read_le(&mut reader)?);
        }

        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination register type.
        let destination_type = LiteralType::read_le(&mut reader)?;

        // Ensure the destination type is allowed.
        if matches!(destination_type, LiteralType::String | LiteralType::Identifier) {
            return Err(error(format!("Failed to parse 'rand.chacha': '{destination_type}' is invalid")));
        }

        // Return the command.
        Ok(Self { operands, destination, destination_type })
    }
}

impl<N: Network> ToBytes for RandChaCha<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is within the bounds.
        if self.operands.len() > MAX_ADDITIONAL_SEEDS {
            return Err(error(format!("The number of operands must be <= {MAX_ADDITIONAL_SEEDS}")));
        }

        // Write the number of operands.
        u8::try_from(self.operands.len()).map_err(|e| error(e.to_string()))?.write_le(&mut writer)?;
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the destination register type.
        self.destination_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::Register};

    type CurrentNetwork = MainnetV0;

    fn valid_destination_types() -> &'static [LiteralType] {
        &[
            LiteralType::Address,
            LiteralType::Boolean,
            LiteralType::Field,
            LiteralType::Group,
            LiteralType::I8,
            LiteralType::I16,
            LiteralType::I32,
            LiteralType::I64,
            LiteralType::I128,
            LiteralType::U8,
            LiteralType::U16,
            LiteralType::U32,
            LiteralType::U64,
            LiteralType::U128,
            LiteralType::Scalar,
        ]
    }

    #[test]
    fn test_parse() {
        for destination_type in valid_destination_types() {
            let instruction = format!("rand.chacha into r1 as {destination_type};");
            let (string, rand) = RandChaCha::<CurrentNetwork>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(rand.operands.len(), 0, "The number of operands is incorrect");
            assert_eq!(rand.destination, Register::Locator(1), "The destination is incorrect");
            assert_eq!(rand.destination_type, *destination_type, "The destination type is incorrect");

            let instruction = format!("rand.chacha r0 into r1 as {destination_type};");
            let (string, rand) = RandChaCha::<CurrentNetwork>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(rand.operands.len(), 1, "The number of operands is incorrect");
            assert_eq!(rand.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
            assert_eq!(rand.destination, Register::Locator(1), "The second operand is incorrect");
            assert_eq!(rand.destination_type, *destination_type, "The destination type is incorrect");

            let instruction = format!("rand.chacha r0 r1 into r2 as {destination_type};");
            let (string, rand) = RandChaCha::<CurrentNetwork>::parse(&instruction).unwrap();
            assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
            assert_eq!(rand.operands.len(), 2, "The number of operands is incorrect");
            assert_eq!(rand.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
            assert_eq!(rand.operands[1], Operand::Register(Register::Locator(1)), "The first operand is incorrect");
            assert_eq!(rand.destination, Register::Locator(2), "The second operand is incorrect");
            assert_eq!(rand.destination_type, *destination_type, "The destination type is incorrect");
        }
    }
}
