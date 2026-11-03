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

use crate::{CallOperator, FinalizeStoreTrait, Opcode, Operand, RegistersTrait, StackTrait};
use console::{
    network::prelude::*,
    program::{Literal, Register, Value},
    types::Boolean,
};

/// A contains command, e.g. `contains accounts[r0] into r1;`.
/// Contains is `true` if a (`key`, `value`) entry exists in `mapping`, stores the result in `destination`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Contains<N: Network> {
    /// The mapping name.
    mapping: CallOperator<N>,
    /// The operands.
    operands: [Operand<N>; 1],
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network> Contains<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Command("contains")
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the mapping.
    #[inline]
    pub const fn mapping(&self) -> &CallOperator<N> {
        &self.mapping
    }

    /// Returns the operand containing the key.
    #[inline]
    pub const fn key(&self) -> &Operand<N> {
        &self.operands[0]
    }

    /// Returns the destination register.
    #[inline]
    pub const fn destination(&self) -> &Register<N> {
        &self.destination
    }

    /// Returns whether this command refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network> Contains<N> {
    /// Finalizes the command.
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: &dyn FinalizeStoreTrait<N>,
        registers: &mut impl RegistersTrait<N>,
    ) -> Result<()> {
        // Determine the program ID and mapping name.
        let (program_id, mapping_name) = match self.mapping {
            CallOperator::Locator(locator) => (*locator.program_id(), *locator.resource()),
            CallOperator::Resource(mapping_name) => (*stack.program_id(), mapping_name),
        };

        // Ensure the mapping exists.
        if !store.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Mapping '{program_id}/{mapping_name}' does not exist");
        }

        // Load the operand as a plaintext.
        let key = registers.load_plaintext(stack, self.key())?;

        // Determine if the key exists in the mapping.
        let contains_key = store.contains_key_speculative(program_id, mapping_name, &key)?;

        // Assign the value to the destination register.
        registers.store(stack, &self.destination, Value::from(Literal::Boolean(Boolean::new(contains_key))))?;

        Ok(())
    }
}

impl<N: Network> Parser for Contains<N> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the mapping name from the string.
        let (string, mapping) = CallOperator::parse(string)?;
        // Parse the "[" from the string.
        let (string, _) = tag("[")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the key operand from the string.
        let (string, key) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "]" from the string.
        let (string, _) = tag("]")(string)?;

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
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Self { mapping, operands: [key], destination }))
    }
}

impl<N: Network> FromStr for Contains<N> {
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

impl<N: Network> Debug for Contains<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Contains<N> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the command.
        write!(f, "{} ", Self::opcode())?;
        // Print the mapping and key operand.
        write!(f, "{}[{}] into ", self.mapping, self.key())?;
        // Print the destination register.
        write!(f, "{};", self.destination)
    }
}

impl<N: Network> FromBytes for Contains<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the mapping name.
        let mapping = CallOperator::read_le(&mut reader)?;
        // Read the key operand.
        let key = Operand::read_le(&mut reader)?;
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Return the command.
        Ok(Self { mapping, operands: [key], destination })
    }
}

impl<N: Network> ToBytes for Contains<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the mapping name.
        self.mapping.write_le(&mut writer)?;
        // Write the key operand.
        self.key().write_le(&mut writer)?;
        // Write the destination register.
        self.destination.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::Register};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, contains) = Contains::<CurrentNetwork>::parse("contains account[r0] into r1;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(contains.mapping, CallOperator::from_str("account").unwrap());
        assert_eq!(contains.operands().len(), 1, "The number of operands is incorrect");
        assert_eq!(contains.key(), &Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(contains.destination, Register::Locator(1), "The second operand is incorrect");

        let (string, contains) =
            Contains::<CurrentNetwork>::parse("contains credits.aleo/account[r0] into r1;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(contains.mapping, CallOperator::from_str("credits.aleo/account").unwrap());
        assert_eq!(contains.operands().len(), 1, "The number of operands is incorrect");
        assert_eq!(contains.key(), &Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(contains.destination, Register::Locator(1), "The second operand is incorrect");
    }

    #[test]
    fn test_from_bytes() {
        let (string, contains) = Contains::<CurrentNetwork>::parse("contains account[r0] into r1;").unwrap();
        assert!(string.is_empty());
        let bytes_le = contains.to_bytes_le().unwrap();
        let result = Contains::<CurrentNetwork>::from_bytes_le(&bytes_le[..]);
        assert!(result.is_ok())
    }
}
