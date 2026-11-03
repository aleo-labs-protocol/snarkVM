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

use crate::{FinalizeOperation, FinalizeStoreTrait, Opcode, Operand, RegistersTrait, StackTrait};
use console::{network::prelude::*, program::Identifier};

/// A remove command, e.g. `remove mapping[r0];`
/// Removes the (`key`, `value`) entry in `mapping`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Remove<N: Network> {
    /// The mapping name.
    mapping: Identifier<N>,
    /// The operands
    operands: [Operand<N>; 1],
}

impl<N: Network> Remove<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Command("remove")
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the mapping name.
    #[inline]
    pub const fn mapping_name(&self) -> &Identifier<N> {
        &self.mapping
    }

    /// Returns the operand containing the key.
    #[inline]
    pub const fn key(&self) -> &Operand<N> {
        &self.operands[0]
    }

    /// Returns whether this command refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network> Remove<N> {
    /// Finalizes the command.
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: &dyn FinalizeStoreTrait<N>,
        registers: &mut impl RegistersTrait<N>,
    ) -> Result<Option<FinalizeOperation<N>>> {
        // Ensure the mapping exists.
        if !store.contains_mapping_speculative(stack.program_id(), &self.mapping)? {
            bail!("Mapping '{}/{}' does not exist", stack.program_id(), self.mapping);
        }

        // Load the key operand as a plaintext.
        let key = registers.load_plaintext(stack, self.key())?;
        // Update the value in storage, and return the finalize operation.
        store.remove_key_value(*stack.program_id(), self.mapping, &key)
    }
}

impl<N: Network> Parser for Remove<N> {
    /// Parses a string into an operation.
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the mapping name from the string.
        let (string, mapping) = Identifier::parse(string)?;
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
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Self { mapping, operands: [key] }))
    }
}

impl<N: Network> FromStr for Remove<N> {
    type Err = Error;

    /// Parses a string into the command.
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

impl<N: Network> Debug for Remove<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Remove<N> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the command, mapping, and key operand.
        write!(f, "{} {}[{}];", Self::opcode(), self.mapping, self.key())
    }
}

impl<N: Network> FromBytes for Remove<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the mapping name.
        let mapping = Identifier::read_le(&mut reader)?;
        // Read the key operand.
        let key = Operand::read_le(&mut reader)?;
        // Return the command.
        Ok(Self { mapping, operands: [key] })
    }
}

impl<N: Network> ToBytes for Remove<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the mapping name.
        self.mapping.write_le(&mut writer)?;
        // Write the key operand.
        self.key().write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::Register};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, remove) = Remove::<CurrentNetwork>::parse("remove account[r1];").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(remove.mapping, Identifier::from_str("account").unwrap());
        assert_eq!(remove.operands().len(), 1, "The number of operands is incorrect");
        assert_eq!(remove.key(), &Operand::Register(Register::Locator(1)), "The first operand is incorrect");
    }
}
