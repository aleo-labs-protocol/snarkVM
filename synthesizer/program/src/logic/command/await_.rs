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

use crate::{Opcode, Operand};
use console::{network::prelude::*, program::Register};

/// An await command, e.g. `await r0;`.
/// Awaits the result of an asynchronous call (a future).
/// Note that asynchronous calls currently do not return a value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Await<N: Network> {
    /// The operands.
    /// Note: Byte and string parsing guarantees that this is a single register operand.
    operands: [Operand<N>; 1],
}

impl<N: Network> Await<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Command("await")
    }

    /// Returns the operands in the command.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the register containing the future.
    #[inline]
    pub fn register(&self) -> &Register<N> {
        // Note: This byte and string parsing guarantees that the operand is a single register.
        let Operand::Register(register) = &self.operands[0] else {
            unreachable!("The operands of an await command must be a single register.")
        };
        // Return the register.
        register
    }

    /// Returns whether this command refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network> Parser for Await<N> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the register from the string.
        let (string, register) = Register::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ';' from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Self { operands: [Operand::Register(register)] }))
    }
}

impl<N: Network> FromStr for Await<N> {
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

impl<N: Network> Debug for Await<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Await<N> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the command.
        write!(f, "await {};", self.register())
    }
}

impl<N: Network> FromBytes for Await<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the register.
        let register = Register::read_le(&mut reader)?;

        Ok(Self { operands: [Operand::Register(register)] })
    }
}

impl<N: Network> ToBytes for Await<N> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the register.
        self.register().write_le(&mut writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::Register};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, await_) = Await::<CurrentNetwork>::parse("await r1;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(await_.register(), &Register::Locator(1));
    }
}
