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
use console::{network::prelude::*, program::Identifier};

/// Jumps to `position`, if `first` equals `second`.
pub type BranchEq<N> = Branch<N, { Variant::BranchEq as u8 }>;
/// Jumps to `position`, if `first` does **not** equal `second`.
pub type BranchNeq<N> = Branch<N, { Variant::BranchNeq as u8 }>;

enum Variant {
    BranchEq,
    BranchNeq,
}

/// Compares `first` and `second` and jumps to `position`, if the condition is met.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Branch<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: [Operand<N>; 2],
    /// The position.
    position: Identifier<N>,
}

impl<N: Network, const VARIANT: u8> Branch<N, VARIANT> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        match VARIANT {
            0 => Opcode::Command("branch.eq"),
            1 => Opcode::Command("branch.neq"),
            _ => panic!("Invalid 'branch' instruction opcode"),
        }
    }

    /// Returns the operands.
    #[inline]
    pub const fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the first operand.
    #[inline]
    pub const fn first(&self) -> &Operand<N> {
        &self.operands[0]
    }

    /// Returns the second operand.
    #[inline]
    pub const fn second(&self) -> &Operand<N> {
        &self.operands[1]
    }

    /// Returns the position.
    #[inline]
    pub const fn position(&self) -> &Identifier<N> {
        &self.position
    }

    /// Returns whether this command refers to an external struct.
    #[inline]
    pub fn contains_external_struct(&self) -> bool {
        false
    }
}

impl<N: Network, const VARIANT: u8> Parser for Branch<N, VARIANT> {
    /// Parses a string into an command.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the first operand from the string.
        let (string, first) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the second operand from the string.
        let (string, second) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the "to" from the string.
        let (string, _) = tag("to")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the position from the string.
        let (string, position) = Identifier::parse(string)?;

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Self { operands: [first, second], position }))
    }
}

impl<N: Network, const VARIANT: u8> FromStr for Branch<N, VARIANT> {
    type Err = Error;

    /// Parses a string into a command.
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

impl<N: Network, const VARIANT: u8> Debug for Branch<N, VARIANT> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for Branch<N, VARIANT> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the command.
        write!(f, "{} {} {} to {};", Self::opcode(), self.first(), self.second(), self.position)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for Branch<N, VARIANT> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the first operand.
        let first = Operand::read_le(&mut reader)?;
        // Read the second operand.
        let second = Operand::read_le(&mut reader)?;
        // Read the position.
        let position = Identifier::read_le(&mut reader)?;

        // Return the command.
        Ok(Self { operands: [first, second], position })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for Branch<N, VARIANT> {
    /// Writes the command to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the first operand.
        self.first().write_le(&mut writer)?;
        // Write the second operand.
        self.second().write_le(&mut writer)?;
        // Write the position.
        self.position.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Identifier, Register},
    };

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, branch) = BranchEq::<CurrentNetwork>::parse("branch.eq r0 r1 to exit;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(branch.first(), &Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(branch.second(), &Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(branch.position, Identifier::from_str("exit").unwrap(), "The position is incorrect");

        let (string, branch) = BranchNeq::<CurrentNetwork>::parse("branch.neq r3 r4 to start;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(branch.first(), &Operand::Register(Register::Locator(3)), "The first operand is incorrect");
        assert_eq!(branch.second(), &Operand::Register(Register::Locator(4)), "The second operand is incorrect");
        assert_eq!(branch.position, Identifier::from_str("start").unwrap(), "The position is incorrect");
    }
}
