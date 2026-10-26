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

use crate::{FinalizeStoreTrait, Opcode, Operand, RegistersTrait, StackTrait};
use console::{
    network::prelude::*,
    program::{Identifier, Literal, Plaintext, PlaintextType, ProgramID, Register, Value},
};

/// A dynamic get command, e.g. `get.dynamic r0 r1 r2[r3] into r4 as u8;`.
/// Resolves the `program` and `mapping` operands, gets the value stored at the `key` operand in `mapping`, and stores the result into `destination`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GetDynamic<N: Network> {
    /// The operands.
    operands: [Operand<N>; 4],
    /// The destination register.
    destination: Register<N>,
    /// The destination type.
    destination_type: PlaintextType<N>,
}

impl<N: Network> GetDynamic<N> {
    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::Command("get.dynamic")
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        &self.operands
    }

    /// Returns the operand containing the program name.
    #[inline]
    pub const fn program_name_operand(&self) -> &Operand<N> {
        &self.operands[0]
    }

    /// Returns the operand containing the program network.
    #[inline]
    pub const fn program_network_operand(&self) -> &Operand<N> {
        &self.operands[1]
    }

    /// Returns the operand containing the mapping name.
    #[inline]
    pub const fn mapping_name_operand(&self) -> &Operand<N> {
        &self.operands[2]
    }

    /// Returns the operand containing the key.
    #[inline]
    pub const fn key_operand(&self) -> &Operand<N> {
        &self.operands[3]
    }

    /// Returns the destination register.
    #[inline]
    pub const fn destination(&self) -> &Register<N> {
        &self.destination
    }

    /// Returns the destination type.
    #[inline]
    pub const fn destination_type(&self) -> &PlaintextType<N> {
        &self.destination_type
    }
}

impl<N: Network> GetDynamic<N> {
    /// Finalizes the command.
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: &dyn FinalizeStoreTrait<N>,
        registers: &mut impl RegistersTrait<N>,
    ) -> Result<()> {
        // Get the program name.
        let program_name = match registers.load(stack, self.program_name_operand())? {
            Value::Plaintext(Plaintext::Literal(Literal::Field(field), _)) => Identifier::from_field(&field)?,
            Value::Plaintext(Plaintext::Literal(Literal::Identifier(id_lit), _)) => {
                Identifier::from_field(&id_lit.to_field()?)?
            }
            _ => bail!("Expected the first operand of `get.dynamic` to be a field or identifier literal."),
        };

        // Get the program network.
        let program_network = match registers.load(stack, self.program_network_operand())? {
            Value::Plaintext(Plaintext::Literal(Literal::Field(field), _)) => Identifier::from_field(&field)?,
            Value::Plaintext(Plaintext::Literal(Literal::Identifier(id_lit), _)) => {
                Identifier::from_field(&id_lit.to_field()?)?
            }
            _ => bail!("Expected the second operand of `get.dynamic` to be a field or identifier literal."),
        };

        // Construct the program ID.
        let program_id = ProgramID::try_from((program_name, program_network))?;

        // Get the mapping name.
        let mapping_name = match registers.load(stack, self.mapping_name_operand())? {
            Value::Plaintext(Plaintext::Literal(Literal::Field(field), _)) => Identifier::from_field(&field)?,
            Value::Plaintext(Plaintext::Literal(Literal::Identifier(id_lit), _)) => {
                Identifier::from_field(&id_lit.to_field()?)?
            }
            _ => bail!("Expected the third operand of `get.dynamic` to be a field or identifier literal."),
        };

        // Ensure the mapping exists.
        if !store.contains_mapping_speculative(&program_id, &mapping_name)? {
            bail!("Mapping '{program_id}/{mapping_name}' does not exist");
        }

        // Load the operand as a plaintext.
        let key = registers.load_plaintext(stack, self.key_operand())?;

        // Get the mapping definition.
        let mapping = stack.get_stack_global(&program_id)?.program().get_mapping(&mapping_name)?;
        // Get the key type.
        let mapping_key_type = mapping.key().plaintext_type();
        // Ensure the key operand matches the mapping key type.
        ensure!(
            stack.matches_plaintext(&key, mapping_key_type).is_ok(),
            "Expected the key to be of type '{mapping_key_type}', found '{key}'."
        );
        // Get the mapping value type.
        let mapping_value_type = mapping.value().plaintext_type();
        // Ensure the destination type matches the mapping value type.
        ensure!(
            &self.destination_type == mapping_value_type,
            "Expected the destination type to be '{mapping_value_type}', found '{}'.",
            self.destination_type
        );

        // Retrieve the value from storage as a plaintext.
        let value = match store.get_value_speculative(program_id, mapping_name, &key)? {
            Some(Value::Plaintext(plaintext)) => Value::Plaintext(plaintext),
            Some(Value::Record(..)) => bail!("Cannot 'get.dynamic' a 'record'"),
            Some(Value::Future(..)) => bail!("Cannot 'get.dynamic' a 'future'"),
            Some(Value::DynamicRecord(..)) => bail!("Cannot 'get.dynamic' a 'dynamic.record'"),
            Some(Value::DynamicFuture(..)) => bail!("Cannot 'get.dynamic' a 'dynamic.future'"),
            // If a key does not exist, then bail.
            None => bail!("Key '{key}' does not exist in mapping '{program_id}/{mapping_name}'"),
        };

        // Assign the value to the destination register.
        registers.store(stack, &self.destination, value)?;

        Ok(())
    }
}

impl<N: Network> Parser for GetDynamic<N> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

        // Parse the program name operand from the string.
        let (string, program_name) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program network operand from the string.
        let (string, program_network) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the mapping name operand from the string.
        let (string, mapping_name) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;

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
        // Parse the "as" keyword from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination type from the string.
        let (string, destination_type) = PlaintextType::parse(string)?;

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Self {
            operands: [program_name, program_network, mapping_name, key],
            destination,
            destination_type,
        }))
    }
}

impl<N: Network> FromStr for GetDynamic<N> {
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

impl<N: Network> Debug for GetDynamic<N> {
    /// Prints the command as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for GetDynamic<N> {
    /// Prints the command to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Print the command.
        write!(f, "{} ", Self::opcode())?;
        // Print the program name, program network, mapping name, and key operand.
        write!(
            f,
            "{} {} {}[{}] into ",
            self.program_name_operand(),
            self.program_network_operand(),
            self.mapping_name_operand(),
            self.key_operand()
        )?;
        // Print the destination register.
        write!(f, "{} as {};", self.destination, self.destination_type())
    }
}

impl<N: Network> FromBytes for GetDynamic<N> {
    /// Reads the command from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the program name.
        let program_name = Operand::read_le(&mut reader)?;
        // Read the program network.
        let program_network = Operand::read_le(&mut reader)?;
        // Read the mapping name.
        let mapping_name = Operand::read_le(&mut reader)?;
        // Read the key operand.
        let key = Operand::read_le(&mut reader)?;
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;
        // Read the destination type.
        let destination_type = PlaintextType::read_le(&mut reader)?;
        // Return the command.
        Ok(Self { operands: [program_name, program_network, mapping_name, key], destination, destination_type })
    }
}

impl<N: Network> ToBytes for GetDynamic<N> {
    /// Writes the command to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the program name.
        self.program_name_operand().write_le(&mut writer)?;
        // Write the program network.
        self.program_network_operand().write_le(&mut writer)?;
        // Write the mapping name.
        self.mapping_name_operand().write_le(&mut writer)?;
        // Write the key operand.
        self.key_operand().write_le(&mut writer)?;
        // Write the destination register.
        self.destination.write_le(&mut writer)?;
        // Write the destination type.
        self.destination_type.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{network::MainnetV0, program::Register};

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, get) = GetDynamic::<CurrentNetwork>::parse("get.dynamic r0 r1 r2[r3] into r4 as Baz;").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(get.operands().len(), 4, "The number of operands is incorrect");
        assert_eq!(
            get.program_name_operand(),
            &Operand::Register(Register::Locator(0)),
            "The first operand is incorrect"
        );
        assert_eq!(
            get.program_network_operand(),
            &Operand::Register(Register::Locator(1)),
            "The second operand is incorrect"
        );
        assert_eq!(
            get.mapping_name_operand(),
            &Operand::Register(Register::Locator(2)),
            "The third operand is incorrect"
        );
        assert_eq!(get.key_operand(), &Operand::Register(Register::Locator(3)), "The fourth operand is incorrect");
        assert_eq!(get.destination, Register::Locator(4), "The destination register is incorrect");
        assert_eq!(
            get.destination_type,
            PlaintextType::Struct(Identifier::from_str("Baz").unwrap()),
            "The destination type is incorrect"
        );
    }

    #[test]
    fn test_from_bytes() {
        let (string, get) = GetDynamic::<CurrentNetwork>::parse("get.dynamic r0 r1 r2[r3] into r4 as u8;").unwrap();
        assert!(string.is_empty());
        let bytes_le = get.to_bytes_le().unwrap();
        let result = GetDynamic::<CurrentNetwork>::from_bytes_le(&bytes_le[..]);
        assert!(result.is_ok())
    }

    #[test]
    fn test_display_parse_roundtrip() {
        let input = "get.dynamic r0 r1 r2[r3] into r4 as u8;";
        let (string, original) = GetDynamic::<CurrentNetwork>::parse(input).unwrap();
        assert!(string.is_empty());
        let displayed = format!("{original}");
        let (remainder, reparsed) = GetDynamic::<CurrentNetwork>::parse(&displayed).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(original, reparsed);
    }
}
