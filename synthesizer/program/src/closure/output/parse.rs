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

impl<N: Network> Parser for Output<N> {
    /// Parses a string into an output statement.
    /// The output statement is of the form `output {operand} as {register_type};`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the output keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the operand from the string.
        let (string, operand) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the register type from the string.
        let (string, register_type) = RegisterType::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;
        // Return the output statement.
        Ok((string, Self { operand, register_type }))
    }
}

impl<N: Network> FromStr for Output<N> {
    type Err = Error;

    /// Parses a string into an output statement.
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

impl<N: Network> Debug for Output<N> {
    /// Prints the output as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Output<N> {
    /// Prints the output statement as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{type_} {operand} as {register_type};",
            type_ = Self::type_name(),
            operand = self.operand,
            register_type = self.register_type
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        network::MainnetV0,
        program::{Literal, Register, U8},
    };

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_output_parse() -> Result<()> {
        // Register
        let output = Output::<CurrentNetwork>::parse("output r0 as field;").unwrap().1;
        assert_eq!(output.operand(), &Operand::Register(Register::<CurrentNetwork>::Locator(0)));
        assert_eq!(output.register_type(), &RegisterType::<CurrentNetwork>::from_str("field")?);

        let output = Output::<CurrentNetwork>::parse("output 0u8 as u8;").unwrap().1;
        assert_eq!(output.operand(), &Operand::Literal(Literal::<CurrentNetwork>::U8(U8::new(0))));
        assert_eq!(output.register_type(), &RegisterType::<CurrentNetwork>::from_str("u8")?);

        // Struct
        let output = Output::<CurrentNetwork>::parse("output r1 as signature;").unwrap().1;
        assert_eq!(output.operand(), &Operand::Register(Register::<CurrentNetwork>::Locator(1)));
        assert_eq!(output.register_type(), &RegisterType::<CurrentNetwork>::from_str("signature")?);

        // Record
        let output = Output::<CurrentNetwork>::parse("output r2 as token.record;").unwrap().1;
        assert_eq!(output.operand(), &Operand::Register(Register::<CurrentNetwork>::Locator(2)));
        assert_eq!(output.register_type(), &RegisterType::<CurrentNetwork>::from_str("token.record")?);

        Ok(())
    }

    #[test]
    fn test_output_display() {
        // Register
        let output = Output::<CurrentNetwork>::parse("output r0 as field;").unwrap().1;
        assert_eq!(format!("{output}"), "output r0 as field;");

        // Literal
        let output = Output::<CurrentNetwork>::parse("output 0u8 as u8;").unwrap().1;
        assert_eq!(format!("{output}"), "output 0u8 as u8;");

        // Struct
        let output = Output::<CurrentNetwork>::parse("output r1 as signature;").unwrap().1;
        assert_eq!(format!("{output}"), "output r1 as signature;");

        // Record
        let output = Output::<CurrentNetwork>::parse("output r2 as token.record;").unwrap().1;
        assert_eq!(format!("{output}"), "output r2 as token.record;");
    }
}
