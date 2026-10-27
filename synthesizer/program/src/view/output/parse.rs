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
    /// The output statement is of the form `output {operand} as {finalize_type};`.
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
        // Parse the finalize type from the string.
        let (string, finalize_type) = FinalizeType::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;
        Ok((string, Self { operand, finalize_type }))
    }
}

impl<N: Network> FromStr for Output<N> {
    type Err = Error;

    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for Output<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Output<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{type_} {operand} as {finalize_type};",
            type_ = Self::type_name(),
            operand = self.operand,
            finalize_type = self.finalize_type,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_output_parse() -> Result<()> {
        // Register operand.
        let output = Output::<CurrentNetwork>::parse("output r0 as field.public;").unwrap().1;
        assert_eq!(output.operand(), &Operand::<CurrentNetwork>::from_str("r0")?);
        assert_eq!(output.finalize_type(), &FinalizeType::<CurrentNetwork>::from_str("field.public")?);

        // Literal operand.
        let output = Output::<CurrentNetwork>::parse("output 1u64 as u64.public;").unwrap().1;
        assert_eq!(output.operand(), &Operand::<CurrentNetwork>::from_str("1u64")?);
        assert_eq!(output.finalize_type(), &FinalizeType::<CurrentNetwork>::from_str("u64.public")?);

        Ok(())
    }

    #[test]
    fn test_output_display() -> Result<()> {
        let output = Output::<CurrentNetwork>::from_str("output r0 as field.public;")?;
        assert_eq!("output r0 as field.public;", output.to_string());

        let output = Output::<CurrentNetwork>::from_str("output 1u64 as u64.public;")?;
        assert_eq!("output 1u64 as u64.public;", output.to_string());

        Ok(())
    }

    #[test]
    fn test_output_parse_fails() {
        // Missing trailing semicolon.
        assert!(Output::<CurrentNetwork>::from_str("output r0 as field.public").is_err());
        // Missing 'as' keyword.
        assert!(Output::<CurrentNetwork>::from_str("output r0 field.public;").is_err());
        // Missing operand.
        assert!(Output::<CurrentNetwork>::from_str("output as field.public;").is_err());
        // Missing 'output' keyword.
        assert!(Output::<CurrentNetwork>::from_str("r0 as field.public;").is_err());
        // Missing finalize type.
        assert!(Output::<CurrentNetwork>::from_str("output r0 as ;").is_err());
    }
}
