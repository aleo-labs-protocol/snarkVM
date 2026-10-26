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

impl<N: Network> Parser for DynamicFuture<N> {
    /// Parses a string into a dynamic future.
    ///
    /// Supports two formats:
    /// - Human-readable: `{ _program_id: foo.aleo, _function_name: bar, _checksum: 0field }`
    /// - Raw field: `{ _program_name: 0field, _program_network: 0field, _function_name: 0field, _checksum: 0field }`
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Try to parse the human-readable format first.
        if let Ok(result) = Self::parse_human_readable(string) {
            return Ok(result);
        }
        // Fall back to raw field format.
        Self::parse_raw_fields(string)
    }
}

impl<N: Network> DynamicFuture<N> {
    /// Parses the human-readable format: `{ _program_id: foo.aleo, _function_name: bar, _checksum: 0field }`.
    fn parse_human_readable(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "{" from the string.
        let (string, _) = tag("{")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_program_id" from the string.
        let (string, _) = tag("_program_id")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program ID from the string.
        let (string, program_id) = ProgramID::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_function_name" from the string.
        let (string, _) = tag("_function_name")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name from the string.
        let (string, function_name) = Identifier::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_checksum" from the string.
        let (string, _) = tag("_checksum")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the argument checksum from the string.
        let (string, checksum) = Field::parse(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "}" from the string.
        let (string, _) = tag("}")(string)?;

        // Convert to field representation.
        // Safe: identifiers are validated to fit within 31 bytes, which always fit in a 253-bit field element.
        let program_name = program_id.name().to_field().expect("identifier always fits in a field element");
        let program_network = program_id.network().to_field().expect("identifier always fits in a field element");
        let function_name_field = function_name.to_field().expect("identifier always fits in a field element");

        Ok((string, Self::new_unchecked(program_name, program_network, function_name_field, checksum, None)))
    }

    /// Parses the raw field format: `{ _program_name: 0field, _program_network: 0field, _function_name: 0field, _checksum: 0field }`.
    fn parse_raw_fields(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "{" from the string.
        let (string, _) = tag("{")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_program_name" from the string.
        let (string, _) = tag("_program_name")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program name from the string.
        let (string, program_name) = Field::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_program_network" from the string.
        let (string, _) = tag("_program_network")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the program network from the string.
        let (string, program_network) = Field::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_function_name" from the string.
        let (string, _) = tag("_function_name")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the function name from the string.
        let (string, function_name) = Field::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_checksum" from the string.
        let (string, _) = tag("_checksum")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the argument checksum from the string.
        let (string, checksum) = Field::parse(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "}" from the string.
        let (string, _) = tag("}")(string)?;

        Ok((string, Self::new_unchecked(program_name, program_network, function_name, checksum, None)))
    }
}

impl<N: Network> FromStr for DynamicFuture<N> {
    type Err = Error;

    /// Returns a future from a string literal.
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

impl<N: Network> Debug for DynamicFuture<N> {
    /// Prints the future as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for DynamicFuture<N> {
    /// Prints the future as a string.
    ///
    /// Attempts to display in human-readable format if the fields can be converted to identifiers.
    /// Falls back to raw field format if conversion fails.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Try to convert fields to identifiers for human-readable display.
        let program_name_id = Identifier::<N>::from_field(&self.program_name);
        let program_network_id = Identifier::<N>::from_field(&self.program_network);
        let function_name_id = Identifier::<N>::from_field(&self.function_name);

        // If all conversions succeed, display human-readable format.
        if let (Ok(name), Ok(network), Ok(function)) = (program_name_id, program_network_id, function_name_id)
            && let Ok(program_id) = ProgramID::try_from((name, network))
        {
            return write!(
                f,
                "{{ _program_id: {program_id}, _function_name: {function}, _checksum: {} }}",
                self.checksum()
            );
        }

        // Fall back to raw field format.
        write!(
            f,
            "{{ _program_name: {}, _program_network: {}, _function_name: {}, _checksum: {} }}",
            self.program_name(),
            self.program_network(),
            self.function_name(),
            self.checksum(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Argument, Future, Plaintext};
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_display_roundtrip() {
        // Create a static future.
        let future = Future::<CurrentNetwork>::new(
            crate::ProgramID::from_str("test.aleo").unwrap(),
            crate::Identifier::from_str("foo").unwrap(),
            vec![Argument::Plaintext(Plaintext::from_str("100u64").unwrap())],
        );

        // Convert to dynamic future.
        let expected = DynamicFuture::from_future(&future).unwrap();

        // Convert to string.
        let expected_string = expected.to_string();

        // Parse the string.
        let candidate = DynamicFuture::<CurrentNetwork>::from_str(&expected_string).unwrap();

        // Verify the fields match.
        assert_eq!(expected.program_name(), candidate.program_name());
        assert_eq!(expected.program_network(), candidate.program_network());
        assert_eq!(expected.function_name(), candidate.function_name());
        assert_eq!(expected.checksum(), candidate.checksum());
    }

    #[test]
    fn test_parse_human_readable() {
        // Parse a dynamic future from a human-readable string.
        let string = "{ _program_id: test.aleo, _function_name: foo, _checksum: 0field }";
        let (remainder, candidate) = DynamicFuture::<CurrentNetwork>::parse(string).unwrap();
        assert!(remainder.is_empty());

        // Verify the program ID and function name can be recovered.
        let program_name = Identifier::<CurrentNetwork>::from_field(candidate.program_name()).unwrap();
        let program_network = Identifier::<CurrentNetwork>::from_field(candidate.program_network()).unwrap();
        let function_name = Identifier::<CurrentNetwork>::from_field(candidate.function_name()).unwrap();

        assert_eq!(program_name.to_string(), "test");
        assert_eq!(program_network.to_string(), "aleo");
        assert_eq!(function_name.to_string(), "foo");
        assert_eq!(*candidate.checksum(), Field::from_u64(0));
    }

    #[test]
    fn test_parse_raw_fields() {
        // Parse a dynamic future from a raw field string.
        let string = "{ _program_name: 0field, _program_network: 0field, _function_name: 0field, _checksum: 0field }";
        let (remainder, candidate) = DynamicFuture::<CurrentNetwork>::parse(string).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(*candidate.program_name(), Field::from_u64(0));
        assert_eq!(*candidate.program_network(), Field::from_u64(0));
        assert_eq!(*candidate.function_name(), Field::from_u64(0));
        assert_eq!(*candidate.checksum(), Field::from_u64(0));
    }

    #[test]
    fn test_display_human_readable() {
        // Create a static future.
        let future = Future::<CurrentNetwork>::new(
            crate::ProgramID::from_str("credits.aleo").unwrap(),
            crate::Identifier::from_str("transfer").unwrap(),
            vec![],
        );

        // Convert to dynamic future.
        let dynamic = DynamicFuture::from_future(&future).unwrap();

        // Check that the display uses human-readable format.
        let display = dynamic.to_string();
        assert!(display.contains("_program_id:"));
        assert!(display.contains("credits.aleo"));
        assert!(display.contains("_function_name:"));
        assert!(display.contains("transfer"));
        assert!(display.contains("_checksum:"));
    }

    #[test]
    fn test_display_fallback_to_raw() {
        // Create a dynamic future with invalid field values that cannot be converted to identifiers.
        let dynamic = DynamicFuture::<CurrentNetwork>::new_unchecked(
            Field::from_u64(u64::MAX),
            Field::from_u64(u64::MAX),
            Field::from_u64(u64::MAX),
            Field::from_u64(0),
            None,
        );

        // Check that the display falls back to raw field format.
        let display = dynamic.to_string();
        assert!(display.contains("_program_name:"));
        assert!(display.contains("_program_network:"));
        assert!(display.contains("_function_name:"));
        assert!(display.contains("_checksum:"));
    }
}
