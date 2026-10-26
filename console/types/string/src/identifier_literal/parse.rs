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

impl<E: Environment> Parser for IdentifierLiteral<E> {
    /// Parses a string into an identifier literal.
    /// Syntax: `'<identifier>'` where identifier matches `[a-zA-Z][a-zA-Z0-9_]*`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Match the opening single quote.
        let (string, _) = tag("'")(string)?;
        // Match identifier content: starts with a letter, followed by alphanumeric or underscore.
        let (string, literal) =
            map_res(recognize(pair(alpha1, many0(alt((alphanumeric1, tag("_")))))), Self::new)(string)?;
        // Match the closing single quote.
        let (string, _) = tag("'")(string)?;
        Ok((string, literal))
    }
}

impl<E: Environment> FromStr for IdentifierLiteral<E> {
    type Err = Error;

    /// Parses a string into an identifier literal.
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

impl<E: Environment> Debug for IdentifierLiteral<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for IdentifierLiteral<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Read the content bytes up to the null terminator.
        let n = self.length() as usize;
        let s = core::str::from_utf8(&self.bytes[..n]).map_err(|_| fmt::Error)?;
        write!(f, "'{s}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    #[test]
    fn test_parse_valid() {
        // Simple identifier.
        let (remainder, literal) = IdentifierLiteral::<CurrentEnvironment>::parse("'hello'").unwrap();
        assert_eq!(remainder, "");
        assert_eq!(literal.to_string(), "'hello'");

        // Identifier with underscores and digits.
        let (remainder, literal) = IdentifierLiteral::<CurrentEnvironment>::parse("'hello_world_42'").unwrap();
        assert_eq!(remainder, "");
        assert_eq!(literal.to_string(), "'hello_world_42'");

        // Single character.
        let (remainder, literal) = IdentifierLiteral::<CurrentEnvironment>::parse("'a'").unwrap();
        assert_eq!(remainder, "");
        assert_eq!(literal.to_string(), "'a'");
    }

    #[test]
    fn test_parse_with_remainder() {
        let (remainder, literal) = IdentifierLiteral::<CurrentEnvironment>::parse("'hello' rest").unwrap();
        assert_eq!(remainder, " rest");
        assert_eq!(literal.to_string(), "'hello'");
    }

    #[test]
    fn test_parse_invalid() {
        // Missing quotes.
        assert!(IdentifierLiteral::<CurrentEnvironment>::parse("hello").is_err());
        // Missing closing quote.
        assert!(IdentifierLiteral::<CurrentEnvironment>::parse("'hello").is_err());
        // Empty content.
        assert!(IdentifierLiteral::<CurrentEnvironment>::parse("''").is_err());
        // Invalid characters.
        assert!(IdentifierLiteral::<CurrentEnvironment>::parse("'hello world'").is_err());
        // Starts with digit.
        assert!(IdentifierLiteral::<CurrentEnvironment>::parse("'1abc'").is_err());
    }

    #[test]
    fn test_parse_roundtrip() {
        let original = IdentifierLiteral::<CurrentEnvironment>::new("hello_world").unwrap();
        let display = original.to_string();
        let recovered = IdentifierLiteral::<CurrentEnvironment>::from_str(&display).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_display() {
        let literal = IdentifierLiteral::<CurrentEnvironment>::new("hello").unwrap();
        assert_eq!(literal.to_string(), "'hello'");
    }

    #[test]
    fn test_parse_random() {
        const ITERATIONS: u64 = 1000;
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let expected = IdentifierLiteral::<CurrentEnvironment>::rand(&mut rng);
            let display = expected.to_string();
            let recovered = IdentifierLiteral::<CurrentEnvironment>::from_str(&display).unwrap();
            assert_eq!(expected, recovered);
        }
    }
}
