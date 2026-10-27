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

impl<N: Network> Parser for EntryType<N> {
    /// Parses a string into the entry type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the mode from the string.
        alt((
            map(pair(PlaintextType::parse, tag(".constant")), |(plaintext_type, _)| Self::Constant(plaintext_type)),
            map(pair(PlaintextType::parse, tag(".public")), |(plaintext_type, _)| Self::Public(plaintext_type)),
            map(pair(PlaintextType::parse, tag(".private")), |(plaintext_type, _)| Self::Private(plaintext_type)),
        ))(string)
    }
}

impl<N: Network> FromStr for EntryType<N> {
    type Err = Error;

    /// Returns the entry type from a string literal.
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

impl<N: Network> Debug for EntryType<N> {
    /// Prints the entry type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for EntryType<N> {
    /// Prints the entry type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Constant(plaintext_type) => write!(f, "{plaintext_type}.constant"),
            Self::Public(plaintext_type) => write!(f, "{plaintext_type}.public"),
            Self::Private(plaintext_type) => write!(f, "{plaintext_type}.private"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() -> Result<()> {
        // Literal type.
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("field.constant")?)),
            EntryType::<CurrentNetwork>::parse("field.constant")
        );
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("field.public")?)),
            EntryType::<CurrentNetwork>::parse("field.public")
        );
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("field.private")?)),
            EntryType::<CurrentNetwork>::parse("field.private")
        );

        // Struct type.
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("signature.constant")?)),
            EntryType::<CurrentNetwork>::parse("signature.constant")
        );
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("signature.public")?)),
            EntryType::<CurrentNetwork>::parse("signature.public")
        );
        assert_eq!(
            Ok(("", EntryType::<CurrentNetwork>::from_str("signature.private")?)),
            EntryType::<CurrentNetwork>::parse("signature.private")
        );

        Ok(())
    }

    #[test]
    fn test_parse_fails() -> Result<()> {
        // Literal type must contain visibility.
        assert!(EntryType::<CurrentNetwork>::parse("field").is_err());
        // Struct type must contain visibility.
        assert!(EntryType::<CurrentNetwork>::parse("signature").is_err());
        // Record type must contain record keyword.
        assert!(EntryType::<CurrentNetwork>::parse("token").is_err());

        // Must be non-empty.
        assert!(EntryType::<CurrentNetwork>::parse("").is_err());

        // Invalid characters.
        assert!(EntryType::<CurrentNetwork>::parse("{}").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("_").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("__").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("___").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("-").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("--").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("---").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("*").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("**").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(EntryType::<CurrentNetwork>::parse("1").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("2").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("3").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("12").is_err());
        assert!(EntryType::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let struct_ = EntryType::<CurrentNetwork>::parse(
            "foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy.private",
        );
        assert!(struct_.is_err());

        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        assert_eq!(EntryType::<CurrentNetwork>::from_str("field.constant")?.to_string(), "field.constant");
        assert_eq!(EntryType::<CurrentNetwork>::from_str("field.public")?.to_string(), "field.public");
        assert_eq!(EntryType::<CurrentNetwork>::from_str("field.private")?.to_string(), "field.private");

        assert_eq!(EntryType::<CurrentNetwork>::from_str("signature.constant")?.to_string(), "signature.constant");
        assert_eq!(EntryType::<CurrentNetwork>::from_str("signature.public")?.to_string(), "signature.public");
        assert_eq!(EntryType::<CurrentNetwork>::from_str("signature.private")?.to_string(), "signature.private");

        Ok(())
    }
}
