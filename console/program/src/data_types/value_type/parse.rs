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

impl<N: Network> Parser for ValueType<N> {
    /// Parses the string into a value type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the mode from the string.
        // Note that the order of the parsers matters.
        alt((
            map(tag("dynamic.record"), |_| Self::DynamicRecord),
            map(tag("dynamic.future"), |_| Self::DynamicFuture),
            map(pair(PlaintextType::parse, tag(".constant")), |(plaintext_type, _)| Self::Constant(plaintext_type)),
            map(pair(PlaintextType::parse, tag(".public")), |(plaintext_type, _)| Self::Public(plaintext_type)),
            map(pair(PlaintextType::parse, tag(".private")), |(plaintext_type, _)| Self::Private(plaintext_type)),
            map(pair(Identifier::parse, tag(".record")), |(identifier, _)| Self::Record(identifier)),
            map(pair(Locator::parse, tag(".record")), |(locator, _)| Self::ExternalRecord(locator)),
            map(pair(Locator::parse, tag(".future")), |(locator, _)| Self::Future(locator)),
        ))(string)
    }
}

impl<N: Network> FromStr for ValueType<N> {
    type Err = Error;

    /// Returns the value type from a string literal.
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

impl<N: Network> Debug for ValueType<N> {
    /// Prints the value type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for ValueType<N> {
    /// Prints the value type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Constant(plaintext_type) => write!(f, "{plaintext_type}.constant"),
            Self::Public(plaintext_type) => write!(f, "{plaintext_type}.public"),
            Self::Private(plaintext_type) => write!(f, "{plaintext_type}.private"),
            Self::Record(identifier) => write!(f, "{identifier}.record"),
            Self::ExternalRecord(locator) => write!(f, "{locator}.record"),
            Self::Future(locator) => write!(f, "{locator}.future"),
            Self::DynamicRecord => write!(f, "dynamic.record"),
            Self::DynamicFuture => write!(f, "dynamic.future"),
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
            Ok(("", ValueType::<CurrentNetwork>::from_str("field.constant")?)),
            ValueType::<CurrentNetwork>::parse("field.constant")
        );
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("field.public")?)),
            ValueType::<CurrentNetwork>::parse("field.public")
        );
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("field.private")?)),
            ValueType::<CurrentNetwork>::parse("field.private")
        );

        // Struct type.
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("signature.constant")?)),
            ValueType::<CurrentNetwork>::parse("signature.constant")
        );
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("signature.public")?)),
            ValueType::<CurrentNetwork>::parse("signature.public")
        );
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("signature.private")?)),
            ValueType::<CurrentNetwork>::parse("signature.private")
        );
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("i8abc.constant")?)),
            ValueType::<CurrentNetwork>::parse("i8abc.constant")
        );

        // Record type.
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("token.record")?)),
            ValueType::<CurrentNetwork>::parse("token.record")
        );
        assert_eq!(
            ValueType::<CurrentNetwork>::Record(Identifier::from_str("message")?),
            ValueType::<CurrentNetwork>::parse("message.record")?.1
        );

        // ExternalRecord type.
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("howard.aleo/message.record")?)),
            ValueType::<CurrentNetwork>::parse("howard.aleo/message.record")
        );
        assert_eq!(
            ValueType::<CurrentNetwork>::ExternalRecord(Locator::from_str("howard.aleo/message")?),
            ValueType::<CurrentNetwork>::parse("howard.aleo/message.record")?.1
        );

        // Future type.
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("credits.aleo/mint_public.future")?)),
            ValueType::<CurrentNetwork>::parse("credits.aleo/mint_public.future")
        );
        assert_eq!(
            ValueType::<CurrentNetwork>::Future(Locator::from_str("credits.aleo/mint_public")?),
            ValueType::<CurrentNetwork>::parse("credits.aleo/mint_public.future")?.1
        );

        // DynamicRecord type
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("dynamic.record")?)),
            ValueType::<CurrentNetwork>::parse("dynamic.record")
        );

        // DynamicFuture type
        assert_eq!(
            Ok(("", ValueType::<CurrentNetwork>::from_str("dynamic.future")?)),
            ValueType::<CurrentNetwork>::parse("dynamic.future")
        );

        Ok(())
    }

    #[test]
    fn test_parse_fails() -> Result<()> {
        // Literal type must contain visibility.
        assert!(ValueType::<CurrentNetwork>::parse("field").is_err());
        // Struct type must contain visibility.
        assert!(ValueType::<CurrentNetwork>::parse("signature").is_err());
        // Record type must contain record keyword.
        assert!(ValueType::<CurrentNetwork>::parse("token").is_err());

        // Must be non-empty.
        assert!(ValueType::<CurrentNetwork>::parse("").is_err());

        // Invalid characters.
        assert!(ValueType::<CurrentNetwork>::parse("{}").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("_").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("__").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("___").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("-").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("--").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("---").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("*").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("**").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(ValueType::<CurrentNetwork>::parse("1").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("2").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("3").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("12").is_err());
        assert!(ValueType::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let struct_ = ValueType::<CurrentNetwork>::parse(
            "foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy.private",
        );
        assert!(struct_.is_err());

        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        assert_eq!(ValueType::<CurrentNetwork>::from_str("field.constant")?.to_string(), "field.constant");
        assert_eq!(ValueType::<CurrentNetwork>::from_str("field.public")?.to_string(), "field.public");
        assert_eq!(ValueType::<CurrentNetwork>::from_str("field.private")?.to_string(), "field.private");

        assert_eq!(ValueType::<CurrentNetwork>::from_str("signature.constant")?.to_string(), "signature.constant");
        assert_eq!(ValueType::<CurrentNetwork>::from_str("signature.public")?.to_string(), "signature.public");
        assert_eq!(ValueType::<CurrentNetwork>::from_str("signature.private")?.to_string(), "signature.private");

        assert_eq!(ValueType::<CurrentNetwork>::from_str("token.record")?.to_string(), "token.record");

        assert_eq!(
            ValueType::<CurrentNetwork>::from_str("howard.aleo/message.record")?.to_string(),
            "howard.aleo/message.record"
        );

        assert_eq!(ValueType::<CurrentNetwork>::from_str("dynamic.record")?.to_string(), "dynamic.record");
        assert_eq!(ValueType::<CurrentNetwork>::from_str("dynamic.future")?.to_string(), "dynamic.future");

        Ok(())
    }
}
