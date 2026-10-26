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

impl<N: Network> Parser for PlaintextType<N> {
    /// Parses a string into a plaintext type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse to determine the plaintext type (order matters).
        alt((
            // Order matters - we shouldn't try to parse Identifier before Locator.
            map(ArrayType::parse, |type_| Self::Array(type_)),
            map(Locator::parse, |locator| Self::ExternalStruct(locator)),
            map(Identifier::parse, |identifier| Self::Struct(identifier)),
            map(LiteralType::parse, |type_| Self::Literal(type_)),
        ))(string)
    }
}

impl<N: Network> FromStr for PlaintextType<N> {
    type Err = Error;

    /// Returns a plaintext type from a string literal.
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

impl<N: Network> Debug for PlaintextType<N> {
    /// Prints the plaintext type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for PlaintextType<N> {
    /// Prints the plaintext type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            // Prints the literal, i.e. field
            Self::Literal(literal) => Display::fmt(literal, f),
            // Prints the struct, i.e. signature
            Self::Struct(struct_) => Display::fmt(struct_, f),
            // Prints the external struct, i.e. foo.aleo/bar
            Self::ExternalStruct(locator) => Display::fmt(locator, f),
            // Prints the array type, i.e. [field; 2u32]
            Self::Array(array) => Display::fmt(array, f),
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
        assert_eq!(
            PlaintextType::parse("field"),
            Ok(("", PlaintextType::<CurrentNetwork>::Literal(LiteralType::Field)))
        );
        assert_eq!(
            PlaintextType::parse("signature"),
            Ok(("", PlaintextType::<CurrentNetwork>::Literal(LiteralType::Signature)))
        );
        assert_eq!(
            PlaintextType::parse("foo"),
            Ok(("", PlaintextType::<CurrentNetwork>::Struct(Identifier::from_str("foo")?)))
        );
        assert_eq!(
            PlaintextType::parse("u8jdsklaj"),
            Ok(("", PlaintextType::<CurrentNetwork>::Struct(Identifier::from_str("u8jdsklaj")?)))
        );
        assert_eq!(
            PlaintextType::parse("[field; 1u32]"),
            Ok(("", PlaintextType::<CurrentNetwork>::Array(ArrayType::from_str("[field; 1u32]")?)))
        );
        Ok(())
    }

    #[test]
    fn test_parse_fails() -> Result<()> {
        // Literal type must not contain visibility.
        assert_eq!(
            Ok((".constant", PlaintextType::<CurrentNetwork>::from_str("field")?)),
            PlaintextType::<CurrentNetwork>::parse("field.constant")
        );
        assert_eq!(
            Ok((".public", PlaintextType::<CurrentNetwork>::from_str("field")?)),
            PlaintextType::<CurrentNetwork>::parse("field.public")
        );
        assert_eq!(
            Ok((".private", PlaintextType::<CurrentNetwork>::from_str("field")?)),
            PlaintextType::<CurrentNetwork>::parse("field.private")
        );

        // Struct type must not contain visibility.
        assert_eq!(
            Ok((".constant", Identifier::<CurrentNetwork>::from_str("foo")?)),
            Identifier::<CurrentNetwork>::parse("foo.constant")
        );
        assert_eq!(
            Ok((".public", Identifier::<CurrentNetwork>::from_str("foo")?)),
            Identifier::<CurrentNetwork>::parse("foo.public")
        );
        assert_eq!(
            Ok((".private", Identifier::<CurrentNetwork>::from_str("foo")?)),
            Identifier::<CurrentNetwork>::parse("foo.private")
        );

        // Array type must not contain visibility.
        assert_eq!(
            Ok((".constant", PlaintextType::<CurrentNetwork>::from_str("[field; 1u32]")?)),
            PlaintextType::<CurrentNetwork>::parse("[field; 1u32].constant")
        );
        assert_eq!(
            Ok((".public", PlaintextType::<CurrentNetwork>::from_str("[field; 1u32]")?)),
            PlaintextType::<CurrentNetwork>::parse("[field; 1u32].public")
        );
        assert_eq!(
            Ok((".private", PlaintextType::<CurrentNetwork>::from_str("[field; 1u32]")?)),
            PlaintextType::<CurrentNetwork>::parse("[field; 1u32].private")
        );

        // Must be non-empty.
        assert!(PlaintextType::<CurrentNetwork>::parse("").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("{}").is_err());

        // Invalid characters.
        assert!(PlaintextType::<CurrentNetwork>::parse("_").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("__").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("___").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("-").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("--").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("---").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("*").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("**").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(PlaintextType::<CurrentNetwork>::parse("1").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("2").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("3").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("12").is_err());
        assert!(PlaintextType::<CurrentNetwork>::parse("111").is_err());

        // Struct types must fit within the data capacity of a base field element.
        let struct_ = PlaintextType::<CurrentNetwork>::parse(
            "foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy",
        );
        assert!(struct_.is_err());

        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        assert_eq!(PlaintextType::<CurrentNetwork>::Literal(LiteralType::Boolean).to_string(), "boolean");
        assert_eq!(PlaintextType::<CurrentNetwork>::Literal(LiteralType::Field).to_string(), "field");
        assert_eq!(PlaintextType::<CurrentNetwork>::Literal(LiteralType::Signature).to_string(), "signature");
        assert_eq!(PlaintextType::<CurrentNetwork>::Struct(Identifier::from_str("foo")?).to_string(), "foo");
        assert_eq!(PlaintextType::<CurrentNetwork>::Struct(Identifier::from_str("bar")?).to_string(), "bar");
        assert_eq!(
            PlaintextType::<CurrentNetwork>::Array(ArrayType::from_str("[field; 8u32]")?).to_string(),
            "[field; 8u32]"
        );
        Ok(())
    }
}
