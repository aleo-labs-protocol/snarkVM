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

impl<N: Network> Parser for FinalizeType<N> {
    /// Parses a string into a finalize type.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the mode from the string (ordering matters).
        alt((
            map(tag("dynamic.future"), |_| Self::DynamicFuture),
            map(pair(Locator::parse, tag(".future")), |(locator, _)| Self::Future(locator)),
            map(pair(PlaintextType::parse, tag(".public")), |(plaintext_type, _)| Self::Plaintext(plaintext_type)),
        ))(string)
    }
}

impl<N: Network> FromStr for FinalizeType<N> {
    type Err = Error;

    /// Returns a finalize type from a string literal.
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

impl<N: Network> Debug for FinalizeType<N> {
    /// Prints the finalize type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for FinalizeType<N> {
    /// Prints the finalize type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            // Prints the plaintext type, i.e. signature
            Self::Plaintext(plaintext_type) => write!(f, "{plaintext_type}.public"),
            // Prints the future type, i.e. future
            Self::Future(locator) => write!(f, "{locator}.future"),
            // Prints out the dynamic future type, i.e. dynamic.future
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
            Ok(("", FinalizeType::<CurrentNetwork>::Plaintext(PlaintextType::from_str("field")?))),
            FinalizeType::<CurrentNetwork>::parse("field.public")
        );

        // Struct type.
        assert_eq!(
            Ok(("", FinalizeType::<CurrentNetwork>::Plaintext(PlaintextType::from_str("signature")?))),
            FinalizeType::<CurrentNetwork>::parse("signature.public")
        );

        // Future type.
        assert_eq!(
            Ok(("", FinalizeType::<CurrentNetwork>::Future(Locator::from_str("credits.aleo/mint_public")?))),
            FinalizeType::<CurrentNetwork>::parse("credits.aleo/mint_public.future")
        );

        // Dynamic future type.
        assert_eq!(
            Ok(("", FinalizeType::<CurrentNetwork>::DynamicFuture)),
            FinalizeType::<CurrentNetwork>::parse("dynamic.future")
        );

        Ok(())
    }

    #[test]
    fn test_parse_fails() -> Result<()> {
        // Must be non-empty.
        assert!(FinalizeType::<CurrentNetwork>::parse("").is_err());

        // Invalid characters.
        assert!(FinalizeType::<CurrentNetwork>::parse("{}").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("_").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("__").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("___").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("-").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("--").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("---").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("*").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("**").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(FinalizeType::<CurrentNetwork>::parse("1").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("2").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("3").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("12").is_err());
        assert!(FinalizeType::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let struct_ = FinalizeType::<CurrentNetwork>::parse(
            "foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy.private",
        );
        assert!(struct_.is_err());

        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        assert_eq!(FinalizeType::<CurrentNetwork>::from_str("field.public")?.to_string(), "field.public");
        assert_eq!(FinalizeType::<CurrentNetwork>::from_str("signature.public")?.to_string(), "signature.public");
        assert_eq!(
            FinalizeType::<CurrentNetwork>::from_str("credits.aleo/mint_public.future")?.to_string(),
            "credits.aleo/mint_public.future"
        );
        assert_eq!(FinalizeType::<CurrentNetwork>::from_str("dynamic.future")?.to_string(), "dynamic.future");

        Ok(())
    }
}
