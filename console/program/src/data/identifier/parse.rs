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

impl<N: Network> Parser for Identifier<N> {
    /// Parses a string into an identifier.
    ///
    /// # Requirements
    /// The identifier must be alphanumeric (or underscore).
    /// The identifier must not start with a number.
    /// The identifier must not be a keyword.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Check for alphanumeric characters and underscores.
        map_res(recognize(pair(alpha1, many0(alt((alphanumeric1, tag("_")))))), |identifier: &str| {
            Self::from_str(identifier)
        })(string)
    }
}

impl<N: Network> FromStr for Identifier<N> {
    type Err = Error;

    /// Reads in an identifier from a string.
    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        // Ensure the identifier is not an empty string, and starts with an ASCII letter.
        // Note. The first character must not be the NULL character for sound encoding of dynamic futures. See the implementation of `ToBits` for `Argument`.
        match identifier.chars().next() {
            Some(character) => ensure!(character.is_ascii_alphabetic(), "Identifier must start with a letter"),
            None => bail!("Identifier cannot be empty"),
        }

        // Ensure the identifier consists of ASCII letters, ASCII digits, and underscores.
        if identifier.chars().any(|character| !character.is_ascii_alphanumeric() && character != '_') {
            bail!("Identifier '{identifier}' must consist of letters, digits, and underscores")
        }

        // Ensure identifier fits within the data capacity of the base field.
        let max_bytes = Field::<N>::size_in_data_bits() / 8; // Note: This intentionally rounds down.
        if identifier.len() > max_bytes {
            bail!("Identifier is too large. Identifiers must be <= {max_bytes} bytes long")
        }

        // Ensure that the identifier is not a literal.
        ensure!(
            !enum_iterator::all::<crate::LiteralType>().any(|lt| lt.type_name() == identifier),
            "Identifier '{identifier}' is a reserved literal type"
        );

        // Note: The string bytes themselves are **not** little-endian. Rather, they are order-preserving
        // for reconstructing the string when recovering the field element back into bytes.
        Ok(Self(
            Field::<N>::from_bits_le(&identifier.as_bytes().to_bits_le())?,
            u8::try_from(identifier.len()).or_halt_with::<N>("Identifier `from_str` exceeds maximum length"),
        ))
    }
}

impl<N: Network> Debug for Identifier<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Identifier<N> {
    /// Prints the identifier as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the identifier to bytes.
        let bytes = self.0.to_bytes_le().map_err(|_| fmt::Error)?;

        // Parse the bytes as a UTF-8 string.
        let string = String::from_utf8(bytes).map_err(|_| fmt::Error)?;

        // Truncate the UTF-8 string at the first instance of '\0'.
        match string.split('\0').next() {
            // Check that the UTF-8 string matches the expected length.
            Some(string) => match string.len() == self.1 as usize {
                // Return the string.
                true => write!(f, "{string}"),
                false => Err(fmt::Error),
            },
            None => Err(fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::identifier::tests::{sample_identifier, sample_identifier_as_string};
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_parse() -> Result<()> {
        // Quick sanity check.
        let (remainder, candidate) = Identifier::<CurrentNetwork>::parse("foo_bar1")?;
        assert_eq!("foo_bar1", candidate.to_string());
        assert_eq!("", remainder);

        // Must be alphanumeric or underscore.
        let (remainder, candidate) = Identifier::<CurrentNetwork>::parse("foo_bar~baz")?;
        assert_eq!("foo_bar", candidate.to_string());
        assert_eq!("~baz", remainder);

        // Must be alphanumeric or underscore.
        let (remainder, candidate) = Identifier::<CurrentNetwork>::parse("foo_bar-baz")?;
        assert_eq!("foo_bar", candidate.to_string());
        assert_eq!("-baz", remainder);

        let mut rng = TestRng::default();

        // Check random identifiers.
        for _ in 0..ITERATIONS {
            // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
            let expected_string = sample_identifier_as_string::<CurrentNetwork>(&mut rng)?;
            // Recover the field element from the bits.
            let expected_field = Field::<CurrentNetwork>::from_bits_le(&expected_string.to_bits_le())?;

            let (remainder, candidate) = Identifier::<CurrentNetwork>::parse(expected_string.as_str()).unwrap();
            assert_eq!(expected_string, candidate.to_string());
            assert_eq!(expected_field, candidate.0);
            assert_eq!(expected_string.len(), candidate.1 as usize);
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_parse_fails() {
        // Must not be solely underscores.
        assert!(Identifier::<CurrentNetwork>::parse("_").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("__").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("___").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("____").is_err());

        // Must not start with a number.
        assert!(Identifier::<CurrentNetwork>::parse("1").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("2").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("3").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("1foo").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("12").is_err());
        assert!(Identifier::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let identifier =
            Identifier::<CurrentNetwork>::parse("foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy");
        assert!(identifier.is_err());
    }

    #[test]
    fn test_from_str() -> Result<()> {
        let candidate = Identifier::<CurrentNetwork>::from_str("foo_bar").unwrap();
        assert_eq!("foo_bar", candidate.to_string());

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random fixed-length alphanumeric string, that always starts with an alphabetic character.
            let expected_string = sample_identifier_as_string::<CurrentNetwork>(&mut rng)?;
            // Recover the field element from the bits.
            let expected_field = Field::<CurrentNetwork>::from_bits_le(&expected_string.to_bits_le())?;

            let candidate = Identifier::<CurrentNetwork>::from_str(&expected_string)?;
            assert_eq!(expected_string, candidate.to_string());
            assert_eq!(expected_field, candidate.0);
            assert_eq!(expected_string.len(), candidate.1 as usize);
        }
        Ok(())
    }

    #[test]
    fn test_from_str_fails() {
        // Must be non-empty.
        assert!(Identifier::<CurrentNetwork>::from_str("").is_err());

        // Must be alphanumeric or underscore.
        assert!(Identifier::<CurrentNetwork>::from_str("foo_bar~baz").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("foo_bar-baz").is_err());

        // Must not be solely underscores.
        assert!(Identifier::<CurrentNetwork>::from_str("_").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("__").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("___").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("____").is_err());

        // Must not start with a number.
        assert!(Identifier::<CurrentNetwork>::from_str("1").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("2").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("3").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("1foo").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("12").is_err());
        assert!(Identifier::<CurrentNetwork>::from_str("111").is_err());

        // Must not start with underscore.
        assert!(Identifier::<CurrentNetwork>::from_str("_foo").is_err());

        // Must be ASCII.
        assert!(Identifier::<CurrentNetwork>::from_str("\u{03b1}").is_err()); // Greek alpha
        assert!(Identifier::<CurrentNetwork>::from_str("\u{03b2}").is_err()); // Greek beta

        // Must fit within the data capacity of a base field element.
        let identifier = Identifier::<CurrentNetwork>::from_str(
            "foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy",
        );
        assert!(identifier.is_err());
    }

    #[test]
    fn test_display() -> Result<()> {
        let identifier = Identifier::<CurrentNetwork>::from_str("foo_bar")?;
        assert_eq!("foo_bar", format!("{identifier}"));
        Ok(())
    }

    #[test]
    fn test_proxy_bits_equivalence() -> Result<()> {
        let mut rng = TestRng::default();
        let identifier: Identifier<CurrentNetwork> = sample_identifier(&mut rng)?;

        // Direct conversion to bytes.
        let bytes1 = identifier.0.to_bytes_le()?;

        // Combined conversion via bits.
        let bits_le = identifier.0.to_bits_le();
        let bytes2 = bits_le.chunks(8).map(u8::from_bits_le).collect::<Result<Vec<u8>, _>>()?;

        assert_eq!(bytes1, bytes2);

        Ok(())
    }
}
