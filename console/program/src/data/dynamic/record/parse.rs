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

impl<N: Network> Parser for DynamicRecord<N> {
    /// Parses a string as a dynamic record: `{ owner: address, _root: field, _nonce: group, _version: u8 }`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "{" from the string.
        let (string, _) = tag("{")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "owner" tag from the string.
        let (string, _) = tag("owner")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the owner from the string.
        let (string, owner) = Address::parse(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_root" tag from the string.
        let (string, _) = tag("_root")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the root from the string.
        let (string, root) = Field::parse(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_nonce" tag from the string.
        let (string, _) = tag("_nonce")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the nonce from the string.
        let (string, nonce) = Group::parse(string)?;

        // There may be an optional "_version" tag. Consume the "," separator if it exists.
        let string = match opt(tag(","))(string)? {
            // The "," was consumed; continue with the advanced string.
            (string, Some(_)) => string,
            // No "," found; keep the string as is.
            (string, None) => string,
        };

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the optional "_version" tag from the string.
        let (string, version) = match opt(tag("_version"))(string)? {
            // If there is no version, then set the version to zero.
            (string, None) => (string, U8::zero()),
            // If there is a version, then parse the version from the string.
            (string, Some(_)) => {
                // Parse the whitespace from the string.
                let (string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the ":" from the string.
                let (string, _) = tag(":")(string)?;
                // Parse the whitespace and comments from the string.
                let (string, _) = Sanitizer::parse(string)?;
                // Parse the version from the string.
                U8::parse(string)?
            }
        };

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the '}' from the string.
        let (string, _) = tag("}")(string)?;
        // Output the dynamic record.
        Ok((string, DynamicRecord::new_unchecked(owner, root, nonce, version, None)))
    }
}

impl<N: Network> FromStr for DynamicRecord<N> {
    type Err = Error;

    /// Returns a dynamic record from a string literal.
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

impl<N: Network> Debug for DynamicRecord<N> {
    /// Prints the dynamic record as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for DynamicRecord<N> {
    /// Prints the dynamic record as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.fmt_internal(f, 0)
    }
}

impl<N: Network> DynamicRecord<N> {
    /// Prints the dynamic record with the given indentation depth.
    fn fmt_internal(&self, f: &mut Formatter, depth: usize) -> fmt::Result {
        /// The number of spaces to indent.
        const INDENT: usize = 2;

        // Print the opening brace.
        write!(f, "{{")?;
        // Print the owner with a comma.
        write!(f, "\n{:indent$}owner: {},", "", self.owner, indent = (depth + 1) * INDENT)?;
        // Print the root with a comma.
        write!(f, "\n{:indent$}_root: {},", "", self.root, indent = (depth + 1) * INDENT)?;
        // Print the nonce with a comma.
        write!(f, "\n{:indent$}_nonce: {},", "", self.nonce, indent = (depth + 1) * INDENT)?;
        // Print the version without a comma.
        write!(f, "\n{:indent$}_version: {}", "", self.version, indent = (depth + 1) * INDENT)?;
        // Print the closing brace.
        write!(f, "\n{:indent$}}}", "", indent = depth * INDENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Entry, Literal, Owner, Record};
    use snarkvm_console_network::MainnetV0;
    use snarkvm_console_types::U64;
    use snarkvm_utilities::{TestRng, Uniform};

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_display_roundtrip() {
        let rng = &mut TestRng::default();

        // Create a simple record.
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();

        // Convert to dynamic record.
        let expected = DynamicRecord::from_record(&record).unwrap();

        // Convert to string.
        let expected_string = expected.to_string();

        // Parse the string.
        let candidate = DynamicRecord::<CurrentNetwork>::from_str(&expected_string).unwrap();

        // Verify the fields match.
        assert_eq!(expected.owner(), candidate.owner());
        assert_eq!(expected.root(), candidate.root());
        assert_eq!(expected.nonce(), candidate.nonce());
        assert_eq!(expected.version(), candidate.version());
    }

    #[test]
    fn test_parse() {
        // Parse a dynamic record from a string.
        let string = "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah, _root: 0field, _nonce: 0group, _version: 0u8 }";
        let (remainder, candidate) = DynamicRecord::<CurrentNetwork>::parse(string).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(
            *candidate.owner(),
            Address::from_str("aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah").unwrap()
        );
        assert_eq!(*candidate.root(), Field::from_u64(0));
        assert_eq!(*candidate.nonce(), Group::zero());
        assert_eq!(*candidate.version(), U8::new(0));
    }

    #[test]
    fn test_parse_without_version() {
        // Parse a dynamic record without a version (should default to 0).
        let string = "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah, _root: 123field, _nonce: 0group }";
        let (remainder, candidate) = DynamicRecord::<CurrentNetwork>::parse(string).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(*candidate.version(), U8::new(0));
    }

    #[test]
    fn test_display() {
        let rng = &mut TestRng::default();

        // Create a simple record.
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            indexmap::IndexMap::new(),
            Group::rand(rng),
            U8::new(1),
        )
        .unwrap();

        // Convert to dynamic record.
        let dynamic = DynamicRecord::from_record(&record).unwrap();

        // Check that the display contains expected fields.
        let display = dynamic.to_string();
        assert!(display.contains("owner:"));
        assert!(display.contains("_root:"));
        assert!(display.contains("_nonce:"));
        assert!(display.contains("_version:"));
    }
}
