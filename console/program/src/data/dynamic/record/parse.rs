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
    /// The string may optionally carry the entry data: `{ ..., _data: { identifier_0: entry_0, ..., identifier_n: entry_n } }`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses a sanitized pair: `identifier: entry`.
        #[allow(clippy::type_complexity)]
        fn parse_entry_pair<N: Network>(string: &str) -> ParserResult<'_, (Identifier<N>, Entry<N, Plaintext<N>>)> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the identifier from the string.
            let (string, identifier) = Identifier::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the ":" from the string.
            let (string, _) = tag(":")(string)?;
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the entry from the string.
            let (string, entry) = Entry::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Return the identifier and entry.
            Ok((string, (identifier, entry)))
        }
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

        // `_version` is optional. The comma is consumed only when the field follows it.
        let (string, version) = match opt(pair(tag(","), pair(Sanitizer::parse, tag("_version"))))(string)? {
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
                let (string, version) = U8::parse(string)?;
                (string, version)
            }
        };

        // `_data` is optional. The comma is consumed only when the field follows it.
        let (string, data) = match opt(pair(tag(","), pair(Sanitizer::parse, tag("_data"))))(string)? {
            // If there is no data, then leave the record data unset.
            (string, None) => (string, None),
            // If there is data, then parse the entries from the string.
            (string, Some(_)) => {
                // Parse the whitespace from the string.
                let (string, _) = Sanitizer::parse_whitespaces(string)?;
                // Parse the ":" from the string.
                let (string, _) = tag(":")(string)?;
                // Parse the whitespace and comments from the string.
                let (string, _) = Sanitizer::parse(string)?;
                // Parse the "{" from the string.
                let (string, _) = tag("{")(string)?;
                // Parse the entries, and check that their Merkle root matches the root.
                let (string, data) = map_res(separated_list0(tag(","), parse_entry_pair), |entries: Vec<_>| {
                    // Prepare the reserved entry names.
                    let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
                    // Ensure the entries have no duplicate names.
                    if has_duplicates(entries.iter().map(|(identifier, _)| identifier).chain(reserved.iter())) {
                        return Err(error("Duplicate entry type found in dynamic record"));
                    }
                    // Ensure the number of entries is within the maximum limit.
                    if entries.len() > N::MAX_DATA_ENTRIES {
                        return Err(error(format!("Found a dynamic record that exceeds size ({})", entries.len())));
                    }
                    // Construct the record data.
                    let data = IndexMap::from_iter(entries);
                    // Check that the Merkle root matches the parsed data.
                    let tree = Self::merkleize_data(&data).map_err(|e| error(e.to_string()))?;
                    if tree.root() != &root {
                        return Err(error(
                            "The root in the dynamic record does not match the one computed from its data",
                        ));
                    }
                    // Return the record data.
                    Ok(data)
                })(string)?;
                // Parse the whitespace and comments from the string.
                let (string, _) = Sanitizer::parse(string)?;
                // Parse the "}" from the string.
                let (string, _) = tag("}")(string)?;
                (string, Some(data))
            }
        };

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the '}' from the string.
        let (string, _) = tag("}")(string)?;
        // Output the dynamic record.
        Ok((string, DynamicRecord::new_unchecked(owner, root, nonce, version, data)))
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
    fn test_parse_with_data() {
        let rng = &mut TestRng::default();

        // Create a record with two entries.
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::rand(rng)))),
            Identifier::from_str("memo").unwrap() => Entry::Public(Plaintext::from(Literal::U64(U64::rand(rng)))),
        };
        let owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            owner,
            data.clone(),
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();

        // Construct the string form with the entry data.
        let entries = data.iter().map(|(name, entry)| format!("{name}: {entry}")).collect::<Vec<_>>().join(", ");
        let string = format!(
            "{{ owner: {}, _root: {}, _nonce: {}, _version: {}, _data: {{ {entries} }} }}",
            expected.owner(),
            expected.root(),
            expected.nonce(),
            expected.version(),
        );

        let candidate = DynamicRecord::<CurrentNetwork>::from_str(&string).unwrap();
        assert_eq!(expected.owner(), candidate.owner());
        assert_eq!(expected.root(), candidate.root());
        assert_eq!(expected.nonce(), candidate.nonce());
        assert_eq!(expected.version(), candidate.version());
        assert_eq!(expected.data(), candidate.data());
        assert_eq!(candidate.data().as_ref(), Some(&data));
    }

    #[test]
    fn test_parse_with_data_rejects_mismatched_root() {
        let rng = &mut TestRng::default();

        // Create a record with one entry.
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
        let expected = DynamicRecord::from_record(&record).unwrap();

        // Construct the string form with a root that does not match the entry data.
        let string = format!(
            "{{ owner: {}, _root: 12345field, _nonce: {}, _version: {}, _data: {{ amount: 1u64.private }} }}",
            expected.owner(),
            expected.nonce(),
            expected.version(),
        );

        assert!(DynamicRecord::<CurrentNetwork>::from_str(&string).is_err());
    }

    #[test]
    fn test_parse_with_data_rejects_duplicate_names() {
        let rng = &mut TestRng::default();

        // Parse a dynamic record with a duplicate entry name in `_data`.
        let string = format!(
            "{{ owner: {}, _root: 0field, _nonce: {}, _version: 0u8, _data: {{ amount: 1u64.private, amount: 2u64.private }} }}",
            Address::<CurrentNetwork>::rand(rng),
            Group::<CurrentNetwork>::rand(rng),
        );
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&string).is_err());

        // Parse a dynamic record with a reserved entry name in `_data`.
        let string = format!(
            "{{ owner: {}, _root: 0field, _nonce: {}, _version: 0u8, _data: {{ owner: 1u64.private }} }}",
            Address::<CurrentNetwork>::rand(rng),
            Group::<CurrentNetwork>::rand(rng),
        );
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&string).is_err());
    }

    #[test]
    fn test_parse_rejects_loose_commas() {
        let owner = "aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah";

        // A comma with no field after it.
        let trailing = format!("{{ owner: {owner}, _root: 0field, _nonce: 0group, _version: 0u8, }}");
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&trailing).is_err(), "trailing comma");

        // A second comma where `_version` and `_data` are both absent.
        let doubled = format!("{{ owner: {owner}, _root: 0field, _nonce: 0group,, }}");
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&doubled).is_err(), "double comma");
        let spaced = format!("{{ owner: {owner}, _root: 0field, _nonce: 0group, , }}");
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&spaced).is_err(), "spaced double comma");

        let rng = &mut TestRng::default();
        let data = indexmap::indexmap! {
            Identifier::from_str("amount").unwrap() => Entry::Private(Plaintext::from(Literal::U64(U64::new(1)))),
        };
        let record_owner = Owner::Public(Address::rand(rng));
        let record = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::from_plaintext(
            record_owner,
            data,
            Group::rand(rng),
            U8::new(0),
        )
        .unwrap();
        let expected = DynamicRecord::from_record(&record).unwrap();
        let valid = format!(
            "{{ owner: {}, _root: {}, _nonce: {}, _version: {}, _data: {{ amount: 1u64.private }} }}",
            expected.owner(),
            expected.root(),
            expected.nonce(),
            expected.version(),
        );
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&valid).is_ok());

        // `_data` is present, so the comma in front of it is required.
        let missing_comma = valid.replacen(", _data:", " _data:", 1);
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&missing_comma).is_err(), "missing comma before _data");

        // The same root matches one entry. A trailing or doubled comma must not parse as that entry.
        let trailing_entry = valid.replacen("1u64.private }", "1u64.private, }", 1);
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&trailing_entry).is_err(), "trailing comma in _data");
        let doubled_entry = valid.replacen("amount: 1u64.private", "amount: 1u64.private,, amount: 2u64.private", 1);
        assert!(DynamicRecord::<CurrentNetwork>::from_str(&doubled_entry).is_err(), "double comma in _data");

        // `_version` may be omitted when the comma that introduces `_data` is present.
        let without_version = format!(
            "{{ owner: {}, _root: {}, _nonce: {}, _data: {{ amount: 1u64.private }} }}",
            expected.owner(),
            expected.root(),
            expected.nonce(),
        );
        let candidate = DynamicRecord::<CurrentNetwork>::from_str(&without_version).unwrap();
        assert_eq!(*candidate.version(), U8::new(0));
        assert_eq!(expected.data(), candidate.data());
    }

    #[test]
    fn test_parse_rejects_oversized_nested_bits() {
        let rng = &mut TestRng::default();
        let owner = Address::<CurrentNetwork>::rand(rng);
        let nonce = Group::<CurrentNetwork>::rand(rng);
        let elements = (0..1024).map(|_| "1u64.private".to_string()).collect::<Vec<_>>().join(", ");
        let string = format!(
            "{{ owner: {owner}, _root: 0field, _nonce: {nonce}, _version: 0u8, _data: {{ amount: [[{elements}]] }} }}"
        );
        let parsed = std::panic::catch_unwind(|| DynamicRecord::<CurrentNetwork>::from_str(&string));
        let parsed = parsed.expect("oversized entry data panicked during parsing");
        assert!(parsed.is_err(), "oversized entry data must be rejected");
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
