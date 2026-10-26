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

impl<N: Network> Parser for RecordType<N> {
    /// Parses a record type as:
    /// ```text
    ///   record message:
    ///       owner as address.private;
    ///       user_defined as u64.public;
    /// ```
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses a string into a tuple.
        fn parse_entry<N: Network>(string: &str) -> ParserResult<'_, (Identifier<N>, EntryType<N>)> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the identifier from the string.
            let (string, identifier) = Identifier::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the "as" from the string.
            let (string, _) = tag("as")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the value type from the string.
            let (string, value_type) = EntryType::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the semicolon ';' keyword from the string.
            let (string, _) = tag(";")(string)?;
            // Return the identifier and value type.
            Ok((string, (identifier, value_type)))
        }

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the type name from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the record name from the string.
        let (string, name) = Identifier::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "owner" tag from the string.
        let (string, _) = tag("owner")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "as" from the string.
        let (string, _) = tag("as")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the owner visibility from the string.
        let (string, owner) = alt((
            map(tag("address.public"), |_| PublicOrPrivate::Public),
            map(tag("address.private"), |_| PublicOrPrivate::Private),
        ))(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ";" from the string.
        let (string, _) = tag(";")(string)?;

        // Parse the entries from the string.
        let (string, entries) = map_res(many0(parse_entry), |entries| {
            // Prepare the reserved entry names.
            let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
            // Ensure the entries has no duplicate names.
            if has_duplicates(entries.iter().map(|(identifier, _)| identifier).chain(reserved.iter())) {
                return Err(error(format!("Duplicate entry type found in record '{name}'")));
            }
            // Ensure the number of members is within the maximum limit.
            if entries.len() > N::MAX_DATA_ENTRIES {
                return Err(error("Failed to parse record: too many entries"));
            }
            Ok(entries)
        })(string)?;

        // Return the record type.
        Ok((string, Self { name, owner, entries: IndexMap::from_iter(entries) }))
    }
}

impl<N: Network> FromStr for RecordType<N> {
    type Err = Error;

    /// Returns an record type from a string literal.
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

impl<N: Network> Debug for RecordType<N> {
    /// Prints the record type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for RecordType<N> {
    /// Prints the record type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{} {}:", Self::type_name(), self.name)?;
        write!(f, "\n    owner as address.{};", self.owner)?;
        self.entries.iter().try_for_each(|(entry_name, entry_type)| write!(f, "\n    {entry_name} as {entry_type};"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() -> Result<()> {
        let expected = RecordType::<CurrentNetwork> {
            name: Identifier::from_str("message")?,
            owner: PublicOrPrivate::Private,
            entries: IndexMap::from_iter(vec![(
                Identifier::from_str("first")?,
                EntryType::from_str("field.constant")?,
            )]),
        };

        let (remainder, candidate) = RecordType::<CurrentNetwork>::parse(
            r"
record message:
    owner as address.private;
    first as field.constant;
",
        )?;
        assert_eq!("\n", remainder);
        assert_eq!(expected, candidate);
        Ok(())
    }

    #[test]
    fn test_parse_fails() {
        // Must be non-empty.
        assert!(RecordType::<CurrentNetwork>::parse("").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("record message:").is_err());

        // Invalid characters.
        assert!(RecordType::<CurrentNetwork>::parse("{}").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("_").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("__").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("___").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("-").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("--").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("---").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("*").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("**").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(RecordType::<CurrentNetwork>::parse("1").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("2").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("3").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("12").is_err());
        assert!(RecordType::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let record =
            RecordType::<CurrentNetwork>::parse("foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy");
        assert!(record.is_err());
    }

    #[test]
    fn test_display() {
        let expected = "record message:\n    owner as address.private;\n    first as field.private;\n    second as field.constant;";
        let message = RecordType::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{message}"));
    }

    #[test]
    fn test_display_fails() {
        // Duplicate identifier.
        let candidate = RecordType::<CurrentNetwork>::from_str(
            "record message:\n    owner as address.private;\n    first as field.public;\n    first as field.constant;",
        );
        assert!(candidate.is_err());

        // Visibility is missing in entry.
        let candidate = RecordType::<CurrentNetwork>::from_str(
            "record message:\n    owner as address.private;\n    first as field;\n    first as field.private;",
        );
        assert!(candidate.is_err());

        // Attempted to store another record inside.
        let candidate = RecordType::<CurrentNetwork>::from_str(
            "record message:\n    owner as address.private;\n    first as token.record;",
        );
        assert!(candidate.is_err());
    }

    #[test]
    fn test_parse_max_members() {
        let mut string = "record message:\n    owner as address.private;\n".to_string();
        for i in 0..CurrentNetwork::MAX_DATA_ENTRIES {
            string += &format!("    member_{i} as field.private;\n");
        }
        let candidate = RecordType::<CurrentNetwork>::parse(&string);
        assert!(candidate.is_ok());
    }

    #[test]
    fn test_parse_too_many_members() {
        let mut string = "record message:\n    owner as address.private;\n".to_string();
        for i in 0..=CurrentNetwork::MAX_DATA_ENTRIES {
            string += &format!("    member_{i} as field.private;\n");
        }
        let candidate = RecordType::<CurrentNetwork>::parse(&string);
        assert!(candidate.is_err());
    }
}
