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

impl<N: Network> Parser for StructType<N> {
    /// Parses a struct as:
    /// ```text
    ///   struct message:
    ///       owner as address;
    ///       amount as u64;
    /// ```
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses a string into a tuple.
        fn parse_tuple<N: Network>(string: &str) -> ParserResult<'_, (Identifier<N>, PlaintextType<N>)> {
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
            // Parse the plaintext type from the string.
            let (string, plaintext_type) = PlaintextType::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the semicolon ';' keyword from the string.
            let (string, _) = tag(";")(string)?;
            // Return the identifier and plaintext type.
            Ok((string, (identifier, plaintext_type)))
        }

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the type name from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the struct name from the string.
        let (string, name) = Identifier::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the members from the string.
        let (string, members) = map_res(many1(parse_tuple), |members| {
            // Ensure the members has no duplicate names.
            if has_duplicates(members.iter().map(|(identifier, _)| identifier)) {
                return Err(error(format!("Duplicate identifier found in struct '{name}'")));
            }
            // Ensure the number of members is within the maximum limit.
            if members.len() > N::MAX_STRUCT_ENTRIES {
                return Err(error("Failed to parse struct: too many members"));
            }
            Ok(members)
        })(string)?;
        // Return the struct.
        Ok((string, Self { name, members: IndexMap::from_iter(members) }))
    }
}

impl<N: Network> FromStr for StructType<N> {
    type Err = Error;

    /// Returns a struct from a string literal.
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

impl<N: Network> Debug for StructType<N> {
    /// Prints the struct type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

#[allow(clippy::format_push_string)]
impl<N: Network> Display for StructType<N> {
    /// Prints the struct type as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut output = format!("{} {}:\n", Self::type_name(), self.name);
        for (identifier, plaintext_type) in &self.members {
            output += &format!("    {identifier} as {plaintext_type};\n");
        }
        output.pop(); // trailing newline
        write!(f, "{output}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() -> Result<()> {
        let expected = StructType::<CurrentNetwork> {
            name: Identifier::from_str("message")?,
            members: IndexMap::from_iter(vec![
                (Identifier::from_str("sender")?, PlaintextType::from_str("address")?),
                (Identifier::from_str("amount")?, PlaintextType::from_str("u64")?),
            ]),
        };

        let (remainder, candidate) = StructType::<CurrentNetwork>::parse(
            r"
struct message:
    sender as address;
    amount as u64;
",
        )?;
        assert_eq!("\n", remainder);
        assert_eq!(expected, candidate);
        Ok(())
    }

    #[test]
    fn test_parse_fails() {
        // Must be non-empty.
        assert!(StructType::<CurrentNetwork>::parse("").is_err());
        assert!(StructType::<CurrentNetwork>::parse("struct message:").is_err());

        // Invalid characters.
        assert!(StructType::<CurrentNetwork>::parse("{}").is_err());
        assert!(StructType::<CurrentNetwork>::parse("_").is_err());
        assert!(StructType::<CurrentNetwork>::parse("__").is_err());
        assert!(StructType::<CurrentNetwork>::parse("___").is_err());
        assert!(StructType::<CurrentNetwork>::parse("-").is_err());
        assert!(StructType::<CurrentNetwork>::parse("--").is_err());
        assert!(StructType::<CurrentNetwork>::parse("---").is_err());
        assert!(StructType::<CurrentNetwork>::parse("*").is_err());
        assert!(StructType::<CurrentNetwork>::parse("**").is_err());
        assert!(StructType::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(StructType::<CurrentNetwork>::parse("1").is_err());
        assert!(StructType::<CurrentNetwork>::parse("2").is_err());
        assert!(StructType::<CurrentNetwork>::parse("3").is_err());
        assert!(StructType::<CurrentNetwork>::parse("1foo").is_err());
        assert!(StructType::<CurrentNetwork>::parse("12").is_err());
        assert!(StructType::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let struct_ =
            StructType::<CurrentNetwork>::parse("foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy");
        assert!(struct_.is_err());
    }

    #[test]
    fn test_display() {
        let expected = "struct message:\n    first as field;\n    second as field;";
        let message = StructType::<CurrentNetwork>::parse(expected).unwrap().1;
        assert_eq!(expected, format!("{message}"));
    }

    #[test]
    fn test_display_fails() {
        // Duplicate identifier.
        let candidate =
            StructType::<CurrentNetwork>::parse("struct message:\n    first as field;\n    first as field;");
        assert!(candidate.is_err());
        // Visibility in plaintext type.
        let candidate = StructType::<CurrentNetwork>::parse(
            "struct message:\n    first as field.public;\n    first as field.private;",
        );
        assert!(candidate.is_err());
    }

    #[test]
    fn test_max_members() {
        let mut string = "struct message:\n".to_string();
        for i in 0..CurrentNetwork::MAX_STRUCT_ENTRIES {
            string += &format!("    member_{i} as field;\n");
        }
        assert!(StructType::<CurrentNetwork>::parse(&string).is_ok());
    }

    #[test]
    fn test_too_many_members() {
        let mut string = "struct message:\n".to_string();
        for i in 0..=CurrentNetwork::MAX_STRUCT_ENTRIES {
            string += &format!("    member_{i} as field;\n");
        }
        assert!(StructType::<CurrentNetwork>::parse(&string).is_err());
    }
}
