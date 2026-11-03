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

impl<N: Network> Parser for Record<N, Plaintext<N>> {
    /// Parses a string as a record: `{ owner: address, identifier_0: entry_0, ..., identifier_n: entry_n, _nonce: field, _version: u8 }`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        /// Parses a sanitized pair: `identifier: entry`.
        #[allow(clippy::type_complexity)]
        fn parse_pair<N: Network>(string: &str) -> ParserResult<'_, (Identifier<N>, Entry<N, Plaintext<N>>)> {
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
        let (string, owner) = alt((
            map(pair(Address::parse, tag(".public")), |(owner, _)| Owner::Public(owner)),
            map(pair(Address::parse, tag(".private")), |(owner, _)| {
                Owner::Private(Plaintext::from(Literal::Address(owner)))
            }),
        ))(string)?;
        // Parse the "," from the string.
        let (string, _) = tag(",")(string)?;

        // Parse the entries.
        let (string, entries) = map_res(separated_list0(tag(","), parse_pair), |entries: Vec<_>| {
            // Prepare the reserved entry names.
            let reserved = [Identifier::from_str("owner").map_err(|e| error(e.to_string()))?];
            // Ensure the entries has no duplicate names.
            if has_duplicates(entries.iter().map(|(identifier, _)| identifier).chain(reserved.iter())) {
                return Err(error("Duplicate entry type found in record"));
            }
            // Ensure the number of entries is within the maximum limit.
            match entries.len() <= N::MAX_DATA_ENTRIES {
                true => Ok(entries),
                false => Err(error(format!("Found a record that exceeds size ({})", entries.len()))),
            }
        })(string)?;

        // If there are entries, then parse the "," from the string.
        let string = match !entries.is_empty() {
            // Parse the "," from the string.
            true => tag(",")(string)?.0,
            false => string,
        };

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "_nonce" tag from the string.
        let (string, _) = tag("_nonce")(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the nonce from the string.
        let (string, (nonce, _)) = pair(Group::parse, tag(".public"))(string)?;

        // There may be an optional "_version" tag. Parse the "," from the string if it exists.
        let string = match opt(tag(","))(string)? {
            // If there is a version, then parse the "," from the string.
            (string, Some(_)) => string,
            // If there is no version, then keep the string as is.
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
                // Parse the whitespace and comments from the string.
                let (string, _) = Sanitizer::parse(string)?;
                // Parse the ":" from the string.
                let (string, _) = tag(":")(string)?;
                // Parse the whitespace and comments from the string.
                let (string, _) = Sanitizer::parse(string)?;
                // Parse the version from the string.
                terminated(U8::parse, tag(".public"))(string)?
            }
        };

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the '}' from the string.
        let (string, _) = tag("}")(string)?;
        // Output the record.
        Ok((string, Record { owner, data: IndexMap::from_iter(entries), nonce, version }))
    }
}

impl<N: Network> FromStr for Record<N, Plaintext<N>> {
    type Err = Error;

    /// Returns a record from a string literal.
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

impl<N: Network> Debug for Record<N, Plaintext<N>> {
    /// Prints the record as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Record<N, Plaintext<N>> {
    /// Prints the record as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.fmt_internal(f, 0)
    }
}

impl<N: Network> Record<N, Plaintext<N>> {
    /// Prints the record with the given indentation depth.
    fn fmt_internal(&self, f: &mut Formatter, depth: usize) -> fmt::Result {
        /// The number of spaces to indent.
        const INDENT: usize = 2;

        // Print the opening brace.
        write!(f, "{{")?;
        // Print the owner with a comma.
        write!(f, "\n{:indent$}owner: {},", "", self.owner, indent = (depth + 1) * INDENT)?;
        // Print the data with a comma.
        for (identifier, entry) in self.data.iter() {
            // Print the identifier.
            write!(f, "\n{:indent$}{identifier}: ", "", indent = (depth + 1) * INDENT)?;
            // Print the entry.
            match entry {
                // If the entry is a literal, print the entry without indentation.
                Entry::Constant(Plaintext::Literal(..))
                | Entry::Public(Plaintext::Literal(..))
                | Entry::Private(Plaintext::Literal(..)) => write!(f, "{entry}")?,
                // If the entry is a struct or an array, print the entry with indentation.
                Entry::Constant(Plaintext::Struct(..))
                | Entry::Public(Plaintext::Struct(..))
                | Entry::Private(Plaintext::Struct(..))
                | Entry::Constant(Plaintext::Array(..))
                | Entry::Public(Plaintext::Array(..))
                | Entry::Private(Plaintext::Array(..)) => entry.fmt_internal(f, depth + 1)?,
            }
            // Print the comma.
            write!(f, ",")?;
        }
        // Print the nonce with a comma.
        write!(f, "\n{:indent$}_nonce: {}.public,", "", self.nonce, indent = (depth + 1) * INDENT)?;
        // Print the version without a comma.
        write!(f, "\n{:indent$}_version: {}.public", "", self.version, indent = (depth + 1) * INDENT)?;
        // Print the closing brace.
        write!(f, "\n{:indent$}}}", "", indent = depth * INDENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_without_version() -> Result<()> {
        // Sanity check.
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let given =
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, _nonce: 0group.public }";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(given)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_parse_with_version() -> Result<()> {
        // Sanity check.
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let given = "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, _nonce: 0group.public, _version: 0u8.public }";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(given)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        // Sanity check.
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
  _nonce: 0group.public,
  _version: 1u8.public
}";
        let given = "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, _nonce: 0group.public, _version: 1u8.public }";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(given)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_parse_without_data_entries() -> Result<()> {
        // Sanity check.
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private,
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let given =
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.private, _nonce: 0group.public }";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(given)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_parse_with_literal_entry() -> Result<()> {
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
  foo: 5u8.constant,
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let given = "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public, foo: 5u8.constant, _nonce: 0group.public }";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(given)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_parse_with_struct_entry() -> Result<()> {
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
  foo: 5u8.public,
  bar: {
    baz: 6u8.constant,
    qux: 7u8.constant
  },
  quux: 8u8.private,
  corge: {
    grault: 9u8.constant,
    garply: {
      waldo: 10u8.constant,
      fred: 11u8.constant
    }
  },
  xyzzy: {
    thud: 12u8.public
  },
  _nonce: 2293253577170800572742339369209137467208538700597121244293392265726446806023group.public,
  _version: 0u8.public
}";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(expected)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        let expected = r"{
  owner: aleo1lhcpfumagern97esytsgdva2ytme043zydlzyprhejsd0gw5vypqqz0zkw.private,
  foo: {
    bar: 0u128.private
  },
  baz: {
    quine: {
      flop: 0u64.private
    },
    slice: 0u16.private,
    flag: true.private,
    square: {
      first: 0u128.private,
      second: 1u128.private,
      third: 2u128.private,
      fourth: 3u128.private
    }
  },
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(expected)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        let expected = r"{
  owner: aleo18ttcegpydcs95yw4je0u400j3u7r26yqr9h8evqps3qa9slrvyrsqjwt9l.private,
  c: {
    c: {
      a: 0u8.private,
      b: 1u8.private
    },
    d: {
      a: 0u8.private,
      b: 1u8.private
    }
  },
  d: {
    c: {
      a: 0u8.private,
      b: 1u8.private
    },
    d: {
      a: 0u8.private,
      b: 1u8.private
    }
  },
  _nonce: 8102307625287186026775464343238779600702564007094834161216556016558567413871group.public,
  _version: 0u8.public
}";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(expected)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        Ok(())
    }

    #[test]
    fn test_parse_with_array_entry() -> Result<()> {
        let expected = r"{
  owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public,
  foo: 5u8.public,
  bar: [
    6u8.private,
    7u8.private,
    8u8.private
  ],
  _nonce: 0group.public,
  _version: 0u8.public
}";
        let (remainder, candidate) = Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(expected)?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
        Ok(())
    }

    #[test]
    fn test_parse_fails() -> Result<()> {
        // Missing owner.
        let expected = "{ foo: 5u8.private, _nonce: 0group.public }";
        assert!(Plaintext::<CurrentNetwork>::parse(expected).is_err());

        // Missing nonce.
        let expected =
            "{ owner: aleo1d5hg2z3ma00382pngntdp68e74zv54jdxy249qhaujhks9c72yrs33ddah.public, foo: 5u8.private }";
        assert!(Plaintext::<CurrentNetwork>::parse(expected).is_err());

        // Entry 'd' contains members with different visibility.
        let expected = r"{
    owner: aleo14tlamssdmg3d0p5zmljma573jghe2q9n6wz29qf36re2glcedcpqfg4add.private,
    a: true.private,
    b: 123456789field.private,
    c: 0group.private,
    d: {
        e: true.private,
        f: 123456789field.public,
        g: 0group.private
    },
    _nonce: 0group.public,
    _version: 0u8.public
}";
        assert!(Plaintext::<CurrentNetwork>::parse(expected).is_err());
        Ok(())
    }
}
