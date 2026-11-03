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

impl<N: Network> Parser for Plaintext<N> {
    /// Parses a string into a plaintext value.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the string into a plaintext value.
        Self::parse_internal(string, 0)
    }
}

impl<N: Network> Plaintext<N> {
    /// Parses a sanitized pair: `identifier: plaintext`.
    fn parse_pair(string: &str, depth: usize) -> ParserResult<'_, (Identifier<N>, Self)> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the identifier from the string.
        let (string, identifier) = Identifier::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the ":" from the string.
        let (string, _) = tag(":")(string)?;
        // Parse the plaintext from the string.
        let (string, plaintext) = Self::parse_internal(string, depth + 1)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Return the identifier and plaintext.
        Ok((string, (identifier, plaintext)))
    }

    /// Parses a plaintext as a struct: `{ identifier_0: plaintext_0, ..., identifier_n: plaintext_n }`.
    fn parse_struct(string: &str, depth: usize) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "{" from the string.
        let (string, _) = tag("{")(string)?;
        // Parse the members.
        let (string, members) =
            map_res(separated_list1(tag(","), |input| Self::parse_pair(input, depth)), |members: Vec<_>| {
                // Ensure the members has no duplicate names.
                if has_duplicates(members.iter().map(|(name, ..)| name)) {
                    return Err(error("Duplicate member in struct"));
                }
                // Ensure the number of structs is within the maximum limit.
                match members.len() <= N::MAX_STRUCT_ENTRIES {
                    true => Ok(members),
                    false => Err(error(format!("Found a plaintext that exceeds size ({})", members.len()))),
                }
            })(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the '}' from the string.
        let (string, _) = tag("}")(string)?;
        // Output the plaintext.
        Ok((string, Self::Struct(IndexMap::from_iter(members), Default::default())))
    }

    /// Parses a plaintext as an array: `[plaintext_0, ..., plaintext_n]`.
    fn parse_array(string: &str, depth: usize) -> ParserResult<'_, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the "[" from the string.
        let (string, _) = tag("[")(string)?;
        // Parse the members.
        let (string, members) = separated_list1(tag(","), |input| Self::parse_internal(input, depth + 1))(string)?;
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the ']' from the string.
        let (string, _) = tag("]")(string)?;
        // Output the plaintext.
        Ok((string, Self::Array(members, Default::default())))
    }

    /// Parses a string into a plaintext value, while tracking the depth of the data.
    fn parse_internal(string: &str, depth: usize) -> ParserResult<'_, Self> {
        // Ensure that the depth is within the maximum limit.
        if depth > N::MAX_DATA_DEPTH {
            return map_res(take(0usize), |_| {
                Err(error(format!("Found a plaintext that exceeds maximum data depth ({})", N::MAX_DATA_DEPTH)))
            })(string);
        }
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the struct or array from the string.
        // Parse to determine the plaintext (order matters).
        alt((
            // Parse a plaintext literal.
            map(Literal::parse, |literal| Self::Literal(literal, Default::default())),
            // Parse a plaintext struct.
            |input| Self::parse_struct(input, depth),
            // Parse a plaintext array.
            |input| Self::parse_array(input, depth),
        ))(string)
    }
}

impl<N: Network> FromStr for Plaintext<N> {
    type Err = Error;

    /// Returns a plaintext from a string literal.
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

impl<N: Network> Debug for Plaintext<N> {
    /// Prints the plaintext as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Plaintext<N> {
    /// Prints the plaintext as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.fmt_internal(f, 0)
    }
}

impl<N: Network> Plaintext<N> {
    /// Prints the plaintext with the given indentation depth.
    fn fmt_internal(&self, f: &mut Formatter, depth: usize) -> fmt::Result {
        /// The number of spaces to indent.
        const INDENT: usize = 2;

        match self {
            // Prints the literal, i.e. 10field
            Self::Literal(literal, ..) => write!(f, "{:indent$}{literal}", "", indent = depth * INDENT),
            // Prints the struct, i.e. { first: 10i64, second: 198u64 }
            Self::Struct(struct_, ..) => {
                // Print the opening brace.
                write!(f, "{{")?;
                // Print the members.
                struct_.iter().enumerate().try_for_each(|(i, (name, plaintext))| {
                    match plaintext {
                        Self::Literal(literal, ..) => match i == struct_.len() - 1 {
                            true => {
                                // Print the last member without a comma.
                                write!(f, "\n{:indent$}{name}: {literal}", "", indent = (depth + 1) * INDENT)?;
                                // Print the closing brace.
                                write!(f, "\n{:indent$}}}", "", indent = depth * INDENT)
                            }
                            // Print the member with a comma.
                            false => write!(f, "\n{:indent$}{name}: {literal},", "", indent = (depth + 1) * INDENT),
                        },
                        Self::Struct(..) | Self::Array(..) => {
                            // Print the member name.
                            write!(f, "\n{:indent$}{name}: ", "", indent = (depth + 1) * INDENT)?;
                            // Print the member.
                            plaintext.fmt_internal(f, depth + 1)?;
                            // Print the closing brace.
                            match i == struct_.len() - 1 {
                                // Print the last member without a comma.
                                true => write!(f, "\n{:indent$}}}", "", indent = depth * INDENT),
                                // Print the member with a comma.
                                false => write!(f, ","),
                            }
                        }
                    }
                })
            }
            // Prints the array, i.e. [ 10u64, 198u64 ]
            Self::Array(array, ..) => {
                // Print the opening bracket.
                write!(f, "[")?;
                // Print the members.
                array.iter().enumerate().try_for_each(|(i, plaintext)| {
                    match plaintext {
                        Self::Literal(literal, ..) => match i == array.len() - 1 {
                            true => {
                                // Print the last member without a comma.
                                write!(f, "\n{:indent$}{literal}", "", indent = (depth + 1) * INDENT)?;
                                // Print the closing bracket.
                                write!(f, "\n{:indent$}]", "", indent = depth * INDENT)
                            }
                            // Print the member with a comma.
                            false => write!(f, "\n{:indent$}{literal},", "", indent = (depth + 1) * INDENT),
                        },
                        Self::Struct(..) | Self::Array(..) => {
                            // Print a newline.
                            write!(f, "\n{:indent$}", "", indent = (depth + 1) * INDENT)?;
                            // Print the member.
                            plaintext.fmt_internal(f, depth + 1)?;
                            // Print the closing brace.
                            match i == array.len() - 1 {
                                // Print the last member without a comma.
                                true => write!(f, "\n{:indent$}]", "", indent = depth * INDENT),
                                // Print the member with a comma.
                                false => write!(f, ","),
                            }
                        }
                    }
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse_literal() -> Result<()> {
        // Sanity check.
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse("5u8")?;
        assert_eq!("5u8", candidate.to_string());
        assert_eq!("", remainder);

        Ok(())
    }

    #[test]
    fn test_parse_struct() -> Result<()> {
        // Sanity check.
        let expected = r"{
  foo: 5u8
}";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse("{ foo: 5u8 }")?;
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        let expected = r"{
  foo: 5u8,
  bar: {
    baz: 10field,
    qux: {
      quux: {
        corge: {
          grault: {
            garply: {
              waldo: {
                fred: {
                  plugh: {
                    xyzzy: {
                      thud: true
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(
            "{ foo: 5u8, bar: { baz: 10field, qux: {quux:{corge :{grault:  {garply:{waldo:{fred:{plugh:{xyzzy: { thud: true}} }}}  }}}}}}",
        )?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        Ok(())
    }

    #[test]
    fn test_parse_fails() {
        // Must be non-empty.
        assert!(Plaintext::<CurrentNetwork>::parse("").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("{}").is_err());

        // Invalid characters.
        assert!(Plaintext::<CurrentNetwork>::parse("_").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("__").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("___").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("-").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("--").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("---").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("*").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("**").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("***").is_err());

        // Must not start with a number.
        assert!(Plaintext::<CurrentNetwork>::parse("1").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("2").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("3").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("1foo").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("12").is_err());
        assert!(Plaintext::<CurrentNetwork>::parse("111").is_err());

        // Must fit within the data capacity of a base field element.
        let plaintext =
            Plaintext::<CurrentNetwork>::parse("foo_bar_baz_qux_quux_quuz_corge_grault_garply_waldo_fred_plugh_xyzzy");
        assert!(plaintext.is_err());
    }

    #[test]
    fn test_nested_structs1() {
        let expected = r"{
  r1: {
    c1: 1u8,
    c2: 2u8,
    c3: 1u8
  },
  r2: {
    c1: 2u8,
    c2: 2u8,
    c3: 1u8
  },
  r3: {
    c1: 1u8,
    c2: 2u8,
    c3: 1u8
  }
}";

        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_nested_structs2() {
        let expected = r"{
  foo: {
    bar: {
      baz: 1u8
    },
    qux: {
      quux: 2u8
    }
  }
}";

        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_nested_structs3() {
        let expected = r"{
  c: {
    a: 0u8,
    b: 1u8
  },
  d: {
    a: 0u8,
    b: 1u8
  }
}";

        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_array() {
        // Test an array of literals.
        let expected = r"[
  1u8,
  2u8,
  3u8
]";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        // Test an array of structs.
        let expected = r"[
  {
    foo: 1u8,
    bar: 2u8
  },
  {
    foo: 3u8,
    bar: 4u8
  },
  {
    foo: 5u8,
    bar: 6u8
  }
]";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_struct_with_arrays() {
        let expected = r"{
  foo: [
    1u8,
    2u8,
    3u8
  ],
  bar: [
    4u8,
    5u8,
    6u8
  ]
}";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    #[test]
    fn test_struct_with_array_of_structs() {
        let expected = r"{
  foo: [
    {
      foo: 1u8,
      bar: 2u8
    },
    {
      foo: 3u8,
      bar: 4u8
    },
    {
      foo: 5u8,
      bar: 6u8
    }
  ],
  bar: [
    {
      foo: [
        1u8,
        2u8,
        3u8
      ],
      bar: [
        4u8,
        5u8,
        6u8
      ]
    },
    {
      foo: [
        7u8,
        8u8,
        9u8
      ],
      bar: [
        10u8,
        11u8,
        12u8
      ]
    },
    {
      foo: [
        13u8,
        14u8,
        15u8
      ],
      bar: [
        16u8,
        17u8,
        18u8
      ]
    }
  ]
}";
        let (remainder, candidate) = Plaintext::<CurrentNetwork>::parse(expected).unwrap();
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);
    }

    // A helper function to get the depth of the plaintext.
    fn get_depth(plaintext: &Plaintext<CurrentNetwork>) -> usize {
        match plaintext {
            Plaintext::Literal(_, _) => 0,
            Plaintext::Struct(members, _) => members.values().map(get_depth).max().unwrap_or(0) + 1,
            Plaintext::Array(elements, _) => elements.iter().map(get_depth).max().unwrap_or(0) + 1,
        }
    }

    #[test]
    fn test_deeply_nested_plaintext() {
        // Creates a string representation of a nested Plaintext array with the given depth and root.
        fn create_nested_array(depth: usize, root: impl Display) -> String {
            // Define the prefix and suffix based on the depth.
            let prefix = if depth == 0 { "".to_string() } else { "[".repeat(depth) };
            let suffix = if depth == 0 { "".to_string() } else { "]".repeat(depth) };
            // Format the string with the prefix, root, and suffix.
            format!("{prefix}{root}{suffix}")
        }

        // Creates a string representation of a nested Plaintext struct with the given depth and root.
        fn create_nested_struct(depth: usize, root: impl Display) -> String {
            // Define the prefix and suffix based on the depth.
            let prefix = if depth == 0 { "".to_string() } else { "{inner:".repeat(depth) };
            let suffix = if depth == 0 { "".to_string() } else { "}".repeat(depth) };
            // Format the string with the prefix, root, and suffix.
            format!("{prefix}{root}{suffix}")
        }

        // Creates a string representation of a nested Plaintext object with alternating structs and arrays with the given depth and root.
        fn create_alternated_nested(depth: usize, root: impl Display) -> String {
            let prefix = (0..depth).map(|i| if i % 2 == 0 { "[" } else { "{inner:" }).collect::<String>();
            let suffix = (0..depth).map(|i| if i % 2 == 0 { "]" } else { "}" }).rev().collect::<String>();
            format!("{prefix}{root}{suffix}")
        }

        // A helper function to run the test.
        fn run_test(expected_depth: usize, input: String, expected_error: bool) {
            // Parse the input string.
            let result = Plaintext::<CurrentNetwork>::parse(&input);
            // Check if the result is an error.
            match expected_error {
                true => {
                    assert!(result.is_err());
                    return;
                }
                false => assert!(result.is_ok()),
            };
            // Unwrap the result.
            let (remainder, candidate) = result.unwrap();
            // Check if the remainder is empty.
            assert!(remainder.is_empty());
            // Check if the candidate is equal to the input, with whitespace removed.
            assert_eq!(input, candidate.to_string().replace("\n", "").replace(" ", ""));
            // Check if the candidate is equal to the expected depth.
            assert_eq!(get_depth(&candidate), expected_depth);
        }

        // Initialize a sequence of depths to check.
        let mut depths = (0usize..100).collect_vec();
        depths.extend((100..1000).step_by(100));
        depths.extend((1000..10000).step_by(1000));
        depths.extend((10000..100000).step_by(10000));

        // Test deeply nested arrays with different literal types.
        for i in depths.iter().copied() {
            run_test(i, create_nested_array(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_array(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }

        // Test deeply nested structs with different literal types.
        for i in depths.iter().copied() {
            run_test(i, create_nested_struct(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_nested_struct(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }

        // Test alternating nested arrays and structs.
        for i in depths.iter().copied() {
            run_test(i, create_alternated_nested(i, "false"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "1u8"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "0u128"), i > CurrentNetwork::MAX_DATA_DEPTH);
            run_test(i, create_alternated_nested(i, "10field"), i > CurrentNetwork::MAX_DATA_DEPTH);
        }
    }
}
